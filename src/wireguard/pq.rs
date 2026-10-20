use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use classic_mceliece_rust as mceliece;
use hyper_util::rt::TokioIo;
use ml_kem::array::typenum::Unsigned;
use ml_kem::ml_kem_1024::DecapsulationKey;
use ml_kem::{Decapsulate, Kem, KeyExport, MlKem1024};
use tokio::net::{TcpSocket, TcpStream};
use tonic::codegen::Service;
use tonic::codegen::http::Uri;
use tonic::codegen::http::uri::PathAndQuery;
use tonic::transport::Endpoint;

use super::keys::{KEY_LEN, generate_private_key, public_key};
use super::{Device, DeviceError};

pub const API_ADDRESS: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(10, 64, 0, 1), 1337);
const REGISTER_PATH: &str = "/ephemeralpeer.EphemeralPeer/RegisterPeerV1";
const MCELIECE_NAME: &str = "Classic-McEliece-460896f-round3";
const MLKEM_NAME: &str = "ML-KEM-1024";
const MLKEM_CIPHERTEXT_LEN: usize = <<MlKem1024 as Kem>::CiphertextSize as Unsigned>::USIZE;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
// Mullvad's client clamps the config connection to a 576-byte MTU so the
// half-megabyte McEliece key survives paths with broken PMTU discovery.
const CONFIG_CLIENT_MSS: u32 = 576 - 20 - 20;
// McEliece key generation recurses deeply and overflows the 2 MiB default.
const KEYGEN_STACK_SIZE: usize = 8 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum PqError {
    #[error("generating KEM keypairs: {0}")]
    KeyGeneration(#[source] io::Error),
    #[error("KEM key generation thread panicked")]
    KeyGenerationPanic,
    #[error("connecting to ephemeral peer API {API_ADDRESS}: {0}")]
    Connect(#[source] tonic::transport::Error),
    #[error("ephemeral peer API not ready: {0}")]
    NotReady(#[source] tonic::transport::Error),
    #[error("registering ephemeral peer: {0}")]
    Register(#[source] Box<tonic::Status>),
    #[error("ephemeral peer response has no post-quantum part")]
    MissingPostQuantum,
    #[error("expected {expected} ciphertexts, got {got}")]
    CiphertextCount { expected: usize, got: usize },
    #[error("{algorithm} ciphertext is {got} bytes instead of {expected}")]
    CiphertextLength {
        algorithm: &'static str,
        expected: usize,
        got: usize,
    },
    #[error("applying ephemeral key: {0}")]
    Device(#[source] DeviceError),
}

#[derive(Clone, PartialEq, prost::Message)]
struct EphemeralPeerRequestV1 {
    #[prost(bytes = "vec", tag = "1")]
    wg_parent_pubkey: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    wg_ephemeral_peer_pubkey: Vec<u8>,
    #[prost(message, optional, tag = "3")]
    post_quantum: Option<PostQuantumRequestV1>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct PostQuantumRequestV1 {
    #[prost(message, repeated, tag = "1")]
    kem_pubkeys: Vec<KemPubkeyV1>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct KemPubkeyV1 {
    #[prost(string, tag = "1")]
    algorithm_name: String,
    #[prost(bytes = "vec", tag = "2")]
    key_data: Vec<u8>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct EphemeralPeerResponseV1 {
    #[prost(message, optional, tag = "1")]
    post_quantum: Option<PostQuantumResponseV1>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct PostQuantumResponseV1 {
    #[prost(bytes = "vec", repeated, tag = "1")]
    ciphertexts: Vec<Vec<u8>>,
}

struct KemKeys {
    mceliece_public: mceliece::PublicKey<'static>,
    mceliece_secret: mceliece::SecretKey<'static>,
    mlkem: DecapsulationKey,
}

impl KemKeys {
    fn generate() -> Self {
        let (mceliece_public, mceliece_secret) = mceliece::keypair_boxed(&mut rand_core_06::OsRng);
        let (mlkem, _) = MlKem1024::generate_keypair();
        Self {
            mceliece_public,
            mceliece_secret,
            mlkem,
        }
    }

    async fn generate_off_runtime() -> Result<Self, PqError> {
        let (sender, receiver) = tokio::sync::oneshot::channel();
        std::thread::Builder::new()
            .name("pq-keygen".to_owned())
            .stack_size(KEYGEN_STACK_SIZE)
            .spawn(move || {
                let _ = sender.send(Self::generate());
            })
            .map_err(PqError::KeyGeneration)?;
        receiver.await.map_err(|_| PqError::KeyGenerationPanic)
    }

    fn request(&self) -> PostQuantumRequestV1 {
        PostQuantumRequestV1 {
            kem_pubkeys: vec![
                KemPubkeyV1 {
                    algorithm_name: MCELIECE_NAME.to_owned(),
                    key_data: self.mceliece_public.as_array().to_vec(),
                },
                KemPubkeyV1 {
                    algorithm_name: MLKEM_NAME.to_owned(),
                    key_data: self.mlkem.encapsulation_key().to_bytes().to_vec(),
                },
            ],
        }
    }

    fn preshared_key(&self, ciphertexts: &[Vec<u8>]) -> Result<[u8; KEY_LEN], PqError> {
        let [mceliece_ciphertext, mlkem_ciphertext] = ciphertexts else {
            return Err(PqError::CiphertextCount {
                expected: 2,
                got: ciphertexts.len(),
            });
        };

        let mceliece_ciphertext =
            <[u8; mceliece::CRYPTO_CIPHERTEXTBYTES]>::try_from(mceliece_ciphertext.as_slice())
                .map_err(|_| PqError::CiphertextLength {
                    algorithm: MCELIECE_NAME,
                    expected: mceliece::CRYPTO_CIPHERTEXTBYTES,
                    got: mceliece_ciphertext.len(),
                })?;
        let mceliece_secret = mceliece::decapsulate_boxed(
            &mceliece::Ciphertext::from(mceliece_ciphertext),
            &self.mceliece_secret,
        );

        let mlkem_secret = self
            .mlkem
            .decapsulate_slice(mlkem_ciphertext)
            .map_err(|_| PqError::CiphertextLength {
                algorithm: MLKEM_NAME,
                expected: MLKEM_CIPHERTEXT_LEN,
                got: mlkem_ciphertext.len(),
            })?;

        let mut psk = [0_u8; KEY_LEN];
        for secret in [
            mceliece_secret.as_array().as_slice(),
            mlkem_secret.as_slice(),
        ] {
            for (byte, value) in psk.iter_mut().zip(secret) {
                *byte ^= value;
            }
        }
        Ok(psk)
    }
}

#[derive(Clone, Copy, Debug)]
struct ClampedConnector {
    address: SocketAddr,
}

impl Service<Uri> for ClampedConnector {
    type Response = TokioIo<TcpStream>;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = io::Result<Self::Response>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _: Uri) -> Self::Future {
        let address = self.address;
        Box::pin(async move {
            let socket = socket2::Socket::new(
                socket2::Domain::for_address(address),
                socket2::Type::STREAM,
                Some(socket2::Protocol::TCP),
            )?;
            socket.set_tcp_mss(CONFIG_CLIENT_MSS)?;
            socket.set_nonblocking(true)?;
            let stream = TcpSocket::from_std_stream(socket.into())
                .connect(address)
                .await?;
            stream.set_nodelay(true)?;
            Ok(TokioIo::new(stream))
        })
    }
}

async fn register(request: EphemeralPeerRequestV1) -> Result<EphemeralPeerResponseV1, PqError> {
    let address = SocketAddr::V4(API_ADDRESS);
    let channel = Endpoint::from_static("http://10.64.0.1:1337")
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .connect_with_connector(ClampedConnector { address })
        .await
        .map_err(PqError::Connect)?;
    let mut client = tonic::client::Grpc::new(channel);
    client.ready().await.map_err(PqError::NotReady)?;
    let response = client
        .unary(
            tonic::Request::new(request),
            PathAndQuery::from_static(REGISTER_PATH),
            tonic_prost::ProstCodec::default(),
        )
        .await
        .map_err(|status| PqError::Register(Box::new(status)))?;
    Ok(response.into_inner())
}

pub async fn negotiate(device: &mut Device) -> Result<(), PqError> {
    let parent_public = public_key(&device.config().private_key);
    let ephemeral_private = generate_private_key();
    let keys = KemKeys::generate_off_runtime().await?;

    tracing::info!("negotiating quantum-resistant tunnel");
    let request = EphemeralPeerRequestV1 {
        wg_parent_pubkey: parent_public.to_vec(),
        wg_ephemeral_peer_pubkey: public_key(&ephemeral_private).to_vec(),
        post_quantum: Some(keys.request()),
    };
    let response = register(request).await?;
    let ciphertexts = response
        .post_quantum
        .ok_or(PqError::MissingPostQuantum)?
        .ciphertexts;
    let psk = keys.preshared_key(&ciphertexts)?;

    device
        .rekey(ephemeral_private, psk)
        .await
        .map_err(PqError::Device)?;
    tracing::info!("quantum-resistant tunnel established");
    Ok(())
}

#[cfg(test)]
mod tests {
    use ml_kem::Encapsulate;
    use prost::Message;

    use super::*;

    #[test]
    fn mullvad_round_three_ciphertext_includes_confirmation() {
        assert_eq!(mceliece::CRYPTO_CIPHERTEXTBYTES, 188);
        assert_eq!(mceliece::CRYPTO_PUBLICKEYBYTES, 524_160);
    }

    #[tokio::test]
    async fn preshared_key_is_xor_of_both_shared_secrets() {
        let keys = KemKeys::generate_off_runtime().await.expect("keygen");
        let request = keys.request();
        assert_eq!(request.kem_pubkeys[0].algorithm_name, MCELIECE_NAME);
        assert_eq!(
            request.kem_pubkeys[0].key_data.len(),
            mceliece::CRYPTO_PUBLICKEYBYTES
        );
        assert_eq!(request.kem_pubkeys[1].algorithm_name, MLKEM_NAME);

        let (mceliece_ciphertext, mceliece_shared) =
            mceliece::encapsulate_boxed(&keys.mceliece_public, &mut rand_core_06::OsRng);
        let (mlkem_ciphertext, mlkem_shared) = keys.mlkem.encapsulation_key().encapsulate();

        let mut expected = [0_u8; KEY_LEN];
        for (index, byte) in expected.iter_mut().enumerate() {
            *byte = mceliece_shared.as_array()[index] ^ mlkem_shared[index];
        }

        let psk = keys
            .preshared_key(&[
                mceliece_ciphertext.as_array().to_vec(),
                mlkem_ciphertext.to_vec(),
            ])
            .expect("valid ciphertexts");
        assert_eq!(psk, expected);
    }

    #[tokio::test]
    async fn preshared_key_rejects_malformed_ciphertexts() {
        let keys = KemKeys::generate_off_runtime().await.expect("keygen");
        assert!(matches!(
            keys.preshared_key(&[vec![0; 3]]),
            Err(PqError::CiphertextCount {
                expected: 2,
                got: 1
            })
        ));
        assert!(matches!(
            keys.preshared_key(&[vec![0; 3], vec![0; 1568]]),
            Err(PqError::CiphertextLength {
                algorithm: MCELIECE_NAME,
                ..
            })
        ));
        assert!(matches!(
            keys.preshared_key(&[vec![0; 156], vec![0; 1568]]),
            Err(PqError::CiphertextLength {
                algorithm: MCELIECE_NAME,
                expected: 188,
                got: 156
            })
        ));
        assert!(matches!(
            keys.preshared_key(&[vec![0; mceliece::CRYPTO_CIPHERTEXTBYTES], vec![0; 3]]),
            Err(PqError::CiphertextLength {
                algorithm: MLKEM_NAME,
                expected: 1568,
                got: 3
            })
        ));
    }

    #[test]
    fn response_decodes_and_skips_daita() {
        let response = EphemeralPeerResponseV1 {
            post_quantum: Some(PostQuantumResponseV1 {
                ciphertexts: vec![vec![1, 2], vec![3]],
            }),
        };
        let mut encoded = response.encode_to_vec();
        // field 2 (DaitaResponseV2), length-delimited, one unknown byte payload
        encoded.extend_from_slice(&[0x12, 0x01, 0x00]);
        let decoded = EphemeralPeerResponseV1::decode(encoded.as_slice()).expect("decodes");
        assert_eq!(decoded, response);
    }
}
