use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use shadowsocks_service::net::packet_window::PacketWindowFilter;
use shadowsocks_service::shadowsocks::{
    ServerConfig,
    config::{ReplayAttackPolicy, ServerType},
    context::Context,
    crypto::{CipherCategory, CipherKind},
    relay::{
        socks5::Address,
        tcprelay::{ProxyListener, ProxyServerStream},
        udprelay::{
            crypto_io::{decrypt_client_payload, encrypt_server_payload},
            options::UdpSocketControlData,
        },
    },
};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{Semaphore, mpsc, watch};
use tokio::task::JoinSet;
use tokio::time::Instant;

use crate::config::ShadowsocksSettings;
use crate::vpn::Status;

const MAX_TCP_CLIENTS: usize = 128;
const MAX_UDP_SESSIONS: usize = 128;
const MAX_UDP_FLOWS: usize = 512;
const UDP_QUEUE: usize = 16;
const SETUP_TIMEOUT: Duration = Duration::from_secs(15);
const UDP_IDLE: Duration = Duration::from_secs(60);
const SESSION_IDLE: Duration = Duration::from_secs(120);

pub fn server_config(settings: &ShadowsocksSettings) -> io::Result<ServerConfig> {
    let method: CipherKind = settings.cipher.parse().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "unsupported Shadowsocks cipher",
        )
    })?;
    if !matches!(
        method.category(),
        CipherCategory::Aead | CipherCategory::Aead2022
    ) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Shadowsocks requires an authenticated AEAD cipher",
        ));
    }
    if settings.password.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "missing Shadowsocks password",
        ));
    }
    ServerConfig::new(settings.listen_address, settings.password.expose(), method).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid Shadowsocks key for cipher",
        )
    })
}

pub struct Server {
    tcp: ProxyListener,
    udp: Arc<EncryptedUdp>,
    log: bool,
}

struct EncryptedUdp {
    socket: UdpSocket,
    context: Arc<Context>,
    config: ServerConfig,
}

impl Server {
    pub async fn bind(settings: ShadowsocksSettings) -> io::Result<Self> {
        let mut config = server_config(&settings)?;
        let mut context = Context::new(ServerType::Server);
        context.set_replay_attack_policy(ReplayAttackPolicy::Reject);
        let context = Arc::new(context);
        let tcp = ProxyListener::bind(Arc::clone(&context), &config).await?;
        config.set_addr(tcp.local_addr()?);
        let socket = UdpSocket::bind(tcp.local_addr()?).await?;
        Ok(Self {
            tcp,
            log: settings.log,
            udp: Arc::new(EncryptedUdp {
                socket,
                context,
                config,
            }),
        })
    }

    pub async fn run(self, mut status: watch::Receiver<Status>) -> io::Result<()> {
        tracing::info!(address = %self.tcp.local_addr()?, "Shadowsocks TCP/UDP proxy listening");
        let permits = Arc::new(Semaphore::new(MAX_TCP_CLIENTS));
        let mut tasks = JoinSet::new();
        let mut sessions = HashMap::<ClientKey, Session>::new();
        let mut flows = HashMap::<(ClientKey, Address), mpsc::Sender<Vec<u8>>>::new();
        let mut cleanup = tokio::time::interval(Duration::from_secs(1));
        let mut buffer = vec![0u8; 65536];
        loop {
            tokio::select! {
                biased;
                changed = status.changed() => {
                    tasks.abort_all();
                    while tasks.join_next().await.is_some() {}
                    flows.clear();
                    if changed.is_err() { return Ok(()); }
                    status.borrow_and_update();
                }
                result = tasks.join_next(), if !tasks.is_empty() => {
                    if let Some(Err(error)) = result && !error.is_cancelled() {
                        return Err(io::Error::other(error));
                    }
                }
                _ = cleanup.tick() => {
                    flows.retain(|_, sender| !sender.is_closed());
                    sessions.retain(|_, session| session.last_seen.elapsed() < SESSION_IDLE);
                    flows.retain(|(client, _), _| sessions.contains_key(client));
                }
                accepted = self.tcp.accept() => {
                    let (client, peer) = accepted?;
                    if !matches!(&*status.borrow(), Status::Running(_)) { continue; }
                    let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else { continue; };
                    let log = self.log;
                    tasks.spawn(async move {
                        let _permit = permit;
                        if let Err(error) = relay_tcp(client, log).await {
                            tracing::debug!(%peer, %error, "Shadowsocks TCP connection closed");
                        }
                    });
                }
                received = self.udp.receive(&mut buffer) => {
                    let (length, peer, target, control) = match received {
                        Ok(packet) => packet,
                        Err(error) => {
                            tracing::debug!(%error, "rejected Shadowsocks UDP packet");
                            continue;
                        }
                    };
                    if !matches!(&*status.borrow(), Status::Running(_)) || target.port() == 0 { continue; }
                    let key = control.as_ref().map_or(ClientKey::Peer(peer), |data| ClientKey::Session(data.client_session_id));
                    if !sessions.contains_key(&key) {
                        if sessions.len() >= MAX_UDP_SESSIONS { continue; }
                        sessions.insert(key, Session::new(peer, control.as_ref())?);
                    }
                    let session = sessions.get_mut(&key).expect("session inserted");
                    if let Some(control) = control
                        && !session.window.validate_packet_id(control.packet_id, u64::MAX) {
                        continue;
                    }
                    if self.log { tracing::info!(%peer, %target, "Shadowsocks UDP relay"); }
                    session.last_seen = Instant::now();
                    session.reply.peer.send_replace(peer);
                    let flow_key = (key, target.clone());
                    if let Some(sender) = flows.get(&flow_key)
                        && !sender.is_closed() {
                        let _ = sender.try_send(buffer[..length].to_vec());
                        continue;
                    }
                    flows.retain(|_, sender| !sender.is_closed());
                    if flows.len() >= MAX_UDP_FLOWS { continue; }
                    let (sender, receiver) = mpsc::channel(UDP_QUEUE);
                    let _ = sender.try_send(buffer[..length].to_vec());
                    flows.insert(flow_key, sender);
                    let listener = Arc::clone(&self.udp);
                    let reply = Arc::clone(&session.reply);
                    tasks.spawn(async move {
                        if let Err(error) = relay_udp(listener, reply, target, receiver).await {
                            tracing::debug!(%error, "Shadowsocks UDP association closed");
                        }
                    });
                }
            }
        }
    }
}

impl EncryptedUdp {
    async fn receive(
        &self,
        buffer: &mut [u8],
    ) -> io::Result<(usize, SocketAddr, Address, Option<UdpSocketControlData>)> {
        let (length, peer) = self.socket.recv_from(buffer).await?;
        let method = self.config.method();
        let salt = if method.category() == CipherCategory::Aead {
            buffer
                .get(..method.salt_len())
                .filter(|_| length >= method.salt_len())
                .map(<[u8]>::to_vec)
        } else {
            None
        };
        let (length, target, control) = decrypt_client_payload(
            &self.context,
            method,
            self.config.key(),
            &mut buffer[..length],
            None,
        )
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid encrypted UDP packet"))?;
        // The core decryptor deliberately omits classic AEAD UDP replay checks.
        if let Some(salt) = salt {
            self.context.check_nonce_replay(method, &salt)?;
        }
        Ok((length, peer, target, control))
    }

    async fn send(
        &self,
        peer: SocketAddr,
        source: &Address,
        control: &UdpSocketControlData,
        payload: &[u8],
    ) -> io::Result<()> {
        let mut packet = Default::default();
        encrypt_server_payload(
            &self.context,
            self.config.method(),
            self.config.key(),
            source,
            control,
            payload,
            &mut packet,
        );
        self.socket.send_to(&packet, peer).await?;
        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum ClientKey {
    Peer(SocketAddr),
    Session(u64),
}

struct Session {
    window: PacketWindowFilter,
    reply: Arc<Reply>,
    last_seen: Instant,
}

struct Reply {
    peer: watch::Sender<SocketAddr>,
    control: UdpSocketControlData,
    packet_id: AtomicU64,
}

impl Session {
    fn new(peer: SocketAddr, control: Option<&UdpSocketControlData>) -> io::Result<Self> {
        let mut control = control.cloned().unwrap_or_default();
        let mut random = [0u8; 8];
        getrandom::fill(&mut random).map_err(io::Error::other)?;
        control.server_session_id = u64::from_ne_bytes(random);
        let (peer, _) = watch::channel(peer);
        Ok(Self {
            window: PacketWindowFilter::new(),
            reply: Arc::new(Reply {
                peer,
                control,
                packet_id: AtomicU64::new(0),
            }),
            last_seen: Instant::now(),
        })
    }
}

async fn relay_tcp(mut client: ProxyServerStream<TcpStream>, log: bool) -> io::Result<()> {
    let mut remote = tokio::time::timeout(SETUP_TIMEOUT, async {
        let target = client.handshake().await?;
        if log {
            tracing::info!(%target, "Shadowsocks TCP relay");
        }
        if target.port() == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "zero destination port",
            ));
        }
        match target {
            Address::SocketAddress(address) => TcpStream::connect(address).await,
            Address::DomainNameAddress(host, port) => {
                TcpStream::connect((host.as_str(), port)).await
            }
        }
    })
    .await
    .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
    tokio::io::copy_bidirectional(&mut client, &mut remote).await?;
    Ok(())
}

async fn relay_udp(
    listener: Arc<EncryptedUdp>,
    reply: Arc<Reply>,
    target: Address,
    mut packets: mpsc::Receiver<Vec<u8>>,
) -> io::Result<()> {
    let remote = tokio::time::timeout(SETUP_TIMEOUT, async {
        let address = match target {
            Address::SocketAddress(address) => address,
            Address::DomainNameAddress(host, port) => {
                tokio::net::lookup_host((host.as_str(), port))
                    .await?
                    .next()
                    .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?
            }
        };
        let bind = if address.is_ipv4() {
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
        } else {
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
        };
        let socket = UdpSocket::bind(bind).await?;
        socket.connect(address).await?;
        Ok::<_, io::Error>(socket)
    })
    .await
    .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
    let source = Address::SocketAddress(remote.peer_addr()?);
    let idle = tokio::time::sleep(UDP_IDLE);
    tokio::pin!(idle);
    let mut buffer = vec![0u8; 65536];
    loop {
        tokio::select! {
            _ = &mut idle => return Ok(()),
            packet = packets.recv() => {
                let Some(packet) = packet else { return Ok(()); };
                remote.send(&packet).await?;
                idle.as_mut().reset(Instant::now() + UDP_IDLE);
            }
            received = remote.recv(&mut buffer) => {
                let length = received?;
                let mut control = reply.control.clone();
                control.packet_id = reply.packet_id.try_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
                    .map_err(|_| io::Error::other("Shadowsocks UDP packet counter exhausted"))?;
                let peer = *reply.peer.borrow();
                tokio::time::timeout(SETUP_TIMEOUT, listener.send(peer, &source, &control, &buffer[..length]))
                    .await.map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shadowsocks_service::shadowsocks::relay::{
        tcprelay::ProxyClientStream,
        udprelay::crypto_io::{decrypt_server_payload, encrypt_client_payload},
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    const CIPHERS: [(&str, &str); 3] = [
        ("chacha20-ietf-poly1305", "test-password"),
        ("aes-256-gcm", "test-password"),
        (
            "2022-blake3-aes-256-gcm",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        ),
    ];

    fn settings(cipher: &str, password: &str) -> ShadowsocksSettings {
        ShadowsocksSettings {
            enabled: true,
            listen_address: "127.0.0.1:0".parse().expect("address"),
            cipher: cipher.into(),
            password: crate::config::Secret::new(password),
            log: false,
        }
    }

    fn running() -> Status {
        Status::Running(crate::vpn::Tunnel {
            interface: "wg0".into(),
            connection: crate::models::Connection {
                ip: Ipv4Addr::LOCALHOST.into(),
                port: 51820,
                hostname: String::new(),
                server_name: String::new(),
                pubkey: String::new(),
            },
            ipv6: false,
        })
    }

    async fn within<F: std::future::Future>(future: F) -> F::Output {
        tokio::time::timeout(Duration::from_secs(3), future)
            .await
            .expect("completed in time")
    }

    #[test]
    fn rejects_invalid_ciphers_and_keys_without_disclosing_secrets() {
        for (cipher, password) in [
            ("none", "secret-value"),
            ("unsupported", "secret-value"),
            ("2022-blake3-aes-256-gcm", "secret-value"),
            ("aes-256-gcm", ""),
        ] {
            let error =
                server_config(&settings(cipher, password)).expect_err("invalid configuration");
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            assert!(!error.to_string().contains("secret-value"));
        }
    }

    #[tokio::test]
    async fn encrypted_tcp_closes_on_stop_and_server_abort() {
        for (cipher, password) in CIPHERS {
            for abort in [false, true] {
                let server = Server::bind(settings(cipher, password))
                    .await
                    .expect("proxy");
                let address = server.tcp.local_addr().expect("proxy address");
                let config = ServerConfig::new(address, password, cipher.parse().expect("cipher"))
                    .expect("config");
                let (status, receiver) = watch::channel(running());
                let mut task = tokio::spawn(server.run(receiver));
                let origin = TcpListener::bind("127.0.0.1:0").await.expect("origin");
                let destination = origin.local_addr().expect("origin address");
                let mut client = within(ProxyClientStream::connect(
                    Context::new_shared(ServerType::Local),
                    &config,
                    Address::SocketAddress(destination),
                ))
                .await
                .expect("encrypted client");
                client.write_all(b"hello").await.expect("encrypted request");
                let (mut upstream, _) = within(origin.accept()).await.expect("upstream");
                let mut buffer = [0u8; 5];
                within(upstream.read_exact(&mut buffer))
                    .await
                    .expect("plaintext request");
                assert_eq!(&buffer, b"hello");
                upstream
                    .write_all(b"world")
                    .await
                    .expect("plaintext response");
                within(client.read_exact(&mut buffer))
                    .await
                    .expect("encrypted response");
                assert_eq!(&buffer, b"world");
                if abort {
                    task.abort();
                    assert!((&mut task).await.expect_err("aborted").is_cancelled());
                } else {
                    status.send_replace(Status::Stopped);
                }
                assert_eq!(
                    within(upstream.read(&mut buffer))
                        .await
                        .expect("origin closed"),
                    0
                );
                assert_eq!(
                    within(client.read(&mut buffer))
                        .await
                        .expect("client closed"),
                    0
                );
                if !abort {
                    drop(status);
                    within(task)
                        .await
                        .expect("server joined")
                        .expect("server stopped");
                }
            }
        }
    }

    #[tokio::test]
    async fn encrypted_udp_roundtrip_replay_authentication_and_tunnel_stop() {
        for (cipher, password) in CIPHERS {
            let server = Server::bind(settings(cipher, password))
                .await
                .expect("proxy");
            let address = server.tcp.local_addr().expect("proxy address");
            let (status, receiver) = watch::channel(running());
            let task = tokio::spawn(server.run(receiver));
            let config = ServerConfig::new(address, password, cipher.parse().expect("cipher"))
                .expect("config");
            let context = Context::new(ServerType::Local);
            let origin = UdpSocket::bind("127.0.0.1:0").await.expect("origin");
            let target = Address::SocketAddress(origin.local_addr().expect("origin address"));
            let client = UdpSocket::bind("127.0.0.1:0").await.expect("client");
            client.connect(address).await.expect("connect");
            let mut control = UdpSocketControlData::default();
            control.client_session_id = 1234;
            control.packet_id = 1;
            let mut packet = Default::default();
            encrypt_client_payload(
                &context,
                config.method(),
                config.key(),
                &target,
                &control,
                &[],
                b"hello",
                &mut packet,
            );
            client.send(&packet).await.expect("encrypted request");
            let mut buffer = vec![0u8; 65536];
            let (length, upstream) = within(origin.recv_from(&mut buffer))
                .await
                .expect("origin request");
            assert_eq!(&buffer[..length], b"hello");
            origin
                .send_to(b"world", upstream)
                .await
                .expect("origin response");
            let length = within(client.recv(&mut buffer))
                .await
                .expect("encrypted response");
            let (length, source, response_control) = decrypt_server_payload(
                &context,
                config.method(),
                config.key(),
                &mut buffer[..length],
            )
            .expect("authenticated response");
            assert_eq!(&buffer[..length], b"world");
            assert_eq!(source, target);
            if let Some(control) = response_control {
                assert_eq!(control.client_session_id, 1234);
            }
            client.send(&packet).await.expect("replay");
            assert!(
                tokio::time::timeout(Duration::from_millis(150), origin.recv(&mut buffer))
                    .await
                    .is_err(),
                "replay reached origin: {cipher}"
            );
            let last = packet.len() - 1;
            packet[last] ^= 1;
            client.send(&packet).await.expect("invalid authentication");
            assert!(
                tokio::time::timeout(Duration::from_millis(150), origin.recv(&mut buffer))
                    .await
                    .is_err(),
                "unauthenticated packet reached origin"
            );
            status.send_replace(Status::Stopped);
            tokio::time::sleep(Duration::from_millis(20)).await;
            origin
                .send_to(b"late response", upstream)
                .await
                .expect("late response");
            assert!(
                tokio::time::timeout(Duration::from_millis(150), client.recv(&mut buffer))
                    .await
                    .is_err()
            );
            control.packet_id = 2;
            let mut next = Default::default();
            encrypt_client_payload(
                &context,
                config.method(),
                config.key(),
                &target,
                &control,
                &[],
                b"blocked",
                &mut next,
            );
            client.send(&next).await.expect("stopped request");
            assert!(
                tokio::time::timeout(Duration::from_millis(150), origin.recv(&mut buffer))
                    .await
                    .is_err()
            );
            status.send_replace(running());
            tokio::time::sleep(Duration::from_millis(20)).await;
            control.packet_id = 3;
            let mut next = Default::default();
            encrypt_client_payload(
                &context,
                config.method(),
                config.key(),
                &target,
                &control,
                &[],
                b"resumed",
                &mut next,
            );
            client.send(&next).await.expect("resumed request");
            let (length, _) = within(origin.recv_from(&mut buffer))
                .await
                .expect("resumed origin");
            assert_eq!(&buffer[..length], b"resumed");
            drop(status);
            within(task).await.expect("joined").expect("stopped");
        }
    }

    #[tokio::test]
    async fn wrong_tcp_password_never_connects_to_origin() {
        let server = Server::bind(settings("aes-256-gcm", "correct-password"))
            .await
            .expect("proxy");
        let address = server.tcp.local_addr().expect("address");
        let (_status, receiver) = watch::channel(running());
        let task = tokio::spawn(server.run(receiver));
        let origin = TcpListener::bind("127.0.0.1:0").await.expect("origin");
        let config =
            ServerConfig::new(address, "wrong-password", CipherKind::AES_256_GCM).expect("config");
        let mut client = ProxyClientStream::connect(
            Context::new_shared(ServerType::Local),
            &config,
            Address::SocketAddress(origin.local_addr().expect("address")),
        )
        .await
        .expect("client");
        client.write_all(b"hello").await.expect("write");
        let mut buffer = [0u8; 1];
        let result = within(client.read(&mut buffer)).await;
        assert!(result.is_err() || matches!(result, Ok(0)));
        assert!(
            tokio::time::timeout(Duration::from_millis(150), origin.accept())
                .await
                .is_err()
        );
        task.abort();
        let _ = task.await;
    }
}
