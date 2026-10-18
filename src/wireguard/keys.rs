use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use x25519_dalek::{PublicKey, StaticSecret};

pub const KEY_LEN: usize = 32;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum KeyError {
    #[error("not valid base64: {0}")]
    Base64(String),
    #[error("decoded key is {0} bytes instead of {KEY_LEN}")]
    Length(usize),
}

pub fn decode_key(encoded: &str) -> Result<[u8; KEY_LEN], KeyError> {
    let bytes = STANDARD
        .decode(encoded.trim())
        .map_err(|err| KeyError::Base64(err.to_string()))?;
    <[u8; KEY_LEN]>::try_from(bytes.as_slice()).map_err(|_| KeyError::Length(bytes.len()))
}

pub fn encode_key(key: &[u8; KEY_LEN]) -> String {
    STANDARD.encode(key)
}

pub fn generate_private_key() -> [u8; KEY_LEN] {
    let mut key = [0_u8; KEY_LEN];
    rand::fill(&mut key);
    clamp(&mut key);
    key
}

pub fn public_key(private_key: &[u8; KEY_LEN]) -> [u8; KEY_LEN] {
    PublicKey::from(&StaticSecret::from(*private_key)).to_bytes()
}

fn clamp(key: &mut [u8; KEY_LEN]) {
    key[0] &= 248;
    key[31] = (key[31] & 127) | 64;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_roundtrip() {
        let encoded = "wOEI9rqqbDwnN8/Bpp22sVz48T71vJ4fYmFWujulwUU=";
        let key = decode_key(encoded).expect("valid key");
        assert_eq!(encode_key(&key), encoded);
    }

    #[test]
    fn decode_rejects_bad_input() {
        assert!(matches!(
            decode_key("not base64!"),
            Err(KeyError::Base64(_))
        ));
        assert_eq!(decode_key("AAAA"), Err(KeyError::Length(3)));
    }

    fn hex(value: &str) -> [u8; KEY_LEN] {
        let mut out = [0_u8; KEY_LEN];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&value[i * 2..i * 2 + 2], 16).expect("hex");
        }
        out
    }

    #[test]
    fn rfc7748_public_key() {
        let private = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let expected = hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        assert_eq!(public_key(&private), expected);
    }

    #[test]
    fn generated_key_is_clamped() {
        let key = generate_private_key();
        assert_eq!(key[0] & 7, 0);
        assert_eq!(key[31] & 128, 0);
        assert_eq!(key[31] & 64, 64);
    }
}
