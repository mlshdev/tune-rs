use crate::models::Servers;

pub fn api_key() -> Result<String, getrandom::Error> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes)?;
    Ok(base58(&bytes))
}

fn base58(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut digits = Vec::<u8>::new();
    for byte in bytes {
        let mut carry = u32::from(*byte);
        for digit in &mut digits {
            carry += u32::from(*digit) * 256;
            *digit = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let mut encoded = "1".repeat(bytes.iter().take_while(|byte| **byte == 0).count());
    encoded.extend(
        digits
            .into_iter()
            .rev()
            .map(|digit| char::from(ALPHABET[usize::from(digit)])),
    );
    encoded
}

pub fn markdown_servers(servers: &Servers) -> String {
    let mut output = String::from(
        "# Mullvad WireGuard relays\n\n| Country | City | Hostname | ISP | Owned | IPv6 |\n| --- | --- | --- | --- | --- | --- |\n",
    );
    let escape = |value: &str| value.replace('|', "\\|").replace(['\n', '\r'], " ");
    for server in &servers.servers {
        output.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} |\n",
            escape(&server.country),
            escape(&server.city),
            escape(&server.hostname),
            escape(&server.isp),
            server.owned,
            server.has_ipv6()
        ));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base58_matches_known_vectors() {
        assert_eq!(base58(b"hello world"), "StV1DL6CwTryKyV");
        assert_eq!(base58(&[0, 0, 1]), "112");
        assert_eq!(base58(&[0; 16]), "1111111111111111");
        assert_eq!(base58(&[]), "");
        let key = api_key().expect("entropy");
        assert!((16..=22).contains(&key.len()));
        assert!(key.bytes().all(|value| {
            b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".contains(&value)
        }));
    }

    #[test]
    fn formats_bundled_mullvad_relays() {
        let data = crate::storage::hardcoded();
        let servers = &data[&crate::provider::ProviderName::Mullvad];
        let output = markdown_servers(servers);
        assert!(output.starts_with("# Mullvad WireGuard relays\n"));
        assert!(output.contains(&servers.servers[0].hostname));
        assert_eq!(
            output.lines().filter(|line| line.starts_with("| ")).count(),
            servers.servers.len() + 2
        );
    }
}
