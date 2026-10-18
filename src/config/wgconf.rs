use std::net::{IpAddr, SocketAddr};

use ipnetwork::IpNetwork;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum WgConfError {
    #[error("line {line}: expected key = value")]
    Syntax { line: usize },
    #[error("line {line}: invalid {key} value {value:?}")]
    Value {
        line: usize,
        key: String,
        value: String,
    },
    #[error("more than one [Peer] section is not supported")]
    MultiplePeers,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WgQuickConfig {
    pub private_key: Option<String>,
    pub addresses: Vec<IpNetwork>,
    pub public_key: Option<String>,
    pub preshared_key: Option<String>,
    pub endpoint_ip: Option<IpAddr>,
    pub endpoint_port: Option<u16>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Section {
    None,
    Interface,
    Peer,
}

/// Parses the subset of a wg-quick configuration needed to connect.
pub fn parse(content: &str) -> Result<WgQuickConfig, WgConfError> {
    let mut config = WgQuickConfig::default();
    let mut section = Section::None;
    let mut peers = 0_usize;
    for (index, raw_line) in content.lines().enumerate() {
        let line_number = index + 1;
        let line = raw_line
            .split_once('#')
            .map_or(raw_line, |(before, _)| before)
            .trim();
        if line.is_empty() {
            continue;
        }
        if line.eq_ignore_ascii_case("[interface]") {
            section = Section::Interface;
            continue;
        }
        if line.eq_ignore_ascii_case("[peer]") {
            peers += 1;
            if peers > 1 {
                return Err(WgConfError::MultiplePeers);
            }
            section = Section::Peer;
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .map(|(k, v)| (k.trim(), v.trim()))
            .ok_or(WgConfError::Syntax { line: line_number })?;
        let invalid = || WgConfError::Value {
            line: line_number,
            key: key.to_owned(),
            value: value.to_owned(),
        };
        match (section, key.to_ascii_lowercase().as_str()) {
            (Section::Interface, "privatekey") => config.private_key = Some(value.to_owned()),
            (Section::Interface, "address") => {
                for part in value.split(',').map(str::trim).filter(|p| !p.is_empty()) {
                    config
                        .addresses
                        .push(parse_address(part).ok_or_else(invalid)?);
                }
            }
            (Section::Peer, "publickey") => config.public_key = Some(value.to_owned()),
            (Section::Peer, "presharedkey") => config.preshared_key = Some(value.to_owned()),
            (Section::Peer, "endpoint") => {
                if let Ok(socket) = value.parse::<SocketAddr>() {
                    config.endpoint_ip = Some(socket.ip());
                    config.endpoint_port = Some(socket.port());
                } else if let Ok(ip) = value.parse::<IpAddr>() {
                    config.endpoint_ip = Some(ip);
                } else {
                    return Err(invalid());
                }
            }
            _ => {}
        }
    }
    Ok(config)
}

fn parse_address(value: &str) -> Option<IpNetwork> {
    if value.contains('/') {
        return value.parse().ok();
    }
    let ip: IpAddr = value.parse().ok()?;
    let prefix = if ip.is_ipv4() { 32 } else { 128 };
    IpNetwork::new(ip, prefix).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_mullvad_style_config() {
        let content = "\
[Interface]
# Device: Tidy Fox
PrivateKey = wOEI9rqqbDwnN8/Bpp22sVz48T71vJ4fYmFWujulwUU=
Address = 10.64.222.21/32,fc00:bbbb:bbbb:bb01::1:de14/128
DNS = 10.64.0.1

[Peer]
PublicKey = 5JMPeO7gXIbR5CnUa/NPNK4L5GqUnreF0/Bozai4pl4=
AllowedIPs = 0.0.0.0/0,::0/0
Endpoint = 185.213.154.66:51820
";
        let config = parse(content).expect("valid config");
        assert_eq!(
            config.private_key.as_deref(),
            Some("wOEI9rqqbDwnN8/Bpp22sVz48T71vJ4fYmFWujulwUU=")
        );
        assert_eq!(config.addresses.len(), 2);
        assert_eq!(config.endpoint_port, Some(51820));
        assert_eq!(
            config.endpoint_ip,
            Some("185.213.154.66".parse().expect("ip"))
        );
    }

    #[test]
    fn rejects_multiple_peers() {
        assert_eq!(parse("[Peer]\n[Peer]\n"), Err(WgConfError::MultiplePeers));
    }

    #[test]
    fn bare_address_gets_host_prefix() {
        let config = parse("[Interface]\nAddress = 10.2.0.2\n").expect("valid");
        assert_eq!(config.addresses[0].prefix(), 32);
    }
}
