use std::net::IpAddr;

use serde::{Deserialize, Serialize};

pub const VPN_WIREGUARD: &str = "wireguard";

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Server {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub vpn: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub country: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub city: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub isp: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub owned: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub server_name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub hostname: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub wgpubkey: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub keep: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ips: Vec<IpAddr>,
}

impl Server {
    pub fn key(&self) -> String {
        format!("{}-{}", self.vpn, self.hostname)
    }

    pub fn has_ipv6(&self) -> bool {
        self.ips.iter().any(IpAddr::is_ipv6)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Servers {
    pub version: u16,
    pub timestamp: i64,
    #[serde(default, skip_serializing_if = "is_false")]
    pub preferred: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub filepath: String,
    #[serde(default)]
    pub servers: Vec<Server>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct Connection {
    pub ip: IpAddr,
    pub port: u16,
    pub hostname: String,
    pub server_name: String,
    pub pubkey: String,
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_roundtrip_omits_defaults() {
        let server = Server {
            vpn: VPN_WIREGUARD.into(),
            hostname: "se-got-wg-001".into(),
            ips: vec!["185.213.154.66".parse().expect("valid ip")],
            ..Server::default()
        };
        let json = serde_json::to_string(&server).expect("serialize");
        assert_eq!(
            json,
            r#"{"vpn":"wireguard","hostname":"se-got-wg-001","ips":["185.213.154.66"]}"#
        );
        let decoded: Server = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded, server);
    }
}
