pub mod keys;
pub mod pq;

use std::net::SocketAddr;
use std::time::{Duration, SystemTime};

use ipnetwork::IpNetwork;
use nl_wireguard::{
    WireguardIpAddress, WireguardParsed, WireguardParsedDeviceFlags, WireguardParsedPeerFlags,
    WireguardPeerParsed,
};

use crate::netlink::{Family, Link, Netlink, NetlinkError, Route, Rule};
use keys::{KEY_LEN, encode_key};

pub const DEFAULT_FWMARK: u32 = 51820;
pub const DEFAULT_RULE_PRIORITY: u32 = 101;

#[derive(Debug, thiserror::Error)]
pub enum DeviceError {
    #[error("wireguard link {0}: {1}")]
    Link(String, #[source] NetlinkError),
    #[error("adding address {0}: {1}")]
    Address(IpNetwork, #[source] NetlinkError),
    #[error("adding route {0}: {1}")]
    Route(Box<Route>, #[source] NetlinkError),
    #[error("adding rule {0}: {1}")]
    Rule(Box<Rule>, #[source] NetlinkError),
    #[error("opening wireguard generic netlink socket: {0}")]
    Connect(#[source] std::io::Error),
    #[error("configuring wireguard device {0}: {1}")]
    Configure(String, #[source] nl_wireguard::WireguardError),
    #[error("reading wireguard device {0}: {1}")]
    Read(String, #[source] nl_wireguard::WireguardError),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceConfig {
    pub interface: String,
    pub private_key: [u8; KEY_LEN],
    pub peer_public_key: [u8; KEY_LEN],
    pub preshared_key: Option<[u8; KEY_LEN]>,
    pub endpoint: SocketAddr,
    pub addresses: Vec<IpNetwork>,
    pub allowed_ips: Vec<IpNetwork>,
    pub persistent_keepalive: Duration,
    pub mtu: u32,
    pub fwmark: u32,
    pub rule_priority: u32,
    pub ipv6: bool,
}

impl DeviceConfig {
    fn keeps(&self, network: &IpNetwork) -> bool {
        self.ipv6 || network.is_ipv4()
    }

    fn peer(
        &self,
        private_key: &[u8; KEY_LEN],
        preshared_key: Option<&[u8; KEY_LEN]>,
    ) -> WireguardParsed {
        let mut peer = WireguardPeerParsed::default();
        peer.public_key = Some(encode_key(&self.peer_public_key));
        peer.preshared_key = preshared_key.map(encode_key);
        peer.endpoint = Some(self.endpoint);
        let keepalive = u16::try_from(self.persistent_keepalive.as_secs()).unwrap_or(u16::MAX);
        peer.persistent_keepalive = (keepalive > 0).then_some(keepalive);
        peer.allowed_ips = Some(
            self.allowed_ips
                .iter()
                .filter(|network| self.keeps(network))
                .map(|network| WireguardIpAddress {
                    prefix_length: network.prefix(),
                    ip_addr: network.ip(),
                    flags: None,
                })
                .collect(),
        );
        peer.flags = Some(vec![WireguardParsedPeerFlags::ReplaceAllowedIps]);

        let mut device = WireguardParsed::default();
        device.iface_name = Some(self.interface.clone());
        device.private_key = Some(encode_key(private_key));
        device.fwmark = Some(self.fwmark);
        device.peers = Some(vec![peer]);
        device.flags = Some(vec![WireguardParsedDeviceFlags::ReplacePeers]);
        device
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PeerStats {
    pub last_handshake: Option<SystemTime>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

#[derive(Debug)]
enum Undo {
    DeleteLink(u32),
    SetDown(u32),
    DeleteRoute(Route),
    DeleteRule(Rule),
}

#[derive(Debug)]
pub struct Device {
    netlink: Netlink,
    config: DeviceConfig,
    link: Link,
    undo: Vec<Undo>,
}

impl Device {
    pub async fn up(netlink: Netlink, config: DeviceConfig) -> Result<Self, DeviceError> {
        let link = netlink
            .wireguard_add(&config.interface, config.mtu)
            .await
            .map_err(|error| DeviceError::Link(config.interface.clone(), error))?;
        let mut device = Self {
            netlink,
            config,
            undo: vec![Undo::DeleteLink(link.index)],
            link,
        };
        if let Err(error) = device.configure_all().await {
            device.down().await;
            return Err(error);
        }
        Ok(device)
    }

    async fn configure_all(&mut self) -> Result<(), DeviceError> {
        let index = self.link.index;
        for address in self
            .config
            .addresses
            .iter()
            .filter(|network| self.config.keeps(network))
        {
            self.netlink
                .address_add(index, *address)
                .await
                .map_err(|error| DeviceError::Address(*address, error))?;
        }

        tracing::info!(endpoint = %self.config.endpoint, "connecting");
        self.configure(
            &self.config.private_key.clone(),
            self.config.preshared_key.as_ref(),
        )
        .await?;

        self.netlink
            .link_set_up(index)
            .await
            .map_err(|error| DeviceError::Link(self.config.interface.clone(), error))?;
        self.undo.push(Undo::SetDown(index));

        for network in self
            .config
            .allowed_ips
            .clone()
            .iter()
            .filter(|network| self.config.keeps(network))
        {
            let mut route = Route::unicast(Family::of(network.ip()), self.config.fwmark);
            route.destination = Some(*network);
            route.output_interface = Some(index);
            match self.netlink.route_add(&route).await {
                Ok(()) => self.undo.push(Undo::DeleteRoute(route)),
                Err(error) if network.is_ipv6() && error.is_permission_denied() => {
                    tracing::error!(%route, %error, "cannot add IPv6 route, continuing without it");
                }
                Err(error) => return Err(DeviceError::Route(Box::new(route), error)),
            }
        }

        let families: &[Family] = if self.config.ipv6 {
            &[Family::V6, Family::V4]
        } else {
            &[Family::V4]
        };
        for family in families {
            let mut rule = Rule::to_table(*family, self.config.rule_priority, self.config.fwmark);
            rule.fwmark = Some(self.config.fwmark);
            rule.invert = true;
            if let Err(error) = self.netlink.rule_add(&rule).await {
                if error.is_exists() {
                    tracing::error!(
                        %rule,
                        "rule already exists; if running in Kubernetes, another container in the pod may use the same firewall mark"
                    );
                }
                return Err(DeviceError::Rule(Box::new(rule), error));
            }
            self.undo.push(Undo::DeleteRule(rule));
        }
        Ok(())
    }

    async fn configure(
        &self,
        private_key: &[u8; KEY_LEN],
        preshared_key: Option<&[u8; KEY_LEN]>,
    ) -> Result<(), DeviceError> {
        let (connection, mut handle, _) =
            nl_wireguard::new_connection().map_err(DeviceError::Connect)?;
        let task = tokio::spawn(connection);
        let result = handle
            .set(self.config.peer(private_key, preshared_key))
            .await
            .map_err(|error| DeviceError::Configure(self.config.interface.clone(), error));
        task.abort();
        result
    }

    pub async fn rekey(
        &mut self,
        private_key: [u8; KEY_LEN],
        preshared_key: [u8; KEY_LEN],
    ) -> Result<(), DeviceError> {
        self.configure(&private_key, Some(&preshared_key)).await?;
        self.config.private_key = private_key;
        self.config.preshared_key = Some(preshared_key);
        Ok(())
    }

    pub async fn stats(&self) -> Result<PeerStats, DeviceError> {
        let (connection, mut handle, _) =
            nl_wireguard::new_connection().map_err(DeviceError::Connect)?;
        let task = tokio::spawn(connection);
        let result = handle
            .get_by_name(&self.config.interface)
            .await
            .map_err(|error| DeviceError::Read(self.config.interface.clone(), error));
        task.abort();
        let peer_key = encode_key(&self.config.peer_public_key);
        let stats = result?
            .peers
            .unwrap_or_default()
            .into_iter()
            .find(|peer| peer.public_key.as_deref() == Some(peer_key.as_str()))
            .map(|peer| PeerStats {
                last_handshake: peer
                    .last_handshake
                    .filter(|since_epoch| !since_epoch.is_zero())
                    .map(|since_epoch| SystemTime::UNIX_EPOCH + since_epoch),
                rx_bytes: peer.rx_bytes.unwrap_or(0),
                tx_bytes: peer.tx_bytes.unwrap_or(0),
            })
            .unwrap_or_default();
        Ok(stats)
    }

    pub fn link(&self) -> &Link {
        &self.link
    }

    pub fn config(&self) -> &DeviceConfig {
        &self.config
    }

    pub async fn down(mut self) {
        while let Some(step) = self.undo.pop() {
            let result = match &step {
                Undo::DeleteRule(rule) => self.netlink.rule_delete(rule).await,
                Undo::DeleteRoute(route) => self.netlink.route_delete(route).await,
                Undo::SetDown(index) => self.netlink.link_set_down(*index).await,
                Undo::DeleteLink(index) => self.netlink.link_delete(*index).await,
            };
            if let Err(error) = result
                && !error.is_not_found()
            {
                tracing::error!(?step, %error, "wireguard cleanup failed");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(ipv6: bool) -> DeviceConfig {
        DeviceConfig {
            interface: "wg0".to_owned(),
            private_key: [1; KEY_LEN],
            peer_public_key: [2; KEY_LEN],
            preshared_key: None,
            endpoint: "[2a07:e340::1]:51820".parse().expect("valid endpoint"),
            addresses: vec![
                "10.64.0.2/32".parse().expect("valid"),
                "fc00::2/128".parse().expect("valid"),
            ],
            allowed_ips: vec![
                "0.0.0.0/0".parse().expect("valid"),
                "::/0".parse().expect("valid"),
            ],
            persistent_keepalive: Duration::from_secs(25),
            mtu: 1320,
            fwmark: DEFAULT_FWMARK,
            rule_priority: DEFAULT_RULE_PRIORITY,
            ipv6,
        }
    }

    #[test]
    fn peer_config_drops_ipv6_allowed_ips_without_ipv6() {
        let config = config(false);
        let device = config.peer(&config.private_key, None);
        let peers = device.peers.expect("one peer");
        let allowed = peers[0].allowed_ips.as_ref().expect("allowed IPs");
        assert_eq!(allowed.len(), 1);
        assert!(allowed[0].ip_addr.is_ipv4());
        assert_eq!(peers[0].persistent_keepalive, Some(25));
        assert_eq!(device.fwmark, Some(DEFAULT_FWMARK));
    }

    #[test]
    fn peer_config_keeps_ipv6_and_psk() {
        let config = config(true);
        let device = config.peer(&config.private_key, Some(&[3; KEY_LEN]));
        let peers = device.peers.expect("one peer");
        assert_eq!(peers[0].allowed_ips.as_ref().map(Vec::len), Some(2));
        assert_eq!(
            peers[0].preshared_key.as_deref(),
            Some(encode_key(&[3; KEY_LEN]).as_str())
        );
    }
}
