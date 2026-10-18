mod duration;
mod env;
mod wgconf;

use std::fmt::{self, Display};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize, Serializer};

pub use duration::{format_duration, parse_duration};
pub use env::{Env, parse_bool};

use crate::dns::upstream::{DnsPreset, UpstreamType};
use crate::provider::ProviderName;
use crate::publicip::PublicIpApi;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("{key}: invalid value {value:?}: {reason}")]
    Invalid {
        key: String,
        value: String,
        reason: String,
    },
    #[error("{0} must be set")]
    Missing(&'static str),
    #[error("{0}")]
    Constraint(String),
    #[error("reading {path}: {source}")]
    ReadFile {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("parsing WireGuard configuration {path}: {source}")]
    WgConf {
        path: PathBuf,
        #[source]
        source: wgconf::WgConfError,
    },
}

impl ConfigError {
    pub fn invalid(key: &str, value: &str, reason: impl Display) -> Self {
        Self::Invalid {
            key: key.to_owned(),
            value: value.to_owned(),
            reason: reason.to_string(),
        }
    }

    fn constraint(message: impl Into<String>) -> Self {
        Self::Constraint(message.into())
    }
}

#[derive(Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(transparent)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(if self.0.is_empty() {
            "[unset]"
        } else {
            "[redacted]"
        })
    }
}

impl Serialize for Secret {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(if self.0.is_empty() { "" } else { "[redacted]" })
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SelectionMode {
    #[default]
    Random,
    Ordered,
}

impl FromStr for SelectionMode {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_lowercase().as_str() {
            "random" => Ok(Self::Random),
            "ordered" => Ok(Self::Ordered),
            other => Err(format!(
                "unknown selection mode {other:?}: expected random or ordered"
            )),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct ServerSelection {
    pub countries: Vec<String>,
    pub cities: Vec<String>,
    pub isps: Vec<String>,
    pub hostnames: Vec<String>,
    pub owned_only: bool,
    pub mode: SelectionMode,
    pub endpoint_ip: Option<IpAddr>,
    pub endpoint_port: Option<u16>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct WireguardSettings {
    pub interface: String,
    pub private_key: Secret,
    pub preshared_key: Secret,
    pub addresses: Vec<IpNetwork>,
    pub allowed_ips: Vec<IpNetwork>,
    pub persistent_keepalive: Duration,
    pub mtu: u32,
    pub quantum_resistant: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PmtudSettings {
    pub icmp_addresses: Vec<IpAddr>,
    pub tcp_addresses: Vec<SocketAddr>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FirewallSettings {
    pub enabled: bool,
    pub vpn_input_ports: Vec<u16>,
    pub input_ports: Vec<u16>,
    pub outbound_subnets: Vec<IpNetwork>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DnsSettings {
    pub server_enabled: bool,
    pub listen_address: SocketAddr,
    pub upstream_type: UpstreamType,
    pub providers: Vec<DnsPreset>,
    pub upstream_plain_addresses: Vec<SocketAddr>,
    pub ipv6: bool,
    pub caching: bool,
    pub update_period: Duration,
    pub block_malicious: bool,
    pub block_ads: bool,
    pub block_surveillance: bool,
    pub allowed_hostnames: Vec<String>,
    pub blocked_hostnames: Vec<String>,
    pub blocked_ips: Vec<IpAddr>,
    pub blocked_ip_prefixes: Vec<IpNetwork>,
    pub rebinding_protection_exempt_hostnames: Vec<String>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SmallCheckType {
    #[default]
    Icmp,
    Dns,
}

impl FromStr for SmallCheckType {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_lowercase().as_str() {
            "icmp" => Ok(Self::Icmp),
            "dns" => Ok(Self::Dns),
            other => Err(format!(
                "unknown small check type {other:?}: expected icmp or dns"
            )),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct HealthSettings {
    pub server_address: SocketAddr,
    pub target_addresses: Vec<String>,
    pub icmp_target_ips: Vec<IpAddr>,
    pub small_check_type: SmallCheckType,
    pub restart_vpn: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct HttpProxySettings {
    pub enabled: bool,
    pub listen_address: SocketAddr,
    pub user: Secret,
    pub password: Secret,
    pub stealth: bool,
    pub log: bool,
}

impl HttpProxySettings {
    pub(crate) fn validate_credentials(&self) -> Result<(), ConfigError> {
        if self.user.is_empty() != self.password.is_empty() {
            return Err(ConfigError::constraint(
                "HTTPPROXY_USER and HTTPPROXY_PASSWORD must be set together",
            ));
        }
        if self.user.expose().contains(':')
            || self.user.expose().chars().any(char::is_control)
            || self.password.expose().chars().any(char::is_control)
        {
            return Err(ConfigError::constraint(
                "HTTPPROXY_USER must not contain a colon; HTTP proxy credentials must not contain control characters",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ShadowsocksSettings {
    pub enabled: bool,
    pub listen_address: SocketAddr,
    pub password: Secret,
    pub cipher: String,
    pub log: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Socks5Settings {
    pub enabled: bool,
    pub listen_address: SocketAddr,
    pub user: Secret,
    pub password: Secret,
}

impl Socks5Settings {
    pub(crate) fn validate_credentials(&self) -> Result<(), ConfigError> {
        if self.user.is_empty() != self.password.is_empty() {
            return Err(ConfigError::constraint(
                "SOCKS5_USER and SOCKS5_PASSWORD must be set together",
            ));
        }
        if self.user.expose().len() > 255 || self.password.expose().len() > 255 {
            return Err(ConfigError::constraint(
                "SOCKS5_USER and SOCKS5_PASSWORD must each fit in 255 UTF-8 bytes",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ControlSettings {
    pub listen_address: SocketAddr,
    pub log: bool,
    pub api_key: Secret,
    pub auth: crate::control::auth::Policy,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct UpdaterSettings {
    pub period: Duration,
    pub min_ratio: f64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PublicIpSettings {
    pub enabled: bool,
    pub file: Option<PathBuf>,
    pub apis: Vec<PublicIpApi>,
    pub token: Secret,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct StorageSettings {
    pub enabled: bool,
    pub directory: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SystemSettings {
    pub puid: u32,
    pub pgid: u32,
    pub timezone: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MetricsSettings {
    pub enabled: bool,
    pub listen_address: SocketAddr,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Settings {
    pub provider: ProviderName,
    pub wireguard: WireguardSettings,
    pub selection: ServerSelection,
    pub pmtud: PmtudSettings,
    pub vpn_up_command: Option<String>,
    pub vpn_down_command: Option<String>,
    pub firewall: FirewallSettings,
    pub dns: DnsSettings,
    pub health: HealthSettings,
    pub http_proxy: HttpProxySettings,
    pub shadowsocks: ShadowsocksSettings,
    pub socks5: Socks5Settings,
    pub control: ControlSettings,
    pub updater: UpdaterSettings,
    pub public_ip: PublicIpSettings,
    pub storage: StorageSettings,
    pub system: SystemSettings,
    pub log_level: String,
    pub metrics: MetricsSettings,
}

const DEFAULT_WG_CONF: &str = "/run/secrets/wg0.conf";

impl Settings {
    pub fn from_env(env: &Env) -> Result<Self, ConfigError> {
        let provider = read_provider(env)?;
        let wg_conf = read_wg_conf(env)?;
        let wireguard = read_wireguard(env, &wg_conf)?;
        let mut selection = read_selection(env)?;
        if selection.endpoint_ip.is_none() {
            selection.endpoint_ip = wg_conf.endpoint_ip;
        }
        if selection.endpoint_port.is_none() {
            selection.endpoint_port = wg_conf.endpoint_port;
        }
        let settings = Self {
            provider,
            wireguard,
            selection,
            pmtud: PmtudSettings {
                icmp_addresses: or_default(env.csv_parse(&["PMTUD_ICMP_ADDRESSES"])?, || {
                    vec![[1, 1, 1, 1].into(), [8, 8, 8, 8].into()]
                }),
                tcp_addresses: or_default(env.csv_parse(&["PMTUD_TCP_ADDRESSES"])?, || {
                    vec![
                        SocketAddr::from(([1, 1, 1, 1], 443)),
                        SocketAddr::from(([8, 8, 8, 8], 443)),
                    ]
                }),
            },
            vpn_up_command: env.string(&["VPN_UP_COMMAND"]),
            vpn_down_command: env.string(&["VPN_DOWN_COMMAND"]),
            firewall: FirewallSettings {
                enabled: env
                    .bool(&[
                        "FIREWALL_ENABLED_DISABLING_IT_SHOOTS_YOU_IN_YOUR_FOOT",
                        "FIREWALL",
                    ])?
                    .unwrap_or(true),
                vpn_input_ports: env.csv_parse(&["FIREWALL_VPN_INPUT_PORTS"])?,
                input_ports: env.csv_parse(&["FIREWALL_INPUT_PORTS"])?,
                outbound_subnets: env.csv_parse(&["FIREWALL_OUTBOUND_SUBNETS", "EXTRA_SUBNETS"])?,
            },
            dns: read_dns(env)?,
            health: HealthSettings {
                server_address: env
                    .parse(&["HEALTH_SERVER_ADDRESS"])?
                    .unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 9999))),
                target_addresses: or_default(
                    env.csv(&["HEALTH_TARGET_ADDRESSES", "HEALTH_TARGET_ADDRESS"]),
                    || vec!["cloudflare.com:443".into(), "github.com:443".into()],
                ),
                icmp_target_ips: or_default(
                    env.csv_parse(&["HEALTH_ICMP_TARGET_IPS", "HEALTH_ICMP_TARGET_IP"])?,
                    || vec![[1, 1, 1, 1].into(), [8, 8, 8, 8].into()],
                ),
                small_check_type: env.parse(&["HEALTH_SMALL_CHECK_TYPE"])?.unwrap_or_default(),
                restart_vpn: env.bool(&["HEALTH_RESTART_VPN"])?.unwrap_or(true),
            },
            http_proxy: HttpProxySettings {
                enabled: env
                    .bool(&["HTTPPROXY", "TINYPROXY", "PROXY"])?
                    .unwrap_or(false),
                listen_address: listen_address(env, &["HTTPPROXY_LISTENING_ADDRESS"], 8888)?,
                user: secret(
                    env,
                    &["HTTPPROXY_USER"],
                    "HTTPPROXY_USER_SECRETFILE",
                    "/run/secrets/httpproxy_user",
                )?,
                password: secret(
                    env,
                    &["HTTPPROXY_PASSWORD"],
                    "HTTPPROXY_PASSWORD_SECRETFILE",
                    "/run/secrets/httpproxy_password",
                )?,
                stealth: env.bool(&["HTTPPROXY_STEALTH"])?.unwrap_or(false),
                log: env
                    .bool(&["HTTPPROXY_LOG", "TINYPROXY_LOG", "PROXY_LOG_LEVEL"])?
                    .unwrap_or(false),
            },
            shadowsocks: ShadowsocksSettings {
                enabled: env.bool(&["SHADOWSOCKS"])?.unwrap_or(false),
                listen_address: listen_address(env, &["SHADOWSOCKS_LISTENING_ADDRESS"], 8388)?,
                password: secret(
                    env,
                    &["SHADOWSOCKS_PASSWORD"],
                    "SHADOWSOCKS_PASSWORD_SECRETFILE",
                    "/run/secrets/shadowsocks_password",
                )?,
                cipher: env
                    .lowercase(&["SHADOWSOCKS_CIPHER", "SHADOWSOCKS_METHOD"])
                    .unwrap_or_else(|| "chacha20-ietf-poly1305".into()),
                log: env.bool(&["SHADOWSOCKS_LOG"])?.unwrap_or(false),
            },
            socks5: Socks5Settings {
                enabled: env.bool(&["SOCKS5"])?.unwrap_or(false),
                listen_address: listen_address(env, &["SOCKS5_LISTENING_ADDRESS"], 1080)?,
                user: secret(
                    env,
                    &["SOCKS5_USER"],
                    "SOCKS5_USER_SECRETFILE",
                    "/run/secrets/socks5_user",
                )?,
                password: secret(
                    env,
                    &["SOCKS5_PASSWORD"],
                    "SOCKS5_PASSWORD_SECRETFILE",
                    "/run/secrets/socks5_password",
                )?,
            },
            control: ControlSettings {
                listen_address: listen_address(env, &["HTTP_CONTROL_SERVER_ADDRESS"], 8000)?,
                log: env.bool(&["HTTP_CONTROL_SERVER_LOG"])?.unwrap_or(true),
                api_key: secret(
                    env,
                    &["HTTP_CONTROL_SERVER_API_KEY"],
                    "HTTP_CONTROL_SERVER_API_KEY_SECRETFILE",
                    "/run/secrets/http_control_server_api_key",
                )?,
                auth: crate::control::auth::Policy::from_env(env)?,
            },
            updater: UpdaterSettings {
                period: env
                    .duration(&["UPDATER_PERIOD"])?
                    .unwrap_or(Duration::from_secs(24 * 3600)),
                min_ratio: env.parse(&["UPDATER_MIN_RATIO"])?.unwrap_or(0.8),
            },
            public_ip: PublicIpSettings {
                enabled: env.bool(&["PUBLICIP_ENABLED"])?.unwrap_or(true),
                file: match env.string(&["PUBLICIP_FILE", "IP_STATUS_FILE"]) {
                    Some(path) if path.eq_ignore_ascii_case("disabled") => None,
                    Some(path) => Some(PathBuf::from(path)),
                    None => Some(PathBuf::from("/tmp/gluetun/ip")),
                },
                apis: or_default(env.csv_parse(&["PUBLICIP_API"])?, || {
                    vec![
                        PublicIpApi::Ipinfo,
                        PublicIpApi::Ifconfigco,
                        PublicIpApi::Ip2location,
                        PublicIpApi::Cloudflare,
                    ]
                }),
                token: secret(
                    env,
                    &["PUBLICIP_API_TOKEN"],
                    "PUBLICIP_API_TOKEN_SECRETFILE",
                    "/run/secrets/publicip_api_token",
                )?,
            },
            storage: StorageSettings {
                enabled: env.bool(&["STORAGE_SERVERS_ENABLED"])?.unwrap_or(true),
                directory: env
                    .string(&["STORAGE_SERVERS_DIRECTORY_PATH"])
                    .map_or_else(|| PathBuf::from("/gluetun/servers"), PathBuf::from),
            },
            system: SystemSettings {
                puid: env.parse(&["PUID", "UID"])?.unwrap_or(1000),
                pgid: env.parse(&["PGID", "GID"])?.unwrap_or(1000),
                timezone: env.string(&["TZ"]),
            },
            log_level: env
                .lowercase(&["LOG_LEVEL"])
                .unwrap_or_else(|| "info".into()),
            metrics: MetricsSettings {
                enabled: match env.lowercase(&["METRICS_TYPE"]).as_deref() {
                    None | Some("noop") => false,
                    Some("prometheus") => true,
                    Some(other) => {
                        return Err(ConfigError::invalid(
                            "METRICS_TYPE",
                            other,
                            "expected noop or prometheus",
                        ));
                    }
                },
                listen_address: listen_address(
                    env,
                    &["METRICS_PROMETHEUS_LISTENING_ADDRESS"],
                    9090,
                )?,
            },
        };
        settings.validate()?;
        Ok(settings)
    }

    pub(crate) fn validate(&self) -> Result<(), ConfigError> {
        let wg = &self.wireguard;
        if wg.private_key.is_empty() {
            return Err(ConfigError::Missing("WIREGUARD_PRIVATE_KEY"));
        }
        crate::wireguard::keys::decode_key(wg.private_key.expose()).map_err(|err| {
            ConfigError::constraint(format!("WIREGUARD_PRIVATE_KEY is not valid: {err}"))
        })?;
        if !wg.preshared_key.is_empty() {
            crate::wireguard::keys::decode_key(wg.preshared_key.expose()).map_err(|err| {
                ConfigError::constraint(format!("WIREGUARD_PRESHARED_KEY is not valid: {err}"))
            })?;
        }
        if wg.addresses.is_empty() {
            return Err(ConfigError::Missing("WIREGUARD_ADDRESSES"));
        }
        if wg.allowed_ips.is_empty() {
            return Err(ConfigError::Missing("WIREGUARD_ALLOWED_IPS"));
        }
        if wg.persistent_keepalive.as_secs() > u64::from(u16::MAX)
            || wg.persistent_keepalive.subsec_nanos() != 0
        {
            return Err(ConfigError::constraint(
                "WireGuard persistent keepalive must be a whole number of seconds between 0 and 65535",
            ));
        }
        let minimum_mtu = if wg.addresses.iter().any(IpNetwork::is_ipv6) {
            1280
        } else {
            576
        };
        if wg.mtu != 0 && !(minimum_mtu..=65535).contains(&wg.mtu) {
            return Err(ConfigError::constraint(
                "WireGuard MTU is outside the supported IP packet size range",
            ));
        }
        if !valid_interface_name(&wg.interface) {
            return Err(ConfigError::invalid(
                "VPN_INTERFACE",
                &wg.interface,
                "must match ^[a-zA-Z0-9_]+$ and be at most 15 characters",
            ));
        }
        if !(0.0..=1.0).contains(&self.updater.min_ratio) || self.updater.min_ratio == 0.0 {
            return Err(ConfigError::constraint(
                "UPDATER_MIN_RATIO must be in (0, 1]",
            ));
        }
        if !self.updater.period.is_zero() && self.updater.period < Duration::from_secs(60) {
            return Err(ConfigError::constraint(
                "UPDATER_PERIOD must be 0 or at least 1m",
            ));
        }
        if std::time::Instant::now()
            .checked_add(self.updater.period)
            .is_none()
        {
            return Err(ConfigError::constraint("UPDATER_PERIOD is too large"));
        }
        if !self.dns.update_period.is_zero() && self.dns.update_period < Duration::from_secs(30) {
            return Err(ConfigError::constraint(
                "DNS_UPDATE_PERIOD must be 0 or at least 30s",
            ));
        }
        if self.dns.upstream_type == UpstreamType::Plain
            && !self.dns.upstream_plain_addresses.is_empty()
        {
            let has_family = |v6: bool| {
                self.dns
                    .upstream_plain_addresses
                    .iter()
                    .any(|addr| addr.is_ipv6() == v6)
            };
            if !has_family(self.dns.ipv6) {
                return Err(ConfigError::constraint(format!(
                    "DNS_UPSTREAM_PLAIN_ADDRESSES has no {} address matching DNS_UPSTREAM_IPV6",
                    if self.dns.ipv6 { "IPv6" } else { "IPv4" }
                )));
            }
        }
        if !self.dns.server_enabled && self.dns.upstream_type != UpstreamType::Plain {
            return Err(ConfigError::constraint(
                "DNS_UPSTREAM_RESOLVER_TYPE must be plain when DNS_SERVER is off",
            ));
        }
        if !self.dns.server_enabled
            && (self.dns.upstream_plain_addresses.is_empty()
                || self
                    .dns
                    .upstream_plain_addresses
                    .iter()
                    .any(|address| address.port() != 53))
        {
            return Err(ConfigError::constraint(
                "DNS_SERVER=off requires DNS_UPSTREAM_PLAIN_ADDRESSES with port 53",
            ));
        }
        if self.dns.server_enabled && self.dns.listen_address.port() != 53 {
            return Err(ConfigError::constraint(
                "DNS_ADDRESS_LISTENING must use port 53 for system DNS",
            ));
        }
        if self.shadowsocks.enabled && self.shadowsocks.password.is_empty() {
            return Err(ConfigError::Missing("SHADOWSOCKS_PASSWORD"));
        }
        if self.shadowsocks.enabled {
            crate::shadowsocks::server_config(&self.shadowsocks)
                .map_err(|error| ConfigError::constraint(error.to_string()))?;
        }
        self.socks5.validate_credentials()?;
        self.http_proxy.validate_credentials()?;
        if self.health.target_addresses.is_empty() {
            return Err(ConfigError::Missing("HEALTH_TARGET_ADDRESSES"));
        }
        Ok(())
    }
}

fn read_provider(env: &Env) -> Result<ProviderName, ConfigError> {
    if let Some(vpn_type) = env.lowercase(&["VPN_TYPE"])
        && vpn_type != "wireguard"
    {
        return Err(ConfigError::invalid(
            "VPN_TYPE",
            &vpn_type,
            "only wireguard (kernel) is supported",
        ));
    }
    for key in [
        "VPN_SERVICE_PROVIDER",
        "VPNSP",
        "UPDATER_VPN_SERVICE_PROVIDERS",
    ] {
        let _: Vec<ProviderName> = env.csv_parse(&[key])?;
    }
    if env
        .bool(&["VPN_PORT_FORWARDING", "PORT_FORWARDING"])?
        .unwrap_or(false)
    {
        return Err(ConfigError::constraint(
            "Mullvad does not support VPN port forwarding",
        ));
    }
    Ok(ProviderName::Mullvad)
}

fn read_wg_conf(env: &Env) -> Result<wgconf::WgQuickConfig, ConfigError> {
    let path = PathBuf::from(
        env.get("WIREGUARD_CONF_SECRETFILE")
            .unwrap_or(DEFAULT_WG_CONF),
    );
    match env::read_secret_file(&path)? {
        Some(content) => {
            wgconf::parse(&content).map_err(|source| ConfigError::WgConf { path, source })
        }
        None => Ok(wgconf::WgQuickConfig::default()),
    }
}

fn read_wireguard(
    env: &Env,
    wg_conf: &wgconf::WgQuickConfig,
) -> Result<WireguardSettings, ConfigError> {
    let private_key = secret(
        env,
        &["WIREGUARD_PRIVATE_KEY"],
        "WIREGUARD_PRIVATE_KEY_SECRETFILE",
        "/run/secrets/wireguard_private_key",
    )?;
    let private_key = if private_key.is_empty() {
        Secret::new(wg_conf.private_key.clone().unwrap_or_default())
    } else {
        private_key
    };
    let preshared_key = secret(
        env,
        &["WIREGUARD_PRESHARED_KEY"],
        "WIREGUARD_PRESHARED_KEY_SECRETFILE",
        "/run/secrets/wireguard_preshared_key",
    )?;
    let preshared_key = if preshared_key.is_empty() {
        Secret::new(wg_conf.preshared_key.clone().unwrap_or_default())
    } else {
        preshared_key
    };
    let addresses_raw = env.secret(
        &["WIREGUARD_ADDRESSES", "WIREGUARD_ADDRESS"],
        "WIREGUARD_ADDRESSES_SECRETFILE",
        "/run/secrets/wireguard_addresses",
    )?;
    let addresses: Vec<IpNetwork> = match addresses_raw {
        Some(raw) => raw
            .split(',')
            .map(str::trim)
            .filter(|part| !part.is_empty())
            .map(|part| {
                part.parse()
                    .map_err(|err| ConfigError::invalid("WIREGUARD_ADDRESSES", part, err))
            })
            .collect::<Result<_, _>>()?,
        None => wg_conf.addresses.clone(),
    };
    let allowed_ips = or_default(env.csv_parse(&["WIREGUARD_ALLOWED_IPS"])?, || {
        vec![
            IpNetwork::new(IpAddr::from([0, 0, 0, 0]), 0).expect("valid prefix"),
            IpNetwork::new(IpAddr::from([0_u16; 8]), 0).expect("valid prefix"),
        ]
    });
    Ok(WireguardSettings {
        interface: env
            .string(&["VPN_INTERFACE", "WIREGUARD_INTERFACE"])
            .unwrap_or_else(|| "wg0".into()),
        private_key,
        preshared_key,
        addresses,
        allowed_ips,
        persistent_keepalive: env
            .duration(&["WIREGUARD_PERSISTENT_KEEPALIVE_INTERVAL"])?
            .unwrap_or(Duration::ZERO),
        mtu: env.parse(&["WIREGUARD_MTU"])?.unwrap_or(0),
        quantum_resistant: env
            .bool(&["WIREGUARD_QUANTUM_RESISTANT", "MULLVAD_POST_QUANTUM_ENABLE"])?
            .unwrap_or(false),
    })
}

fn read_selection(env: &Env) -> Result<ServerSelection, ConfigError> {
    for key in [
        "FREE_ONLY",
        "PREMIUM_ONLY",
        "STREAM_ONLY",
        "SECURE_CORE_ONLY",
        "TOR_ONLY",
        "PORT_FORWARD_ONLY",
        "MULTIHOP_ONLY",
    ] {
        if env.bool(&[key])?.unwrap_or(false) {
            return Err(ConfigError::constraint(format!(
                "{key} is not supported for Mullvad"
            )));
        }
    }
    for key in [
        "SERVER_REGIONS",
        "REGION",
        "SERVER_NAMES",
        "SERVER_NAME",
        "SERVER_NUMBER",
        "SERVER_CATEGORIES",
    ] {
        if env.string(&[key]).is_some() {
            return Err(ConfigError::constraint(format!(
                "{key} is not supported for Mullvad"
            )));
        }
    }
    Ok(ServerSelection {
        countries: env.csv(&["SERVER_COUNTRIES", "COUNTRY"]),
        cities: env.csv(&["SERVER_CITIES", "CITY"]),
        isps: env.csv(&["ISP"]),
        hostnames: env.csv(&["SERVER_HOSTNAMES", "SERVER_HOSTNAME"]),
        owned_only: env.bool(&["OWNED_ONLY", "OWNED"])?.unwrap_or(false),
        mode: env.parse(&["SERVER_SELECTION_MODE"])?.unwrap_or_default(),
        endpoint_ip: env.parse(&["WIREGUARD_ENDPOINT_IP", "VPN_ENDPOINT_IP"])?,
        endpoint_port: env.parse(&["WIREGUARD_ENDPOINT_PORT", "VPN_ENDPOINT_PORT"])?,
    })
}

fn read_dns(env: &Env) -> Result<DnsSettings, ConfigError> {
    let server_enabled = env.bool(&["DNS_SERVER", "DOT"])?.unwrap_or(true);
    Ok(DnsSettings {
        server_enabled,
        listen_address: listen_address(env, &["DNS_ADDRESS_LISTENING", "DNS_SERVER_ADDRESS"], 53)?,
        upstream_type: env
            .parse(&["DNS_UPSTREAM_RESOLVER_TYPE"])?
            .unwrap_or(if server_enabled {
                UpstreamType::Dot
            } else {
                UpstreamType::Plain
            }),
        providers: or_default(
            env.csv_parse(&["DNS_UPSTREAM_RESOLVERS", "DOT_PROVIDERS"])?,
            || vec![DnsPreset::Mullvad],
        ),
        upstream_plain_addresses: env
            .csv(&["DNS_UPSTREAM_PLAIN_ADDRESSES", "DNS_ADDRESS"])
            .into_iter()
            .map(|value| parse_dns_address(&value))
            .collect::<Result<_, _>>()?,
        ipv6: env
            .bool(&["DNS_UPSTREAM_IPV6", "DOT_IPV6"])?
            .unwrap_or(false),
        caching: env.bool(&["DNS_CACHING", "DOT_CACHING"])?.unwrap_or(true),
        update_period: env
            .duration(&["DNS_UPDATE_PERIOD"])?
            .unwrap_or(Duration::from_secs(24 * 3600)),
        block_malicious: env.bool(&["BLOCK_MALICIOUS"])?.unwrap_or(true),
        block_ads: env.bool(&["BLOCK_ADS"])?.unwrap_or(false),
        block_surveillance: env
            .bool(&["BLOCK_SURVEILLANCE", "BLOCK_NSA"])?
            .unwrap_or(false),
        allowed_hostnames: env.csv_lowercase(&["DNS_UNBLOCK_HOSTNAMES", "UNBLOCK"]),
        blocked_hostnames: env.csv_lowercase(&["DNS_BLOCK_HOSTNAMES"]),
        blocked_ips: env.csv_parse(&["DNS_BLOCK_IPS"])?,
        blocked_ip_prefixes: env.csv_parse(&["DNS_BLOCK_IP_PREFIXES"])?,
        rebinding_protection_exempt_hostnames: env
            .csv_lowercase(&["DNS_REBINDING_PROTECTION_EXEMPT_HOSTNAMES"]),
    })
}

fn parse_dns_address(value: &str) -> Result<SocketAddr, ConfigError> {
    if let Ok(socket) = value.parse::<SocketAddr>() {
        return Ok(socket);
    }
    value
        .parse::<IpAddr>()
        .map(|ip| SocketAddr::new(ip, 53))
        .map_err(|err| ConfigError::invalid("DNS_UPSTREAM_PLAIN_ADDRESSES", value, err))
}

fn listen_address(env: &Env, keys: &[&str], default_port: u16) -> Result<SocketAddr, ConfigError> {
    let Some(value) = env.get_first(keys) else {
        return Ok(SocketAddr::from(([0, 0, 0, 0], default_port)));
    };
    parse_listen_address(value)
        .ok_or_else(|| ConfigError::invalid(keys[0], value, "expected [host]:port"))
}

pub fn parse_listen_address(value: &str) -> Option<SocketAddr> {
    if let Some(port) = value.strip_prefix(':') {
        return port
            .parse::<u16>()
            .ok()
            .map(|port| SocketAddr::from(([0, 0, 0, 0], port)));
    }
    value.parse().ok()
}

fn secret(
    env: &Env,
    keys: &[&str],
    file_key: &str,
    default_file: &str,
) -> Result<Secret, ConfigError> {
    Ok(Secret::new(
        env.secret(keys, file_key, default_file)?
            .unwrap_or_default(),
    ))
}

fn or_default<T>(values: Vec<T>, default: impl FnOnce() -> Vec<T>) -> Vec<T> {
    if values.is_empty() { default() } else { values }
}

pub fn valid_interface_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 15
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "wOEI9rqqbDwnN8/Bpp22sVz48T71vJ4fYmFWujulwUU=";

    fn base_env(extra: &[(&str, &str)]) -> Env {
        let mut pairs = vec![
            ("VPN_SERVICE_PROVIDER", "mullvad"),
            ("WIREGUARD_PRIVATE_KEY", KEY),
            ("WIREGUARD_ADDRESSES", "10.64.222.21/32"),
            ("WIREGUARD_CONF_SECRETFILE", "/nonexistent/wg0.conf"),
        ];
        pairs.extend_from_slice(extra);
        Env::from_pairs(pairs)
    }

    #[test]
    fn defaults() {
        let settings = Settings::from_env(&base_env(&[])).expect("valid settings");
        assert_eq!(settings.provider, ProviderName::Mullvad);
        assert_eq!(settings.wireguard.interface, "wg0");
        assert_eq!(settings.wireguard.allowed_ips.len(), 2);
        assert!(settings.firewall.enabled);
        assert!(settings.dns.server_enabled);
        assert_eq!(settings.dns.upstream_type, UpstreamType::Dot);
        assert_eq!(settings.dns.update_period, Duration::from_secs(86_400));
        assert_eq!(
            settings.health.server_address,
            SocketAddr::from(([127, 0, 0, 1], 9999))
        );
        assert_eq!(settings.control.listen_address.port(), 8000);
    }

    #[test]
    fn socks5_credentials_are_optional_but_must_be_a_complete_pair() {
        for extra in [
            vec![("SOCKS5", "on")],
            vec![
                ("SOCKS5", "on"),
                ("SOCKS5_USER", ""),
                ("SOCKS5_PASSWORD", ""),
            ],
        ] {
            let settings = Settings::from_env(&base_env(&extra)).expect("unauthenticated SOCKS5");
            assert!(settings.socks5.user.is_empty());
            assert!(settings.socks5.password.is_empty());
        }
        let settings = Settings::from_env(&base_env(&[
            ("SOCKS5", "on"),
            ("SOCKS5_USER", "browser"),
            ("SOCKS5_PASSWORD", "secret-value"),
        ]))
        .expect("authenticated SOCKS5");
        assert_eq!(settings.socks5.user.expose(), "browser");
        assert_eq!(settings.socks5.password.expose(), "secret-value");
        assert!(
            !serde_json::to_string(&settings.socks5)
                .expect("redacted settings")
                .contains("secret-value")
        );
        for extra in [
            vec![("SOCKS5", "on"), ("SOCKS5_USER", "secret-value")],
            vec![("SOCKS5", "on"), ("SOCKS5_PASSWORD", "secret-value")],
        ] {
            let error =
                Settings::from_env(&base_env(&extra)).expect_err("partial credentials rejected");
            assert!(error.to_string().contains("must be set together"));
            assert!(!error.to_string().contains("secret-value"));
        }
    }

    #[test]
    fn http_credentials_are_optional_validated_and_redacted() {
        for extra in [
            vec![("HTTPPROXY", "on")],
            vec![("HTTPPROXY_USER", ""), ("HTTPPROXY_PASSWORD", "")],
            vec![
                ("HTTPPROXY_USER", "browser"),
                ("HTTPPROXY_PASSWORD", "secret:value"),
            ],
        ] {
            let settings = Settings::from_env(&base_env(&extra)).expect("valid HTTP credentials");
            assert!(
                !serde_json::to_string(&settings.http_proxy)
                    .expect("settings")
                    .contains("secret:value")
            );
        }
        for extra in [
            vec![("HTTPPROXY_USER", "secret-value")],
            vec![("HTTPPROXY_PASSWORD", "secret-value")],
            vec![
                ("HTTPPROXY_USER", "invalid:user"),
                ("HTTPPROXY_PASSWORD", "secret-value"),
            ],
            vec![
                ("HTTPPROXY_USER", "browser"),
                ("HTTPPROXY_PASSWORD", "secret\nvalue"),
            ],
        ] {
            let error =
                Settings::from_env(&base_env(&extra)).expect_err("invalid HTTP credentials");
            assert!(!error.to_string().contains("secret"));
        }
    }

    #[test]
    fn socks5_credentials_obey_protocol_byte_limits() {
        let limit = "a".repeat(255);
        Settings::from_env(&base_env(&[
            ("SOCKS5", "on"),
            ("SOCKS5_USER", &limit),
            ("SOCKS5_PASSWORD", &limit),
        ]))
        .expect("255-byte credentials");
        for oversized in ["a".repeat(256), "é".repeat(128)] {
            for (user, password) in [
                (oversized.as_str(), "password"),
                ("user", oversized.as_str()),
            ] {
                let error = Settings::from_env(&base_env(&[
                    ("SOCKS5", "on"),
                    ("SOCKS5_USER", user),
                    ("SOCKS5_PASSWORD", password),
                ]))
                .expect_err("oversized credentials");
                assert!(error.to_string().contains("255 UTF-8 bytes"));
                assert!(!error.to_string().contains(&oversized));
            }
        }
    }

    #[test]
    fn rejects_openvpn() {
        let err = Settings::from_env(&base_env(&[("VPN_TYPE", "openvpn")])).expect_err("must fail");
        assert!(err.to_string().contains("VPN_TYPE"));
    }

    #[test]
    fn rejects_other_providers_including_aliases_and_updater() {
        for key in [
            "VPN_SERVICE_PROVIDER",
            "VPNSP",
            "UPDATER_VPN_SERVICE_PROVIDERS",
        ] {
            for value in ["airvpn", "ivpn", "nordvpn", "protonvpn", "mullvad,ivpn"] {
                let error =
                    Settings::from_env(&base_env(&[(key, value)])).expect_err("unsupported");
                assert!(error.to_string().contains("only mullvad"));
            }
        }
    }

    #[test]
    fn defaults_to_mullvad_without_provider_setting() {
        let env = Env::from_pairs([
            ("WIREGUARD_PRIVATE_KEY", KEY),
            ("WIREGUARD_ADDRESSES", "10.64.0.2/32"),
            ("WIREGUARD_QUANTUM_RESISTANT", "on"),
            ("WIREGUARD_CONF_SECRETFILE", "/nonexistent"),
        ]);
        let settings = Settings::from_env(&env).expect("valid");
        assert_eq!(settings.provider, ProviderName::Mullvad);
        assert!(settings.wireguard.quantum_resistant);
    }

    #[test]
    fn listen_address_forms() {
        assert_eq!(
            parse_listen_address(":8000"),
            Some(SocketAddr::from(([0, 0, 0, 0], 8000)))
        );
        assert_eq!(
            parse_listen_address("127.0.0.1:9999"),
            Some(SocketAddr::from(([127, 0, 0, 1], 9999)))
        );
        assert_eq!(parse_listen_address("nonsense"), None);
    }

    #[test]
    fn interface_names() {
        assert!(valid_interface_name("wg0"));
        assert!(!valid_interface_name("wg-0"));
        assert!(!valid_interface_name("a_very_long_interface"));
    }

    #[test]
    fn disabled_dns_requires_plain_upstreams_and_selects_plain_by_default() {
        assert!(Settings::from_env(&base_env(&[("DNS_SERVER", "off")])).is_err());
        let settings = Settings::from_env(&base_env(&[
            ("DNS_SERVER", "off"),
            ("DNS_UPSTREAM_PLAIN_ADDRESSES", "1.1.1.1"),
        ]))
        .expect("plain DNS is configured");
        assert_eq!(settings.dns.upstream_type, UpstreamType::Plain);
        assert!(!settings.dns.server_enabled);
    }

    #[test]
    fn rejects_vpn_port_forwarding() {
        for key in ["VPN_PORT_FORWARDING", "PORT_FORWARDING"] {
            let error = Settings::from_env(&base_env(&[(key, "on")])).expect_err("unsupported");
            assert!(
                error
                    .to_string()
                    .contains("does not support VPN port forwarding")
            );
        }
    }
}
