use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};

use crate::config::{PmtudSettings, Secret, SelectionMode, Settings};

#[derive(Serialize)]
pub(super) struct View {
    r#type: &'static str,
    provider: ProviderView,
    wireguard: WireguardView,
    pmtud: PmtudSettings,
    up_command: String,
    down_command: String,
}

#[derive(Serialize)]
struct ProviderView {
    name: &'static str,
    server_selection: SelectionView,
}

#[derive(Serialize)]
struct SelectionView {
    vpn: &'static str,
    mode: SelectionMode,
    countries: Vec<String>,
    cities: Vec<String>,
    isps: Vec<String>,
    hostnames: Vec<String>,
    owned_only: bool,
    mullvad_post_quantum: bool,
    wireguard: EndpointView,
}

#[derive(Serialize)]
struct EndpointView {
    endpoint_ip: IpAddr,
    endpoint_port: u16,
    public_key: &'static str,
}

#[derive(Serialize)]
struct WireguardView {
    private_key: Secret,
    pre_shared_key: Secret,
    addresses: Vec<IpNetwork>,
    allowed_ips: Vec<IpNetwork>,
    interface: String,
    persistent_keep_alive_interval: u64,
    mtu: u32,
    implementation: &'static str,
}

impl From<&Settings> for View {
    fn from(settings: &Settings) -> Self {
        let selection = &settings.selection;
        let wireguard = &settings.wireguard;
        Self {
            r#type: "wireguard",
            provider: ProviderView {
                name: "mullvad",
                server_selection: SelectionView {
                    vpn: "wireguard",
                    mode: selection.mode,
                    countries: selection.countries.clone(),
                    cities: selection.cities.clone(),
                    isps: selection.isps.clone(),
                    hostnames: selection.hostnames.clone(),
                    owned_only: selection.owned_only,
                    mullvad_post_quantum: wireguard.quantum_resistant,
                    wireguard: EndpointView {
                        endpoint_ip: selection
                            .endpoint_ip
                            .unwrap_or(Ipv4Addr::UNSPECIFIED.into()),
                        endpoint_port: selection.endpoint_port.unwrap_or(0),
                        public_key: "",
                    },
                },
            },
            wireguard: WireguardView {
                private_key: wireguard.private_key.clone(),
                pre_shared_key: wireguard.preshared_key.clone(),
                addresses: wireguard.addresses.clone(),
                allowed_ips: wireguard.allowed_ips.clone(),
                interface: wireguard.interface.clone(),
                persistent_keep_alive_interval: wireguard
                    .persistent_keepalive
                    .as_secs()
                    .saturating_mul(1_000_000_000),
                mtu: wireguard.mtu,
                implementation: "kernel",
            },
            pmtud: settings.pmtud.clone(),
            up_command: settings.vpn_up_command.clone().unwrap_or_default(),
            down_command: settings.vpn_down_command.clone().unwrap_or_default(),
        }
    }
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(super) struct Patch {
    r#type: Option<String>,
    provider: Option<ProviderPatch>,
    wireguard: Option<WireguardPatch>,
    pmtud: Option<PmtudPatch>,
    up_command: Option<String>,
    down_command: Option<String>,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ProviderPatch {
    name: Option<String>,
    server_selection: Option<SelectionPatch>,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct SelectionPatch {
    vpn: Option<String>,
    mode: Option<SelectionMode>,
    countries: Option<Vec<String>>,
    cities: Option<Vec<String>>,
    isps: Option<Vec<String>>,
    hostnames: Option<Vec<String>>,
    owned_only: Option<bool>,
    mullvad_post_quantum: Option<bool>,
    wireguard: Option<EndpointPatch>,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct EndpointPatch {
    endpoint_ip: Option<IpAddr>,
    endpoint_port: Option<u16>,
    public_key: Option<String>,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct WireguardPatch {
    private_key: Option<Secret>,
    pre_shared_key: Option<Secret>,
    addresses: Option<Vec<IpNetwork>>,
    allowed_ips: Option<Vec<IpNetwork>>,
    interface: Option<String>,
    persistent_keep_alive_interval: Option<u64>,
    mtu: Option<u32>,
    implementation: Option<String>,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct PmtudPatch {
    icmp_addresses: Option<Vec<IpAddr>>,
    tcp_addresses: Option<Vec<SocketAddr>>,
}

impl Patch {
    pub(super) fn apply(self, settings: &Settings) -> Result<Settings, &'static str> {
        let mut updated = settings.clone();
        if self
            .r#type
            .as_deref()
            .is_some_and(|value| value != "wireguard")
        {
            return Err("only kernel WireGuard is supported");
        }
        if let Some(provider) = self.provider {
            if provider
                .name
                .as_deref()
                .is_some_and(|value| value != "mullvad")
            {
                return Err("only Mullvad is supported");
            }
            if let Some(selection) = provider.server_selection {
                if selection
                    .vpn
                    .as_deref()
                    .is_some_and(|value| value != "wireguard")
                {
                    return Err("only WireGuard relay selection is supported");
                }
                if let Some(value) = selection.mode {
                    updated.selection.mode = value;
                }
                if let Some(value) = selection.countries {
                    updated.selection.countries = value;
                }
                if let Some(value) = selection.cities {
                    updated.selection.cities = value;
                }
                if let Some(value) = selection.isps {
                    updated.selection.isps = value;
                }
                if let Some(value) = selection.hostnames {
                    updated.selection.hostnames = value;
                }
                if let Some(value) = selection.owned_only {
                    updated.selection.owned_only = value;
                }
                if let Some(value) = selection.mullvad_post_quantum {
                    updated.wireguard.quantum_resistant = value;
                }
                if let Some(endpoint) = selection.wireguard {
                    if endpoint.public_key.is_some_and(|value| !value.is_empty()) {
                        return Err("Mullvad relay keys come from the validated relay list");
                    }
                    if let Some(value) = endpoint.endpoint_ip {
                        updated.selection.endpoint_ip = (!value.is_unspecified()).then_some(value);
                    }
                    if let Some(value) = endpoint.endpoint_port {
                        updated.selection.endpoint_port = (value != 0).then_some(value);
                    }
                }
            }
        }
        if let Some(wireguard) = self.wireguard {
            if wireguard
                .implementation
                .as_deref()
                .is_some_and(|value| value != "kernel")
            {
                return Err("userspace WireGuard is not supported");
            }
            if let Some(value) = wireguard.private_key
                && value.expose() != "[redacted]"
            {
                updated.wireguard.private_key = value;
            }
            if let Some(value) = wireguard.pre_shared_key
                && value.expose() != "[redacted]"
            {
                updated.wireguard.preshared_key = value;
            }
            if let Some(value) = wireguard.addresses {
                updated.wireguard.addresses = value;
            }
            if let Some(value) = wireguard.allowed_ips {
                updated.wireguard.allowed_ips = value;
            }
            if let Some(value) = wireguard.interface {
                updated.wireguard.interface = value;
            }
            if let Some(value) = wireguard.persistent_keep_alive_interval {
                updated.wireguard.persistent_keepalive = Duration::from_nanos(value);
            }
            if let Some(value) = wireguard.mtu {
                updated.wireguard.mtu = value;
            }
        }
        if let Some(pmtud) = self.pmtud {
            if let Some(value) = pmtud.icmp_addresses {
                updated.pmtud.icmp_addresses = value;
            }
            if let Some(value) = pmtud.tcp_addresses {
                updated.pmtud.tcp_addresses = value;
            }
        }
        if updated
            .pmtud
            .tcp_addresses
            .iter()
            .any(|value| value.port() == 0)
        {
            return Err("PMTUD TCP targets require a nonzero port");
        }
        if let Some(value) = self.up_command {
            updated.vpn_up_command = (!value.is_empty()).then_some(value);
        }
        if let Some(value) = self.down_command {
            updated.vpn_down_command = (!value.is_empty()).then_some(value);
        }
        Ok(updated)
    }
}
