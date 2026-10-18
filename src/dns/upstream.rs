use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use serde::{Serialize, Serializer};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum UpstreamType {
    #[default]
    Dot,
    Doh,
    Plain,
}

impl FromStr for UpstreamType {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_lowercase().as_str() {
            "dot" => Ok(Self::Dot),
            "doh" => Ok(Self::Doh),
            "plain" => Ok(Self::Plain),
            other => Err(format!(
                "unknown upstream type {other:?}: expected dot, doh or plain"
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DnsPreset {
    Cloudflare,
    CloudflareSecurity,
    CloudflareFamily,
    Google,
    Quad9,
    Quad9Unsecured,
    CiraPrivate,
    CiraProtected,
    CiraFamily,
    CleanBrowsingSecurity,
    CleanBrowsingFamily,
    CleanBrowsingAdult,
    Mullvad,
    MullvadAdblock,
    MullvadBase,
    MullvadExtended,
    MullvadFamily,
    MullvadAll,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PresetServer {
    pub tls_name: &'static str,
    pub doh_path: &'static str,
    pub ipv4: [Ipv4Addr; 2],
    pub ipv6: [Ipv6Addr; 2],
}

impl PresetServer {
    pub fn addresses(&self, ipv6: bool) -> Vec<IpAddr> {
        let mut out: Vec<IpAddr> = Vec::with_capacity(4);
        if ipv6 {
            out.extend(self.ipv6.iter().copied().map(IpAddr::V6));
        }
        out.extend(self.ipv4.iter().copied().map(IpAddr::V4));
        out.dedup();
        out
    }
}

const fn v4(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
    Ipv4Addr::new(a, b, c, d)
}

#[allow(clippy::too_many_arguments)]
const fn v6(a: u16, b: u16, c: u16, d: u16, e: u16, f: u16, g: u16, h: u16) -> Ipv6Addr {
    Ipv6Addr::new(a, b, c, d, e, f, g, h)
}

const fn mullvad(tls_name: &'static str, last: u8) -> PresetServer {
    PresetServer {
        tls_name,
        doh_path: "/dns-query",
        ipv4: [v4(194, 242, 2, last), v4(194, 242, 2, last)],
        ipv6: [
            v6(0x2a07, 0xe340, 0, 0, 0, 0, 0, last as u16),
            v6(0x2a07, 0xe340, 0, 0, 0, 0, 0, last as u16),
        ],
    }
}

impl DnsPreset {
    pub const ALL: [Self; 18] = [
        Self::Cloudflare,
        Self::CloudflareSecurity,
        Self::CloudflareFamily,
        Self::Google,
        Self::Quad9,
        Self::Quad9Unsecured,
        Self::CiraPrivate,
        Self::CiraProtected,
        Self::CiraFamily,
        Self::CleanBrowsingSecurity,
        Self::CleanBrowsingFamily,
        Self::CleanBrowsingAdult,
        Self::Mullvad,
        Self::MullvadAdblock,
        Self::MullvadBase,
        Self::MullvadExtended,
        Self::MullvadFamily,
        Self::MullvadAll,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            Self::Cloudflare => "cloudflare",
            Self::CloudflareSecurity => "cloudflare security",
            Self::CloudflareFamily => "cloudflare family",
            Self::Google => "google",
            Self::Quad9 => "quad9",
            Self::Quad9Unsecured => "quad9 unsecured",
            Self::CiraPrivate => "cira private",
            Self::CiraProtected => "cira protected",
            Self::CiraFamily => "cira family",
            Self::CleanBrowsingSecurity => "cleanbrowsing security",
            Self::CleanBrowsingFamily => "cleanbrowsing family",
            Self::CleanBrowsingAdult => "cleanbrowsing adult",
            Self::Mullvad => "mullvad",
            Self::MullvadAdblock => "mullvad adblock",
            Self::MullvadBase => "mullvad base",
            Self::MullvadExtended => "mullvad extended",
            Self::MullvadFamily => "mullvad family",
            Self::MullvadAll => "mullvad all",
        }
    }

    pub const fn server(self) -> PresetServer {
        match self {
            Self::Cloudflare => PresetServer {
                tls_name: "cloudflare-dns.com",
                doh_path: "/dns-query",
                ipv4: [v4(1, 1, 1, 1), v4(1, 0, 0, 1)],
                ipv6: [
                    v6(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111),
                    v6(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1001),
                ],
            },
            Self::CloudflareSecurity => PresetServer {
                tls_name: "security.cloudflare-dns.com",
                doh_path: "/dns-query",
                ipv4: [v4(1, 1, 1, 2), v4(1, 0, 0, 2)],
                ipv6: [
                    v6(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1112),
                    v6(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1002),
                ],
            },
            Self::CloudflareFamily => PresetServer {
                tls_name: "family.cloudflare-dns.com",
                doh_path: "/dns-query",
                ipv4: [v4(1, 1, 1, 3), v4(1, 0, 0, 3)],
                ipv6: [
                    v6(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1113),
                    v6(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1003),
                ],
            },
            Self::Google => PresetServer {
                tls_name: "dns.google",
                doh_path: "/dns-query",
                ipv4: [v4(8, 8, 8, 8), v4(8, 8, 4, 4)],
                ipv6: [
                    v6(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888),
                    v6(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8844),
                ],
            },
            Self::Quad9 => PresetServer {
                tls_name: "dns.quad9.net",
                doh_path: "/dns-query",
                ipv4: [v4(9, 9, 9, 9), v4(149, 112, 112, 112)],
                ipv6: [
                    v6(0x2620, 0xfe, 0, 0, 0, 0, 0, 0xfe),
                    v6(0x2620, 0xfe, 0, 0, 0, 0, 0, 0x9),
                ],
            },
            Self::Quad9Unsecured => PresetServer {
                tls_name: "dns10.quad9.net",
                doh_path: "/dns-query",
                ipv4: [v4(9, 9, 9, 10), v4(149, 112, 112, 10)],
                ipv6: [
                    v6(0x2620, 0xfe, 0, 0, 0, 0, 0, 0x10),
                    v6(0x2620, 0xfe, 0, 0, 0, 0, 0xfe, 0x10),
                ],
            },
            Self::CiraPrivate => PresetServer {
                tls_name: "private.canadianshield.cira.ca",
                doh_path: "/dns-query",
                ipv4: [v4(149, 112, 121, 10), v4(149, 112, 122, 10)],
                ipv6: [
                    v6(0x2620, 0x10a, 0x80bb, 0, 0, 0, 0, 0x10),
                    v6(0x2620, 0x10a, 0x80bc, 0, 0, 0, 0, 0x10),
                ],
            },
            Self::CiraProtected => PresetServer {
                tls_name: "protected.canadianshield.cira.ca",
                doh_path: "/dns-query",
                ipv4: [v4(149, 112, 121, 20), v4(149, 112, 122, 20)],
                ipv6: [
                    v6(0x2620, 0x10a, 0x80bb, 0, 0, 0, 0, 0x20),
                    v6(0x2620, 0x10a, 0x80bc, 0, 0, 0, 0, 0x20),
                ],
            },
            Self::CiraFamily => PresetServer {
                tls_name: "family.canadianshield.cira.ca",
                doh_path: "/dns-query",
                ipv4: [v4(149, 112, 121, 30), v4(149, 112, 122, 30)],
                ipv6: [
                    v6(0x2620, 0x10a, 0x80bb, 0, 0, 0, 0, 0x30),
                    v6(0x2620, 0x10a, 0x80bc, 0, 0, 0, 0, 0x30),
                ],
            },
            Self::CleanBrowsingSecurity => PresetServer {
                tls_name: "security-filter-dns.cleanbrowsing.org",
                doh_path: "/doh/security-filter/",
                ipv4: [v4(185, 228, 168, 9), v4(185, 228, 169, 9)],
                ipv6: [
                    v6(0x2a0d, 0x2a00, 1, 0, 0, 0, 0, 2),
                    v6(0x2a0d, 0x2a00, 2, 0, 0, 0, 0, 2),
                ],
            },
            Self::CleanBrowsingFamily => PresetServer {
                tls_name: "family-filter-dns.cleanbrowsing.org",
                doh_path: "/doh/family-filter/",
                ipv4: [v4(185, 228, 168, 168), v4(185, 228, 169, 168)],
                ipv6: [
                    v6(0x2a0d, 0x2a00, 1, 0, 0, 0, 0, 0),
                    v6(0x2a0d, 0x2a00, 2, 0, 0, 0, 0, 0),
                ],
            },
            Self::CleanBrowsingAdult => PresetServer {
                tls_name: "adult-filter-dns.cleanbrowsing.org",
                doh_path: "/doh/adult-filter/",
                ipv4: [v4(185, 228, 168, 10), v4(185, 228, 169, 11)],
                ipv6: [
                    v6(0x2a0d, 0x2a00, 1, 0, 0, 0, 0, 1),
                    v6(0x2a0d, 0x2a00, 2, 0, 0, 0, 0, 1),
                ],
            },
            Self::Mullvad => mullvad("dns.mullvad.net", 2),
            Self::MullvadAdblock => mullvad("adblock.dns.mullvad.net", 3),
            Self::MullvadBase => mullvad("base.dns.mullvad.net", 4),
            Self::MullvadExtended => mullvad("extended.dns.mullvad.net", 5),
            Self::MullvadFamily => mullvad("family.dns.mullvad.net", 6),
            Self::MullvadAll => mullvad("all.dns.mullvad.net", 9),
        }
    }

    pub fn doh_url(self) -> String {
        let server = self.server();
        format!("https://{}{}", server.tls_name, server.doh_path)
    }
}

impl fmt::Display for DnsPreset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for DnsPreset {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let normalized = value.trim().to_ascii_lowercase().replace(['-', '_'], " ");
        let normalized = match normalized.as_str() {
            "quad9 secured" => "quad9",
            other => other,
        };
        Self::ALL
            .into_iter()
            .find(|preset| preset.name() == normalized)
            .ok_or_else(|| {
                let names: Vec<&str> = Self::ALL.iter().map(|p| p.name()).collect();
                format!(
                    "unknown DNS resolver {value:?}: expected one of {}",
                    names.join(", ")
                )
            })
    }
}

impl Serialize for DnsPreset {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mullvad_presets() {
        let base: DnsPreset = "Mullvad-Base".parse().expect("preset");
        assert_eq!(base, DnsPreset::MullvadBase);
        let server = base.server();
        assert_eq!(server.ipv4[0], Ipv4Addr::new(194, 242, 2, 4));
        assert_eq!(
            server.ipv6[0],
            "2a07:e340::4".parse::<Ipv6Addr>().expect("ip")
        );
        assert_eq!(base.doh_url(), "https://base.dns.mullvad.net/dns-query");
        assert_eq!(server.addresses(true).len(), 2);
    }

    #[test]
    fn all_presets_roundtrip() {
        for preset in DnsPreset::ALL {
            assert_eq!(preset.name().parse::<DnsPreset>(), Ok(preset));
        }
        assert_eq!("quad9 secured".parse::<DnsPreset>(), Ok(DnsPreset::Quad9));
    }
}
