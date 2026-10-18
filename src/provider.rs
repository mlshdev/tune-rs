mod select;

use std::fmt;
use std::str::FromStr;

use serde::{Serialize, Serializer};

pub use select::{ConnectionPicker, SelectError, filter_servers, get_connection};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProviderName {
    Mullvad,
}

impl ProviderName {
    pub const ALL: [Self; 1] = [Self::Mullvad];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Mullvad => "mullvad",
        }
    }

    pub const fn default_wireguard_port(self) -> u16 {
        51820
    }
}

impl fmt::Display for ProviderName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, thiserror::Error)]
#[error("unsupported VPN service provider {0:?}: only mullvad is supported")]
pub struct UnknownProvider(String);

impl FromStr for ProviderName {
    type Err = UnknownProvider;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let lower = value.to_ascii_lowercase();
        Self::ALL
            .into_iter()
            .find(|name| name.as_str() == lower)
            .ok_or(UnknownProvider(value.to_owned()))
    }
}

impl Serialize for ProviderName {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_case_insensitive() {
        assert_eq!(
            "Mullvad".parse::<ProviderName>().ok(),
            Some(ProviderName::Mullvad)
        );
        assert!("openvpn-provider".parse::<ProviderName>().is_err());
    }
}
