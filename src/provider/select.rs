use std::cmp::Ordering;
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Mutex;

use rand::seq::SliceRandom;

use crate::config::{SelectionMode, ServerSelection};
use crate::models::{Connection, Server, VPN_WIREGUARD};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SelectError {
    #[error("no server found in server data")]
    NoServers,
    #[error("no server found for filters: {0}")]
    NoMatch(String),
    #[error("no connection to pick from")]
    NoConnection,
    #[error("target IP address {ip} not found in {count} filtered connections")]
    TargetIpNotFound { ip: IpAddr, count: usize },
}

pub fn filter_servers(
    servers: &[Server],
    selection: &ServerSelection,
) -> Result<Vec<Server>, SelectError> {
    if servers.is_empty() {
        return Err(SelectError::NoServers);
    }
    let kept: Vec<Server> = servers
        .iter()
        .filter(|server| !is_filtered(server, selection))
        .cloned()
        .collect();
    if kept.is_empty() {
        return Err(SelectError::NoMatch(describe(selection)));
    }
    Ok(kept)
}

fn is_filtered(server: &Server, selection: &ServerSelection) -> bool {
    server.vpn != VPN_WIREGUARD
        || (selection.owned_only && !server.owned)
        || rejects(&server.country, &selection.countries)
        || rejects(&server.city, &selection.cities)
        || rejects(&server.isp, &selection.isps)
        || rejects(&server.hostname, &selection.hostnames)
}

fn rejects(value: &str, possibilities: &[String]) -> bool {
    !possibilities.is_empty() && !possibilities.iter().any(|p| p.eq_ignore_ascii_case(value))
}

fn describe(selection: &ServerSelection) -> String {
    let mut parts = vec![format!("VPN {VPN_WIREGUARD}")];
    let mut list = |singular: &str, plural: &str, values: &[String]| match values {
        [] => {}
        [one] => parts.push(format!("{singular} {one}")),
        many => parts.push(format!("{plural} {}", many.join(", "))),
    };
    list("country", "countries", &selection.countries);
    list("city", "cities", &selection.cities);
    list("ISP", "ISPs", &selection.isps);
    list("hostname", "hostnames", &selection.hostnames);
    if selection.owned_only {
        parts.push("owned servers only".into());
    }
    parts.join("; ")
}

fn match_index(value: &str, possibilities: &[String]) -> usize {
    possibilities
        .iter()
        .position(|p| p.eq_ignore_ascii_case(value))
        .unwrap_or(0)
}

pub(crate) fn selection_tier(server: &Server, selection: &ServerSelection) -> usize {
    if !selection.hostnames.is_empty() {
        match_index(&server.hostname, &selection.hostnames)
    } else if !selection.cities.is_empty() {
        match_index(&server.city, &selection.cities)
    } else if !selection.countries.is_empty() {
        match_index(&server.country, &selection.countries)
    } else if !selection.isps.is_empty() {
        match_index(&server.isp, &selection.isps)
    } else {
        0
    }
}

fn ipv6_first(a: bool, b: bool) -> Ordering {
    b.cmp(&a)
}

fn sort_by_tier(servers: &mut [Server], selection: &ServerSelection) {
    servers.sort_by_cached_key(|server| {
        (
            match_index(&server.country, &selection.countries),
            selection_tier(server, selection),
            !server.has_ipv6(),
        )
    });
}

#[derive(Clone, Debug)]
struct Candidate {
    country_priority: usize,
    connection: Connection,
}

#[derive(Debug, Default)]
pub struct ConnectionPicker {
    state: Mutex<PickerState>,
}

#[derive(Debug, Default)]
struct PickerState {
    fingerprint: u64,
    candidates: Vec<Candidate>,
    failed: HashSet<Connection>,
}

impl ConnectionPicker {
    fn pick(&self, mut candidates: Vec<Candidate>, mode: SelectionMode) -> Connection {
        let fingerprint = fingerprint_pool(&candidates, mode);
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.fingerprint != fingerprint || state.candidates.is_empty() {
            state.fingerprint = fingerprint;
            if mode == SelectionMode::Random {
                candidates.shuffle(&mut rand::rng());
                candidates.sort_by_key(|candidate| {
                    (
                        candidate.country_priority,
                        !candidate.connection.ip.is_ipv6(),
                    )
                });
            }
            state.candidates = candidates;
            state.failed.clear();
        }
        if state
            .candidates
            .iter()
            .all(|candidate| state.failed.contains(&candidate.connection))
        {
            state.failed.clear();
        }
        state
            .candidates
            .iter()
            .find(|candidate| !state.failed.contains(&candidate.connection))
            .expect("nonempty candidate pool")
            .connection
            .clone()
    }

    pub fn record_failure(&self, connection: &Connection) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state
            .candidates
            .iter()
            .any(|candidate| candidate.connection == *connection)
        {
            state.failed.insert(connection.clone());
        }
    }

    pub fn record_success(&self) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .failed
            .clear();
    }

    pub fn reset(&self) {
        *self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = PickerState::default();
    }
}

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

fn fnv1a(mut hash: u64, bytes: &[u8]) -> u64 {
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

fn fingerprint_pool(candidates: &[Candidate], mode: SelectionMode) -> u64 {
    let initial = fnv1a(FNV_OFFSET, &[u8::from(mode == SelectionMode::Ordered)]);
    candidates.iter().fold(initial, |mut hash, candidate| {
        let c = &candidate.connection;
        hash = fnv1a(hash, &candidate.country_priority.to_be_bytes());
        let ip = match c.ip {
            IpAddr::V4(v4) => v4.octets().to_vec(),
            IpAddr::V6(v6) => v6.octets().to_vec(),
        };
        for field in [
            VPN_WIREGUARD.as_bytes(),
            &ip,
            &c.port.to_be_bytes(),
            b"udp",
            c.hostname.as_bytes(),
            c.pubkey.as_bytes(),
            c.server_name.as_bytes(),
        ] {
            hash = fnv1a(hash, field);
            hash = fnv1a(hash, b"|");
        }
        fnv1a(hash, b"\n")
    })
}

pub fn get_connection(
    servers: &[Server],
    selection: &ServerSelection,
    default_port: u16,
    ipv6_supported: bool,
    picker: &ConnectionPicker,
) -> Result<Connection, SelectError> {
    let mut servers = filter_servers(servers, selection)?;
    let ordered = selection.mode == SelectionMode::Ordered;
    if ordered {
        sort_by_tier(&mut servers, selection);
    } else {
        servers.sort_by_key(|server| match_index(&server.country, &selection.countries));
    }
    let port = selection.endpoint_port.unwrap_or(default_port);
    let mut connections = Vec::new();
    for server in &mut servers {
        if ordered {
            server
                .ips
                .sort_by(|a, b| ipv6_first(a.is_ipv6(), b.is_ipv6()));
        }
        connections.extend(
            server
                .ips
                .iter()
                .filter(|ip| ipv6_supported || ip.is_ipv4())
                .map(|&ip| Candidate {
                    country_priority: match_index(&server.country, &selection.countries),
                    connection: Connection {
                        ip,
                        port,
                        hostname: server.hostname.clone(),
                        server_name: server.server_name.clone(),
                        pubkey: server.wgpubkey.clone(),
                    },
                }),
        );
    }
    if connections.is_empty() {
        return Err(SelectError::NoConnection);
    }
    match selection.endpoint_ip.filter(|ip| !ip.is_unspecified()) {
        Some(target) => connections
            .into_iter()
            .find(|candidate| candidate.connection.ip == target)
            .map(|candidate| candidate.connection)
            .ok_or(SelectError::TargetIpNotFound {
                ip: target,
                count: servers.len(),
            }),
        None => Ok(picker.pick(connections, selection.mode)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server(hostname: &str, country: &str, city: &str, ips: &[&str]) -> Server {
        Server {
            vpn: VPN_WIREGUARD.into(),
            hostname: hostname.into(),
            country: country.into(),
            city: city.into(),
            wgpubkey: format!("key-{hostname}"),
            ips: ips.iter().map(|ip| ip.parse().expect("ip")).collect(),
            ..Server::default()
        }
    }

    fn fixtures() -> Vec<Server> {
        vec![
            server("a", "Sweden", "Gothenburg", &["1.1.1.1"]),
            server("b", "Sweden", "Stockholm", &["2.2.2.2", "2001:db8::2"]),
            server("c", "Germany", "Berlin", &["3.3.3.3"]),
        ]
    }

    fn country_fixtures() -> Vec<Server> {
        vec![
            server(
                "ar-1",
                "Argentina",
                "Buenos Aires",
                &["192.0.2.1", "2001:db8::1"],
            ),
            server("cz-1", "Czech Republic", "Prague", &["192.0.2.2"]),
            server(
                "cz-2",
                "Czech Republic",
                "Prague",
                &["192.0.2.3", "2001:db8::3"],
            ),
        ]
    }

    fn country_selection(mode: SelectionMode) -> ServerSelection {
        ServerSelection {
            countries: vec!["czech republic".into(), "Argentina".into()],
            mode,
            ..Default::default()
        }
    }

    #[test]
    fn countries_are_priorities_in_both_modes_and_exhaust_primary_endpoints_first() {
        for mode in [SelectionMode::Random, SelectionMode::Ordered] {
            for _ in 0..32 {
                let picker = ConnectionPicker::default();
                let selection = country_selection(mode);
                let mut attempted = HashSet::new();
                for _ in 0..3 {
                    let connection =
                        get_connection(&country_fixtures(), &selection, 51820, true, &picker)
                            .expect("primary");
                    assert!(connection.hostname.starts_with("cz-"));
                    assert!(
                        attempted.insert(connection.clone()),
                        "failed endpoint retried before exhausting its country"
                    );
                    picker.record_failure(&connection);
                }
                let fallback =
                    get_connection(&country_fixtures(), &selection, 51820, true, &picker)
                        .expect("fallback");
                assert_eq!(fallback.hostname, "ar-1");
            }
        }
    }

    #[test]
    fn successful_connections_do_not_consume_the_country_priority() {
        for mode in [SelectionMode::Random, SelectionMode::Ordered] {
            let picker = ConnectionPicker::default();
            let selection = country_selection(mode);
            for _ in 0..16 {
                let connection =
                    get_connection(&country_fixtures(), &selection, 51820, true, &picker)
                        .expect("primary");
                assert!(connection.hostname.starts_with("cz-"));
                picker.record_success();
            }
        }
    }

    #[test]
    fn successful_fallback_rechecks_primary_on_next_failure() {
        for mode in [SelectionMode::Random, SelectionMode::Ordered] {
            let picker = ConnectionPicker::default();
            let selection = country_selection(mode);
            for _ in 0..3 {
                let connection =
                    get_connection(&country_fixtures(), &selection, 51820, true, &picker)
                        .expect("primary");
                picker.record_failure(&connection);
            }
            let fallback = get_connection(&country_fixtures(), &selection, 51820, true, &picker)
                .expect("fallback");
            assert_eq!(fallback.hostname, "ar-1");
            picker.record_success();
            picker.record_failure(&fallback);
            let retried = get_connection(&country_fixtures(), &selection, 51820, true, &picker)
                .expect("primary retried");
            assert!(retried.hostname.starts_with("cz-"));
        }
    }

    #[test]
    fn missing_primary_country_and_new_relays_update_the_priority_pool() {
        for mode in [SelectionMode::Random, SelectionMode::Ordered] {
            let picker = ConnectionPicker::default();
            let selection = country_selection(mode);
            let mut servers = vec![country_fixtures().remove(0)];
            let fallback = get_connection(&servers, &selection, 51820, true, &picker)
                .expect("available fallback");
            assert_eq!(fallback.hostname, "ar-1");
            picker.record_failure(&fallback);
            servers.push(country_fixtures().remove(1));
            let primary =
                get_connection(&servers, &selection, 51820, true, &picker).expect("new primary");
            assert!(primary.hostname.starts_with("cz-"));
        }
    }

    #[test]
    fn exhausted_country_list_and_explicit_reset_restart_with_primary() {
        for mode in [SelectionMode::Random, SelectionMode::Ordered] {
            let picker = ConnectionPicker::default();
            let selection = country_selection(mode);
            let mut attempted = HashSet::new();
            for _ in 0..5 {
                let connection =
                    get_connection(&country_fixtures(), &selection, 51820, true, &picker)
                        .expect("candidate");
                assert!(attempted.insert(connection.clone()));
                picker.record_failure(&connection);
            }
            let first = get_connection(&country_fixtures(), &selection, 51820, true, &picker)
                .expect("new attempt cycle");
            assert!(first.hostname.starts_with("cz-"));
            picker.record_failure(&first);
            picker.reset();
            let reset = get_connection(&country_fixtures(), &selection, 51820, true, &picker)
                .expect("manual restart");
            assert!(reset.hostname.starts_with("cz-"));
        }
    }

    #[test]
    fn country_fallback_keeps_city_and_ipv6_filters() {
        let picker = ConnectionPicker::default();
        let mut selection = country_selection(SelectionMode::Random);
        selection.cities = vec!["Buenos Aires".into()];
        let fallback = get_connection(&country_fixtures(), &selection, 51820, false, &picker)
            .expect("matching city");
        assert_eq!(fallback.hostname, "ar-1");
        assert!(fallback.ip.is_ipv4());
        selection.cities = vec!["Amsterdam".into()];
        assert!(matches!(
            get_connection(&country_fixtures(), &selection, 51820, true, &picker),
            Err(SelectError::NoMatch(_))
        ));
    }

    #[test]
    fn filters_case_insensitive() {
        let selection = ServerSelection {
            countries: vec!["sweden".into()],
            ..Default::default()
        };
        let kept = filter_servers(&fixtures(), &selection).expect("match");
        assert_eq!(kept.len(), 2);
        let selection = ServerSelection {
            countries: vec!["France".into()],
            ..Default::default()
        };
        assert!(matches!(
            filter_servers(&fixtures(), &selection),
            Err(SelectError::NoMatch(_))
        ));
    }

    #[test]
    fn ordered_uses_tier_then_ipv6() {
        let selection = ServerSelection {
            cities: vec!["Stockholm".into(), "Berlin".into(), "Gothenburg".into()],
            mode: SelectionMode::Ordered,
            ..Default::default()
        };
        let picker = ConnectionPicker::default();
        let first = get_connection(&fixtures(), &selection, 51820, true, &picker).expect("conn");
        assert_eq!(first.hostname, "b");
        assert!(first.ip.is_ipv6());
        picker.record_failure(&first);
        let second = get_connection(&fixtures(), &selection, 51820, true, &picker).expect("conn");
        assert_eq!(second.hostname, "b");
        assert!(second.ip.is_ipv4());
        picker.record_failure(&second);
        let third = get_connection(&fixtures(), &selection, 51820, true, &picker).expect("conn");
        assert_eq!(third.hostname, "c");
    }

    #[test]
    fn ipv6_skipped_when_unsupported() {
        let selection = ServerSelection {
            hostnames: vec!["b".into()],
            ..Default::default()
        };
        let picker = ConnectionPicker::default();
        for _ in 0..4 {
            let conn =
                get_connection(&fixtures(), &selection, 51820, false, &picker).expect("conn");
            assert!(conn.ip.is_ipv4());
        }
    }

    #[test]
    fn endpoint_ip_selects_server() {
        let selection = ServerSelection {
            endpoint_ip: Some("3.3.3.3".parse().expect("ip")),
            endpoint_port: Some(1234),
            ..Default::default()
        };
        let conn = get_connection(
            &fixtures(),
            &selection,
            51820,
            false,
            &ConnectionPicker::default(),
        )
        .expect("conn");
        assert_eq!(conn.pubkey, "key-c");
        assert_eq!(conn.port, 1234);
    }
}
