use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use ipnetwork::IpNetwork;
use tokio::sync::{RwLock, watch};

use crate::config::DnsSettings;
use crate::vpn::Status;

const MAX_LIST_BYTES: u64 = 16 * 1024 * 1024;
const FETCH_TIMEOUT: Duration = Duration::from_secs(30);
const LIST_BASE: &str = "https://raw.githubusercontent.com/qdm12/files/master";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Category {
    Malicious,
    Ads,
    Surveillance,
}

impl Category {
    const ALL: [Self; 3] = [Self::Malicious, Self::Ads, Self::Surveillance];

    const fn name(self) -> &'static str {
        match self {
            Self::Malicious => "malicious",
            Self::Ads => "ads",
            Self::Surveillance => "surveillance",
        }
    }

    fn enabled(self, settings: &DnsSettings) -> bool {
        match self {
            Self::Malicious => settings.block_malicious,
            Self::Ads => settings.block_ads,
            Self::Surveillance => settings.block_surveillance,
        }
    }
}

#[derive(Clone, Debug, Default)]
struct List {
    hostnames: HashSet<String>,
    ips: HashSet<IpAddr>,
    prefixes: Vec<IpNetwork>,
}

#[derive(Default)]
pub struct Blocklists {
    current: RwLock<List>,
}

impl Blocklists {
    pub async fn blocks_hostname(&self, hostname: &str) -> bool {
        let current = self.current.read().await;
        if current.hostnames.contains(hostname) {
            return true;
        }
        hostname
            .match_indices('.')
            .any(|(index, _)| current.hostnames.contains(&hostname[index + 1..]))
    }

    pub async fn blocks_ip(&self, ip: IpAddr) -> bool {
        let current = self.current.read().await;
        current.ips.contains(&ip) || current.prefixes.iter().any(|network| network.contains(ip))
    }

    async fn replace(&self, lists: &HashMap<Category, List>) {
        let mut next = List::default();
        for list in lists.values() {
            next.hostnames.extend(list.hostnames.iter().cloned());
            next.ips.extend(list.ips.iter().copied());
            next.prefixes.extend(list.prefixes.iter().copied());
        }
        tracing::info!(
            hostnames = next.hostnames.len(),
            ips = next.ips.len(),
            prefixes = next.prefixes.len(),
            "DNS blocklists updated"
        );
        *self.current.write().await = next;
    }
}

pub async fn update_loop(
    settings: DnsSettings,
    blocklists: Arc<Blocklists>,
    mut status: watch::Receiver<Status>,
) {
    let client = match reqwest::Client::builder()
        .no_proxy()
        .timeout(FETCH_TIMEOUT)
        .build()
    {
        Ok(client) => client,
        Err(error) => {
            tracing::error!(%error, "configuring DNS blocklist downloader");
            return;
        }
    };
    let mut lists = HashMap::new();
    'update_loop: loop {
        while !matches!(&*status.borrow_and_update(), Status::Running(_)) {
            if status.changed().await.is_err() {
                return;
            }
        }
        for category in Category::ALL {
            if !category.enabled(&settings) {
                continue;
            }
            if !matches!(&*status.borrow(), Status::Running(_)) {
                break;
            }
            let host_url = format!("{LIST_BASE}/{}-hostnames.updated", category.name());
            let ip_url = format!("{LIST_BASE}/{}-ips.updated", category.name());
            let hostnames = tokio::select! {
                result = fetch(&client, &host_url) => result,
                update = status.changed() => {
                    if update.is_err() { return; }
                    continue 'update_loop;
                }
            };
            let ips = tokio::select! {
                result = fetch(&client, &ip_url) => result,
                update = status.changed() => {
                    if update.is_err() { return; }
                    continue 'update_loop;
                }
            };
            let current = lists.entry(category).or_insert_with(List::default);
            match hostnames {
                Ok(lines) => current.hostnames = parse_hostnames(&lines),
                Err(error) => tracing::warn!(%error, url = %host_url, "downloading DNS blocklist"),
            }
            match ips {
                Ok(lines) => {
                    (current.ips, current.prefixes) = parse_ips(&lines);
                }
                Err(error) => tracing::warn!(%error, url = %ip_url, "downloading DNS blocklist"),
            }
            blocklists.replace(&lists).await;
        }
        if settings.update_period.is_zero() {
            while matches!(&*status.borrow_and_update(), Status::Running(_)) {
                if status.changed().await.is_err() {
                    return;
                }
            }
        } else {
            tokio::select! {
                () = tokio::time::sleep(settings.update_period) => {},
                result = status.changed() => if result.is_err() { return; },
            }
        }
    }
}

async fn fetch(client: &reqwest::Client, url: &str) -> Result<String, String> {
    let response = client
        .get(url)
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(|error| error.to_string())?;
    if response
        .content_length()
        .is_some_and(|length| length > MAX_LIST_BYTES)
    {
        return Err(format!("blocklist larger than {MAX_LIST_BYTES} bytes"));
    }
    let bytes = response.bytes().await.map_err(|error| error.to_string())?;
    if bytes.len() as u64 > MAX_LIST_BYTES {
        return Err(format!("blocklist larger than {MAX_LIST_BYTES} bytes"));
    }
    String::from_utf8(bytes.to_vec()).map_err(|error| error.to_string())
}

fn lines(content: &str) -> impl Iterator<Item = &str> {
    content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
}

fn parse_hostnames(content: &str) -> HashSet<String> {
    lines(content)
        .filter_map(|line| {
            let host = line.trim_end_matches('.').to_ascii_lowercase();
            (!host.is_empty() && !host.contains(char::is_whitespace)).then_some(host)
        })
        .collect()
}

fn parse_ips(content: &str) -> (HashSet<IpAddr>, Vec<IpNetwork>) {
    let mut ips = HashSet::new();
    let mut prefixes = Vec::new();
    for line in lines(content) {
        if let Ok(ip) = line.parse() {
            ips.insert(ip);
        } else if let Ok(prefix) = line.parse() {
            prefixes.push(prefix);
        }
    }
    (ips, prefixes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn filters_hostname_boundaries_and_ip_ranges() {
        let blocklists = Blocklists::default();
        let list = List {
            hostnames: parse_hostnames("# comment\nExample.COM\n"),
            ips: HashSet::from(["1.2.3.4".parse().expect("IP")]),
            prefixes: parse_ips("10.1.0.0/16\n").1,
        };
        blocklists
            .replace(&HashMap::from([(Category::Malicious, list)]))
            .await;
        assert!(blocklists.blocks_hostname("sub.example.com").await);
        assert!(!blocklists.blocks_hostname("badexample.com").await);
        assert!(blocklists.blocks_ip("10.1.2.3".parse().expect("IP")).await);
        assert!(blocklists.blocks_ip("1.2.3.4".parse().expect("IP")).await);
    }
}
