use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use serde::Deserialize;
use tokio::sync::watch;

use crate::config::UpdaterSettings;
use crate::control::lifecycle::{self, State};
use crate::models::{Server, VPN_WIREGUARD};
use crate::provider::ProviderName;
use crate::storage::{Storage, StorageError};
use crate::vpn::Status;
use crate::wireguard::keys::decode_key;

const RELAYS_URL: &str = "https://api.mullvad.net/app/v1/relays";
const MAX_BODY: usize = 8 * 1024 * 1024;
const RETRY_DELAY: Duration = Duration::from_secs(60);

#[derive(Debug, thiserror::Error)]
pub enum UpdateError {
    #[error("requesting Mullvad relays: {0}")]
    Request(#[from] reqwest::Error),
    #[error("Mullvad relay API returned HTTP {0}")]
    Http(reqwest::StatusCode),
    #[error("Mullvad relay response exceeds {MAX_BODY} bytes")]
    TooLarge,
    #[error("decoding Mullvad relays: {0}")]
    Decode(#[from] serde_json::Error),
    #[error("invalid Mullvad relay {hostname:?}: {reason}")]
    Invalid {
        hostname: String,
        reason: &'static str,
    },
    #[error("Mullvad returned no active WireGuard relays")]
    Empty,
    #[error("Mullvad relay count decreased from {previous} to {received}, below UPDATER_MIN_RATIO")]
    TooFew { previous: usize, received: usize },
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error("joining relay storage worker: {0}")]
    Worker(#[from] tokio::task::JoinError),
}

#[derive(Deserialize)]
struct RelayList {
    locations: BTreeMap<String, Location>,
    wireguard: Wireguard,
}

#[derive(Deserialize)]
struct Location {
    country: String,
    city: String,
}

#[derive(Deserialize)]
struct Wireguard {
    relays: Vec<Relay>,
}

#[derive(Deserialize)]
struct Relay {
    hostname: String,
    location: String,
    active: bool,
    owned: bool,
    provider: String,
    ipv4_addr_in: Ipv4Addr,
    ipv6_addr_in: Option<Ipv6Addr>,
    public_key: String,
}

fn parse_relays(body: &[u8]) -> Result<Vec<Server>, UpdateError> {
    let list: RelayList = serde_json::from_slice(body)?;
    let mut hostnames = BTreeSet::new();
    let mut servers = Vec::new();
    for relay in list
        .wireguard
        .relays
        .into_iter()
        .filter(|relay| relay.active)
    {
        let invalid = |reason| UpdateError::Invalid {
            hostname: relay.hostname.clone(),
            reason,
        };
        if relay.hostname.is_empty()
            || !relay
                .hostname
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-')
            || !hostnames.insert(relay.hostname.to_ascii_lowercase())
        {
            return Err(invalid("empty, malformed, or duplicate hostname"));
        }
        let location = list
            .locations
            .get(&relay.location)
            .ok_or_else(|| invalid("unknown location"))?;
        if location.country.is_empty() || location.city.is_empty() {
            return Err(invalid("empty country or city"));
        }
        let key =
            decode_key(&relay.public_key).map_err(|_| invalid("invalid WireGuard public key"))?;
        if key == [0; 32] {
            return Err(invalid("zero WireGuard public key"));
        }
        if relay.ipv4_addr_in.is_unspecified()
            || relay.ipv4_addr_in.is_loopback()
            || relay.ipv4_addr_in.is_multicast()
            || relay.ipv4_addr_in.is_private()
            || relay.ipv4_addr_in.is_link_local()
            || relay.ipv4_addr_in.is_broadcast()
        {
            return Err(invalid("invalid IPv4 endpoint"));
        }
        let mut ips = vec![relay.ipv4_addr_in.into()];
        if let Some(ip) = relay.ipv6_addr_in {
            if ip.is_unspecified()
                || ip.is_loopback()
                || ip.is_multicast()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
            {
                return Err(invalid("invalid IPv6 endpoint"));
            }
            ips.push(ip.into());
        }
        servers.push(Server {
            vpn: VPN_WIREGUARD.into(),
            country: location.country.clone(),
            city: location.city.clone(),
            isp: relay.provider,
            owned: relay.owned,
            hostname: relay.hostname.to_ascii_lowercase(),
            wgpubkey: relay.public_key,
            ips,
            ..Server::default()
        });
    }
    if servers.is_empty() {
        return Err(UpdateError::Empty);
    }
    crate::storage::sort_servers(&mut servers);
    Ok(servers)
}

pub struct Updater {
    settings: UpdaterSettings,
    storage: Storage,
    client: reqwest::Client,
}

impl Updater {
    pub async fn refresh(&self) -> Result<usize, UpdateError> {
        self.update(RELAYS_URL).await
    }

    pub fn new(settings: UpdaterSettings, storage: Storage) -> Result<Self, UpdateError> {
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(30))
            .user_agent(concat!("tune/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self {
            settings,
            storage,
            client,
        })
    }

    pub async fn run(self, status: watch::Receiver<Status>) {
        self.run_at(status, RELAYS_URL).await;
    }

    pub async fn run_controlled(self, status: watch::Receiver<Status>, control: lifecycle::Worker) {
        self.run_controlled_at(status, control, RELAYS_URL).await;
    }

    async fn run_at(self, status: watch::Receiver<Status>, url: &str) {
        let (_controller, worker) = lifecycle::channel();
        self.run_controlled_at(status, worker, url).await;
    }

    async fn run_controlled_at(
        self,
        mut status: watch::Receiver<Status>,
        mut control: lifecycle::Worker,
        url: &str,
    ) {
        let mut next = (!self.settings.period.is_zero()).then(Instant::now);
        loop {
            let running = matches!(*status.borrow_and_update(), Status::Running(_));
            tokio::select! {
                biased;
                command = control.next() => {
                    let Some(command) = command else { return; };
                    next = (command.state == State::Running).then(Instant::now);
                    control.publish(command.state);
                    command.acknowledge();
                    continue;
                }
                changed = status.changed() => {
                    if changed.is_err() { return; }
                    continue;
                }
                () = async {
                    if let Some(deadline) = next { tokio::time::sleep_until(deadline.into()).await; }
                    else { std::future::pending::<()>().await; }
                }, if running => {}
            }
            control.publish(State::Running);
            let mut update = Box::pin(self.update(url));
            loop {
                tokio::select! {
                    biased;
                    command = control.next() => {
                        let Some(command) = command else { return; };
                        if command.state == State::Running && !command.restart {
                            command.acknowledge();
                            continue;
                        }
                        next = (command.state == State::Running).then(Instant::now);
                        drop(update);
                        control.publish(command.state);
                        command.acknowledge();
                        break;
                    }
                    changed = status.changed() => {
                        if changed.is_err() { return; }
                        next = Some(Instant::now());
                        control.publish(State::Stopped);
                        break;
                    }
                    result = &mut update => {
                        let delay = match result {
                            Ok(_) => self.settings.period,
                            Err(error) => {
                                tracing::warn!(%error, "Mullvad relay update failed; retaining existing relays");
                                RETRY_DELAY
                            }
                        };
                        next = (!self.settings.period.is_zero()).then(|| Instant::now() + delay);
                        control.publish(State::Stopped);
                        break;
                    }
                }
            }
        }
    }

    async fn update(&self, url: &str) -> Result<usize, UpdateError> {
        let existing = self.storage.servers_object(ProviderName::Mullvad);
        if existing.preferred {
            tracing::debug!("skipping Mullvad relay update: persisted list is preferred");
            return Ok(existing.servers.len());
        }
        let mut response = self.client.get(url).send().await?;
        if response.status() != reqwest::StatusCode::OK {
            return Err(UpdateError::Http(response.status()));
        }
        if response
            .content_length()
            .is_some_and(|len| len > MAX_BODY as u64)
        {
            return Err(UpdateError::TooLarge);
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            if body.len().saturating_add(chunk.len()) > MAX_BODY {
                return Err(UpdateError::TooLarge);
            }
            body.extend_from_slice(&chunk);
        }
        let mut servers = parse_relays(&body)?;
        let previous = existing
            .servers
            .iter()
            .filter(|server| !server.keep)
            .count();
        let count = servers.len();
        if (count as f64) < previous as f64 * self.settings.min_ratio {
            return Err(UpdateError::TooFew {
                previous,
                received: count,
            });
        }
        for kept in existing.servers.into_iter().filter(|server| server.keep) {
            if let Some(server) = servers.iter_mut().find(|server| server.key() == kept.key()) {
                *server = kept;
            } else {
                servers.push(kept);
            }
        }
        let storage = self.storage.clone();
        tokio::task::spawn_blocking(move || storage.set_servers(ProviderName::Mullvad, servers))
            .await??;
        tracing::info!(count, "Mullvad relay list updated");
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    #[tokio::test]
    async fn manual_update_works_with_zero_period_and_stop_cancels_download() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        async fn read_request(connection: &mut tokio::net::TcpStream) {
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                request.push(connection.read_u8().await.expect("request byte"));
                assert!(request.len() < 8192);
            }
            assert!(request.starts_with(b"GET /relays HTTP/1.1\r\n"));
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listen");
        let url = format!("http://{}/relays", listener.local_addr().expect("address"));
        let storage = Storage::new(None).expect("storage");
        let updater = Updater::new(
            UpdaterSettings {
                period: Duration::ZERO,
                min_ratio: 0.0001,
            },
            storage.clone(),
        )
        .expect("updater");
        let (vpn, status) = watch::channel(Status::Running(crate::vpn::Tunnel {
            interface: "wg0".into(),
            connection: crate::models::Connection {
                ip: Ipv4Addr::LOCALHOST.into(),
                port: 51820,
                hostname: String::new(),
                server_name: String::new(),
                pubkey: String::new(),
            },
            ipv6: false,
        }));
        let (controller, worker) = lifecycle::channel();
        let task =
            tokio::spawn(async move { updater.run_controlled_at(status, worker, &url).await });
        assert!(
            tokio::time::timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_err()
        );
        controller
            .apply(State::Running, false)
            .await
            .expect("start");
        let (mut connection, _) = tokio::time::timeout(Duration::from_secs(2), listener.accept())
            .await
            .expect("download started")
            .expect("accept");
        let mut buffer = [0u8; 2048];
        read_request(&mut connection).await;
        assert_eq!(controller.state(), State::Running);
        controller
            .apply(State::Stopped, false)
            .await
            .expect("stop acknowledged");
        assert_eq!(controller.state(), State::Stopped);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), connection.read(&mut buffer))
                .await
                .expect("connection cancelled")
                .expect("EOF"),
            0
        );
        controller
            .apply(State::Running, true)
            .await
            .expect("restart");
        let (mut connection, _) = tokio::time::timeout(Duration::from_secs(2), listener.accept())
            .await
            .expect("download restarted")
            .expect("accept");
        read_request(&mut connection).await;
        let body = fixture().to_string();
        connection
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            )
            .await
            .expect("response");
        tokio::time::timeout(Duration::from_secs(2), async {
            while controller.state() != State::Stopped {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("update completed");
        assert_eq!(storage.servers(ProviderName::Mullvad).len(), 1);
        assert!(
            tokio::time::timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_err()
        );
        drop(vpn);
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("stopped")
            .expect("joined");
    }

    fn fixture() -> Value {
        json!({
            "locations": {"se-got": {"country": "Sweden", "city": "Gothenburg"}},
            "wireguard": {"relays": [{
                "hostname": "se-got-wg-001", "location": "se-got", "active": true,
                "owned": true, "provider": "Mullvad", "ipv4_addr_in": "185.213.154.66",
                "ipv6_addr_in": "2a03:1b20:5:f011::a01f",
                "public_key": "ofyfRvMPB0PPIGGItNL+5tNdvTKXuWye5CfjPgPNvQ8="
            }]},
            "openvpn": {"relays": [{"hostname": "not-wireguard"}]}
        })
    }

    fn parse(value: &Value) -> Result<Vec<Server>, UpdateError> {
        parse_relays(&serde_json::to_vec(value).expect("encode fixture"))
    }

    #[test]
    fn converts_only_active_wireguard_relays() {
        let mut value = fixture();
        let mut inactive = value["wireguard"]["relays"][0].clone();
        inactive["active"] = json!(false);
        value["wireguard"]["relays"]
            .as_array_mut()
            .expect("relays")
            .push(inactive);
        let servers = parse(&value).expect("parse relays");
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].country, "Sweden");
        assert_eq!(servers[0].city, "Gothenburg");
        assert!(servers[0].owned);
        assert!(servers[0].has_ipv6());
    }

    #[test]
    fn rejects_corrupt_lists() {
        for (key, replacement) in [
            ("public_key", json!("bad")),
            ("location", json!("unknown")),
            ("ipv4_addr_in", json!("127.0.0.1")),
            ("ipv6_addr_in", json!("fc00::1")),
            ("hostname", json!("")),
            ("active", json!(false)),
        ] {
            let mut value = fixture();
            value["wireguard"]["relays"][0][key] = replacement;
            assert!(parse(&value).is_err(), "{key}");
        }
        let mut duplicate = fixture();
        let relay = duplicate["wireguard"]["relays"][0].clone();
        duplicate["wireguard"]["relays"]
            .as_array_mut()
            .expect("relays")
            .push(relay);
        assert!(parse(&duplicate).is_err());
    }

    #[tokio::test]
    async fn downloads_validates_and_preserves_last_good_list() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listen");
        let url = format!("http://{}/relays", listener.local_addr().expect("address"));
        let app = axum::Router::new().route(
            "/relays",
            axum::routing::get(|| async { axum::Json(fixture()) }),
        );
        let task = tokio::spawn(async move { axum::serve(listener, app).await.expect("serve") });
        let storage = Storage::new(None).expect("storage");
        let original = storage.servers(ProviderName::Mullvad);
        let mut updater = Updater::new(
            UpdaterSettings {
                period: RETRY_DELAY,
                min_ratio: 0.8,
            },
            storage.clone(),
        )
        .expect("updater");
        assert!(matches!(
            updater.update(&url).await,
            Err(UpdateError::TooFew { .. })
        ));
        assert_eq!(storage.servers(ProviderName::Mullvad), original);
        updater.settings.min_ratio = 0.0001;
        assert_eq!(updater.update(&url).await.expect("update"), 1);
        assert_eq!(
            storage.servers(ProviderName::Mullvad)[0].hostname,
            "se-got-wg-001"
        );
        task.abort();
    }

    #[tokio::test]
    async fn waits_for_running_tunnel_and_exits_on_closed_status() {
        let storage = Storage::new(None).expect("storage");
        let original = storage.servers_object(ProviderName::Mullvad);
        let updater = Updater::new(
            UpdaterSettings {
                period: RETRY_DELAY,
                min_ratio: 0.8,
            },
            storage.clone(),
        )
        .expect("updater");
        let (sender, receiver) = watch::channel(Status::Stopped);
        let task = tokio::spawn(updater.run(receiver));
        tokio::task::yield_now().await;
        assert!(!task.is_finished());
        assert_eq!(storage.servers_object(ProviderName::Mullvad), original);
        drop(sender);
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("stops")
            .expect("joins");
    }

    #[tokio::test]
    async fn kept_relays_survive_refresh_and_invalid_http_does_not_replace_them() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listen");
        let url = format!("http://{}", listener.local_addr().expect("address"));
        let app = axum::Router::new()
            .route(
                "/valid",
                axum::routing::get(|| async { axum::Json(fixture()) }),
            )
            .route(
                "/redirect",
                axum::routing::get(|| async { axum::response::Redirect::temporary("/valid") }),
            )
            .route("/invalid", axum::routing::get(|| async { "not JSON" }))
            .route(
                "/large",
                axum::routing::get(|| async {
                    axum::body::Body::from_stream(futures::stream::iter([
                        Ok::<_, std::io::Error>(vec![b' '; MAX_BODY]),
                        Ok(vec![b' ']),
                    ]))
                }),
            );
        let task = tokio::spawn(async move { axum::serve(listener, app).await.expect("serve") });
        let storage = Storage::new(None).expect("storage");
        let mut kept = parse(&fixture()).expect("relay").remove(0);
        kept.keep = true;
        kept.ips = vec!["185.213.154.67".parse().expect("override")];
        let mut extra = kept.clone();
        extra.hostname = "se-got-wg-custom".into();
        storage
            .set_servers(ProviderName::Mullvad, vec![kept.clone(), extra.clone()])
            .expect("set");
        let updater = Updater::new(
            UpdaterSettings {
                period: RETRY_DELAY,
                min_ratio: 0.8,
            },
            storage.clone(),
        )
        .expect("updater");
        updater
            .update(&format!("{url}/valid"))
            .await
            .expect("update");
        let expected = vec![kept, extra];
        assert_eq!(storage.servers(ProviderName::Mullvad), expected);
        for path in ["/missing", "/redirect", "/invalid", "/large"] {
            assert!(
                updater.update(&format!("{url}{path}")).await.is_err(),
                "{path}"
            );
            assert_eq!(storage.servers(ProviderName::Mullvad), expected);
        }
        task.abort();
    }

    #[tokio::test]
    async fn stopping_vpn_cancels_inflight_download() {
        use std::sync::Arc;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listen");
        let url = format!("http://{}/relays", listener.local_addr().expect("address"));
        let started = Arc::new(tokio::sync::Notify::new());
        let request_started = Arc::clone(&started);
        let app = axum::Router::new().route(
            "/relays",
            axum::routing::get(move || {
                let started = Arc::clone(&request_started);
                async move {
                    started.notify_one();
                    tokio::time::sleep(Duration::from_secs(60)).await;
                    axum::Json(fixture())
                }
            }),
        );
        let server = tokio::spawn(async move { axum::serve(listener, app).await.expect("serve") });
        let storage = Storage::new(None).expect("storage");
        let original = storage.servers_object(ProviderName::Mullvad);
        let updater = Updater::new(
            UpdaterSettings {
                period: RETRY_DELAY,
                min_ratio: 0.8,
            },
            storage.clone(),
        )
        .expect("updater");
        let (sender, receiver) = watch::channel(Status::Stopped);
        let task = tokio::spawn(async move { updater.run_at(receiver, &url).await });
        assert!(
            tokio::time::timeout(Duration::from_millis(50), started.notified())
                .await
                .is_err()
        );
        sender.send_replace(Status::Running(crate::vpn::Tunnel {
            interface: "wg0".into(),
            ipv6: false,
            connection: crate::models::Connection {
                ip: "185.213.154.66".parse().expect("endpoint"),
                port: 51820,
                hostname: "se-got-wg-001".into(),
                server_name: String::new(),
                pubkey: String::new(),
            },
        }));
        tokio::time::timeout(Duration::from_secs(2), started.notified())
            .await
            .expect("request starts");
        sender.send_replace(Status::Stopped);
        drop(sender);
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("download cancelled")
            .expect("joins");
        assert_eq!(storage.servers_object(ProviderName::Mullvad), original);
        server.abort();
    }

    #[tokio::test]
    #[ignore = "requires public Mullvad API access"]
    async fn live_mullvad_relay_schema() {
        let storage = Storage::new(None).expect("storage");
        let updater = Updater::new(
            UpdaterSettings {
                period: RETRY_DELAY,
                min_ratio: 0.8,
            },
            storage,
        )
        .expect("updater");
        assert!(updater.update(RELAYS_URL).await.expect("live update") > 100);
    }
}
