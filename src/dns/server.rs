use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::RData;
use ipnetwork::IpNetwork;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{Mutex, Semaphore, watch};
use tokio::task::JoinSet;
use tokio::time::Instant;
use tokio_rustls::TlsConnector;

use crate::config::DnsSettings;
use crate::control::lifecycle::{self, State};
use crate::dns::blocklist::{self, Blocklists};
use crate::dns::resolve::{ResolveError, Resolver};
use crate::routing::is_private;
use crate::vpn::Status;

const MAX_CLIENTS: usize = 128;
const CACHE_SIZE: usize = 4096;
const MAX_UDP: usize = 4096;
const CLIENT_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug, thiserror::Error)]
pub enum DnsError {
    #[error("binding DNS server: {0}")]
    Bind(#[from] io::Error),
    #[error("configuring DNS upstream: {0}")]
    Upstream(#[from] ResolveError),
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct CacheKey {
    name: String,
    record_type: String,
    record_class: String,
}

#[derive(Clone)]
struct CacheEntry {
    response: Message,
    created: Instant,
    expires: Instant,
}

#[derive(Default)]
struct Cache(Mutex<HashMap<CacheKey, CacheEntry>>);

impl Cache {
    async fn get(&self, key: &CacheKey, id: u16) -> Option<Message> {
        let mut entries = self.0.lock().await;
        let entry = entries.get(key)?;
        let now = Instant::now();
        if now >= entry.expires {
            entries.remove(key);
            return None;
        }
        let elapsed =
            u32::try_from(now.duration_since(entry.created).as_secs()).unwrap_or(u32::MAX);
        let mut response = entry.response.clone();
        response.metadata.id = id;
        for record in response
            .answers
            .iter_mut()
            .chain(response.authorities.iter_mut())
            .chain(response.additionals.iter_mut())
        {
            record.ttl = record.ttl.saturating_sub(elapsed);
        }
        Some(response)
    }

    async fn insert(&self, key: CacheKey, response: &Message) {
        if response.metadata.response_code != ResponseCode::NoError || response.answers.is_empty() {
            return;
        }
        let ttl = response
            .answers
            .iter()
            .chain(response.authorities.iter())
            .chain(response.additionals.iter())
            .map(|record| record.ttl)
            .min()
            .unwrap_or(0);
        if ttl == 0 {
            return;
        }
        let now = Instant::now();
        let mut entries = self.0.lock().await;
        if entries.len() >= CACHE_SIZE {
            entries.retain(|_, entry| entry.expires > now);
            if entries.len() >= CACHE_SIZE
                && let Some(oldest) = entries
                    .iter()
                    .min_by_key(|(_, entry)| entry.expires)
                    .map(|(key, _)| key.clone())
            {
                entries.remove(&oldest);
            }
        }
        entries.insert(
            key,
            CacheEntry {
                response: response.clone(),
                created: now,
                expires: now + Duration::from_secs(u64::from(ttl)),
            },
        );
    }
}

#[derive(Clone)]
struct Handler {
    settings: DnsSettings,
    resolver: Resolver,
    cache: Arc<Cache>,
    blocklists: Arc<Blocklists>,
    status: watch::Receiver<Status>,
    enabled: Arc<AtomicBool>,
}

impl Handler {
    fn running(&self) -> bool {
        self.enabled.load(Ordering::Acquire) && matches!(&*self.status.borrow(), Status::Running(_))
    }

    async fn answer(&self, bytes: &[u8]) -> Option<Message> {
        let request = match Message::from_vec(bytes) {
            Ok(request) => request,
            Err(error) => {
                tracing::debug!(%error, "invalid DNS request");
                if bytes.len() < 12 {
                    return None;
                }
                let id = u16::from_be_bytes([bytes[0], bytes[1]]);
                return Some(Message::error_msg(id, OpCode::Query, ResponseCode::FormErr));
            }
        };
        if request.metadata.message_type != MessageType::Query {
            return None;
        }
        if request.metadata.op_code != OpCode::Query {
            return Some(error_response(&request, ResponseCode::NotImp));
        }
        if request.queries.len() != 1 || request.signature.is_some() {
            return Some(error_response(&request, ResponseCode::FormErr));
        }
        if !self.running() {
            return Some(error_response(&request, ResponseCode::ServFail));
        }
        let name = normalize(&request.queries[0].name().to_utf8());
        if !self.is_allowed_name(&name)
            && (self.is_blocked_name(&name) || self.blocklists.blocks_hostname(&name).await)
        {
            return Some(error_response(&request, ResponseCode::NXDomain));
        }
        let key = CacheKey {
            name: name.clone(),
            record_type: request.queries[0].query_type().to_string(),
            record_class: request.queries[0].query_class().to_string(),
        };
        let cacheable = self.settings.caching
            && request.edns.is_none()
            && request.metadata.recursion_desired
            && !request.metadata.checking_disabled
            && request.additionals.is_empty();
        if cacheable && let Some(response) = self.cache.get(&key, request.metadata.id).await {
            if self.is_blocked_response(&name, &response)
                || self.is_listed_response(&response).await
            {
                return Some(error_response(&request, ResponseCode::NXDomain));
            }
            return Some(response);
        }
        let mut response = match self.resolver.query(&request).await {
            Ok(response) => response,
            Err(error) => {
                tracing::warn!(%error, %name, "resolving DNS request");
                return Some(error_response(&request, ResponseCode::ServFail));
            }
        };
        if !self.running() {
            return Some(error_response(&request, ResponseCode::ServFail));
        }
        if self.is_blocked_response(&name, &response) || self.is_listed_response(&response).await {
            return Some(error_response(&request, ResponseCode::NXDomain));
        }
        if cacheable {
            self.cache.insert(key, &response).await;
        }
        response.metadata.id = request.metadata.id;
        Some(response)
    }

    fn is_blocked_name(&self, name: &str) -> bool {
        self.settings
            .blocked_hostnames
            .iter()
            .any(|blocked| matches_domain(name, blocked))
    }

    fn is_allowed_name(&self, name: &str) -> bool {
        self.settings
            .allowed_hostnames
            .iter()
            .any(|allowed| matches_domain(name, allowed))
    }

    fn is_blocked_response(&self, name: &str, response: &Message) -> bool {
        response.answers.iter().any(|record| {
            let ip = match &record.data {
                RData::A(address) => IpAddr::V4(address.0),
                RData::AAAA(address) => IpAddr::V6(address.0),
                _ => return false,
            };
            self.settings.blocked_ips.contains(&ip)
                || self
                    .settings
                    .blocked_ip_prefixes
                    .iter()
                    .any(|prefix: &IpNetwork| prefix.contains(ip))
                || ((is_private(ip) || ip.is_unspecified())
                    && !self
                        .settings
                        .rebinding_protection_exempt_hostnames
                        .iter()
                        .any(|exempt| matches_domain(name, exempt.trim_start_matches("*."))))
        })
    }

    async fn is_listed_response(&self, response: &Message) -> bool {
        for record in &response.answers {
            let ip = match &record.data {
                RData::A(address) => IpAddr::V4(address.0),
                RData::AAAA(address) => IpAddr::V6(address.0),
                _ => continue,
            };
            if self.blocklists.blocks_ip(ip).await {
                return true;
            }
        }
        false
    }
}

fn normalize(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

fn matches_domain(name: &str, domain: &str) -> bool {
    let domain = domain.trim_start_matches("*.").trim_end_matches('.');
    name.eq_ignore_ascii_case(domain)
        || name.len() > domain.len()
            && name
                .get(name.len() - domain.len() - 1..)
                .is_some_and(|tail| tail.starts_with('.') && tail[1..].eq_ignore_ascii_case(domain))
}

fn error_response(request: &Message, code: ResponseCode) -> Message {
    let mut response = Message::error_msg(request.metadata.id, request.metadata.op_code, code);
    response.queries.clone_from(&request.queries);
    response.metadata.recursion_desired = request.metadata.recursion_desired;
    response.metadata.recursion_available = true;
    response.edns.clone_from(&request.edns);
    response
}

fn udp_response(response: &Message, request: &[u8]) -> io::Result<Vec<u8>> {
    let limit = Message::from_vec(request)
        .ok()
        .and_then(|message| message.edns.map(|edns| usize::from(edns.max_payload())))
        .unwrap_or(512)
        .clamp(512, MAX_UDP);
    let bytes = response.to_vec().map_err(io::Error::other)?;
    if bytes.len() <= limit {
        return Ok(bytes);
    }
    let mut truncated = response.clone();
    truncated.answers.clear();
    truncated.authorities.clear();
    truncated.additionals.clear();
    truncated.metadata.truncation = true;
    let bytes = truncated.to_vec().map_err(io::Error::other)?;
    if bytes.len() <= limit {
        Ok(bytes)
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DNS question exceeds UDP limit",
        ))
    }
}

pub struct Server {
    udp: Arc<UdpSocket>,
    tcp: TcpListener,
    settings: DnsSettings,
    resolver: Resolver,
}

impl Server {
    pub async fn bind(settings: DnsSettings, connector: TlsConnector) -> Result<Self, DnsError> {
        let resolver = Resolver::new(&settings, connector)?;
        let udp = UdpSocket::bind(settings.listen_address).await?;
        let tcp = TcpListener::bind(settings.listen_address).await?;
        Ok(Self {
            udp: Arc::new(udp),
            tcp,
            settings,
            resolver,
        })
    }

    pub async fn run(self, status: watch::Receiver<Status>) -> io::Result<()> {
        let (_controller, worker) = lifecycle::channel();
        self.run_controlled(status, worker).await
    }

    pub async fn run_controlled(
        self,
        mut status: watch::Receiver<Status>,
        mut control: lifecycle::Worker,
    ) -> io::Result<()> {
        tracing::info!(address = %self.udp.local_addr()?, "DNS server listening over UDP and TCP");
        let blocklists = Arc::new(Blocklists::default());
        let mut tasks = JoinSet::new();
        let mut background = JoinSet::new();
        let update_blocklists = self.settings.block_malicious
            || self.settings.block_ads
            || self.settings.block_surveillance;
        if update_blocklists {
            background.spawn(blocklist::update_loop(
                self.settings.clone(),
                Arc::clone(&blocklists),
                status.clone(),
            ));
        }
        let handler = Handler {
            settings: self.settings,
            resolver: self.resolver,
            cache: Arc::new(Cache::default()),
            blocklists,
            status: status.clone(),
            enabled: Arc::new(AtomicBool::new(true)),
        };
        control.publish(State::Running);
        let permits = Arc::new(Semaphore::new(MAX_CLIENTS));
        let mut buffer = [0u8; MAX_UDP];
        loop {
            tokio::select! {
                biased;
                command = control.next() => {
                    let Some(command) = command else { return Ok(()); };
                    let enabled = command.state == State::Running;
                    if command.restart || enabled != handler.enabled.load(Ordering::Acquire) {
                        handler.enabled.store(false, Ordering::Release);
                        tasks.abort_all();
                        background.abort_all();
                        while tasks.join_next().await.is_some() {}
                        while background.join_next().await.is_some() {}
                        handler.cache.0.lock().await.clear();
                        if enabled && update_blocklists {
                            background.spawn(blocklist::update_loop(handler.settings.clone(), Arc::clone(&handler.blocklists), status.clone()));
                        }
                        handler.enabled.store(enabled, Ordering::Release);
                    }
                    control.publish(command.state);
                    command.acknowledge();
                }
                changed = status.changed() => {
                    tasks.abort_all();
                    while tasks.join_next().await.is_some() {}
                    handler.cache.0.lock().await.clear();
                    if changed.is_err() { return Ok(()); }
                    status.borrow_and_update();
                }
                Some(result) = tasks.join_next(), if !tasks.is_empty() => {
                    if let Err(error) = result {
                        tracing::error!(%error, "DNS request task failed");
                    }
                }
                Some(result) = background.join_next(), if !background.is_empty() => {
                    if let Err(error) = result { return Err(io::Error::other(error)); }
                    return Err(io::Error::other("DNS blocklist updater stopped unexpectedly"));
                }
                packet = self.udp.recv_from(&mut buffer) => {
                    let (length, peer) = packet?;
                    let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
                        continue;
                    };
                    let request = buffer[..length].to_vec();
                    let socket = Arc::clone(&self.udp);
                    let handler = handler.clone();
                    tasks.spawn(async move {
                        let _permit = permit;
                        if let Some(response) = handler.answer(&request).await {
                            match udp_response(&response, &request) {
                                Ok(bytes) => {
                                    if let Err(error) = socket.send_to(&bytes, peer).await {
                                        tracing::debug!(%error, %peer, "sending DNS reply");
                                    }
                                }
                                Err(error) => tracing::debug!(%error, %peer, "encoding DNS reply"),
                            }
                        }
                    });
                }
                accepted = self.tcp.accept() => {
                    let (stream, peer) = accepted?;
                    let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
                        continue;
                    };
                    let handler = handler.clone();
                    tasks.spawn(async move {
                        let _permit = permit;
                        if let Err(error) = handle_tcp(stream, handler).await {
                            tracing::debug!(%error, %peer, "DNS TCP client disconnected");
                        }
                    });
                }
            }
        }
    }
}

async fn handle_tcp(mut stream: TcpStream, handler: Handler) -> io::Result<()> {
    loop {
        let length = match tokio::time::timeout(CLIENT_TIMEOUT, stream.read_u16()).await {
            Ok(Ok(length)) => usize::from(length),
            Ok(Err(error)) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Ok(Err(error)) => return Err(error),
            Err(_) => return Ok(()),
        };
        if length < 12 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "short DNS request",
            ));
        }
        let mut request = vec![0; length];
        tokio::time::timeout(CLIENT_TIMEOUT, stream.read_exact(&mut request))
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
        let response = tokio::time::timeout(CLIENT_TIMEOUT, handler.answer(&request))
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?;
        if let Some(response) = response {
            let response = response.to_vec().map_err(io::Error::other)?;
            let length = u16::try_from(response.len())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "DNS reply too large"))?;
            stream.write_all(&length.to_be_bytes()).await?;
            stream.write_all(&response).await?;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::Query;
    use hickory_proto::rr::{Name, Record, RecordType};
    use std::net::Ipv4Addr;

    fn settings() -> DnsSettings {
        crate::config::Settings::from_env(&crate::config::Env::from_pairs([
            ("VPN_SERVICE_PROVIDER", "mullvad"),
            (
                "WIREGUARD_PRIVATE_KEY",
                "wOEI9rqqbDwnN8/Bpp22sVz48T71vJ4fYmFWujulwUU=",
            ),
            ("WIREGUARD_ADDRESSES", "10.64.222.21/32"),
            ("WIREGUARD_CONF_SECRETFILE", "/nonexistent/wg0.conf"),
            ("DNS_UPSTREAM_RESOLVER_TYPE", "plain"),
        ]))
        .expect("valid settings")
        .dns
    }

    fn query(name: &str) -> Message {
        let mut request = Message::query();
        request.add_query(Query::query(
            Name::from_ascii(name).expect("name"),
            RecordType::A,
        ));
        request
    }

    fn running() -> Status {
        Status::Running(crate::vpn::Tunnel {
            interface: "wg0".into(),
            connection: crate::models::Connection {
                ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: 51820,
                hostname: String::new(),
                server_name: String::new(),
                pubkey: String::new(),
            },
            ipv6: false,
        })
    }

    #[tokio::test]
    async fn control_cancels_inflight_queries_and_resumes_listeners() {
        let upstream = UdpSocket::bind("127.0.0.1:0").await.expect("upstream");
        let mut settings = settings();
        settings.listen_address = "127.0.0.1:0".parse().expect("address");
        settings.upstream_plain_addresses = vec![upstream.local_addr().expect("address")];
        settings.block_malicious = false;
        settings.block_ads = false;
        settings.block_surveillance = false;
        let server = Server::bind(settings, crate::tls::connector().expect("TLS"))
            .await
            .expect("DNS");
        let udp_address = server.udp.local_addr().expect("UDP");
        let tcp_address = server.tcp.local_addr().expect("TCP");
        let (_vpn, status) = watch::channel(running());
        let (controller, worker) = lifecycle::channel();
        let task = tokio::spawn(server.run_controlled(status, worker));
        let client = UdpSocket::bind("127.0.0.1:0").await.expect("client");
        client.connect(udp_address).await.expect("connect");
        let request = query("example.com.").to_vec().expect("query");
        client.send(&request).await.expect("send");
        let mut buffer = [0u8; MAX_UDP];
        let (_, peer) =
            tokio::time::timeout(Duration::from_secs(2), upstream.recv_from(&mut buffer))
                .await
                .expect("forwarded")
                .expect("request");
        let mut tcp = TcpStream::connect(tcp_address).await.expect("TCP client");
        tcp.write_all(&u16::try_from(request.len()).expect("length").to_be_bytes())
            .await
            .expect("TCP length");
        tcp.write_all(&request).await.expect("TCP query");
        tokio::time::timeout(Duration::from_secs(2), upstream.recv_from(&mut buffer))
            .await
            .expect("TCP query forwarded")
            .expect("query");
        controller
            .apply(State::Stopped, false)
            .await
            .expect("stop acknowledged");
        assert_eq!(controller.state(), State::Stopped);
        let response = Message::response(1, OpCode::Query).to_vec().expect("reply");
        upstream
            .send_to(&response, peer)
            .await
            .expect("late response");
        assert!(
            tokio::time::timeout(Duration::from_millis(100), client.recv(&mut buffer))
                .await
                .is_err()
        );
        client.send(&request).await.expect("stopped query");
        let length = tokio::time::timeout(Duration::from_secs(2), client.recv(&mut buffer))
            .await
            .expect("reply")
            .expect("receive");
        assert_eq!(
            Message::from_vec(&buffer[..length])
                .expect("DNS reply")
                .metadata
                .response_code,
            ResponseCode::ServFail
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(100), upstream.recv_from(&mut buffer))
                .await
                .is_err()
        );
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), tcp.read(&mut buffer))
                .await
                .expect("closed TCP")
                .expect("EOF"),
            0
        );
        controller
            .apply(State::Running, false)
            .await
            .expect("start acknowledged");
        assert_eq!(controller.state(), State::Running);
        client.send(&request).await.expect("resumed query");
        tokio::time::timeout(Duration::from_secs(2), upstream.recv_from(&mut buffer))
            .await
            .expect("forwarded again")
            .expect("query");
        controller
            .apply(State::Running, true)
            .await
            .expect("restart acknowledged");
        assert_eq!(controller.state(), State::Running);
        drop(controller);
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("stopped")
            .expect("joined")
            .expect("server");
    }

    #[test]
    fn domain_matching_is_label_bounded() {
        assert!(matches_domain("a.example.com", "example.com"));
        assert!(matches_domain("EXAMPLE.COM", "example.com"));
        assert!(!matches_domain("badexample.com", "example.com"));
    }

    #[tokio::test]
    async fn cache_rewrites_id_and_ttl() {
        let cache = Cache::default();
        let key = CacheKey {
            name: "example.com".into(),
            record_type: "A".into(),
            record_class: "IN".into(),
        };
        let name = Name::from_ascii("example.com.").expect("name");
        let mut response = Message::response(42, OpCode::Query);
        response.add_query(Query::query(name.clone(), RecordType::A));
        response.add_answer(Record::from_rdata(
            name,
            30,
            RData::A(hickory_proto::rr::rdata::A(Ipv4Addr::new(1, 1, 1, 1))),
        ));
        cache.insert(key.clone(), &response).await;
        let hit = cache.get(&key, 9).await.expect("cached");
        assert_eq!(hit.metadata.id, 9);
        assert!(hit.answers[0].ttl <= 30);
    }

    #[tokio::test]
    async fn forwards_only_while_tunnel_is_running_and_filters_answers() {
        let upstream = UdpSocket::bind("127.0.0.1:0").await.expect("upstream");
        let upstream_address = upstream.local_addr().expect("address");
        let mock = tokio::spawn(async move {
            let mut buffer = [0u8; 512];
            loop {
                let (length, peer) = upstream.recv_from(&mut buffer).await.expect("receive");
                let request = Message::from_vec(&buffer[..length]).expect("DNS query");
                let mut response = Message::response(request.metadata.id, OpCode::Query);
                response.queries.clone_from(&request.queries);
                let name = request.queries[0].name().clone();
                response.add_answer(Record::from_rdata(
                    name,
                    30,
                    RData::A(hickory_proto::rr::rdata::A(Ipv4Addr::new(1, 1, 1, 1))),
                ));
                upstream
                    .send_to(&response.to_vec().expect("encode"), peer)
                    .await
                    .expect("reply");
            }
        });
        let mut settings = settings();
        settings.block_malicious = false;
        settings.upstream_plain_addresses = vec![upstream_address];
        let resolver =
            Resolver::new(&settings, crate::tls::connector().expect("TLS")).expect("resolver");
        let (status, receiver) = watch::channel(Status::Stopped);
        let handler = Handler {
            settings,
            resolver,
            cache: Arc::new(Cache::default()),
            blocklists: Arc::new(Blocklists::default()),
            status: receiver,
            enabled: Arc::new(AtomicBool::new(true)),
        };
        let request = query("example.com.");
        let denied = handler
            .answer(&request.to_vec().expect("encode"))
            .await
            .expect("response");
        assert_eq!(denied.metadata.response_code, ResponseCode::ServFail);
        status.send_replace(running());
        let answer = handler
            .answer(&request.to_vec().expect("encode"))
            .await
            .expect("response");
        assert_eq!(answer.metadata.response_code, ResponseCode::NoError);
        assert_eq!(answer.answers.len(), 1);
        status.send_replace(Status::Stopped);
        let denied = handler
            .answer(&request.to_vec().expect("encode"))
            .await
            .expect("response");
        assert_eq!(denied.metadata.response_code, ResponseCode::ServFail);
        mock.abort();
    }

    #[tokio::test]
    async fn udp_and_tcp_listeners_refuse_queries_while_stopped() {
        let reservation = TcpListener::bind("127.0.0.1:0").await.expect("port");
        let address = reservation.local_addr().expect("address");
        drop(reservation);
        let mut settings = settings();
        settings.listen_address = address;
        settings.block_malicious = false;
        let server = Server::bind(settings, crate::tls::connector().expect("TLS"))
            .await
            .expect("DNS server");
        let (status, receiver) = watch::channel(Status::Stopped);
        let task = tokio::spawn(server.run(receiver));
        let request = query("example.com.").to_vec().expect("encode");

        let udp = UdpSocket::bind("127.0.0.1:0").await.expect("UDP client");
        udp.send_to(&request, address).await.expect("send");
        let mut buffer = [0u8; 512];
        let (size, _) = tokio::time::timeout(Duration::from_secs(2), udp.recv_from(&mut buffer))
            .await
            .expect("UDP response")
            .expect("receive");
        let response = Message::from_vec(&buffer[..size]).expect("DNS response");
        assert_eq!(response.metadata.response_code, ResponseCode::ServFail);

        let mut tcp = TcpStream::connect(address).await.expect("TCP connect");
        tcp.write_all(&(request.len() as u16).to_be_bytes())
            .await
            .expect("length");
        tcp.write_all(&request).await.expect("send");
        let size = tokio::time::timeout(Duration::from_secs(2), tcp.read_u16())
            .await
            .expect("TCP response")
            .expect("length") as usize;
        let mut buffer = vec![0; size];
        tcp.read_exact(&mut buffer).await.expect("receive");
        let response = Message::from_vec(&buffer).expect("DNS response");
        assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
        drop(status);
        task.abort();
    }
}
