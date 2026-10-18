use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use axum::Router;
use axum::http::{Method, StatusCode};
use axum::routing::any;
use hickory_proto::op::{Message, Query};
use hickory_proto::rr::{Name, RecordType};
use rustls::pki_types::ServerName;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::{Instant, timeout};
use tokio_rustls::TlsConnector;

use crate::config::{HealthSettings, SmallCheckType};
use crate::icmp;

const STARTUP_TIMEOUT: Duration = Duration::from_secs(6);
const SMALL_CHECK_PERIOD: Duration = Duration::from_secs(60);
const FULL_CHECK_PERIOD: Duration = Duration::from_secs(300);
const SMALL_TRY_TIMEOUTS: [u64; 10] = [5, 5, 5, 10, 10, 10, 15, 15, 15, 30];
const FULL_TRY_TIMEOUTS: [u64; 3] = [10, 15, 30];
const DNS_CHECK_HOSTNAME: &str = "github.com.";
const ICMP_PAYLOAD_LEN: usize = 32;

// Plain UDP resolvers, so health checks never touch the DoT/DoH TCP connections.
const DNS_CHECK_SERVERS: [Ipv4Addr; 12] = [
    Ipv4Addr::new(1, 1, 1, 1),
    Ipv4Addr::new(1, 0, 0, 1),
    Ipv4Addr::new(8, 8, 8, 8),
    Ipv4Addr::new(8, 8, 4, 4),
    Ipv4Addr::new(9, 9, 9, 9),
    Ipv4Addr::new(149, 112, 112, 112),
    Ipv4Addr::new(208, 67, 222, 222),
    Ipv4Addr::new(208, 67, 220, 220),
    Ipv4Addr::new(88, 198, 92, 222),
    Ipv4Addr::new(12, 159, 2, 159),
    Ipv4Addr::new(149, 112, 121, 20),
    Ipv4Addr::new(149, 112, 122, 20),
];

#[derive(Debug, thiserror::Error)]
pub enum CheckError {
    #[error("invalid target address {0:?}")]
    Address(String),
    #[error("resolving {0}: {1}")]
    Resolve(String, #[source] io::Error),
    #[error("no IPv4 address found for {0}")]
    NoIpv4(String),
    #[error("dialing {0}: {1}")]
    Dial(SocketAddr, #[source] io::Error),
    #[error("running TLS handshake with {0}: {1}")]
    Tls(String, #[source] io::Error),
    #[error("ICMP is not permitted: {0}")]
    IcmpNotPermitted(#[source] io::Error),
    #[error("ICMP echo to {0}: {1}")]
    Icmp(IpAddr, #[source] io::Error),
    #[error("with DNS server {0}: {1}")]
    Dns(SocketAddr, String),
    #[error("timed out")]
    Timeout,
    #[error("canceled")]
    Canceled,
}

#[derive(Debug)]
pub struct Attempt {
    pub duration: Duration,
    pub error: CheckError,
}

#[derive(Debug, thiserror::Error)]
pub enum HealthError {
    #[error("healthcheck did not run yet")]
    NotRunYet,
    #[error("startup check: all check tries failed: {}", join_startup(.0))]
    Startup(Vec<CheckError>),
    #[error("{kind} check: {check}: all check tries failed:{}", join_attempts(.attempts))]
    Periodic {
        kind: PeriodicKind,
        check: &'static str,
        attempts: Vec<Attempt>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeriodicKind {
    Small,
    Full,
}

impl fmt::Display for PeriodicKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Small => "small periodic",
            Self::Full => "full periodic",
        })
    }
}

fn join_startup(errors: &[CheckError]) -> String {
    errors
        .iter()
        .enumerate()
        .map(|(i, error)| {
            format!(
                "parallel attempt {}/{} failed: {error}",
                i + 1,
                errors.len()
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn join_attempts(attempts: &[Attempt]) -> String {
    attempts
        .iter()
        .enumerate()
        .map(|(i, attempt)| {
            format!(
                "\n\tattempt {} ({}ms): {}",
                i + 1,
                attempt.duration.as_millis(),
                attempt.error
            )
        })
        .collect()
}

#[derive(Clone, Debug)]
pub struct HealthStatus(Arc<RwLock<Option<String>>>);

impl Default for HealthStatus {
    fn default() -> Self {
        Self(Arc::new(RwLock::new(Some(
            HealthError::NotRunYet.to_string(),
        ))))
    }
}

impl HealthStatus {
    pub fn is_healthy(&self) -> bool {
        self.get().is_none()
    }

    pub fn reset(&self) {
        match self.0.write() {
            Ok(mut guard) => *guard = Some(HealthError::NotRunYet.to_string()),
            Err(poisoned) => *poisoned.into_inner() = Some(HealthError::NotRunYet.to_string()),
        }
    }

    pub fn set(&self, result: Result<(), &HealthError>) {
        let value = result.err().map(ToString::to_string);
        match self.0.write() {
            Ok(mut guard) => *guard = value,
            Err(poisoned) => *poisoned.into_inner() = value,
        }
    }

    fn get(&self) -> Option<String> {
        match self.0.read() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }
}

pub async fn serve(listener: TcpListener, status: HealthStatus) -> io::Result<()> {
    let app = Router::new().fallback(any(move |method: Method| {
        let status = status.clone();
        async move {
            if method != Method::GET {
                return (
                    StatusCode::BAD_REQUEST,
                    "method not supported for healthcheck".to_owned(),
                );
            }
            match status.get() {
                None => (StatusCode::OK, String::new()),
                Some(error) => (StatusCode::INTERNAL_SERVER_ERROR, error),
            }
        }
    }));
    let address = listener.local_addr()?;
    tracing::info!(%address, "health server listening");
    axum::serve(listener, app).await
}

pub struct Checker {
    tls_targets: Vec<String>,
    icmp_targets: Vec<IpAddr>,
    small_check: SmallCheckType,
    connector: TlsConnector,
    dns_server_index: usize,
    small_deadline: Instant,
    full_deadline: Instant,
}

impl Checker {
    pub fn new(settings: &HealthSettings, connector: TlsConnector) -> Self {
        let now = Instant::now();
        Self {
            tls_targets: settings.target_addresses.clone(),
            icmp_targets: settings.icmp_target_ips.clone(),
            small_check: settings.small_check_type,
            connector,
            dns_server_index: 0,
            small_deadline: now,
            full_deadline: now,
        }
    }

    pub fn set_server_ip(&mut self, settings: &HealthSettings, server_ip: IpAddr) {
        self.icmp_targets = match settings.icmp_target_ips.as_slice() {
            [ip] if ip.is_unspecified() => vec![server_ip],
            ips => ips.to_vec(),
        };
    }

    pub async fn startup(&mut self) -> Result<(), HealthError> {
        let now = Instant::now();
        self.small_deadline = now + SMALL_CHECK_PERIOD;
        self.full_deadline = now + FULL_CHECK_PERIOD;
        let attempts = self.tls_targets.iter().map(|target| {
            Box::pin(timeout(
                STARTUP_TIMEOUT,
                tcp_tls_check(&self.connector, target),
            ))
        });
        let mut pending: Vec<_> = attempts.collect();
        let mut errors = Vec::with_capacity(pending.len());
        while !pending.is_empty() {
            let (result, _, rest) = futures::future::select_all(pending).await;
            match result {
                Ok(Ok(())) => return Ok(()),
                Ok(Err(error)) => {
                    tracing::debug!(%error, "startup check parallel attempt failed");
                    errors.push(error);
                }
                Err(_) => errors.push(CheckError::Timeout),
            }
            pending = rest;
        }
        Err(HealthError::Startup(errors))
    }

    pub async fn next_periodic(&mut self) -> Result<(), HealthError> {
        if self.small_deadline <= self.full_deadline {
            tokio::time::sleep_until(self.small_deadline).await;
            let result = self.small_check().await;
            self.small_deadline = Instant::now() + SMALL_CHECK_PERIOD;
            result
        } else {
            tokio::time::sleep_until(self.full_deadline).await;
            let result = self.full_check().await;
            self.full_deadline = Instant::now() + FULL_CHECK_PERIOD;
            result
        }
    }

    async fn small_check(&mut self) -> Result<(), HealthError> {
        let mut attempts = Vec::new();
        for (try_index, seconds) in SMALL_TRY_TIMEOUTS.into_iter().enumerate() {
            let start = Instant::now();
            let limit = Duration::from_secs(seconds);
            let result = match self.small_check {
                SmallCheckType::Dns => self.dns_check(limit).await,
                SmallCheckType::Icmp => {
                    let target = self.icmp_targets[try_index % self.icmp_targets.len()];
                    match timeout(limit, icmp_echo(target)).await {
                        Ok(Err(CheckError::IcmpNotPermitted(error))) => {
                            tracing::info!(%error, "ICMP is not permitted; switching to plain DNS over UDP checks");
                            self.small_check = SmallCheckType::Dns;
                            self.dns_check(limit).await
                        }
                        Ok(result) => result,
                        Err(_) => Err(CheckError::Timeout),
                    }
                }
            };
            match result {
                Ok(()) => return Ok(()),
                Err(error) => {
                    tracing::debug!(
                        check = small_check_name(self.small_check),
                        attempt = try_index + 1,
                        max = SMALL_TRY_TIMEOUTS.len(),
                        %error,
                        "health check attempt failed"
                    );
                    attempts.push(Attempt {
                        duration: start.elapsed(),
                        error,
                    });
                }
            }
        }
        Err(HealthError::Periodic {
            kind: PeriodicKind::Small,
            check: small_check_name(self.small_check),
            attempts,
        })
    }

    async fn full_check(&self) -> Result<(), HealthError> {
        let mut attempts = Vec::new();
        for (try_index, seconds) in FULL_TRY_TIMEOUTS.into_iter().enumerate() {
            let start = Instant::now();
            let target = &self.tls_targets[try_index % self.tls_targets.len()];
            let result = timeout(
                Duration::from_secs(seconds),
                tcp_tls_check(&self.connector, target),
            )
            .await
            .unwrap_or(Err(CheckError::Timeout));
            match result {
                Ok(()) => return Ok(()),
                Err(error) => {
                    tracing::debug!(check = "TCP+TLS dial", attempt = try_index + 1, max = FULL_TRY_TIMEOUTS.len(), %error, "health check attempt failed");
                    attempts.push(Attempt {
                        duration: start.elapsed(),
                        error,
                    });
                }
            }
        }
        Err(HealthError::Periodic {
            kind: PeriodicKind::Full,
            check: "TCP+TLS dial",
            attempts,
        })
    }

    async fn dns_check(&mut self, limit: Duration) -> Result<(), CheckError> {
        let server = SocketAddr::from((DNS_CHECK_SERVERS[self.dns_server_index], 53));
        let result = timeout(limit, dns_lookup(server))
            .await
            .unwrap_or_else(|_| Err("timed out".to_owned()));
        result.map_err(|reason| {
            self.dns_server_index = (self.dns_server_index + 1) % DNS_CHECK_SERVERS.len();
            CheckError::Dns(server, reason)
        })
    }
}

fn small_check_name(check: SmallCheckType) -> &'static str {
    match check {
        SmallCheckType::Icmp => "ICMP echo",
        SmallCheckType::Dns => "plain DNS over UDP",
    }
}

fn split_target(target: &str) -> Result<(String, u16), CheckError> {
    let invalid = || CheckError::Address(target.to_owned());
    if let Ok(address) = target.parse::<SocketAddr>() {
        return Ok((address.ip().to_string(), address.port()));
    }
    match target.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => {
            let port = port.parse().map_err(|_| invalid())?;
            let host = host.trim_start_matches('[').trim_end_matches(']');
            if host.is_empty() {
                return Err(invalid());
            }
            Ok((host.to_owned(), port))
        }
        None if !target.is_empty() => Ok((target.to_owned(), 443)),
        _ => Err(invalid()),
    }
}

async fn tcp_tls_check(connector: &TlsConnector, target: &str) -> Result<(), CheckError> {
    let (host, port) = split_target(target)?;
    let addresses: Vec<SocketAddrV4> = tokio::net::lookup_host((host.as_str(), port))
        .await
        .map_err(|error| CheckError::Resolve(host.clone(), error))?
        .filter_map(|address| match address {
            SocketAddr::V4(v4) => Some(v4),
            SocketAddr::V6(_) => None,
        })
        .collect();
    let mut last_error = None;
    let mut stream = None;
    for address in addresses {
        match TcpStream::connect(address).await {
            Ok(connected) => {
                stream = Some(connected);
                break;
            }
            Err(error) => last_error = Some(CheckError::Dial(address.into(), error)),
        }
    }
    let stream = match (stream, last_error) {
        (Some(stream), _) => stream,
        (None, Some(error)) => return Err(error),
        (None, None) => return Err(CheckError::NoIpv4(host)),
    };
    if port == 443 {
        let server_name = ServerName::try_from(host.clone())
            .map_err(|_| CheckError::Address(target.to_owned()))?;
        connector
            .connect(server_name, stream)
            .await
            .map_err(|error| CheckError::Tls(host, error))?;
    }
    Ok(())
}

async fn dns_lookup(server: SocketAddr) -> Result<(), String> {
    let name = Name::from_ascii(DNS_CHECK_HOSTNAME).map_err(|error| error.to_string())?;
    let mut request = Message::query();
    request.metadata.recursion_desired = true;
    request.add_query(Query::query(name, RecordType::A));
    let id = request.metadata.id;
    let bytes = request.to_vec().map_err(|error| error.to_string())?;

    let socket = UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))
        .await
        .map_err(|error| error.to_string())?;
    socket
        .connect(server)
        .await
        .map_err(|error| error.to_string())?;
    socket
        .send(&bytes)
        .await
        .map_err(|error| error.to_string())?;
    let mut buffer = [0_u8; 1232];
    loop {
        let length = socket
            .recv(&mut buffer)
            .await
            .map_err(|error| error.to_string())?;
        let Ok(response) = Message::from_vec(&buffer[..length]) else {
            continue;
        };
        if response.metadata.id != id {
            continue;
        }
        let found = response
            .answers
            .iter()
            .any(|record| record.record_type() == RecordType::A);
        return if found {
            Ok(())
        } else {
            Err(format!(
                "no IPs found from DNS lookup (response code {})",
                response.metadata.response_code
            ))
        };
    }
}

async fn icmp_echo(target: IpAddr) -> Result<(), CheckError> {
    let types = icmp::EchoTypes::of(target);
    let socket = icmp::ping_socket(target, false).map_err(|error| {
        if icmp::is_not_permitted(&error) {
            CheckError::IcmpNotPermitted(error)
        } else {
            CheckError::Icmp(target, error)
        }
    })?;

    let sequence: u16 = rand::random();
    let mut payload = [0_u8; ICMP_PAYLOAD_LEN];
    rand::fill(&mut payload);
    let request = icmp::echo_request(types.request, sequence, &payload);
    socket
        .send_to(&request, SocketAddr::new(target, 0))
        .await
        .map_err(|error| CheckError::Icmp(target, error))?;

    let mut buffer = [0_u8; 1500];
    loop {
        let (length, from) = socket
            .recv_from(&mut buffer)
            .await
            .map_err(|error| CheckError::Icmp(target, error))?;
        if from.ip() == target
            && icmp::parse_echo_reply(&buffer[..length], types.reply)
                == Some((sequence, payload.as_slice()))
        {
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_target_defaults_to_443() {
        assert_eq!(
            split_target("github.com").expect("valid"),
            ("github.com".to_owned(), 443)
        );
        assert_eq!(
            split_target("cloudflare.com:80").expect("valid"),
            ("cloudflare.com".to_owned(), 80)
        );
        assert_eq!(
            split_target("1.1.1.1:443").expect("valid"),
            ("1.1.1.1".to_owned(), 443)
        );
        assert!(split_target("host:notaport").is_err());
        assert!(split_target(":443").is_err());
    }

    #[test]
    fn periodic_error_lists_attempts() {
        let error = HealthError::Periodic {
            kind: PeriodicKind::Full,
            check: "TCP+TLS dial",
            attempts: vec![Attempt {
                duration: Duration::from_millis(10_000),
                error: CheckError::Timeout,
            }],
        };
        assert_eq!(
            error.to_string(),
            "full periodic check: TCP+TLS dial: all check tries failed:\n\tattempt 1 (10000ms): timed out"
        );
    }

    #[test]
    fn unspecified_icmp_target_uses_server_ip() {
        let settings = HealthSettings {
            server_address: SocketAddr::from(([127, 0, 0, 1], 9999)),
            target_addresses: vec!["github.com:443".to_owned()],
            icmp_target_ips: vec![IpAddr::V4(Ipv4Addr::UNSPECIFIED)],
            small_check_type: SmallCheckType::Icmp,
            restart_vpn: true,
        };
        let mut checker = Checker::new(&settings, crate::tls::connector().expect("TLS config"));
        checker.set_server_ip(&settings, IpAddr::V4(Ipv4Addr::new(185, 1, 2, 3)));
        assert_eq!(
            checker.icmp_targets,
            vec![IpAddr::V4(Ipv4Addr::new(185, 1, 2, 3))]
        );
    }

    #[tokio::test]
    async fn status_serves_error_then_ok() {
        let status = HealthStatus::default();
        assert_eq!(status.get().as_deref(), Some("healthcheck did not run yet"));
        status.set(Ok(()));
        assert_eq!(status.get(), None);
        status.reset();
        assert_eq!(status.get().as_deref(), Some("healthcheck did not run yet"));
        status.set(Err(&HealthError::Startup(vec![CheckError::Timeout])));
        assert_eq!(
            status.get().as_deref(),
            Some("startup check: all check tries failed: parallel attempt 1/1 failed: timed out")
        );
    }
}
