use std::io;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::AsRawFd;
use std::time::Duration;

use rustls::pki_types::ServerName;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::TcpSocket;
use tokio::time::{Instant, timeout, timeout_at};
use tokio_rustls::TlsConnector;

use crate::icmp;
use crate::netlink::{Family, Netlink, NetlinkError};
use crate::routing::{Routing, RoutingError};

const ETHERNET_MTU: u32 = 1500;
const MIN_IPV4_MTU: u32 = 68;
const MIN_IPV6_MTU: u32 = 1280;
const IPV4_HEADER_LEN: u32 = 20;
const IPV6_HEADER_LEN: u32 = 40;
const UDP_HEADER_LEN: u32 = 8;
const TCP_HEADER_LEN: u32 = 20;
const WIREGUARD_HEADER_LEN: u32 = 32;
// Most likely TCP options such as the 12 bytes of timestamps; matches gluetun.
const ADVMSS_EXTRA_OVERHEAD: u32 = 20;
// Linux rejects TCP_MAXSEG below TCP_MIN_MSS.
const TCP_MIN_MSS: u32 = 88;
const TCP_TIMESTAMP_OPTION_LEN: u32 = 12;
const TCPI_OPT_TIMESTAMPS: u8 = 1;
const ICMP_TRY_TIMEOUT: Duration = Duration::from_secs(1);
// A TCP handshake plus a TLS round trip through the tunnel needs more than a bare echo.
const TCP_TRY_TIMEOUT: Duration = Duration::from_secs(3);
const ICMP_TO_TCP_MARGIN: u32 = 150;
const MTUS_PER_ROUND: usize = 11;
// RFC 1122 allows echo replies truncated to 576 minus the IPv4 header and options.
const CONSERVATIVE_REPLY_LEN: usize = 556;
const MAX_REPLY_LEN: usize = 9216;

#[derive(Debug, thiserror::Error)]
pub enum PmtudError {
    #[error("getting VPN routes: {0}")]
    Routes(#[source] RoutingError),
    #[error("getting VPN interface {0}: {1}")]
    Link(String, #[source] NetlinkError),
    #[error("VPN interface {0} not found")]
    LinkNotFound(String),
    #[error("setting VPN interface {interface} MTU to {mtu}: {source}")]
    SetMtu {
        interface: String,
        mtu: u32,
        #[source]
        source: NetlinkError,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum DiscoverError {
    #[error("ICMP path MTU discovery against {0}: {1}")]
    Icmp(IpAddr, #[source] io::Error),
    #[error("no TCP address to verify the path MTU against")]
    NoTcpAddress,
    #[error("PMTUD succeeded with ICMP but failed with TCP - discarding ICMP obtained MTU {0}")]
    TcpAfterIcmp(u32),
    #[error("PMTUD failed with both ICMP and TCP")]
    Failed,
}

#[derive(Debug, thiserror::Error)]
enum IcmpError {
    #[error("ICMP is not permitted: {0}")]
    NotPermitted(#[source] io::Error),
    #[error("MTU not found: ICMP might be blocked")]
    NotFound,
    #[error(transparent)]
    Io(io::Error),
}

pub struct Targets {
    pub icmp: Vec<IpAddr>,
    pub tcp: Vec<SocketAddr>,
}

impl Targets {
    pub fn new(icmp: &[IpAddr], tcp: &[SocketAddr], ipv6: bool) -> Self {
        Self {
            icmp: icmp
                .iter()
                .copied()
                .filter(|ip| ipv6 || ip.is_ipv4())
                .collect(),
            tcp: tcp
                .iter()
                .copied()
                .filter(|address| ipv6 || address.is_ipv4())
                .collect(),
        }
    }
}

pub fn max_theoretical_vpn_mtu(outer_ipv6: bool) -> u32 {
    ETHERNET_MTU - ip_header_len(outer_ipv6) - UDP_HEADER_LEN - WIREGUARD_HEADER_LEN
}

fn ip_header_len(ipv6: bool) -> u32 {
    if ipv6 {
        IPV6_HEADER_LEN
    } else {
        IPV4_HEADER_LEN
    }
}

pub fn advmss(mtu: u32, ipv6: bool) -> u32 {
    mtu.saturating_sub(ip_header_len(ipv6) + TCP_HEADER_LEN + ADVMSS_EXTRA_OVERHEAD)
}

pub fn mtus_to_test(min: u32, max: u32) -> Vec<u32> {
    assert!(min <= max, "minimum MTU {min} exceeds maximum MTU {max}");
    let diff = max - min;
    let steps = u32::try_from(MTUS_PER_ROUND - 1).unwrap_or(u32::MAX);
    if diff <= steps + 1 {
        return (min..=max).collect();
    }
    let mut mtus: Vec<u32> = (0..steps)
        .map(|index| min + (diff * index + steps / 2) / steps)
        .collect();
    mtus.push(max);
    mtus
}

pub async fn update_to_max_mtu(
    netlink: &Netlink,
    routing: &Routing,
    connector: &TlsConnector,
    interface: &str,
    outer_ipv6: bool,
    targets: &Targets,
) -> Result<(), PmtudError> {
    tracing::info!("finding maximum MTU, this can take up to 12 seconds");
    let routes = routing
        .vpn_routes(interface)
        .await
        .map_err(PmtudError::Routes)?;
    let link = netlink
        .link_by_name(interface)
        .await
        .map_err(|error| PmtudError::Link(interface.to_owned(), error))?
        .ok_or_else(|| PmtudError::LinkNotFound(interface.to_owned()))?;
    let original_mtu = link.mtu.unwrap_or(ETHERNET_MTU);
    let max_mtu = max_theoretical_vpn_mtu(outer_ipv6);
    let set_mtu = async |mtu: u32| {
        netlink
            .link_set_mtu(link.index, mtu)
            .await
            .map_err(|source| PmtudError::SetMtu {
                interface: interface.to_owned(),
                mtu,
                source,
            })
    };

    tracing::debug!(
        interface,
        mtu = max_mtu,
        "VPN interface MTU temporarily raised"
    );
    set_mtu(max_mtu).await?;

    let mut mtu = match path_mtu_discover(connector, targets, max_mtu).await {
        Ok(mtu) => {
            tracing::info!(
                interface,
                mtu,
                "setting VPN interface MTU to maximum valid MTU"
            );
            mtu
        }
        Err(error) => {
            tracing::info!(interface, mtu = original_mtu, %error, "reverting VPN interface MTU");
            original_mtu
        }
    };

    for mut route in routes {
        let ipv6 = route.family == Family::V6;
        route.advmss = Some(advmss(mtu, ipv6));
        if let Err(error) = netlink.route_replace(&route).await {
            tracing::info!(
                interface,
                mtu = original_mtu,
                %route,
                %error,
                "reverting VPN interface MTU: setting safe TCP MSS failed"
            );
            mtu = original_mtu;
            break;
        }
    }

    set_mtu(mtu).await
}

pub async fn path_mtu_discover(
    connector: &TlsConnector,
    targets: &Targets,
    max_mtu: u32,
) -> Result<u32, DiscoverError> {
    let mut icmp_mtu = None;
    for &target in &targets.icmp {
        match icmp_discover(target, max_mtu).await {
            Ok(mtu) => {
                tracing::debug!(%target, mtu, "ICMP path MTU discovery found maximum valid MTU");
                icmp_mtu = Some(mtu);
                break;
            }
            Err(error @ (IcmpError::NotPermitted(_) | IcmpError::NotFound)) => {
                tracing::debug!(%target, %error, "ICMP path MTU discovery failed");
            }
            Err(IcmpError::Io(error)) => return Err(DiscoverError::Icmp(target, error)),
        }
    }

    let first_tcp = targets.tcp.first().ok_or(DiscoverError::NoTcpAddress)?;
    let ipv6 = first_tcp.is_ipv6();
    let floor = if ipv6 { MIN_IPV6_MTU } else { MIN_IPV4_MTU }
        .max(ip_header_len(ipv6) + TCP_HEADER_LEN + TCP_MIN_MSS);
    let (min, max) = match icmp_mtu {
        Some(mtu) => (mtu.saturating_sub(ICMP_TO_TCP_MARGIN).max(floor), mtu),
        None => (floor, max_mtu),
    };
    match tcp_discover(connector, &targets.tcp, min, max).await {
        Some(mtu) => {
            tracing::debug!(mtu, "TCP path MTU discovery found maximum valid MTU");
            Ok(mtu)
        }
        None => Err(icmp_mtu.map_or(DiscoverError::Failed, DiscoverError::TcpAfterIcmp)),
    }
}

async fn icmp_discover(target: IpAddr, max_mtu: u32) -> Result<u32, IcmpError> {
    let min = if target.is_ipv6() {
        MIN_IPV6_MTU
    } else {
        MIN_IPV4_MTU
    };
    let (mut low, mut high) = (min, max_mtu.max(min));
    loop {
        let mtus = mtus_to_test(low, high);
        if mtus.len() == 1 {
            return Ok(low);
        }
        tracing::debug!(?mtus, "ICMP testing MTUs");
        let ok = icmp_round(target, &mtus).await?;
        match next_range(&mtus, &ok) {
            Next::Found(mtu) => return Ok(mtu),
            Next::Narrow(next_low, next_high) => (low, high) = (next_low, next_high),
            Next::NoneOk => return Err(IcmpError::NotFound),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Next {
    Found(u32),
    Narrow(u32, u32),
    NoneOk,
}

fn next_range(mtus: &[u32], ok: &[bool]) -> Next {
    if ok.last() == Some(&true) {
        return mtus.last().map_or(Next::NoneOk, |&mtu| Next::Found(mtu));
    }
    (0..mtus.len().saturating_sub(1))
        .rev()
        .find(|&index| ok[index])
        .map_or(Next::NoneOk, |index| {
            Next::Narrow(mtus[index], mtus[index + 1] - 1)
        })
}

async fn icmp_round(target: IpAddr, mtus: &[u32]) -> Result<Vec<bool>, IcmpError> {
    let types = icmp::EchoTypes::of(target);
    let socket = icmp::ping_socket(target, true).map_err(|error| {
        if icmp::is_not_permitted(&error) {
            IcmpError::NotPermitted(error)
        } else {
            IcmpError::Io(error)
        }
    })?;
    let header_len = usize::try_from(ip_header_len(target.is_ipv6())).unwrap_or(usize::MAX);
    let base_sequence: u16 = rand::random();
    let mut sent_lengths = Vec::with_capacity(mtus.len());
    let destination = SocketAddr::new(target, 0);
    for (index, &mtu) in mtus.iter().enumerate() {
        let packet_len = usize::try_from(mtu).unwrap_or(usize::MAX);
        let payload = payload(packet_len.saturating_sub(header_len + icmp::HEADER_LEN));
        let sequence = base_sequence.wrapping_add(u16::try_from(index).unwrap_or(u16::MAX));
        let request = icmp::echo_request(types.request, sequence, &payload);
        match socket.send_to(&request, destination).await {
            Ok(_) => sent_lengths.push(Some(header_len + request.len())),
            Err(error) if error.raw_os_error() == Some(libc::EMSGSIZE) => {
                sent_lengths.push(None);
            }
            Err(error) if icmp::is_not_permitted(&error) => {
                return Err(IcmpError::NotPermitted(error));
            }
            Err(error) => return Err(IcmpError::Io(error)),
        }
    }

    let mut ok = vec![false; mtus.len()];
    let mut pending = sent_lengths
        .iter()
        .filter(|length| length.is_some())
        .count();
    let deadline = Instant::now() + ICMP_TRY_TIMEOUT;
    let mut buffer = vec![0_u8; MAX_REPLY_LEN];
    while pending > 0 {
        let Ok(received) = timeout_at(deadline, socket.recv_from(&mut buffer)).await else {
            break;
        };
        let (length, from) = received.map_err(IcmpError::Io)?;
        if from.ip() != target {
            continue;
        }
        let Some((sequence, reply_payload)) =
            icmp::parse_echo_reply(&buffer[..length], types.reply)
        else {
            continue;
        };
        let index = usize::from(sequence.wrapping_sub(base_sequence));
        let (Some(Some(sent)), Some(false)) = (sent_lengths.get(index), ok.get(index).copied())
        else {
            continue;
        };
        let received_len = header_len + length;
        let truncated = received_len < *sent && received_len == CONSERVATIVE_REPLY_LEN;
        if (truncated || received_len == *sent) && payload(reply_payload.len()) == reply_payload {
            ok[index] = true;
            pending -= 1;
        } else {
            tracing::debug!(
                sent,
                received = received_len,
                "ICMP echo reply size mismatch"
            );
        }
    }
    Ok(ok)
}

fn payload(length: usize) -> Vec<u8> {
    (0..length).map(|index| (index % 251) as u8).collect()
}

// Without NET_RAW, gluetun's raw SYN probes are unavailable: clamp our MSS with TCP_MAXSEG so
// every segment in both directions is exactly the tested MTU, then require a TLS handshake whose
// post-quantum ClientHello and certificate flight each span several full-size segments.
async fn tcp_discover(
    connector: &TlsConnector,
    targets: &[SocketAddr],
    min: u32,
    mut max: u32,
) -> Option<u32> {
    let target = best_tcp_target(targets, &mut max).await?;
    let min = min.min(max);
    let ipv6 = target.is_ipv6();
    let (mut low, mut high) = (min, max);
    loop {
        let mtus = mtus_to_test(low, high);
        if mtus.len() == 1 {
            return Some(low);
        }
        tracing::debug!(?mtus, %target, "TCP testing MTUs");
        let ok = futures::future::join_all(mtus.iter().map(|&mtu| async move {
            let mss = mtu - ip_header_len(ipv6) - TCP_HEADER_LEN;
            matches!(
                timeout(TCP_TRY_TIMEOUT, tcp_test(connector, target, Some(mss))).await,
                Ok(Ok(()))
            )
        }))
        .await;
        match next_range(&mtus, &ok) {
            Next::Found(mtu) => return Some(mtu),
            Next::Narrow(next_low, next_high) => (low, high) = (next_low, next_high),
            Next::NoneOk => return None,
        }
    }
}

// A server advertising a small MSS would make every larger MTU pass, so cap the search at the
// largest MTU the best reachable server can exercise.
async fn best_tcp_target(targets: &[SocketAddr], max: &mut u32) -> Option<SocketAddr> {
    let limits = futures::future::join_all(targets.iter().map(|&target| async move {
        match timeout(TCP_TRY_TIMEOUT, peer_mtu_limit(target)).await {
            Ok(Ok(limit)) => Some((target, limit)),
            Ok(Err(error)) => {
                tracing::debug!(%target, %error, "TCP path MTU discovery target unreachable");
                None
            }
            Err(_) => {
                tracing::debug!(%target, "TCP path MTU discovery target timed out");
                None
            }
        }
    }))
    .await;
    let (target, limit) = limits
        .into_iter()
        .flatten()
        .max_by_key(|(_, limit)| *limit)?;
    *max = (*max).min(limit);
    Some(target)
}

async fn peer_mtu_limit(target: SocketAddr) -> io::Result<u32> {
    let socket = tcp_socket(target, None)?;
    let stream = socket.connect(target).await?;
    let info = tcp_info(&stream)?;
    let options = if info.tcpi_options & TCPI_OPT_TIMESTAMPS != 0 {
        TCP_TIMESTAMP_OPTION_LEN
    } else {
        0
    };
    Ok(ip_header_len(target.is_ipv6()) + TCP_HEADER_LEN + info.tcpi_snd_mss + options)
}

async fn tcp_test(
    connector: &TlsConnector,
    target: SocketAddr,
    mss: Option<u32>,
) -> io::Result<()> {
    let stream = tcp_socket(target, mss)?.connect(target).await?;
    let server_name = ServerName::IpAddress(target.ip().into());
    match connector.connect(server_name, stream).await {
        Ok(_) => Ok(()),
        Err(error) if received_certificate(&error) => Ok(()),
        Err(error) => Err(error),
    }
}

fn received_certificate(error: &io::Error) -> bool {
    error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>())
        .is_some_and(|error| matches!(error, rustls::Error::InvalidCertificate(_)))
}

fn tcp_socket(target: SocketAddr, mss: Option<u32>) -> io::Result<TcpSocket> {
    let socket = Socket::new(
        Domain::for_address(target),
        Type::STREAM,
        Some(Protocol::TCP),
    )?;
    icmp::set_pmtudisc_probe(&socket, target.ip())?;
    if let Some(mss) = mss {
        socket.set_tcp_mss(mss)?;
    }
    socket.set_nonblocking(true)?;
    Ok(TcpSocket::from_std_stream(std::net::TcpStream::from(
        socket,
    )))
}

fn tcp_info(stream: &tokio::net::TcpStream) -> io::Result<libc::tcp_info> {
    // SAFETY: tcp_info is plain old data, so the all-zero bit pattern is a valid value.
    let mut info: libc::tcp_info = unsafe { std::mem::zeroed() };
    let mut length = libc::socklen_t::try_from(size_of::<libc::tcp_info>())
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: the pointers describe a live, writable tcp_info and its length for the call.
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_INFO,
            (&raw mut info).cast(),
            &raw mut length,
        )
    };
    if result == 0 {
        Ok(info)
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn max_theoretical_mtu_per_family() {
        assert_eq!(max_theoretical_vpn_mtu(false), 1440);
        assert_eq!(max_theoretical_vpn_mtu(true), 1420);
        assert_eq!(advmss(1440, false), 1380);
        assert_eq!(advmss(1420, true), 1340);
    }

    #[test]
    fn mtus_to_test_matches_gluetun() {
        assert_eq!(mtus_to_test(1400, 1400), vec![1400]);
        assert_eq!(mtus_to_test(1400, 1405), (1400..=1405).collect::<Vec<_>>());
        assert_eq!(mtus_to_test(1400, 1411), (1400..=1411).collect::<Vec<_>>());
        assert_eq!(
            mtus_to_test(1280, 1440),
            vec![
                1280, 1296, 1312, 1328, 1344, 1360, 1376, 1392, 1408, 1424, 1440
            ]
        );
        assert_eq!(
            mtus_to_test(68, 1440),
            vec![68, 205, 342, 480, 617, 754, 891, 1028, 1166, 1303, 1440]
        );
    }

    #[test]
    fn next_range_narrows_on_highest_success() {
        let mtus = [1000, 1100, 1200];
        assert_eq!(next_range(&mtus, &[true, true, true]), Next::Found(1200));
        assert_eq!(
            next_range(&mtus, &[true, true, false]),
            Next::Narrow(1100, 1199)
        );
        assert_eq!(
            next_range(&mtus, &[true, false, false]),
            Next::Narrow(1000, 1099)
        );
        assert_eq!(next_range(&mtus, &[false, false, false]), Next::NoneOk);
    }

    #[test]
    fn targets_drop_ipv6_without_ipv6() {
        let targets = Targets::new(
            &[
                "1.1.1.1".parse().expect("valid"),
                "::1".parse().expect("valid"),
            ],
            &[
                "1.1.1.1:443".parse().expect("valid"),
                "[::1]:443".parse().expect("valid"),
            ],
            false,
        );
        assert_eq!(targets.icmp.len(), 1);
        assert_eq!(targets.tcp.len(), 1);
    }

    #[tokio::test]
    #[ignore = "needs network access and an unprivileged ping group range"]
    async fn discovers_container_path_mtu() {
        let targets = Targets::new(
            &["1.1.1.1".parse().expect("valid")],
            &["1.1.1.1:443".parse().expect("valid")],
            false,
        );
        let connector = crate::tls::connector().expect("TLS connector");
        let mtu = path_mtu_discover(&connector, &targets, ETHERNET_MTU)
            .await
            .expect("path MTU");
        assert!((1280..=ETHERNET_MTU).contains(&mtu), "{mtu}");
    }
}
