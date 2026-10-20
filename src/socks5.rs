use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ipnetwork::IpNetwork;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{Semaphore, watch};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::Instant;

use crate::config::Socks5Settings;
use crate::vpn::Status;

const MAX_CLIENTS: usize = 128;
const MAX_ASSOCIATIONS: usize = 128;
const MAX_FLOWS: usize = 512;
const MAX_DATAGRAM: usize = 65535;
const FLOW_IDLE: Duration = Duration::from_secs(60);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub struct Server {
    listener: TcpListener,
    settings: Arc<Socks5Settings>,
    udp: Arc<Udp>,
}

impl Server {
    pub async fn bind(settings: Socks5Settings) -> io::Result<Self> {
        settings
            .validate_credentials()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let listener = TcpListener::bind(settings.listen_address).await?;
        let datagrams = UdpSocket::bind(listener.local_addr()?).await?;
        let port = datagrams.local_addr()?.port();
        let udp = Arc::new(Udp {
            socket: Arc::new(datagrams),
            allowed_cidrs: settings.allowed_cidrs.clone(),
            advertised: settings.udp_advertised_address,
            port,
            state: Mutex::new(UdpState::default()),
        });
        Ok(Self {
            listener,
            settings: Arc::new(settings),
            udp,
        })
    }

    pub async fn run(self, mut status: watch::Receiver<Status>) -> io::Result<()> {
        tracing::info!(address = %self.listener.local_addr()?, "SOCKS5 proxy listening");
        let permits = Arc::new(Semaphore::new(MAX_CLIENTS));
        let udp = Arc::clone(&self.udp);
        let udp_status = status.clone();
        let udp_relay = udp_loop(udp, udp_status);
        tokio::pin!(udp_relay);
        let mut tasks = JoinSet::new();
        loop {
            tokio::select! {
                biased;
                changed = status.changed() => {
                    self.udp.reset();
                    tasks.abort_all();
                    while tasks.join_next().await.is_some() {}
                    if changed.is_err() {
                        return Ok(());
                    }
                    status.borrow_and_update();
                }
                result = &mut udp_relay => return result,
                Some(result) = tasks.join_next(), if !tasks.is_empty() => {
                    if let Err(error) = result {
                        tracing::error!(%error, "SOCKS5 connection task failed");
                    }
                }
                accepted = self.listener.accept() => {
                    let (stream, peer) = accepted?;
                    let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
                        continue;
                    };
                    let settings = Arc::clone(&self.settings);
                    let udp = Arc::clone(&self.udp);
                    let status = status.clone();
                    tasks.spawn(async move {
                        let _permit = permit;
                        if let Err(error) = handle(stream, &settings, status, Some(udp)).await {
                            tracing::debug!(%error, %peer, "SOCKS5 client disconnected");
                        }
                    });
                }
            }
        }
    }
}

async fn handle(
    mut client: TcpStream,
    settings: &Socks5Settings,
    mut status: watch::Receiver<Status>,
    udp: Option<Arc<Udp>>,
) -> io::Result<()> {
    let handshake = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        connect(&mut client, settings, &status, udp),
    )
    .await
    .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
    match handshake {
        Some(Relay::Tcp(mut remote)) => tokio::select! {
            result = tokio::io::copy_bidirectional(&mut client, &mut remote) => result.map(|_| ()),
            () = until_stopped(&mut status) => Ok(()),
        },
        Some(Relay::Udp(guard)) => {
            let _guard = guard;
            let mut discard = tokio::io::sink();
            tokio::select! {
                result = tokio::io::copy(&mut client, &mut discard) => result.map(|_| ()),
                () = until_stopped(&mut status) => Ok(()),
            }
        }
        None => Ok(()),
    }
}

enum Relay {
    Tcp(TcpStream),
    Udp(AssociationGuard),
}

async fn connect(
    client: &mut TcpStream,
    settings: &Socks5Settings,
    status: &watch::Receiver<Status>,
    udp: Option<Arc<Udp>>,
) -> io::Result<Option<Relay>> {
    let mut hello = [0u8; 2];
    client.read_exact(&mut hello).await?;
    if hello[0] != 5 || hello[1] == 0 {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    let mut methods = vec![0u8; usize::from(hello[1])];
    client.read_exact(&mut methods).await?;
    let authenticated = !settings.user.is_empty();
    let selected = if authenticated { 2 } else { 0 };
    if !methods.contains(&selected) {
        client.write_all(&[5, 255]).await?;
        return Ok(None);
    }
    client.write_all(&[5, selected]).await?;
    if authenticated && !authenticate(client, settings).await? {
        return Ok(None);
    }

    let mut header = [0u8; 4];
    client.read_exact(&mut header).await?;
    if header[0] != 5 || header[2] != 0 {
        reply(client, 1, None).await?;
        return Ok(None);
    }
    if header[1] == 3 {
        let Some(udp) = udp else {
            reply(client, 1, None).await?;
            return Ok(None);
        };
        if !matches!(&*status.borrow(), Status::Running(_)) {
            reply(client, 2, None).await?;
            return Ok(None);
        }
        let expected = match read_udp_endpoint(client, header[3]).await? {
            Some(expected) => expected,
            None => {
                reply(client, 8, None).await?;
                return Ok(None);
            }
        };
        let Some(key) = udp.register(expected, client.peer_addr()?.ip()) else {
            reply(client, 1, None).await?;
            return Ok(None);
        };
        let control_local = client.local_addr()?;
        let advertised = udp.advertised_address(control_local);
        let association = AssociationGuard {
            udp: Arc::clone(&udp),
            key,
        };
        reply(client, 0, Some(advertised)).await?;
        return Ok(Some(Relay::Udp(association)));
    }
    if header[1] != 1 {
        reply(client, 7, None).await?;
        return Ok(None);
    }
    let target = match header[3] {
        1 => {
            let mut ip = [0u8; 4];
            client.read_exact(&mut ip).await?;
            IpAddr::V4(Ipv4Addr::from(ip)).to_string()
        }
        4 => {
            let mut ip = [0u8; 16];
            client.read_exact(&mut ip).await?;
            IpAddr::V6(Ipv6Addr::from(ip)).to_string()
        }
        3 => {
            let length = client.read_u8().await?;
            if length == 0 {
                reply(client, 8, None).await?;
                return Ok(None);
            }
            let mut hostname = vec![0u8; usize::from(length)];
            client.read_exact(&mut hostname).await?;
            match String::from_utf8(hostname) {
                Ok(hostname) => hostname,
                Err(_) => {
                    reply(client, 8, None).await?;
                    return Ok(None);
                }
            }
        }
        _ => {
            reply(client, 8, None).await?;
            return Ok(None);
        }
    };
    let port = client.read_u16().await?;
    if port == 0 || !matches!(&*status.borrow(), Status::Running(_)) {
        reply(client, 2, None).await?;
        return Ok(None);
    }

    let connected =
        tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect((target.as_str(), port))).await;
    let remote = match connected {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) => {
            let reason = if error.kind() == io::ErrorKind::ConnectionRefused {
                5
            } else {
                4
            };
            reply(client, reason, None).await?;
            return Ok(None);
        }
        Err(_) => {
            reply(client, 6, None).await?;
            return Ok(None);
        }
    };
    if !matches!(&*status.borrow(), Status::Running(_)) {
        reply(client, 2, None).await?;
        return Ok(None);
    }
    reply(client, 0, remote.local_addr().ok()).await?;
    Ok(Some(Relay::Tcp(remote)))
}

async fn until_stopped(status: &mut watch::Receiver<Status>) {
    loop {
        if status.changed().await.is_err()
            || !matches!(&*status.borrow_and_update(), Status::Running(_))
        {
            return;
        }
    }
}

async fn authenticate(client: &mut TcpStream, settings: &Socks5Settings) -> io::Result<bool> {
    let mut header = [0u8; 2];
    client.read_exact(&mut header).await?;
    if header[0] != 1 || header[1] == 0 {
        client.write_all(&[1, 1]).await?;
        return Ok(false);
    }
    let mut user = vec![0u8; usize::from(header[1])];
    client.read_exact(&mut user).await?;
    let length = client.read_u8().await?;
    let mut password = vec![0u8; usize::from(length)];
    client.read_exact(&mut password).await?;
    let user_matches = constant_time_equal(settings.user.expose().as_bytes(), &user);
    let password_matches = constant_time_equal(settings.password.expose().as_bytes(), &password);
    let matched = user_matches & password_matches;
    client.write_all(&[1, u8::from(!matched)]).await?;
    Ok(matched)
}

fn constant_time_equal(expected: &[u8], actual: &[u8]) -> bool {
    if expected.len() != actual.len() {
        return false;
    }
    expected
        .iter()
        .zip(actual)
        .fold(0u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

async fn reply(client: &mut TcpStream, result: u8, address: Option<SocketAddr>) -> io::Result<()> {
    let address = address.unwrap_or(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)));
    let mut response = vec![5, result, 0];
    match address.ip() {
        IpAddr::V4(ip) => {
            response.push(1);
            response.extend(ip.octets());
        }
        IpAddr::V6(ip) => {
            response.push(4);
            response.extend(ip.octets());
        }
    }
    response.extend(address.port().to_be_bytes());
    client.write_all(&response).await
}

async fn read_udp_endpoint(
    client: &mut TcpStream,
    atyp: u8,
) -> io::Result<Option<Option<SocketAddr>>> {
    let ip = match atyp {
        1 => {
            let mut octets = [0u8; 4];
            client.read_exact(&mut octets).await?;
            Some(IpAddr::V4(Ipv4Addr::from(octets)))
        }
        4 => {
            let mut octets = [0u8; 16];
            client.read_exact(&mut octets).await?;
            Some(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        3 => {
            let length = client.read_u8().await?;
            let mut name = vec![0u8; usize::from(length)];
            client.read_exact(&mut name).await?;
            if String::from_utf8(name).is_err() {
                return Ok(None);
            }
            None
        }
        _ => return Ok(None),
    };
    let port = client.read_u16().await?;
    Ok(Some(Some(SocketAddr::new(
        ip.unwrap_or(Ipv4Addr::UNSPECIFIED.into()),
        port,
    ))))
}

enum UdpDestination {
    Ip(SocketAddr),
    Domain(String, u16),
}

fn decode_udp_datagram(packet: &[u8]) -> Option<(UdpDestination, &[u8])> {
    const HEADER: usize = 3;
    if packet.len() <= HEADER || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 {
        return None;
    }
    let rest = &packet[HEADER..];
    let (destination, rest) = match *rest.first()? {
        1 => {
            let octets: [u8; 4] = rest.get(1..5)?.try_into().expect("four octets");
            (
                UdpDestination::Ip(SocketAddr::new(IpAddr::V4(octets.into()), 0)),
                &rest[5..],
            )
        }
        4 => {
            let octets: [u8; 16] = rest.get(1..17)?.try_into().expect("sixteen octets");
            (
                UdpDestination::Ip(SocketAddr::new(IpAddr::V6(octets.into()), 0)),
                &rest[17..],
            )
        }
        3 => {
            let length = usize::from(*rest.get(1)?);
            let name = rest.get(2..2 + length)?;
            let name = String::from_utf8(name.to_vec()).ok()?;
            let rest = rest.get(2 + length..)?;
            (UdpDestination::Domain(name, 0), rest)
        }
        _ => return None,
    };
    let port = u16::from_be_bytes([*rest.first()?, *rest.get(1)?]);
    let payload = rest.get(2..)?;
    if payload.is_empty() || port == 0 {
        return None;
    }
    let destination = match destination {
        UdpDestination::Ip(address) => UdpDestination::Ip(SocketAddr::new(address.ip(), port)),
        UdpDestination::Domain(name, _) => UdpDestination::Domain(name, port),
    };
    Some((destination, payload))
}

fn encode_udp_header(dest: SocketAddr) -> Vec<u8> {
    let mut packet = vec![0, 0, 0];
    match dest.ip() {
        IpAddr::V4(ip) => {
            packet.push(1);
            packet.extend(ip.octets());
        }
        IpAddr::V6(ip) => {
            packet.push(4);
            packet.extend(ip.octets());
        }
    }
    packet.extend(dest.port().to_be_bytes());
    packet
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct AssociationKey(u64);

struct Association {
    ip: IpAddr,
    port: u16,
    endpoint: Option<SocketAddr>,
}

struct Flow {
    socket: Arc<UdpSocket>,
    pump: JoinHandle<io::Result<()>>,
    last: Instant,
}

impl Drop for Flow {
    fn drop(&mut self) {
        self.pump.abort();
    }
}

#[derive(Default)]
struct UdpState {
    next_key: u64,
    associations: HashMap<AssociationKey, Association>,
    bound: HashMap<SocketAddr, AssociationKey>,
    flows: HashMap<(AssociationKey, SocketAddr), Flow>,
}

struct Udp {
    socket: Arc<UdpSocket>,
    allowed_cidrs: Vec<IpNetwork>,
    advertised: Option<SocketAddr>,
    port: u16,
    state: Mutex<UdpState>,
}

impl Udp {
    fn advertised_address(&self, control_local: SocketAddr) -> SocketAddr {
        self.advertised
            .unwrap_or_else(|| SocketAddr::new(control_local.ip(), self.port))
    }

    fn register(&self, expected: Option<SocketAddr>, control_ip: IpAddr) -> Option<AssociationKey> {
        let mut state = self.state.lock().expect("not poisoned");
        if state.associations.len() >= MAX_ASSOCIATIONS {
            return None;
        }
        let control_ip = control_ip.to_canonical();
        if expected.is_some_and(|endpoint| {
            !endpoint.ip().is_unspecified() && endpoint.ip().to_canonical() != control_ip
        }) {
            return None;
        }
        let port = expected.map_or(0, |endpoint| endpoint.port());
        let endpoint = (port != 0).then(|| SocketAddr::new(control_ip, port));
        if endpoint.is_some_and(|endpoint| state.bound.contains_key(&endpoint)) {
            return None;
        }
        let key = AssociationKey(state.next_key.checked_add(1)?);
        state.next_key = key.0;
        state.associations.insert(
            key,
            Association {
                ip: control_ip,
                port,
                endpoint,
            },
        );
        if let Some(endpoint) = endpoint {
            state.bound.insert(endpoint, key);
        }
        Some(key)
    }

    fn unregister(&self, key: &AssociationKey) {
        let mut state = self.state.lock().expect("not poisoned");
        if let Some(association) = state.associations.remove(key)
            && let Some(endpoint) = association.endpoint
        {
            state.bound.remove(&endpoint);
        }
        state.flows.retain(|(owner, _), _| owner != key);
    }

    fn accept_client(&self, source: SocketAddr) -> Option<AssociationKey> {
        let source = SocketAddr::new(source.ip().to_canonical(), source.port());
        if !self.allowed_cidrs.is_empty()
            && !self
                .allowed_cidrs
                .iter()
                .any(|cidr| cidr.contains(source.ip()))
        {
            return None;
        }
        let mut state = self.state.lock().expect("not poisoned");
        if let Some(key) = state.bound.get(&source) {
            return Some(*key);
        }
        let key = state
            .associations
            .iter()
            .filter(|(_, association)| {
                association.endpoint.is_none()
                    && association.ip == source.ip()
                    && (association.port == 0 || association.port == source.port())
            })
            .map(|(key, _)| *key)
            .min_by_key(|key| key.0)?;
        state.associations.get_mut(&key)?.endpoint = Some(source);
        state.bound.insert(source, key);
        Some(key)
    }

    async fn forward(
        &self,
        key: AssociationKey,
        source: SocketAddr,
        dest: SocketAddr,
        payload: &[u8],
    ) -> io::Result<()> {
        enum Decision {
            Existing(Arc<UdpSocket>),
            Fresh,
            Dropped,
        }
        let decision = {
            let mut state = self.state.lock().expect("not poisoned");
            if state.bound.get(&source) != Some(&key) {
                return Ok(());
            }
            if let Some(flow) = state.flows.get_mut(&(key, dest)) {
                flow.last = Instant::now();
                Decision::Existing(Arc::clone(&flow.socket))
            } else if state.flows.len() >= MAX_FLOWS {
                Decision::Dropped
            } else {
                Decision::Fresh
            }
        };
        let socket = match decision {
            Decision::Existing(socket) => socket,
            Decision::Dropped => {
                tracing::debug!(%source, %dest, "SOCKS5 UDP flow limit reached; dropping");
                return Ok(());
            }
            Decision::Fresh => {
                let local = if dest.is_ipv4() {
                    SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0)
                } else {
                    SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0)
                };
                let socket = Arc::new(UdpSocket::bind(local).await?);
                socket.connect(dest).await?;
                let pump = tokio::spawn(udp_pump(
                    Arc::clone(&socket),
                    Arc::clone(&self.socket),
                    source,
                    dest,
                ));
                let mut state = self.state.lock().expect("not poisoned");
                if state.bound.get(&source) != Some(&key) || state.flows.len() >= MAX_FLOWS {
                    pump.abort();
                    return Ok(());
                }
                state.flows.insert(
                    (key, dest),
                    Flow {
                        socket: Arc::clone(&socket),
                        pump,
                        last: Instant::now(),
                    },
                );
                socket
            }
        };
        socket.writable().await?;
        let state = self.state.lock().expect("not poisoned");
        if state.bound.get(&source) != Some(&key) {
            return Ok(());
        }
        match socket.try_send(payload) {
            Ok(_) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(()),
            Err(error) => Err(error),
        }
    }

    fn sweep(&self) {
        let mut state = self.state.lock().expect("not poisoned");
        state.flows.retain(|_, flow| {
            if !flow.pump.is_finished() && flow.last.elapsed() < FLOW_IDLE {
                true
            } else {
                flow.pump.abort();
                false
            }
        });
    }

    fn reset(&self) {
        let mut state = self.state.lock().expect("not poisoned");
        for flow in state.flows.values() {
            flow.pump.abort();
        }
        state.flows.clear();
        state.bound.clear();
        state.associations.clear();
    }
}

struct AssociationGuard {
    udp: Arc<Udp>,
    key: AssociationKey,
}

impl Drop for AssociationGuard {
    fn drop(&mut self) {
        self.udp.unregister(&self.key);
    }
}

async fn udp_pump(
    socket: Arc<UdpSocket>,
    relay: Arc<UdpSocket>,
    client: SocketAddr,
    dest: SocketAddr,
) -> io::Result<()> {
    let mut buffer = vec![0u8; MAX_DATAGRAM];
    loop {
        let size = socket.recv(&mut buffer).await?;
        let mut packet = encode_udp_header(dest);
        packet.extend_from_slice(&buffer[..size]);
        relay.send_to(&packet, client).await?;
    }
}

async fn udp_loop(udp: Arc<Udp>, mut status: watch::Receiver<Status>) -> io::Result<()> {
    let mut buffer = vec![0u8; MAX_DATAGRAM];
    let mut sweep = tokio::time::interval(FLOW_IDLE);
    sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            biased;
            changed = status.changed() => {
                if changed.is_err() {
                    return Ok(());
                }
                status.borrow_and_update();
            }
            _ = sweep.tick() => udp.sweep(),
            received = udp.socket.recv_from(&mut buffer) => {
                let (size, source) = received?;
                let source = SocketAddr::new(source.ip().to_canonical(), source.port());
                if !matches!(&*status.borrow(), Status::Running(_)) {
                    continue;
                }
                let Some((destination, payload)) = decode_udp_datagram(&buffer[..size]) else {
                    continue;
                };
                let Some(key) = udp.accept_client(source) else {
                    continue;
                };
                let dest = match destination {
                    UdpDestination::Ip(address) => Some(address),
                    UdpDestination::Domain(name, port) => {
                        match tokio::net::lookup_host((name.as_str(), port)).await {
                            Ok(mut resolved) => resolved.next(),
                            Err(error) => {
                                tracing::debug!(%error, %source, "SOCKS5 UDP destination did not resolve");
                                continue;
                            }
                        }
                    }
                };
                let Some(dest) = dest else {
                    continue;
                };
                if !matches!(&*status.borrow(), Status::Running(_)) { continue; }
                if let Err(error) = udp.forward(key, source, dest, payload).await {
                    tracing::debug!(%error, %source, %dest, "SOCKS5 UDP forward failed");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn running() -> Status {
        Status::Running(crate::vpn::Tunnel {
            interface: "wg0".into(),
            connection: crate::models::Connection {
                ip: Ipv4Addr::LOCALHOST.into(),
                port: 51820,
                hostname: String::new(),
                server_name: String::new(),
                pubkey: String::new(),
            },
            ipv6: false,
        })
    }

    async fn within<F: std::future::Future>(future: F) -> F::Output {
        tokio::time::timeout(Duration::from_secs(3), future)
            .await
            .expect("completed in time")
    }

    fn authenticated_settings() -> Socks5Settings {
        let mut settings = settings();
        settings.enabled = true;
        settings.listen_address = "127.0.0.1:0".parse().expect("address");
        settings.user = crate::config::Secret::new("browser");
        settings.password = crate::config::Secret::new("secret-value");
        settings
    }

    async fn proxy() -> (
        SocketAddr,
        watch::Sender<Status>,
        tokio::task::JoinHandle<io::Result<()>>,
    ) {
        let server = Server::bind(authenticated_settings()).await.expect("proxy");
        let address = server.listener.local_addr().expect("address");
        let (status, receiver) = watch::channel(running());
        (address, status, tokio::spawn(server.run(receiver)))
    }

    async fn credentials(client: &mut TcpStream, user: &[u8], password: &[u8]) -> [u8; 2] {
        let mut packet = vec![1, u8::try_from(user.len()).expect("user length")];
        packet.extend_from_slice(user);
        packet.push(u8::try_from(password.len()).expect("password length"));
        packet.extend_from_slice(password);
        client.write_all(&packet).await.expect("credentials");
        let mut response = [0u8; 2];
        within(client.read_exact(&mut response))
            .await
            .expect("authentication response");
        response
    }

    async fn associate(address: SocketAddr) -> (TcpStream, SocketAddr) {
        let mut client = TcpStream::connect(address).await.expect("control");
        client.write_all(&[5, 1, 2]).await.expect("methods");
        let mut method = [0; 2];
        within(client.read_exact(&mut method))
            .await
            .expect("method");
        assert_eq!(method, [5, 2]);
        assert_eq!(
            credentials(&mut client, b"browser", b"secret-value").await,
            [1, 0]
        );
        client
            .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .expect("associate");
        let mut response = [0; 10];
        within(client.read_exact(&mut response))
            .await
            .expect("reply");
        assert_eq!(&response[..4], &[5, 0, 0, 1]);
        let ip = Ipv4Addr::new(response[4], response[5], response[6], response[7]);
        (
            client,
            SocketAddr::new(ip.into(), u16::from_be_bytes([response[8], response[9]])),
        )
    }

    #[tokio::test]
    async fn udp_ipv4_client_reaches_ipv6_destination() {
        let (address, status, task) = proxy().await;
        let (_control, relay) = associate(address).await;
        let client = UdpSocket::bind("127.0.0.1:0").await.expect("client");
        let remote = UdpSocket::bind("[::1]:0").await.expect("IPv6 remote");
        let destination = remote.local_addr().expect("remote address");
        let mut request = encode_udp_header(destination);
        request.extend(b"IPv6");
        client.send_to(&request, relay).await.expect("send");
        let mut buffer = [0; 64];
        let (size, peer) = within(remote.recv_from(&mut buffer))
            .await
            .expect("IPv6 payload");
        assert_eq!(&buffer[..size], b"IPv6");
        remote.send_to(b"reply", peer).await.expect("reply");
        let (size, _) = within(client.recv_from(&mut buffer))
            .await
            .expect("relay reply");
        assert_eq!(&buffer[..22], encode_udp_header(destination).as_slice());
        assert_eq!(&buffer[22..size], b"reply");
        drop(status);
        within(task).await.expect("joined").expect("stopped");
    }

    #[tokio::test]
    async fn udp_control_outlives_handshake_deadline() {
        let (address, status, task) = proxy().await;
        let (control, _) = associate(address).await;
        tokio::time::pause();
        tokio::time::advance(HANDSHAKE_TIMEOUT + Duration::from_secs(1)).await;
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        let mut byte = [0];
        let read = control.try_read(&mut byte);
        assert!(
            matches!(read, Err(ref error) if error.kind() == io::ErrorKind::WouldBlock),
            "control must remain open, got {read:?}"
        );
        tokio::time::resume();
        drop(status);
        within(task).await.expect("joined").expect("stopped");
    }

    #[tokio::test]
    async fn lazy_association_guard_removes_the_learned_endpoint() {
        let server = Server::bind(authenticated_settings())
            .await
            .expect("server");
        let endpoint: SocketAddr = "127.0.0.1:12345".parse().expect("endpoint");
        let key = server
            .udp
            .register(None, endpoint.ip())
            .expect("association");
        let guard = AssociationGuard {
            udp: Arc::clone(&server.udp),
            key,
        };
        assert!(server.udp.accept_client(endpoint).is_some());
        drop(guard);
        assert!(
            server.udp.accept_client(endpoint).is_none(),
            "closed association still owns a UDP endpoint"
        );
    }

    #[tokio::test]
    async fn closing_udp_control_aborts_flows_and_rejects_more_datagrams() {
        let server = Server::bind(authenticated_settings()).await.expect("proxy");
        let address = server.listener.local_addr().expect("address");
        let udp = Arc::clone(&server.udp);
        let (status, receiver) = watch::channel(running());
        let task = tokio::spawn(server.run(receiver));
        let (control, relay) = associate(address).await;
        let client = UdpSocket::bind("127.0.0.1:0").await.expect("client");
        let remote = UdpSocket::bind("127.0.0.1:0").await.expect("remote");
        let mut request = encode_udp_header(remote.local_addr().expect("address"));
        request.extend(b"first");
        client.send_to(&request, relay).await.expect("send");
        let mut buffer = [0; 64];
        within(remote.recv_from(&mut buffer))
            .await
            .expect("payload");
        let socket = {
            let state = udp.state.lock().expect("state");
            Arc::downgrade(&state.flows.values().next().expect("flow").socket)
        };
        drop(control);
        within(async {
            loop {
                if udp.state.lock().expect("state").associations.is_empty()
                    && socket.upgrade().is_none()
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await;
        assert!(
            udp.accept_client(client.local_addr().expect("address"))
                .is_none()
        );
        client
            .send_to(&request, relay)
            .await
            .expect("send after close");
        assert!(
            tokio::time::timeout(Duration::from_millis(50), remote.recv_from(&mut buffer))
                .await
                .is_err()
        );
        drop(status);
        within(task).await.expect("joined").expect("stopped");
    }

    #[tokio::test]
    async fn association_ownership_survives_reset_without_endpoint_hijacking() {
        let server = Server::bind(authenticated_settings()).await.expect("proxy");
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let endpoint: SocketAddr = "127.0.0.1:12345".parse().expect("endpoint");
        let old = server.udp.register(Some(endpoint), ip).expect("old");
        assert!(
            server.udp.register(Some(endpoint), ip).is_none(),
            "duplicate endpoint must not replace its owner"
        );
        assert!(
            server
                .udp
                .register(
                    Some("127.0.0.2:12345".parse().expect("foreign endpoint")),
                    ip
                )
                .is_none()
        );
        server.udp.reset();
        let new = server.udp.register(Some(endpoint), ip).expect("new");
        assert_ne!(old, new);
        server.udp.unregister(&old);
        assert_eq!(server.udp.accept_client(endpoint), Some(new));
        server.udp.unregister(&new);
        assert!(server.udp.accept_client(endpoint).is_none());
    }

    #[tokio::test]
    async fn unspecified_client_ip_preserves_the_requested_udp_source_port() {
        let server = Server::bind(authenticated_settings()).await.expect("proxy");
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let key = server
            .udp
            .register(Some("0.0.0.0:12345".parse().expect("endpoint")), ip)
            .expect("association");
        assert!(
            server
                .udp
                .accept_client("127.0.0.1:12346".parse().expect("wrong port"))
                .is_none()
        );
        assert_eq!(
            server
                .udp
                .accept_client("127.0.0.1:12345".parse().expect("right port")),
            Some(key)
        );
    }

    #[tokio::test]
    async fn authenticated_udp_association_relays_datagrams() {
        let (address, status, task) = proxy().await;
        let remote = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("remote");
        let datagrams = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("client UDP");
        let mut client = TcpStream::connect(address).await.expect("client TCP");
        client.write_all(&[5, 1, 2]).await.expect("methods");
        let mut selected = [0; 2];
        within(client.read_exact(&mut selected))
            .await
            .expect("method");
        assert_eq!(selected, [5, 2]);
        assert_eq!(
            credentials(&mut client, b"browser", b"secret-value").await,
            [1, 0]
        );
        client
            .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .expect("UDP ASSOCIATE");
        let mut response = [0; 10];
        within(client.read_exact(&mut response))
            .await
            .expect("association reply");
        assert_eq!(&response[..4], &[5, 0, 0, 1]);
        let advertised = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(
                response[4],
                response[5],
                response[6],
                response[7],
            )),
            u16::from_be_bytes([response[8], response[9]]),
        );
        assert!(advertised.port() != 0);
        let mut packet = vec![0, 0, 0, 1, 127, 0, 0, 1];
        packet.extend(
            remote
                .local_addr()
                .expect("remote address")
                .port()
                .to_be_bytes(),
        );
        packet.extend(b"hello");
        datagrams
            .send_to(&packet, advertised)
            .await
            .expect("send UDP");
        let mut buffer = [0; 64];
        let (size, peer) = within(remote.recv_from(&mut buffer))
            .await
            .expect("upstream");
        assert_eq!(&buffer[..size], b"hello");
        remote.send_to(b"world", peer).await.expect("reply");
        let (size, source) = within(datagrams.recv_from(&mut buffer))
            .await
            .expect("relay reply");
        assert_eq!(source, advertised);
        assert_eq!(&buffer[..10], &packet[..10]);
        assert_eq!(&buffer[10..size], b"world");
        drop(status);
        drop(client);
        within(task).await.expect("joined").expect("stopped");
    }

    #[tokio::test]
    async fn udp_association_rejects_datagrams_outside_allowed_cidrs() {
        let mut settings = authenticated_settings();
        settings.allowed_cidrs = vec!["127.0.0.2/32".parse().expect("allowed CIDR")];
        let server = Server::bind(settings).await.expect("proxy");
        let address = server.listener.local_addr().expect("address");
        let (status, receiver) = watch::channel(running());
        let task = tokio::spawn(server.run(receiver));
        let remote = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("remote");
        let datagrams = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("client UDP");
        let mut client = TcpStream::connect(address).await.expect("client TCP");
        client.write_all(&[5, 1, 2]).await.expect("methods");
        let mut selected = [0u8; 2];
        within(client.read_exact(&mut selected))
            .await
            .expect("method");
        assert_eq!(
            credentials(&mut client, b"browser", b"secret-value").await,
            [1, 0]
        );
        client
            .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .expect("UDP ASSOCIATE");
        let mut response = [0u8; 10];
        within(client.read_exact(&mut response))
            .await
            .expect("association reply");
        assert_eq!(&response[..3], &[5, 0, 0]);
        let advertised = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(
                response[4],
                response[5],
                response[6],
                response[7],
            )),
            u16::from_be_bytes([response[8], response[9]]),
        );
        let mut packet = vec![0, 0, 0, 1, 127, 0, 0, 1];
        packet.extend(
            remote
                .local_addr()
                .expect("remote address")
                .port()
                .to_be_bytes(),
        );
        packet.extend(b"hello");
        datagrams
            .send_to(&packet, advertised)
            .await
            .expect("send UDP");
        let mut buffer = [0u8; 16];
        assert!(
            tokio::time::timeout(Duration::from_millis(200), remote.recv_from(&mut buffer))
                .await
                .is_err(),
            "datagram from a non-allowed client IP is dropped"
        );
        drop(status);
        drop(client);
        within(task).await.expect("joined").expect("stopped");
    }

    #[tokio::test]
    async fn udp_association_survives_tunnel_stop_and_start() {
        let (address, status, task) = proxy().await;
        let remote = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("remote");
        let datagrams = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("client UDP");
        let associate = |status_running: bool| async move {
            let mut control = TcpStream::connect(address).await.expect("client TCP");
            control.write_all(&[5, 1, 2]).await.expect("methods");
            let mut selected = [0u8; 2];
            within(control.read_exact(&mut selected))
                .await
                .expect("method");
            assert_eq!(selected, [5, 2]);
            assert_eq!(
                credentials(&mut control, b"browser", b"secret-value").await,
                [1, 0]
            );
            control
                .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
                .await
                .expect("UDP ASSOCIATE");
            let mut response = [0u8; 10];
            within(control.read_exact(&mut response))
                .await
                .expect("association reply");
            let reply_status = if status_running { 0 } else { 2 };
            assert_eq!(&response[..2], &[5, reply_status]);
            let advertised = SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(
                    response[4],
                    response[5],
                    response[6],
                    response[7],
                )),
                u16::from_be_bytes([response[8], response[9]]),
            );
            (control, advertised)
        };
        let (control, advertised) = associate(true).await;
        let mut packet = vec![0, 0, 0, 1, 127, 0, 0, 1];
        packet.extend(
            remote
                .local_addr()
                .expect("remote address")
                .port()
                .to_be_bytes(),
        );
        packet.extend(b"first");
        datagrams
            .send_to(&packet, advertised)
            .await
            .expect("send UDP");
        let mut buffer = [0u8; 64];
        let (size, _) = within(remote.recv_from(&mut buffer))
            .await
            .expect("upstream before stop");
        assert_eq!(&buffer[..size], b"first");
        status.send_replace(Status::Stopped);
        let mut stopped = control;
        let _ = stopped.read(&mut buffer).await;
        drop(stopped);
        status.send_replace(running());
        let (_control, advertised) = associate(true).await;
        let mut packet = vec![0, 0, 0, 1, 127, 0, 0, 1];
        packet.extend(
            remote
                .local_addr()
                .expect("remote address")
                .port()
                .to_be_bytes(),
        );
        packet.extend(b"second");
        datagrams
            .send_to(&packet, advertised)
            .await
            .expect("send UDP after restart");
        let (size, peer) = within(remote.recv_from(&mut buffer))
            .await
            .expect("upstream after restart");
        assert_eq!(&buffer[..size], b"second");
        remote.send_to(b"replied", peer).await.expect("reply");
        let (size, source) = within(datagrams.recv_from(&mut buffer))
            .await
            .expect("relay reply after restart");
        assert_eq!(source, advertised);
        assert_eq!(&buffer[10..size], b"replied");
        drop(status);
        within(task).await.expect("joined").expect("stopped");
    }

    #[tokio::test]
    async fn udp_association_advertises_the_configured_address() {
        let mut settings = authenticated_settings();
        settings.udp_advertised_address = Some("192.0.2.10:1080".parse().expect("advertised"));
        let server = Server::bind(settings).await.expect("proxy");
        let address = server.listener.local_addr().expect("address");
        let (status, receiver) = watch::channel(running());
        let task = tokio::spawn(server.run(receiver));
        let mut client = TcpStream::connect(address).await.expect("client TCP");
        client.write_all(&[5, 1, 2]).await.expect("methods");
        let mut selected = [0u8; 2];
        within(client.read_exact(&mut selected))
            .await
            .expect("method");
        assert_eq!(
            credentials(&mut client, b"browser", b"secret-value").await,
            [1, 0]
        );
        client
            .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .expect("UDP ASSOCIATE");
        let mut response = [0u8; 10];
        within(client.read_exact(&mut response))
            .await
            .expect("association reply");
        assert_eq!(response, [5, 0, 0, 1, 192, 0, 2, 10, 4, 56]);
        drop(status);
        drop(client);
        within(task).await.expect("joined").expect("stopped");
    }

    #[tokio::test]
    async fn authenticated_proxy_relays_tcp_and_cancels_on_tunnel_stop() {
        let echo = TcpListener::bind("127.0.0.1:0").await.expect("echo");
        let destination = echo.local_addr().expect("address");
        let (address, status, task) = proxy().await;
        let mut client = TcpStream::connect(address).await.expect("client");
        client.write_all(&[5, 2, 0, 2]).await.expect("methods");
        let mut selected = [0u8; 2];
        within(client.read_exact(&mut selected))
            .await
            .expect("selected method");
        assert_eq!(selected, [5, 2]);
        assert_eq!(
            credentials(&mut client, b"browser", b"secret-value").await,
            [1, 0]
        );
        let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
        request.extend(destination.port().to_be_bytes());
        client.write_all(&request).await.expect("CONNECT");
        let mut response = [0u8; 10];
        within(client.read_exact(&mut response))
            .await
            .expect("CONNECT response");
        assert_eq!(response[..2], [5, 0]);
        let (mut remote, _) = within(echo.accept()).await.expect("upstream");
        client.write_all(b"hello").await.expect("payload");
        let mut buffer = [0u8; 5];
        within(remote.read_exact(&mut buffer))
            .await
            .expect("upstream payload");
        assert_eq!(&buffer, b"hello");
        remote.write_all(b"world").await.expect("reply");
        within(client.read_exact(&mut buffer))
            .await
            .expect("client reply");
        assert_eq!(&buffer, b"world");
        status.send_replace(Status::Stopped);
        assert_eq!(
            within(client.read(&mut buffer)).await.expect("client EOF"),
            0
        );
        assert_eq!(
            within(remote.read(&mut buffer))
                .await
                .expect("upstream EOF"),
            0
        );
        drop(status);
        within(task).await.expect("joined").expect("stopped");
    }

    #[tokio::test]
    async fn configured_credentials_prevent_unauthenticated_downgrade() {
        let (address, status, task) = proxy().await;
        let mut client = TcpStream::connect(address).await.expect("client");
        client.write_all(&[5, 1, 0]).await.expect("no-auth request");
        let mut response = [0u8; 2];
        within(client.read_exact(&mut response))
            .await
            .expect("method rejection");
        assert_eq!(response, [5, 255]);
        assert_eq!(within(client.read(&mut response)).await.expect("EOF"), 0);
        drop(status);
        within(task).await.expect("joined").expect("stopped");
    }

    #[tokio::test]
    async fn rejects_wrong_username_password_and_empty_password() {
        let (address, status, task) = proxy().await;
        for (user, password) in [
            (b"browser".as_slice(), b"wrong".as_slice()),
            (b"Browser".as_slice(), b"secret-value".as_slice()),
            (b"browser".as_slice(), b"".as_slice()),
        ] {
            let mut client = TcpStream::connect(address).await.expect("client");
            client.write_all(&[5, 1, 2]).await.expect("methods");
            let mut selected = [0u8; 2];
            within(client.read_exact(&mut selected))
                .await
                .expect("selected method");
            assert_eq!(selected, [5, 2]);
            assert_eq!(credentials(&mut client, user, password).await, [1, 1]);
            assert_eq!(within(client.read(&mut selected)).await.expect("EOF"), 0);
        }
        drop(status);
        within(task).await.expect("joined").expect("stopped");
    }

    #[tokio::test]
    async fn bind_rejects_incomplete_credentials_instead_of_opening_an_unauthenticated_proxy() {
        for user_only in [false, true] {
            let mut settings = authenticated_settings();
            if user_only {
                settings.password = crate::config::Secret::default();
            } else {
                settings.user = crate::config::Secret::default();
            }
            let error = Server::bind(settings)
                .await
                .err()
                .expect("incomplete credentials rejected");
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            assert!(!error.to_string().contains("secret-value"));
        }
    }

    fn settings() -> Socks5Settings {
        crate::config::Settings::from_env(&crate::config::Env::from_pairs([
            ("VPN_SERVICE_PROVIDER", "mullvad"),
            (
                "WIREGUARD_PRIVATE_KEY",
                "wOEI9rqqbDwnN8/Bpp22sVz48T71vJ4fYmFWujulwUU=",
            ),
            ("WIREGUARD_ADDRESSES", "10.64.222.21/32"),
            ("WIREGUARD_CONF_SECRETFILE", "/nonexistent/wg0.conf"),
        ]))
        .expect("settings")
        .socks5
    }

    #[tokio::test]
    async fn refuses_connection_when_vpn_is_stopped() {
        let settings = settings();
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listen");
        let address = listener.local_addr().expect("address");
        let (_sender, status) = watch::channel(Status::Stopped);
        let task = tokio::spawn(async move {
            let (connection, _) = listener.accept().await.expect("accept");
            handle(connection, &settings, status, None)
                .await
                .expect("handle");
        });
        let mut client = TcpStream::connect(address).await.expect("connect");
        client.write_all(&[5, 1, 0]).await.expect("methods");
        let mut selected = [0u8; 2];
        client.read_exact(&mut selected).await.expect("selection");
        assert_eq!(selected, [5, 0]);
        client
            .write_all(&[5, 1, 0, 1, 1, 1, 1, 1, 0, 80])
            .await
            .expect("request");
        let mut response = [0u8; 10];
        client.read_exact(&mut response).await.expect("reply");
        assert_eq!(&response[..4], &[5, 2, 0, 1]);
        task.await.expect("server task");
    }

    #[tokio::test]
    async fn relays_tcp_until_tunnel_stops() {
        let echo = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("echo listener");
        let destination = echo.local_addr().expect("echo address");
        let echo_task = tokio::spawn(async move {
            let (mut stream, _) = echo.accept().await.expect("echo accept");
            let mut buffer = [0u8; 5];
            stream.read_exact(&mut buffer).await.expect("echo request");
            stream.write_all(&buffer).await.expect("echo reply");
        });

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("proxy listener");
        let address = listener.local_addr().expect("proxy address");
        let (status_tx, status_rx) = watch::channel(Status::Running(crate::vpn::Tunnel {
            interface: "wg0".into(),
            connection: crate::models::Connection {
                ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: 51820,
                hostname: String::new(),
                server_name: String::new(),
                pubkey: String::new(),
            },
            ipv6: false,
        }));
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("proxy accept");
            handle(stream, &settings(), status_rx, None)
                .await
                .expect("proxy handled");
        });
        let mut client = TcpStream::connect(address).await.expect("client");
        client.write_all(&[5, 1, 0]).await.expect("methods");
        let mut selected = [0u8; 2];
        client.read_exact(&mut selected).await.expect("selection");
        assert_eq!(selected, [5, 0]);
        let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
        request.extend(destination.port().to_be_bytes());
        client.write_all(&request).await.expect("connect request");
        let mut response = [0u8; 10];
        client
            .read_exact(&mut response)
            .await
            .expect("connect reply");
        assert_eq!(&response[..4], &[5, 0, 0, 1]);
        client.write_all(b"hello").await.expect("payload");
        let mut echoed = [0u8; 5];
        client.read_exact(&mut echoed).await.expect("echoed");
        assert_eq!(&echoed, b"hello");
        status_tx.send_replace(Status::Stopped);
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("proxy closes")
            .expect("join");
        echo_task.await.expect("echo joins");
    }
}
