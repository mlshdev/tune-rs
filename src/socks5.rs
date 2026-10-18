use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;

use crate::config::Socks5Settings;
use crate::vpn::Status;

const MAX_CLIENTS: usize = 128;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub struct Server {
    listener: TcpListener,
    settings: Arc<Socks5Settings>,
}

impl Server {
    pub async fn bind(settings: Socks5Settings) -> io::Result<Self> {
        settings
            .validate_credentials()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let listener = TcpListener::bind(settings.listen_address).await?;
        Ok(Self {
            listener,
            settings: Arc::new(settings),
        })
    }

    pub async fn run(self, mut status: watch::Receiver<Status>) -> io::Result<()> {
        tracing::info!(address = %self.listener.local_addr()?, "SOCKS5 proxy listening");
        let permits = Arc::new(Semaphore::new(MAX_CLIENTS));
        let mut tasks = JoinSet::new();
        loop {
            tokio::select! {
                biased;
                changed = status.changed() => {
                    tasks.abort_all();
                    while tasks.join_next().await.is_some() {}
                    if changed.is_err() { return Ok(()); }
                    status.borrow_and_update();
                }
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
                    let status = status.clone();
                    tasks.spawn(async move {
                        let _permit = permit;
                        if let Err(error) = handle(stream, &settings, status).await {
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
) -> io::Result<()> {
    let handshake =
        tokio::time::timeout(HANDSHAKE_TIMEOUT, connect(&mut client, settings, &status))
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
    let Some(mut remote) = handshake else {
        return Ok(());
    };
    tokio::select! {
        result = tokio::io::copy_bidirectional(&mut client, &mut remote) => result.map(|_| ()),
        () = until_stopped(&mut status) => Ok(()),
    }
}

async fn connect(
    client: &mut TcpStream,
    settings: &Socks5Settings,
    status: &watch::Receiver<Status>,
) -> io::Result<Option<TcpStream>> {
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
    Ok(Some(remote))
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
            handle(connection, &settings, status).await.expect("handle");
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
            handle(stream, &settings(), status_rx)
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
