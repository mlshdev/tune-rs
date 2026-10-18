use std::convert::Infallible;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use base64::Engine;
use futures::future::BoxFuture;
use hyper::body::Incoming;
use hyper::header::{
    CONNECTION, HOST, HeaderMap, HeaderName, PROXY_AUTHENTICATE, PROXY_AUTHORIZATION,
};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, mpsc, watch};
use tokio::task::JoinSet;
use tokio_rustls::TlsConnector;

use crate::config::HttpProxySettings;
use crate::vpn::Status;

const MAX_CLIENTS: usize = 128;
const DIAL_TIMEOUT: Duration = Duration::from_secs(10);

pub struct Server {
    listener: TcpListener,
    settings: Arc<HttpProxySettings>,
    connector: TlsConnector,
}

impl Server {
    pub async fn bind(settings: HttpProxySettings) -> io::Result<Self> {
        settings
            .validate_credentials()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let listener = TcpListener::bind(settings.listen_address).await?;
        Ok(Self {
            listener,
            settings: Arc::new(settings),
            connector: crate::tls::connector().map_err(io::Error::other)?,
        })
    }

    pub async fn run(self, mut status: watch::Receiver<Status>) -> io::Result<()> {
        tracing::info!(address = %self.listener.local_addr()?, "HTTP proxy listening");
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
                        tracing::error!(%error, "HTTP proxy client task failed");
                    }
                }
                accepted = self.listener.accept() => {
                    let (stream, peer) = accepted?;
                    let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else { continue; };
                    let settings = Arc::clone(&self.settings);
                    let connector = self.connector.clone();
                    let status = status.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                        if let Err(error) = serve_client(stream, settings, status, connector, peer).await {
                            tracing::debug!(%error, %peer, "HTTP proxy connection closed");
                        }
                    });
                }
            }
        }
    }
}

async fn serve_client(
    stream: TcpStream,
    settings: Arc<HttpProxySettings>,
    status: watch::Receiver<Status>,
    connector: TlsConnector,
    peer: SocketAddr,
) -> Result<(), hyper::Error> {
    let (sender, mut receiver) = mpsc::channel::<BoxFuture<'static, ()>>(8);
    let service = service_fn(move |request| {
        handle(
            request,
            Arc::clone(&settings),
            status.clone(),
            sender.clone(),
            connector.clone(),
            peer,
        )
    });
    let builder = hyper::server::conn::http1::Builder::new();
    let connection = builder
        .serve_connection(TokioIo::new(stream), service)
        .with_upgrades();
    tokio::pin!(connection);
    let mut tasks = JoinSet::new();
    let mut closed = false;
    loop {
        if closed && receiver.is_empty() && tasks.is_empty() {
            return Ok(());
        }
        tokio::select! {
            result = &mut connection, if !closed => {
                result?;
                closed = true;
            }
            Some(task) = receiver.recv(), if !closed || !receiver.is_empty() => { tasks.spawn(task); }
            Some(result) = tasks.join_next(), if !tasks.is_empty() => {
                if let Err(error) = result {
                    tracing::error!(%error, "HTTP proxy relay task failed");
                    return Ok(());
                }
            }
        }
    }
}

fn response(status: StatusCode, message: &'static str) -> Response<Body> {
    Response::builder()
        .status(status)
        .body(Body::from(message))
        .expect("valid proxy response")
}

fn authorized(request: &Request<Incoming>, settings: &HttpProxySettings) -> bool {
    if settings.user.is_empty() {
        return true;
    }
    let Some(encoded) = request
        .headers()
        .get(PROXY_AUTHORIZATION)
        .and_then(|header| header.to_str().ok())
        .and_then(|header| header.split_once(' '))
        .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("Basic"))
        .map(|(_, credentials)| credentials.trim_start_matches(' '))
    else {
        return false;
    };
    let Ok(actual) = base64::engine::general_purpose::STANDARD.decode(encoded) else {
        return false;
    };
    let expected = format!("{}:{}", settings.user.expose(), settings.password.expose());
    constant_time_equal(expected.as_bytes(), &actual)
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

fn strip_hop_headers(headers: &mut HeaderMap) {
    let named: Vec<HeaderName> = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|name| HeaderName::from_bytes(name.trim().as_bytes()).ok())
        .collect();
    for name in named {
        headers.remove(name);
    }
    for name in [
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ] {
        headers.remove(name);
    }
}

async fn handle(
    mut request: Request<Incoming>,
    settings: Arc<HttpProxySettings>,
    status: watch::Receiver<Status>,
    tasks: mpsc::Sender<BoxFuture<'static, ()>>,
    connector: TlsConnector,
    peer: SocketAddr,
) -> Result<Response<Body>, Infallible> {
    if !authorized(&request, &settings) {
        let mut response = response(
            StatusCode::PROXY_AUTHENTICATION_REQUIRED,
            "proxy authentication required",
        );
        response.headers_mut().insert(
            PROXY_AUTHENTICATE,
            "Basic realm=\"tune\"".parse().expect("valid header"),
        );
        return Ok(response);
    }
    if !matches!(&*status.borrow(), Status::Running(_)) {
        return Ok(response(
            StatusCode::SERVICE_UNAVAILABLE,
            "VPN is not running",
        ));
    }
    let Some(authority) = request.uri().authority().cloned() else {
        return Ok(response(
            StatusCode::BAD_REQUEST,
            "absolute URI or CONNECT host required",
        ));
    };
    let https = request.uri().scheme_str() == Some("https");
    if request.method() != Method::CONNECT
        && !matches!(request.uri().scheme_str(), Some("http" | "https"))
    {
        return Ok(response(
            StatusCode::BAD_REQUEST,
            "HTTP or HTTPS absolute URI required",
        ));
    }
    let port = authority
        .port_u16()
        .unwrap_or(if request.method() == Method::CONNECT || https {
            443
        } else {
            80
        });
    if port == 0 {
        return Ok(response(StatusCode::BAD_REQUEST, "invalid target port"));
    }
    if settings.log {
        tracing::info!(method = %request.method(), host = authority.host(), port, "HTTP proxy request");
    }
    let host = authority
        .host()
        .trim_start_matches('[')
        .trim_end_matches(']');
    let stream = match tokio::time::timeout(DIAL_TIMEOUT, TcpStream::connect((host, port))).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) => {
            tracing::debug!(%error, host = authority.host(), "HTTP proxy dial failed");
            return Ok(response(
                StatusCode::BAD_GATEWAY,
                "cannot connect to target",
            ));
        }
        Err(_) => return Ok(response(StatusCode::GATEWAY_TIMEOUT, "target timed out")),
    };
    if !matches!(&*status.borrow(), Status::Running(_)) {
        return Ok(response(
            StatusCode::SERVICE_UNAVAILABLE,
            "VPN is not running",
        ));
    }
    if request.method() == Method::CONNECT {
        let upgrade = hyper::upgrade::on(&mut request);
        if tasks
            .try_send(Box::pin(async move {
                let Ok(upgraded) = upgrade.await else {
                    return;
                };
                let mut client = TokioIo::new(upgraded);
                let mut remote = stream;
                let mut status = status;
                tokio::select! {
                    result = tokio::io::copy_bidirectional(&mut client, &mut remote) => {
                        if let Err(error) = result {
                            tracing::debug!(%error, "HTTP CONNECT tunnel closed");
                        }
                    }
                    () = until_stopped(&mut status) => {}
                }
            }))
            .is_err()
        {
            return Ok(response(
                StatusCode::SERVICE_UNAVAILABLE,
                "proxy relay capacity reached",
            ));
        }
        return Ok(response(StatusCode::OK, ""));
    }
    let stream: Box<dyn ProxyStream> = if https {
        let name = match rustls::pki_types::ServerName::try_from(host.to_owned()) {
            Ok(name) => name,
            Err(_) => return Ok(response(StatusCode::BAD_REQUEST, "invalid TLS server name")),
        };
        match tokio::time::timeout(DIAL_TIMEOUT, connector.connect(name, stream)).await {
            Ok(Ok(stream)) => Box::new(stream),
            Ok(Err(error)) => {
                tracing::debug!(%error, "HTTP proxy upstream TLS handshake failed");
                return Ok(response(
                    StatusCode::BAD_GATEWAY,
                    "upstream TLS handshake failed",
                ));
            }
            Err(_) => {
                return Ok(response(
                    StatusCode::GATEWAY_TIMEOUT,
                    "upstream TLS handshake timed out",
                ));
            }
        }
    } else {
        Box::new(stream)
    };
    let path = request
        .uri()
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");
    let uri = match path.parse::<Uri>() {
        Ok(uri) => uri,
        Err(_) => return Ok(response(StatusCode::BAD_REQUEST, "invalid request URI")),
    };
    *request.uri_mut() = uri;
    strip_hop_headers(request.headers_mut());
    if !settings.stealth {
        let forwarded = request
            .headers()
            .get("x-forwarded-for")
            .and_then(|value| value.to_str().ok())
            .map_or_else(
                || peer.ip().to_string(),
                |prior| format!("{prior},{}", peer.ip()),
            );
        if let Ok(value) = forwarded.parse() {
            request.headers_mut().insert("x-forwarded-for", value);
        }
    }
    request
        .headers_mut()
        .insert(HOST, authority.as_str().parse().expect("valid authority"));
    let (mut sender, connection) =
        match hyper::client::conn::http1::handshake(TokioIo::new(stream)).await {
            Ok(connection) => connection,
            Err(error) => {
                tracing::debug!(%error, "HTTP proxy upstream handshake failed");
                return Ok(response(
                    StatusCode::BAD_GATEWAY,
                    "upstream HTTP handshake failed",
                ));
            }
        };
    if tasks
        .try_send(Box::pin(async move {
            if let Err(error) = connection.await {
                tracing::debug!(%error, "HTTP proxy upstream disconnected");
            }
        }))
        .is_err()
    {
        return Ok(response(
            StatusCode::SERVICE_UNAVAILABLE,
            "proxy relay capacity reached",
        ));
    }
    match sender.send_request(request).await {
        Ok(mut response) => {
            strip_hop_headers(response.headers_mut());
            Ok(response.map(Body::new))
        }
        Err(error) => {
            tracing::debug!(%error, "HTTP proxy upstream request failed");
            Ok(response(StatusCode::BAD_GATEWAY, "upstream request failed"))
        }
    }
}

trait ProxyStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> ProxyStream for T {}

async fn until_stopped(status: &mut watch::Receiver<Status>) {
    loop {
        if status.changed().await.is_err()
            || !matches!(&*status.borrow_and_update(), Status::Running(_))
        {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn authenticated_settings() -> HttpProxySettings {
        let mut settings = settings();
        settings.listen_address = "127.0.0.1:0".parse().expect("address");
        settings.user = crate::config::Secret::new("browser");
        settings.password = crate::config::Secret::new("secret:value");
        settings
    }

    #[tokio::test]
    async fn authentication_protects_http_and_connect_without_dialing_origin() {
        let origin = TcpListener::bind("127.0.0.1:0").await.expect("origin");
        let target = origin.local_addr().expect("address");
        let server = Server::bind(authenticated_settings()).await.expect("proxy");
        let address = server.listener.local_addr().expect("address");
        let (status, receiver) = watch::channel(running());
        let task = tokio::spawn(server.run(receiver));
        for method in ["GET", "CONNECT"] {
            for authorization in [
                "",
                "Basic invalid!",
                "Bearer token",
                "Basic YnJvd3Nlcjp3cm9uZw==",
            ] {
                let mut client = TcpStream::connect(address).await.expect("client");
                let uri = if method == "CONNECT" {
                    target.to_string()
                } else {
                    format!("http://{target}/")
                };
                client.write_all(format!("{method} {uri} HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: {authorization}\r\nConnection: close\r\n\r\n").as_bytes()).await.expect("request");
                let response = String::from_utf8(read_header(&mut client).await).expect("headers");
                assert!(response.starts_with("HTTP/1.1 407"), "{response}");
                assert!(
                    response
                        .to_ascii_lowercase()
                        .contains("proxy-authenticate: basic")
                );
                assert!(!response.contains("secret"));
            }
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(50), origin.accept())
                .await
                .is_err()
        );
        drop(status);
        within(task).await.expect("joined").expect("stopped");
    }

    #[tokio::test]
    async fn authenticated_http_and_connect_relay_without_leaking_proxy_credentials() {
        for connect in [false, true] {
            let origin = TcpListener::bind("127.0.0.1:0").await.expect("origin");
            let target = origin.local_addr().expect("address");
            let server = Server::bind(authenticated_settings()).await.expect("proxy");
            let address = server.listener.local_addr().expect("address");
            let (status, receiver) = watch::channel(running());
            let task = tokio::spawn(server.run(receiver));
            let mut client = TcpStream::connect(address).await.expect("client");
            let credentials =
                base64::engine::general_purpose::STANDARD.encode("browser:secret:value");
            let request = if connect {
                format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n")
            } else {
                format!("GET http://{target}/hello HTTP/1.1\r\nHost: {target}\r\n")
            };
            client
                .write_all(
                    format!("{request}Proxy-Authorization: bAsIc {credentials}\r\n\r\n").as_bytes(),
                )
                .await
                .expect("request");
            let (mut upstream, _) = within(origin.accept()).await.expect("upstream");
            if connect {
                assert!(read_header(&mut client).await.starts_with(b"HTTP/1.1 200"));
                client.write_all(b"hello").await.expect("payload");
                let mut payload = [0u8; 5];
                within(upstream.read_exact(&mut payload))
                    .await
                    .expect("payload");
                assert_eq!(&payload, b"hello");
            } else {
                let request = String::from_utf8(read_header(&mut upstream).await).expect("headers");
                assert!(request.starts_with("GET /hello HTTP/1.1"));
                assert!(!request.to_ascii_lowercase().contains("proxy-authorization"));
                assert!(!request.contains(&credentials));
                upstream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                    .await
                    .expect("response");
                assert!(read_header(&mut client).await.starts_with(b"HTTP/1.1 200"));
            }
            drop(status);
            within(task).await.expect("joined").expect("stopped");
        }
    }

    #[tokio::test]
    async fn bind_rejects_incomplete_http_credentials() {
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
                .expect("partial credentials");
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        }
    }

    async fn within<F: std::future::Future>(future: F) -> F::Output {
        tokio::time::timeout(Duration::from_secs(3), future)
            .await
            .expect("completed in time")
    }

    async fn read_header(stream: &mut TcpStream) -> Vec<u8> {
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            header.push(within(stream.read_u8()).await.expect("header byte"));
            assert!(header.len() < 8192);
        }
        header
    }

    #[tokio::test]
    async fn stealth_controls_forwarded_headers() {
        for stealth in [false, true] {
            let origin = TcpListener::bind("127.0.0.1:0").await.expect("origin");
            let target = origin.local_addr().expect("address");
            let mut settings = settings();
            settings.listen_address = "127.0.0.1:0".parse().expect("address");
            settings.stealth = stealth;
            let server = Server::bind(settings).await.expect("proxy");
            let address = server.listener.local_addr().expect("address");
            let (_status, receiver) = watch::channel(running());
            let task = tokio::spawn(server.run(receiver));
            let mut client = TcpStream::connect(address).await.expect("client");
            client.write_all(format!("GET http://{target}/ HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n").as_bytes()).await.expect("request");
            let (mut upstream, _) = within(origin.accept()).await.expect("accept");
            let headers = String::from_utf8(read_header(&mut upstream).await)
                .expect("headers")
                .to_ascii_lowercase();
            assert_eq!(headers.contains("x-forwarded-for: 127.0.0.1\r\n"), !stealth);
            task.abort();
            let _ = task.await;
        }
    }

    #[tokio::test]
    async fn https_absolute_uri_requires_an_authenticated_tls_connection() {
        let origin = TcpListener::bind("127.0.0.1:0").await.expect("origin");
        let target = origin.local_addr().expect("address");
        let mut settings = settings();
        settings.listen_address = "127.0.0.1:0".parse().expect("address");
        let server = Server::bind(settings).await.expect("proxy");
        let address = server.listener.local_addr().expect("address");
        let (_status, receiver) = watch::channel(running());
        let task = tokio::spawn(server.run(receiver));
        let mut client = TcpStream::connect(address).await.expect("client");
        client
            .write_all(
                format!(
                    "GET https://{target}/ HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .expect("request");
        let (mut upstream, _) = within(origin.accept()).await.expect("TLS connection");
        let mut hello = [0u8; 5];
        within(upstream.read_exact(&mut hello))
            .await
            .expect("TLS record");
        assert_eq!(hello[0], 22);
        upstream
            .write_all(b"HTTP/1.1 200 OK\r\n\r\n")
            .await
            .expect("invalid TLS response");
        assert!(read_header(&mut client).await.starts_with(b"HTTP/1.1 502"));
        task.abort();
        let _ = task.await;
    }

    #[test]
    fn removes_hop_headers_and_connection_nominated_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(CONNECTION, "keep-alive, x-private".parse().expect("header"));
        headers.insert("x-private", "secret".parse().expect("header"));
        headers.insert("keep-alive", "timeout=10".parse().expect("header"));
        headers.insert(PROXY_AUTHORIZATION, "Basic secret".parse().expect("header"));
        headers.insert("content-type", "text/plain".parse().expect("header"));
        strip_hop_headers(&mut headers);
        assert_eq!(headers.len(), 1);
        assert!(headers.contains_key("content-type"));
    }

    #[tokio::test]
    async fn streaming_http_and_connect_close_on_tunnel_change_and_server_abort() {
        for connect in [false, true] {
            for abort in [false, true] {
                let origin = TcpListener::bind("127.0.0.1:0").await.expect("origin");
                let target = origin.local_addr().expect("target");
                let mut settings = settings();
                settings.listen_address = "127.0.0.1:0".parse().expect("address");
                let server = Server::bind(settings).await.expect("proxy");
                let address = server.listener.local_addr().expect("address");
                let (status, receiver) = watch::channel(running());
                let mut task = tokio::spawn(server.run(receiver));
                let mut client = TcpStream::connect(address).await.expect("client");
                let request = if connect {
                    format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n")
                } else {
                    format!("GET http://{target}/stream HTTP/1.1\r\nHost: {target}\r\n\r\n")
                };
                client.write_all(request.as_bytes()).await.expect("request");
                let (mut upstream, _) = within(origin.accept()).await.expect("upstream");
                if !connect {
                    read_header(&mut upstream).await;
                    upstream
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 10000\r\n\r\n")
                        .await
                        .expect("streaming response");
                }
                assert!(read_header(&mut client).await.starts_with(b"HTTP/1.1 200"));
                upstream.write_all(b"hello").await.expect("payload");
                let mut buffer = [0u8; 5];
                within(client.read_exact(&mut buffer))
                    .await
                    .expect("streamed payload");
                assert_eq!(&buffer, b"hello");
                if abort {
                    task.abort();
                    assert!((&mut task).await.expect_err("aborted").is_cancelled());
                } else {
                    status.send_replace(Status::Stopped);
                }
                assert_eq!(
                    within(upstream.read(&mut buffer))
                        .await
                        .expect("upstream EOF"),
                    0
                );
                assert_eq!(
                    within(client.read(&mut buffer)).await.expect("client EOF"),
                    0
                );
                if !abort {
                    drop(status);
                    within(task).await.expect("joined").expect("stopped");
                }
            }
        }
    }

    fn settings() -> HttpProxySettings {
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
        .http_proxy
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

    #[test]
    fn compares_credentials_without_truncation() {
        assert!(constant_time_equal(b"a:b", b"a:b"));
        assert!(!constant_time_equal(b"a:b", b"a:c"));
        assert!(!constant_time_equal(b"a:b", b"a:b:extra"));
    }

    #[tokio::test]
    async fn refuses_http_proxy_when_vpn_is_down() {
        let mut settings = settings();
        settings.listen_address = "127.0.0.1:0".parse().expect("address");
        let server = Server::bind(settings).await.expect("proxy");
        let address = server.listener.local_addr().expect("address");
        let (_status, receiver) = watch::channel(Status::Stopped);
        let task = tokio::spawn(server.run(receiver));
        let mut client = TcpStream::connect(address).await.expect("client");
        client.write_all(b"GET http://127.0.0.1:80/ HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
            .await.expect("request");
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), client.read_to_end(&mut response))
            .await
            .expect("response")
            .expect("read");
        assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 503"));
        task.abort();
    }

    #[tokio::test]
    async fn connects_and_relays_http_connect() {
        let echo = TcpListener::bind("127.0.0.1:0").await.expect("echo");
        let target = echo.local_addr().expect("target");
        let echo_task = tokio::spawn(async move {
            let (mut stream, _) = echo.accept().await.expect("accept");
            let mut bytes = [0u8; 5];
            stream.read_exact(&mut bytes).await.expect("read");
            stream.write_all(&bytes).await.expect("reply");
        });
        let mut settings = settings();
        settings.listen_address = "127.0.0.1:0".parse().expect("address");
        let server = Server::bind(settings).await.expect("proxy");
        let address = server.listener.local_addr().expect("address");
        let (status, receiver) = watch::channel(running());
        let task = tokio::spawn(server.run(receiver));
        let mut client = TcpStream::connect(address).await.expect("client");
        client
            .write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
            .await
            .expect("CONNECT");
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            header.push(
                tokio::time::timeout(Duration::from_secs(2), client.read_u8())
                    .await
                    .expect("response")
                    .expect("read"),
            );
        }
        assert!(String::from_utf8_lossy(&header).starts_with("HTTP/1.1 200"));
        client.write_all(b"hello").await.expect("payload");
        let mut response = [0u8; 5];
        client.read_exact(&mut response).await.expect("echo");
        assert_eq!(&response, b"hello");
        status.send_replace(Status::Stopped);
        echo_task.await.expect("echo task");
        task.abort();
    }

    #[tokio::test]
    async fn forwards_absolute_uri_without_proxy_credentials() {
        let origin = TcpListener::bind("127.0.0.1:0").await.expect("origin");
        let target = origin.local_addr().expect("address");
        let origin_task = tokio::spawn(async move {
            let (mut stream, _) = origin.accept().await.expect("accept");
            let mut request = [0u8; 1024];
            let length = stream.read(&mut request).await.expect("read");
            let request = String::from_utf8_lossy(&request[..length]);
            assert!(request.starts_with("GET /hello HTTP/1.1\r\n"), "{request}");
            assert!(!request.to_ascii_lowercase().contains("proxy-authorization"));
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
                )
                .await
                .expect("respond");
        });
        let mut settings = settings();
        settings.listen_address = "127.0.0.1:0".parse().expect("address");
        let server = Server::bind(settings).await.expect("proxy");
        let address = server.listener.local_addr().expect("address");
        let (_status, receiver) = watch::channel(running());
        let task = tokio::spawn(server.run(receiver));
        let mut client = TcpStream::connect(address).await.expect("client");
        client.write_all(format!("GET http://{target}/hello HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: Basic dGVzdA==\r\nConnection: close\r\n\r\n").as_bytes())
            .await.expect("send");
        let mut bytes = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), client.read_to_end(&mut bytes))
            .await
            .expect("response")
            .expect("read");
        let response = String::from_utf8_lossy(&bytes);
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(response.ends_with("hello"), "{response}");
        origin_task.await.expect("origin task");
        task.abort();
    }
}
