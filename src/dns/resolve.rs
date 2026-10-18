use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use hickory_proto::op::{Message, MessageType};
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio_rustls::TlsConnector;

use crate::config::DnsSettings;
use crate::dns::upstream::UpstreamType;

const TIMEOUT: Duration = Duration::from_secs(6);
const MAX_RESPONSE: usize = u16::MAX as usize;

#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    #[error("no DNS upstreams configured")]
    NoUpstreams,
    #[error("DNS request encoding: {0}")]
    Encode(String),
    #[error("DNS upstream I/O: {0}")]
    Io(#[from] io::Error),
    #[error("DNS upstream HTTP: {0}")]
    Http(#[from] reqwest::Error),
    #[error("DNS upstream returned an invalid response")]
    InvalidResponse,
    #[error("DNS upstream timed out")]
    Timeout,
}

#[derive(Clone)]
struct Endpoint {
    address: SocketAddr,
    tls_name: &'static str,
    doh_url: String,
    http: Option<reqwest::Client>,
}

#[derive(Clone)]
pub struct Resolver {
    kind: UpstreamType,
    endpoints: Vec<Endpoint>,
    connector: TlsConnector,
}

impl Resolver {
    pub fn new(settings: &DnsSettings, connector: TlsConnector) -> Result<Self, ResolveError> {
        let mut endpoints = Vec::new();
        if settings.upstream_type == UpstreamType::Plain
            && !settings.upstream_plain_addresses.is_empty()
        {
            for address in &settings.upstream_plain_addresses {
                if address.is_ipv6() == settings.ipv6 {
                    endpoints.push(Endpoint {
                        address: *address,
                        tls_name: "",
                        doh_url: String::new(),
                        http: None,
                    });
                }
            }
        } else {
            for preset in &settings.providers {
                let server = preset.server();
                let ips: Vec<IpAddr> = if settings.ipv6 {
                    server.ipv6.into_iter().map(IpAddr::V6).collect()
                } else {
                    server.ipv4.into_iter().map(IpAddr::V4).collect()
                };
                for ip in ips {
                    if endpoints.iter().any(|endpoint: &Endpoint| {
                        endpoint.address.ip() == ip && endpoint.tls_name == server.tls_name
                    }) {
                        continue;
                    }
                    let port = match settings.upstream_type {
                        UpstreamType::Plain => 53,
                        UpstreamType::Dot => 853,
                        UpstreamType::Doh => 443,
                    };
                    let http = if settings.upstream_type == UpstreamType::Doh {
                        Some(
                            reqwest::Client::builder()
                                .no_proxy()
                                .redirect(reqwest::redirect::Policy::none())
                                .resolve(server.tls_name, SocketAddr::new(ip, 443))
                                .timeout(TIMEOUT)
                                .build()?,
                        )
                    } else {
                        None
                    };
                    endpoints.push(Endpoint {
                        address: SocketAddr::new(ip, port),
                        tls_name: server.tls_name,
                        doh_url: preset.doh_url(),
                        http,
                    });
                }
            }
        }
        if endpoints.is_empty() {
            return Err(ResolveError::NoUpstreams);
        }
        Ok(Self {
            kind: settings.upstream_type,
            endpoints,
            connector,
        })
    }

    pub async fn query(&self, request: &Message) -> Result<Message, ResolveError> {
        let bytes = request
            .to_vec()
            .map_err(|error| ResolveError::Encode(error.to_string()))?;
        let mut last = ResolveError::NoUpstreams;
        for endpoint in &self.endpoints {
            let result = tokio::time::timeout(TIMEOUT, self.query_one(endpoint, &bytes)).await;
            let response = match result {
                Ok(Ok(response)) => response,
                Ok(Err(error)) => {
                    last = error;
                    continue;
                }
                Err(_) => {
                    last = ResolveError::Timeout;
                    continue;
                }
            };
            let Ok(message) = Message::from_vec(&response) else {
                last = ResolveError::InvalidResponse;
                continue;
            };
            if message.metadata.message_type != MessageType::Response
                || message.metadata.id != request.metadata.id
                || message.queries != request.queries
            {
                last = ResolveError::InvalidResponse;
                continue;
            }
            return Ok(message);
        }
        Err(last)
    }

    async fn query_one(
        &self,
        endpoint: &Endpoint,
        request: &[u8],
    ) -> Result<Vec<u8>, ResolveError> {
        match self.kind {
            UpstreamType::Plain => {
                let local = if endpoint.address.is_ipv6() {
                    SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
                } else {
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
                };
                let socket = UdpSocket::bind(local).await?;
                socket.connect(endpoint.address).await?;
                socket.send(request).await?;
                let mut buffer = vec![0; MAX_RESPONSE];
                let count = socket.recv(&mut buffer).await?;
                buffer.truncate(count);
                if Message::from_vec(&buffer).is_ok_and(|message| message.metadata.truncation) {
                    return self.query_tcp(endpoint, request).await;
                }
                Ok(buffer)
            }
            UpstreamType::Dot => {
                let stream = TcpStream::connect(endpoint.address).await?;
                let name = ServerName::try_from(endpoint.tls_name.to_owned())
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
                let mut stream = self.connector.connect(name, stream).await?;
                exchange(&mut stream, request).await.map_err(Into::into)
            }
            UpstreamType::Doh => {
                let client = endpoint.http.as_ref().ok_or(ResolveError::NoUpstreams)?;
                let response = client
                    .post(&endpoint.doh_url)
                    .header(reqwest::header::CONTENT_TYPE, "application/dns-message")
                    .header(reqwest::header::ACCEPT, "application/dns-message")
                    .body(request.to_vec())
                    .send()
                    .await?
                    .error_for_status()?;
                if response
                    .headers()
                    .get(reqwest::header::CONTENT_TYPE)
                    .is_none_or(|value| !value.as_bytes().starts_with(b"application/dns-message"))
                {
                    return Err(ResolveError::InvalidResponse);
                }
                let data = response.bytes().await?;
                if data.len() > MAX_RESPONSE {
                    return Err(ResolveError::InvalidResponse);
                }
                Ok(data.to_vec())
            }
        }
    }

    async fn query_tcp(
        &self,
        endpoint: &Endpoint,
        request: &[u8],
    ) -> Result<Vec<u8>, ResolveError> {
        let mut stream = TcpStream::connect(endpoint.address).await?;
        exchange(&mut stream, request).await.map_err(Into::into)
    }
}

async fn exchange<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    stream: &mut S,
    request: &[u8],
) -> io::Result<Vec<u8>> {
    let length = u16::try_from(request.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "DNS request is too large"))?;
    stream.write_all(&length.to_be_bytes()).await?;
    stream.write_all(request).await?;
    let length = stream.read_u16().await?;
    if length < 12 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "short DNS response",
        ));
    }
    let mut response = vec![0; usize::from(length)];
    stream.read_exact(&mut response).await?;
    Ok(response)
}
