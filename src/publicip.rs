use std::fmt;
use std::net::IpAddr;
use std::path::Path;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize, Serializer};
use tracing::{info, warn};

use crate::config::{PublicIpSettings, Secret};

const FETCH_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PublicIpApi {
    Ipinfo,
    Ifconfigco,
    Ip2location,
    Cloudflare,
}

impl PublicIpApi {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Ipinfo => "ipinfo",
            Self::Ifconfigco => "ifconfigco",
            Self::Ip2location => "ip2location",
            Self::Cloudflare => "cloudflare",
        }
    }
}

impl fmt::Display for PublicIpApi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for PublicIpApi {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "ipinfo" => Ok(Self::Ipinfo),
            "ifconfigco" | "ifconfig.co" => Ok(Self::Ifconfigco),
            "ip2location" => Ok(Self::Ip2location),
            "cloudflare" => Ok(Self::Cloudflare),
            other => Err(format!(
                "unknown public IP API {other:?}: expected ipinfo, ifconfigco, ip2location or cloudflare"
            )),
        }
    }
}

impl Serialize for PublicIpApi {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.name())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct PublicIp {
    pub public_ip: Option<IpAddr>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub region: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub country: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub city: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub hostname: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub location: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub organization: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub postal_code: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub timezone: String,
}

#[derive(Debug, thiserror::Error)]
pub enum PublicIpError {
    #[error("{api}: too many requests")]
    TooManyRequests { api: PublicIpApi },
    #[error("{api}: bad HTTP status {status}")]
    Status {
        api: PublicIpApi,
        status: StatusCode,
    },
    #[error("{api}: {source}")]
    Http {
        api: PublicIpApi,
        #[source]
        source: reqwest::Error,
    },
    #[error("{api}: response has no IP address")]
    NoIp { api: PublicIpApi },
    #[error("all public IP APIs failed: {0}")]
    AllFailed(String),
    #[error("writing public IP file: {0}")]
    File(#[from] std::io::Error),
}

#[derive(Deserialize)]
struct IpinfoResponse {
    ip: Option<IpAddr>,
    #[serde(default)]
    region: String,
    #[serde(default)]
    country: String,
    #[serde(default)]
    city: String,
    #[serde(default)]
    hostname: String,
    #[serde(default)]
    loc: String,
    #[serde(default)]
    org: String,
    #[serde(default)]
    postal: String,
    #[serde(default)]
    timezone: String,
}

#[derive(Deserialize)]
struct EchoipResponse {
    ip: Option<IpAddr>,
    #[serde(default)]
    country: String,
    #[serde(default)]
    region_name: String,
    #[serde(default)]
    zip_code: String,
    #[serde(default)]
    city: String,
    latitude: Option<f64>,
    longitude: Option<f64>,
    #[serde(default)]
    hostname: String,
    #[serde(default)]
    time_zone: String,
    #[serde(default)]
    asn_org: String,
}

#[derive(Deserialize)]
struct Ip2locationResponse {
    ip: Option<IpAddr>,
    #[serde(default)]
    country_name: String,
    #[serde(default)]
    region_name: String,
    #[serde(default)]
    city_name: String,
    latitude: Option<f64>,
    longitude: Option<f64>,
    #[serde(default)]
    zip_code: String,
    #[serde(default)]
    time_zone: String,
    #[serde(default, rename = "as")]
    autonomous_system: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CloudflareResponse {
    #[serde(default)]
    hostname: String,
    client_ip: Option<IpAddr>,
    #[serde(default)]
    as_organization: String,
    #[serde(default)]
    country: String,
    #[serde(default)]
    city: String,
    #[serde(default)]
    region: String,
    #[serde(default)]
    postal_code: String,
    #[serde(default)]
    latitude: String,
    #[serde(default)]
    longitude: String,
}

fn coords(latitude: Option<f64>, longitude: Option<f64>) -> String {
    match (latitude, longitude) {
        (Some(lat), Some(lon)) => format!("{lat},{lon}"),
        _ => String::new(),
    }
}

pub struct Fetcher {
    client: Client,
    apis: Vec<PublicIpApi>,
    token: Secret,
    banned: Mutex<Vec<PublicIpApi>>,
}

impl Fetcher {
    pub fn new(client: Client, apis: Vec<PublicIpApi>, token: Secret) -> Self {
        Self {
            client,
            apis,
            token,
            banned: Mutex::new(Vec::new()),
        }
    }

    pub async fn fetch(&self) -> Result<PublicIp, PublicIpError> {
        let mut errors = Vec::new();
        let banned = self
            .banned
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let mut candidates: Vec<PublicIpApi> = self
            .apis
            .iter()
            .copied()
            .filter(|api| !banned.contains(api))
            .collect();
        if candidates.is_empty() {
            self.banned
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clear();
            candidates.clone_from(&self.apis);
        }
        for api in candidates {
            match self.fetch_one(api).await {
                Ok(result) => return Ok(result),
                Err(err) => {
                    if matches!(err, PublicIpError::TooManyRequests { .. }) {
                        self.banned
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .push(api);
                    }
                    errors.push(err.to_string());
                }
            }
        }
        Err(PublicIpError::AllFailed(errors.join("; ")))
    }

    async fn get<T: for<'de> Deserialize<'de>>(
        &self,
        api: PublicIpApi,
        request: reqwest::RequestBuilder,
    ) -> Result<T, PublicIpError> {
        let response = request
            .timeout(FETCH_TIMEOUT)
            .send()
            .await
            .map_err(|source| PublicIpError::Http { api, source })?;
        match response.status() {
            StatusCode::OK => {}
            StatusCode::TOO_MANY_REQUESTS => return Err(PublicIpError::TooManyRequests { api }),
            status => return Err(PublicIpError::Status { api, status }),
        }
        response
            .json::<T>()
            .await
            .map_err(|source| PublicIpError::Http { api, source })
    }

    async fn fetch_one(&self, api: PublicIpApi) -> Result<PublicIp, PublicIpError> {
        let token = self.token.expose();
        let result = match api {
            PublicIpApi::Ipinfo => {
                let mut request = self.client.get("https://ipinfo.io/");
                if !token.is_empty() {
                    request = request.bearer_auth(token);
                }
                let data: IpinfoResponse = self.get(api, request).await?;
                PublicIp {
                    public_ip: data.ip,
                    region: data.region,
                    country: data.country,
                    city: data.city,
                    hostname: data.hostname,
                    location: data.loc,
                    organization: data.org,
                    postal_code: data.postal,
                    timezone: data.timezone,
                }
            }
            PublicIpApi::Ifconfigco => {
                let request = self.client.get("https://ifconfig.co/json");
                let data: EchoipResponse = self.get(api, request).await?;
                PublicIp {
                    public_ip: data.ip,
                    region: data.region_name,
                    country: data.country,
                    city: data.city,
                    hostname: data.hostname,
                    location: coords(data.latitude, data.longitude),
                    organization: data.asn_org,
                    postal_code: data.zip_code,
                    timezone: data.time_zone,
                }
            }
            PublicIpApi::Ip2location => {
                let mut request = self.client.get("https://api.ip2location.io/");
                if !token.is_empty() {
                    request = request.query(&[("key", token)]);
                }
                let data: Ip2locationResponse = self.get(api, request).await?;
                PublicIp {
                    public_ip: data.ip,
                    region: data.region_name,
                    country: data.country_name,
                    city: data.city_name,
                    hostname: String::new(),
                    location: coords(data.latitude, data.longitude),
                    organization: data.autonomous_system,
                    postal_code: data.zip_code,
                    timezone: data.time_zone,
                }
            }
            PublicIpApi::Cloudflare => {
                let request = self
                    .client
                    .get("https://speed.cloudflare.com/meta")
                    .header(reqwest::header::REFERER, "https://speed.cloudflare.com");
                let data: CloudflareResponse = self.get(api, request).await?;
                let location = if data.latitude.is_empty() {
                    String::new()
                } else {
                    format!("{},{}", data.latitude, data.longitude)
                };
                PublicIp {
                    public_ip: data.client_ip,
                    region: data.region,
                    country: data.country,
                    city: data.city,
                    hostname: data.hostname,
                    location,
                    organization: data.as_organization,
                    postal_code: data.postal_code,
                    timezone: String::new(),
                }
            }
        };
        if result.public_ip.is_none() {
            return Err(PublicIpError::NoIp { api });
        }
        Ok(result)
    }
}

#[derive(Clone)]
pub struct PublicIpService {
    settings: PublicIpSettings,
    fetcher: Arc<Fetcher>,
    current: Arc<Mutex<PublicIp>>,
    owner: (u32, u32),
}

impl PublicIpService {
    pub fn new(settings: PublicIpSettings, client: Client, owner: (u32, u32)) -> Self {
        let fetcher = Fetcher::new(client, settings.apis.clone(), settings.token.clone());
        Self {
            settings,
            fetcher: Arc::new(fetcher),
            current: Arc::new(Mutex::new(PublicIp::default())),
            owner,
        }
    }

    pub fn current(&self) -> PublicIp {
        self.current
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    pub async fn refresh(&self) {
        if !self.settings.enabled {
            return;
        }
        const ATTEMPTS: u32 = 3;
        for attempt in 1..=ATTEMPTS {
            match self.fetcher.fetch().await {
                Ok(result) => {
                    let ip = result
                        .public_ip
                        .map(|ip| ip.to_string())
                        .unwrap_or_default();
                    info!(
                        public_ip = %ip,
                        country = %result.country,
                        region = %result.region,
                        city = %result.city,
                        organization = %result.organization,
                        "public IP address fetched"
                    );
                    if let Some(path) = &self.settings.file
                        && let Err(err) = write_owned(path, ip.as_bytes(), self.owner)
                    {
                        warn!(error = %err, path = %path.display(), "writing public IP file");
                    }
                    *self
                        .current
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = result;
                    return;
                }
                Err(err) => {
                    warn!(error = %err, attempt, "fetching public IP address");
                    tokio::time::sleep(Duration::from_secs(u64::from(attempt) * 2)).await;
                }
            }
        }
    }

    pub fn clear(&self) {
        *self
            .current
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = PublicIp::default();
        if let Some(path) = &self.settings.file
            && let Err(err) = std::fs::remove_file(path)
            && err.kind() != std::io::ErrorKind::NotFound
        {
            warn!(error = %err, path = %path.display(), "removing public IP file");
        }
    }
}

pub fn write_owned(path: &Path, content: &[u8], (uid, gid): (u32, u32)) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, content)?;
    let metadata = std::fs::metadata(path)?;
    if metadata.uid() == uid && metadata.gid() == gid {
        Ok(())
    } else {
        std::os::unix::fs::chown(path, Some(uid), Some(gid))
    }
}
