use std::io;
use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tokio::sync::watch;

use crate::config::{ControlSettings, Settings};
use crate::publicip::{PublicIp, PublicIpService};
use crate::routing::Ipv6Support;
use crate::storage::Storage;
use crate::vpn::{Desired, Status};

pub mod auth;
pub mod lifecycle;
mod vpnsettings;

#[derive(Clone)]
pub struct Components {
    pub dns: Option<lifecycle::Controller>,
    pub updater: lifecycle::Controller,
}

#[derive(Serialize)]
struct Version {
    version: &'static str,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
enum VpnState {
    Stopped,
    Starting,
    Running,
    Stopping,
    Crashed,
}

impl From<&Status> for VpnState {
    fn from(value: &Status) -> Self {
        match value {
            Status::Stopped => Self::Stopped,
            Status::Starting => Self::Starting,
            Status::Running(_) => Self::Running,
            Status::Stopping => Self::Stopping,
            Status::Crashed => Self::Crashed,
        }
    }
}

#[derive(Serialize)]
struct StatusResponse {
    status: VpnState,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum RequestedState {
    Running,
    Stopped,
}

#[derive(Deserialize)]
struct StatusRequest {
    status: RequestedState,
}

#[derive(Serialize)]
struct Outcome {
    outcome: &'static str,
}

struct ControlState {
    settings: watch::Sender<Arc<Settings>>,
    public_ip: PublicIpService,
    desired: watch::Sender<Desired>,
    status: watch::Receiver<Status>,
    components: Components,
    storage: Storage,
    ipv6: Ipv6Support,
    settings_lock: tokio::sync::Mutex<()>,
}

fn constant_time_equal(expected: &str, provided: &str) -> bool {
    if expected.len() != provided.len() {
        return false;
    }
    expected
        .as_bytes()
        .iter()
        .zip(provided.as_bytes())
        .fold(0u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

async fn auth(
    State(config): State<Arc<ControlSettings>>,
    request: Request,
    next: Next,
) -> Response {
    if config.auth.authorized(
        request.method(),
        request.uri(),
        request.headers(),
        &config.api_key,
    ) {
        next.run(request).await
    } else {
        (
            StatusCode::UNAUTHORIZED,
            [("www-authenticate", "Basic realm=\"tune\"")],
            "authentication required",
        )
            .into_response()
    }
}

async fn version() -> Json<Version> {
    Json(Version {
        version: env!("CARGO_PKG_VERSION"),
    })
}

async fn vpn_status(State(state): State<Arc<ControlState>>) -> Json<StatusResponse> {
    Json(StatusResponse {
        status: VpnState::from(&*state.status.borrow()),
    })
}

async fn vpn_set_status(
    State(state): State<Arc<ControlState>>,
    Json(request): Json<StatusRequest>,
) -> Json<Outcome> {
    let desired = match request.status {
        RequestedState::Running => Desired::Running,
        RequestedState::Stopped => Desired::Stopped,
    };
    state.desired.send_replace(desired);
    Json(Outcome {
        outcome: "VPN state change requested",
    })
}

async fn vpn_settings(State(state): State<Arc<ControlState>>) -> Json<vpnsettings::View> {
    Json(vpnsettings::View::from(state.settings.borrow().as_ref()))
}

async fn vpn_set_settings(
    State(state): State<Arc<ControlState>>,
    Json(patch): Json<vpnsettings::Patch>,
) -> Response {
    let _guard = state.settings_lock.lock().await;
    let current = Arc::clone(&state.settings.borrow());
    let updated = match patch.apply(&current) {
        Ok(settings) => settings,
        Err(error) => return (StatusCode::BAD_REQUEST, error).into_response(),
    };
    if let Err(error) = updated.validate() {
        return (StatusCode::BAD_REQUEST, error.to_string()).into_response();
    }
    if !state.ipv6.is_supported()
        && updated
            .wireguard
            .addresses
            .iter()
            .all(ipnetwork::IpNetwork::is_ipv6)
    {
        return (
            StatusCode::BAD_REQUEST,
            "IPv6-only addresses require IPv6 support",
        )
            .into_response();
    }
    if let Err(error) = crate::provider::get_connection(
        &state.storage.servers(updated.provider),
        &updated.selection,
        updated.provider.default_wireguard_port(),
        state.ipv6 == Ipv6Support::Internet,
        &crate::provider::ConnectionPicker::default(),
    ) {
        return (StatusCode::BAD_REQUEST, error.to_string()).into_response();
    }
    if *current == updated {
        return "settings left unchanged".into_response();
    }
    if state.desired.is_closed() {
        return (StatusCode::SERVICE_UNAVAILABLE, "VPN loop is unavailable").into_response();
    }
    state.settings.send_replace(Arc::new(updated));
    state.desired.send_replace(Desired::Restart);
    "settings updated; VPN restart requested".into_response()
}

async fn public_ip_handler(State(state): State<Arc<ControlState>>) -> Json<PublicIp> {
    Json(state.public_ip.current())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ComponentStatus {
    status: lifecycle::State,
}

async fn dns_status(State(state): State<Arc<ControlState>>) -> Json<ComponentStatus> {
    Json(ComponentStatus {
        status: state
            .components
            .dns
            .as_ref()
            .map_or(lifecycle::State::Stopped, lifecycle::Controller::state),
    })
}

async fn updater_status(State(state): State<Arc<ControlState>>) -> Json<ComponentStatus> {
    Json(ComponentStatus {
        status: state.components.updater.state(),
    })
}

fn component_error(error: lifecycle::Error) -> Response {
    let code = match error {
        lifecycle::Error::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        lifecycle::Error::Timeout => StatusCode::GATEWAY_TIMEOUT,
    };
    (code, error.to_string()).into_response()
}

async fn set_component(
    controller: Option<&lifecycle::Controller>,
    requested: lifecycle::State,
    restart: bool,
) -> Response {
    let Some(controller) = controller else {
        return (
            StatusCode::CONFLICT,
            "DNS server is disabled in configuration",
        )
            .into_response();
    };
    match controller.apply(requested, restart).await {
        Ok(()) => Json(Outcome {
            outcome: "service state change applied",
        })
        .into_response(),
        Err(error) => component_error(error),
    }
}

async fn dns_set_status(
    State(state): State<Arc<ControlState>>,
    Json(request): Json<ComponentStatus>,
) -> Response {
    set_component(state.components.dns.as_ref(), request.status, false).await
}

async fn updater_set_status(
    State(state): State<Arc<ControlState>>,
    Json(request): Json<ComponentStatus>,
) -> Response {
    set_component(Some(&state.components.updater), request.status, false).await
}

async fn dns_restart(State(state): State<Arc<ControlState>>) -> Response {
    set_component(
        state.components.dns.as_ref(),
        lifecycle::State::Running,
        true,
    )
    .await
}

async fn updater_restart(State(state): State<Arc<ControlState>>) -> Response {
    set_component(
        Some(&state.components.updater),
        lifecycle::State::Running,
        true,
    )
    .await
}

async fn legacy_version() -> axum::response::Redirect {
    axum::response::Redirect::permanent("/v1/version")
}

pub struct Runtime {
    pub settings: watch::Sender<Arc<Settings>>,
    pub public_ip: PublicIpService,
    pub desired: watch::Sender<Desired>,
    pub status: watch::Receiver<Status>,
    pub components: Components,
    pub storage: Storage,
    pub ipv6: Ipv6Support,
}

pub async fn serve(
    listener: TcpListener,
    config: &ControlSettings,
    runtime: Runtime,
) -> io::Result<()> {
    let address = listener.local_addr()?;
    let state = Arc::new(ControlState {
        settings: runtime.settings,
        public_ip: runtime.public_ip,
        desired: runtime.desired,
        status: runtime.status,
        components: runtime.components,
        storage: runtime.storage,
        ipv6: runtime.ipv6,
        settings_lock: tokio::sync::Mutex::new(()),
    });
    let authentication = Arc::new(config.clone());
    let app = Router::new()
        .route("/v1/version", get(version))
        .route("/v1/vpn/status", get(vpn_status).put(vpn_set_status))
        .route("/v1/vpn/settings", get(vpn_settings).put(vpn_set_settings))
        .route("/v1/publicip/ip", get(public_ip_handler))
        .route("/v1/dns/status", get(dns_status).put(dns_set_status))
        .route(
            "/v1/updater/status",
            get(updater_status).put(updater_set_status),
        )
        .route("/version", get(legacy_version))
        .route("/unbound/actions/restart", get(dns_restart))
        .route("/updater/restart", get(updater_restart))
        .route_layer(middleware::from_fn_with_state(authentication, auth))
        .with_state(state);
    tracing::info!(%address, auth = !config.api_key.is_empty(), "control server listening");
    axum::serve(listener, app).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn settings_updates_are_validated_atomic_and_restart_the_vpn() {
        let settings = Settings::from_env(&crate::config::Env::from_pairs([
            (
                "WIREGUARD_PRIVATE_KEY",
                "wOEI9rqqbDwnN8/Bpp22sVz48T71vJ4fYmFWujulwUU=",
            ),
            ("WIREGUARD_ADDRESSES", "10.64.222.21/32"),
            ("WIREGUARD_CONF_SECRETFILE", "/nonexistent/wg0.conf"),
        ]))
        .expect("settings");
        let config = settings.control.clone();
        let public_ip = PublicIpService::new(
            settings.public_ip.clone(),
            reqwest::Client::new(),
            (1000, 1000),
        );
        let (settings, settings_rx) = watch::channel(Arc::new(settings));
        let (desired, desired_rx) = watch::channel(Desired::Stopped);
        let desired_check = desired.clone();
        let (_status, status) = watch::channel(Status::Stopped);
        let (dns, mut dns_worker) = lifecycle::channel();
        let (updater, mut updater_worker) = lifecycle::channel();
        let workers = [
            tokio::spawn(async move {
                while let Some(command) = dns_worker.next().await {
                    dns_worker.publish(command.state);
                    command.acknowledge();
                }
            }),
            tokio::spawn(async move {
                while let Some(command) = updater_worker.next().await {
                    updater_worker.publish(command.state);
                    command.acknowledge();
                }
            }),
        ];
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listen");
        let base = format!("http://{}", listener.local_addr().expect("address"));
        let task = tokio::spawn(async move {
            serve(
                listener,
                &config,
                Runtime {
                    settings,
                    public_ip,
                    desired,
                    status,
                    components: Components {
                        dns: Some(dns),
                        updater,
                    },
                    storage: Storage::new(None).expect("storage"),
                    ipv6: Ipv6Support::Internet,
                },
            )
            .await
        });
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("client");
        let url = format!("{base}/v1/vpn/settings");
        let original = Arc::clone(&settings_rx.borrow());
        for patch in [
            serde_json::json!({"provider": {"name": "protonvpn"}}),
            serde_json::json!({"wireguard": {"private_key": "invalid-secret"}}),
            serde_json::json!({"wireguard": {"mtu": 1}}),
            serde_json::json!({"provider": {"server_selection": {"hostnames": ["does-not-exist"]}}}),
        ] {
            let response = client.put(&url).json(&patch).send().await.expect("request");
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert_eq!(*settings_rx.borrow().as_ref(), *original);
            assert_eq!(*desired_rx.borrow(), Desired::Stopped);
        }
        let patch = serde_json::json!({"provider": {"server_selection": {"countries": ["Sweden"], "mode": "ordered", "mullvad_post_quantum": true}}, "wireguard": {"mtu": 1420}});
        let response = client.put(&url).json(&patch).send().await.expect("patch");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(settings_rx.borrow().wireguard.mtu, 1420);
        assert!(settings_rx.borrow().wireguard.quantum_resistant);
        assert_eq!(*desired_rx.borrow(), Desired::Restart);
        desired_check.send_replace(Desired::Stopped);
        let response = client
            .put(&url)
            .json(&patch)
            .send()
            .await
            .expect("idempotent patch");
        assert_eq!(
            response.text().await.expect("outcome"),
            "settings left unchanged"
        );
        assert_eq!(*desired_rx.borrow(), Desired::Stopped);
        let view: serde_json::Value = client
            .get(&url)
            .send()
            .await
            .expect("get")
            .json()
            .await
            .expect("settings JSON");
        assert_eq!(view["type"], "wireguard");
        assert_eq!(view["provider"]["name"], "mullvad");
        assert_eq!(view["wireguard"]["private_key"], "[redacted]");
        assert!(view.get("socks5").is_none());
        let response = client
            .put(&url)
            .json(&view)
            .send()
            .await
            .expect("redacted roundtrip");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            settings_rx.borrow().wireguard.private_key,
            original.wireguard.private_key
        );
        for component in ["dns", "updater"] {
            for status in ["running", "stopped"] {
                let url = format!("{base}/v1/{component}/status");
                assert_eq!(
                    client
                        .put(&url)
                        .json(&serde_json::json!({"status": status}))
                        .send()
                        .await
                        .expect("set status")
                        .status(),
                    StatusCode::OK
                );
                let state: serde_json::Value = client
                    .get(&url)
                    .send()
                    .await
                    .expect("status")
                    .json()
                    .await
                    .expect("JSON");
                assert_eq!(state["status"], status);
            }
        }
        for path in ["/unbound/actions/restart", "/updater/restart"] {
            assert_eq!(
                client
                    .get(format!("{base}{path}"))
                    .send()
                    .await
                    .expect("restart")
                    .status(),
                StatusCode::OK
            );
        }
        assert_eq!(
            client
                .get(format!("{base}/version"))
                .send()
                .await
                .expect("redirect")
                .status(),
            StatusCode::PERMANENT_REDIRECT
        );
        task.abort();
        let _ = task.await;
        for worker in workers {
            worker.abort();
            let _ = worker.await;
        }
    }

    #[test]
    fn authentication_uses_exact_bearer_token() {
        assert!(constant_time_equal("token", "token"));
        assert!(!constant_time_equal("token", "token2"));
        assert!(!constant_time_equal("token", "tokan"));
    }

    #[tokio::test]
    async fn control_api_authenticates_and_stops_the_vpn() {
        let settings = crate::config::Settings::from_env(&crate::config::Env::from_pairs([
            ("VPN_SERVICE_PROVIDER", "mullvad"),
            (
                "WIREGUARD_PRIVATE_KEY",
                "wOEI9rqqbDwnN8/Bpp22sVz48T71vJ4fYmFWujulwUU=",
            ),
            ("WIREGUARD_ADDRESSES", "10.64.222.21/32"),
            ("WIREGUARD_CONF_SECRETFILE", "/nonexistent/wg0.conf"),
        ]))
        .expect("settings");
        let mut config = settings.control.clone();
        config.api_key = crate::config::Secret::new("test-token");
        let service = PublicIpService::new(
            settings.public_ip.clone(),
            reqwest::Client::new(),
            (1000, 1000),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let (desired, receiver) = watch::channel(Desired::Running);
        let (_status, status_receiver) = watch::channel(Status::Stopped);
        let (settings, _settings_rx) = watch::channel(Arc::new(settings));
        let server = tokio::spawn(async move {
            serve(
                listener,
                &config,
                Runtime {
                    settings,
                    public_ip: service,
                    desired,
                    status: status_receiver,
                    components: Components {
                        dns: None,
                        updater: lifecycle::channel().0,
                    },
                    storage: Storage::new(None).expect("storage"),
                    ipv6: Ipv6Support::Internet,
                },
            )
            .await
        });

        async fn request(address: std::net::SocketAddr, http: &str) -> String {
            let mut connection = tokio::net::TcpStream::connect(address)
                .await
                .expect("connect");
            connection.write_all(http.as_bytes()).await.expect("send");
            let mut response = Vec::new();
            tokio::time::timeout(
                std::time::Duration::from_secs(2),
                connection.read_to_end(&mut response),
            )
            .await
            .expect("response in time")
            .expect("read");
            String::from_utf8(response).expect("HTTP response")
        }

        let unauthorized = request(
            address,
            "GET /v1/vpn/status HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(unauthorized.starts_with("HTTP/1.1 401"));
        let authorized = request(address, "GET /v1/vpn/status HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer test-token\r\nConnection: close\r\n\r\n").await;
        assert!(authorized.contains("\"status\":\"stopped\""));
        let put = request(address, "PUT /v1/vpn/status HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer test-token\r\nContent-Type: application/json\r\nContent-Length: 20\r\nConnection: close\r\n\r\n{\"status\":\"stopped\"}").await;
        assert!(put.starts_with("HTTP/1.1 200"), "{put}");
        assert_eq!(*receiver.borrow(), Desired::Stopped);
        server.abort();
    }
}
