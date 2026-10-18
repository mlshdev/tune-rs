use tune::{
    config, control, dns, firewall, health, httpproxy, logging, metrics, netlink, provider,
    publicip, routing, shadowsocks, socks5, storage, tls, updater, vpn, wireguard,
};

use std::io::Read;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::{Parser, Subcommand, ValueEnum};
use tokio::net::TcpListener;
use tokio::sync::watch;

use crate::config::{Env, Settings};
use crate::firewall::Firewall;
use crate::routing::{DefaultRoute, LocalNetwork, Routing};
use crate::vpn::{Desired, Status, Vpn};

const IPV6_CHECK_ADDRESSES: [SocketAddr; 2] = [
    SocketAddr::new(
        std::net::IpAddr::V6(std::net::Ipv6Addr::new(
            0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111,
        )),
        443,
    ),
    SocketAddr::new(
        std::net::IpAddr::V6(std::net::Ipv6Addr::new(
            0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888,
        )),
        443,
    ),
];

#[derive(Parser)]
#[command(
    name = "tune",
    version,
    about = "Kernel WireGuard VPN client container"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    Run,
    Healthcheck,
    Genkey {
        #[arg(long, value_enum, default_value = "apikey")]
        r#type: KeyType,
    },
    Pubkey,
    FormatServers {
        #[arg(long, value_enum, default_value = "markdown")]
        format: ServerFormat,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    Update {
        #[arg(long)]
        directory: Option<PathBuf>,
        #[arg(long, alias = "minratio")]
        min_ratio: Option<f64>,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum KeyType {
    Apikey,
    Wireguard,
}

#[derive(Clone, Copy, ValueEnum)]
enum ServerFormat {
    Markdown,
    Json,
    Summary,
}

#[derive(Debug, thiserror::Error)]
enum CliError {
    #[error(transparent)]
    Config(#[from] config::ConfigError),
    #[error(transparent)]
    Logging(#[from] logging::LoggingError),
    #[error(transparent)]
    Key(#[from] wireguard::keys::KeyError),
    #[error("reading standard input: {0}")]
    Stdin(std::io::Error),
    #[error("writing output: {0}")]
    Output(std::io::Error),
    #[error("generating API key: {0}")]
    Random(#[from] getrandom::Error),
    #[error("encoding JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("creating async runtime: {0}")]
    Runtime(std::io::Error),
    #[error("receiving shutdown signal: {0}")]
    Signal(std::io::Error),
    #[error("health server: {0}")]
    HealthServer(std::io::Error),
    #[error("health server stopped unexpectedly")]
    HealthExited,
    #[error("DNS server: {0}")]
    DnsServer(std::io::Error),
    #[error("DNS server stopped unexpectedly")]
    DnsExited,
    #[error("control server: {0}")]
    ControlServer(std::io::Error),
    #[error("control server stopped unexpectedly")]
    ControlExited,
    #[error("metrics server: {0}")]
    MetricsServer(std::io::Error),
    #[error("metrics server stopped unexpectedly")]
    MetricsExited,
    #[error("SOCKS5 server: {0}")]
    Socks5Server(std::io::Error),
    #[error("SOCKS5 server stopped unexpectedly")]
    Socks5Exited,
    #[error("HTTP proxy server: {0}")]
    HttpProxyServer(std::io::Error),
    #[error("HTTP proxy server stopped unexpectedly")]
    HttpProxyExited,
    #[error("Shadowsocks server: {0}")]
    ShadowsocksServer(std::io::Error),
    #[error("Shadowsocks server stopped unexpectedly")]
    ShadowsocksExited,
    #[error("VPN loop stopped unexpectedly")]
    VpnExited,
    #[error("Mullvad relay updater stopped unexpectedly")]
    UpdaterExited,
    #[error(transparent)]
    Updater(#[from] updater::UpdateError),
    #[error("joining background task: {0}")]
    Task(#[from] tokio::task::JoinError),
    #[error(transparent)]
    Netlink(#[from] netlink::NetlinkError),
    #[error(transparent)]
    Routing(#[from] routing::RoutingError),
    #[error(transparent)]
    Firewall(#[from] firewall::FirewallError),
    #[error(transparent)]
    Storage(#[from] storage::StorageError),
    #[error(transparent)]
    Dns(#[from] dns::DnsError),
    #[error("configuring system DNS: {0}")]
    SystemDns(std::io::Error),
    #[error(transparent)]
    Tls(#[from] rustls::Error),
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command.unwrap_or(Command::Run) {
        Command::Run => run(),
        Command::Healthcheck => return healthcheck(),
        Command::Genkey { r#type } => genkey(r#type),
        Command::Pubkey => pubkey(),
        Command::FormatServers { format, output } => format_servers(format, output),
        Command::Update {
            directory,
            min_ratio,
        } => update_servers(directory, min_ratio),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), CliError> {
    let env = Env::from_process();
    let settings = Settings::from_env(&env)?;
    logging::init(
        &settings.log_level,
        env.get("ENVIRONMENT").unwrap_or("production"),
    )?;
    tracing::info!(settings = %serde_json::to_string(&settings)?, "settings loaded");
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(CliError::Runtime)?;
    runtime.block_on(run_async(Arc::new(settings)))
}

async fn run_async(settings: Arc<Settings>) -> Result<(), CliError> {
    let shutdown = Shutdown::new().map_err(CliError::Signal)?;
    let routing = Arc::new(Routing::new(netlink::Netlink::connect()?));
    let defaults = routing.default_routes().await?;
    let local_networks = routing.local_networks().await?;
    let firewall = Arc::new(Firewall::new(
        defaults.clone(),
        local_networks.clone(),
        settings.firewall.outbound_subnets.clone(),
    ));
    let storage = storage::Storage::new(
        settings
            .storage
            .enabled
            .then(|| settings.storage.directory.clone()),
    )?;
    let connector = tls::connector()?;
    let public_ip = publicip::PublicIpService::new(
        settings.public_ip.clone(),
        reqwest::Client::new(),
        (settings.system.puid, settings.system.pgid),
    );
    let health_status = health::HealthStatus::default();
    let listener = TcpListener::bind(settings.health.server_address)
        .await
        .map_err(CliError::HealthServer)?;
    let control_listener = TcpListener::bind(settings.control.listen_address)
        .await
        .map_err(CliError::ControlServer)?;
    let metrics_listener = if settings.metrics.enabled {
        Some(
            TcpListener::bind(settings.metrics.listen_address)
                .await
                .map_err(CliError::MetricsServer)?,
        )
    } else {
        None
    };
    let socks5 = if settings.socks5.enabled {
        Some(
            socks5::Server::bind(settings.socks5.clone())
                .await
                .map_err(CliError::Socks5Server)?,
        )
    } else {
        None
    };
    let http_proxy = if settings.http_proxy.enabled {
        Some(
            httpproxy::Server::bind(settings.http_proxy.clone())
                .await
                .map_err(CliError::HttpProxyServer)?,
        )
    } else {
        None
    };
    let shadowsocks = if settings.shadowsocks.enabled {
        Some(
            shadowsocks::Server::bind(settings.shadowsocks.clone())
                .await
                .map_err(CliError::ShadowsocksServer)?,
        )
    } else {
        None
    };
    let dns = if settings.dns.server_enabled {
        Some(dns::Server::bind(settings.dns.clone(), connector.clone()).await?)
    } else {
        None
    };

    let startup = async {
        firewall.set_enabled(settings.firewall.enabled).await?;
        for &port in &settings.firewall.input_ports {
            firewall.set_allowed_port(port, None).await?;
        }
        routing.add_local_rules(&local_networks).await?;
        routing
            .setup(&defaults, &settings.firewall.outbound_subnets)
            .await?;
        let ipv6 = routing
            .ipv6_support(&IPV6_CHECK_ADDRESSES, firewall.as_ref())
            .await?;
        tracing::info!(?ipv6, "IPv6 support detected");
        Ok::<_, CliError>(ipv6)
    }
    .await;

    let result = match startup {
        Ok(ipv6) => {
            let resolver = match dns::SystemResolver::install(&settings.dns) {
                Ok(resolver) => resolver,
                Err(error) => {
                    let cleanup =
                        teardown_network(&routing, &firewall, &defaults, &local_networks).await;
                    if let Err(cleanup) = cleanup {
                        tracing::error!(%cleanup, "cleaning up after system DNS configuration failed");
                    }
                    return Err(CliError::SystemDns(error));
                }
            };
            let vpn = Vpn {
                settings,
                routing: Arc::clone(&routing),
                firewall: Arc::clone(&firewall),
                storage,
                public_ip,
                health_status: health_status.clone(),
                connector,
                ipv6,
                picker: provider::ConnectionPicker::default(),
            };
            let result = run_services(
                vpn,
                Services {
                    listener,
                    control_listener,
                    metrics_listener,
                    dns,
                    socks5,
                    http_proxy,
                    shadowsocks,
                },
                health_status,
                shutdown,
            )
            .await;
            let restore = resolver.restore();
            if let Err(error) = &restore {
                tracing::error!(%error, "restoring system DNS");
            }
            result.and(restore.map_err(CliError::SystemDns))
        }
        Err(error) => Err(error),
    };
    let cleanup = teardown_network(&routing, &firewall, &defaults, &local_networks).await;
    result?;
    cleanup
}

async fn teardown_network(
    routing: &Routing,
    firewall: &Firewall,
    defaults: &[DefaultRoute],
    networks: &[LocalNetwork],
) -> Result<(), CliError> {
    let filter = firewall.seal().await;
    let routes = routing.teardown(defaults).await;
    let local = routing.remove_local_rules(networks).await;
    if let Err(error) = &routes {
        tracing::error!(%error, "tearing down routes");
    }
    if let Err(error) = &local {
        tracing::error!(%error, "removing local routing rules");
    }
    if let Err(error) = &filter {
        tracing::error!(%error, "sealing firewall");
    }
    routes?;
    local?;
    filter?;
    Ok(())
}

struct Services {
    listener: TcpListener,
    control_listener: TcpListener,
    metrics_listener: Option<TcpListener>,
    dns: Option<dns::Server>,
    socks5: Option<socks5::Server>,
    http_proxy: Option<httpproxy::Server>,
    shadowsocks: Option<shadowsocks::Server>,
}

async fn run_services(
    vpn: Vpn,
    services: Services,
    health_status: health::HealthStatus,
    mut shutdown: Shutdown,
) -> Result<(), CliError> {
    let Services {
        listener,
        control_listener,
        metrics_listener,
        dns,
        socks5,
        http_proxy,
        shadowsocks,
    } = services;
    let (desired_tx, desired_rx) = watch::channel(Desired::Running);
    let (status_tx, status_rx) = watch::channel(Status::Stopped);
    let control_settings = vpn.settings.control.clone();
    let (settings, settings_rx) = watch::channel(Arc::clone(&vpn.settings));
    let metrics_settings = settings_rx.clone();
    let control_storage = vpn.storage.clone();
    let control_ipv6 = vpn.ipv6;
    let public_ip = vpn.public_ip.clone();
    let control_desired = desired_tx.clone();
    let control_status = status_rx.clone();
    let metrics_status = status_rx.clone();
    let metrics_health = health_status.clone();
    let updater = updater::Updater::new(vpn.settings.updater.clone(), vpn.storage.clone())?;
    let (updater_control, updater_worker) = control::lifecycle::channel();
    let (dns_control, dns_worker) = control::lifecycle::channel();
    let components = control::Components {
        dns: dns.as_ref().map(|_| dns_control),
        updater: updater_control,
    };
    let mut updater_task = Some(tokio::spawn(
        updater.run_controlled(status_rx.clone(), updater_worker),
    ));
    let mut vpn_task = tokio::spawn(vpn.run(desired_rx, status_tx, settings_rx));
    let mut health_task = tokio::spawn(health::serve(listener, health_status));
    let mut control_task = tokio::spawn(async move {
        control::serve(
            control_listener,
            &control_settings,
            control::Runtime {
                settings,
                public_ip,
                desired: control_desired,
                status: control_status,
                components,
                storage: control_storage,
                ipv6: control_ipv6,
            },
        )
        .await
    });
    let mut metrics_task = metrics_listener.map(|listener| {
        tokio::spawn(metrics::serve(
            listener,
            metrics_status,
            metrics_health,
            metrics_settings,
        ))
    });
    let mut socks5_task = socks5.map(|server| tokio::spawn(server.run(status_rx.clone())));
    let mut http_proxy_task = http_proxy.map(|server| tokio::spawn(server.run(status_rx.clone())));
    let mut shadowsocks_task =
        shadowsocks.map(|server| tokio::spawn(server.run(status_rx.clone())));
    let mut dns_task =
        dns.map(|server| tokio::spawn(server.run_controlled(status_rx.clone(), dns_worker)));

    let result = tokio::select! {
        () = shutdown.wait() => Ok(()),
        health = &mut health_task => match health {
            Ok(Ok(())) => Err(CliError::HealthExited),
            Ok(Err(error)) => Err(CliError::HealthServer(error)),
            Err(error) => Err(CliError::Task(error)),
        },
        vpn = &mut vpn_task => match vpn {
            Ok(()) => Err(CliError::VpnExited),
            Err(error) => Err(CliError::Task(error)),
        },
        updater = async { updater_task.as_mut().expect("updater task exists").await }, if updater_task.is_some() => match updater {
            Ok(()) => Err(CliError::UpdaterExited),
            Err(error) => Err(CliError::Task(error)),
        },
        dns = async { dns_task.as_mut().expect("DNS task exists").await }, if dns_task.is_some() => match dns {
            Ok(Ok(())) => Err(CliError::DnsExited),
            Ok(Err(error)) => Err(CliError::DnsServer(error)),
            Err(error) => Err(CliError::Task(error)),
        },
        control = &mut control_task => match control {
            Ok(Ok(())) => Err(CliError::ControlExited),
            Ok(Err(error)) => Err(CliError::ControlServer(error)),
            Err(error) => Err(CliError::Task(error)),
        },
        metrics = async { metrics_task.as_mut().expect("metrics task exists").await }, if metrics_task.is_some() => match metrics {
            Ok(Ok(())) => Err(CliError::MetricsExited),
            Ok(Err(error)) => Err(CliError::MetricsServer(error)),
            Err(error) => Err(CliError::Task(error)),
        },
        socks5 = async { socks5_task.as_mut().expect("SOCKS5 task exists").await }, if socks5_task.is_some() => match socks5 {
            Ok(Ok(())) => Err(CliError::Socks5Exited),
            Ok(Err(error)) => Err(CliError::Socks5Server(error)),
            Err(error) => Err(CliError::Task(error)),
        },
        http_proxy = async { http_proxy_task.as_mut().expect("HTTP proxy task exists").await }, if http_proxy_task.is_some() => match http_proxy {
            Ok(Ok(())) => Err(CliError::HttpProxyExited),
            Ok(Err(error)) => Err(CliError::HttpProxyServer(error)),
            Err(error) => Err(CliError::Task(error)),
        },
        shadowsocks = async { shadowsocks_task.as_mut().expect("Shadowsocks task exists").await }, if shadowsocks_task.is_some() => match shadowsocks {
            Ok(Ok(())) => Err(CliError::ShadowsocksExited),
            Ok(Err(error)) => Err(CliError::ShadowsocksServer(error)),
            Err(error) => Err(CliError::Task(error)),
        },
    };
    desired_tx.send_replace(Desired::Shutdown);
    if let Some(task) = updater_task.take() {
        task.abort();
        let _ = task.await;
    }
    let vpn_join = if !vpn_task.is_finished() {
        vpn_task.await.map_err(CliError::Task)
    } else {
        Ok(())
    };
    if !health_task.is_finished() {
        health_task.abort();
        let _ = health_task.await;
    }
    if !control_task.is_finished() {
        control_task.abort();
        let _ = control_task.await;
    }
    if let Some(task) = metrics_task.take()
        && !task.is_finished()
    {
        task.abort();
        let _ = task.await;
    }
    if let Some(task) = socks5_task.take()
        && !task.is_finished()
    {
        task.abort();
        let _ = task.await;
    }
    if let Some(task) = http_proxy_task.take()
        && !task.is_finished()
    {
        task.abort();
        let _ = task.await;
    }
    if let Some(task) = shadowsocks_task.take()
        && !task.is_finished()
    {
        task.abort();
        let _ = task.await;
    }
    if let Some(task) = dns_task.take()
        && !task.is_finished()
    {
        task.abort();
        let _ = task.await;
    }
    result?;
    vpn_join
}

struct Shutdown {
    term: tokio::signal::unix::Signal,
    interrupt: tokio::signal::unix::Signal,
}

impl Shutdown {
    fn new() -> std::io::Result<Self> {
        use tokio::signal::unix::{SignalKind, signal};
        Ok(Self {
            term: signal(SignalKind::terminate())?,
            interrupt: signal(SignalKind::interrupt())?,
        })
    }

    async fn wait(&mut self) {
        tokio::select! {
            _ = self.term.recv() => {},
            _ = self.interrupt.recv() => {},
        }
    }
}

fn pubkey() -> Result<(), CliError> {
    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .map_err(CliError::Stdin)?;
    let private = wireguard::keys::decode_key(&input)?;
    println!(
        "{}",
        wireguard::keys::encode_key(&wireguard::keys::public_key(&private))
    );
    Ok(())
}

fn genkey(kind: KeyType) -> Result<(), CliError> {
    let key = match kind {
        KeyType::Apikey => tune::cli::api_key()?,
        KeyType::Wireguard => wireguard::keys::encode_key(&wireguard::keys::generate_private_key()),
    };
    println!("{key}");
    Ok(())
}

fn format_servers(format: ServerFormat, output: Option<PathBuf>) -> Result<(), CliError> {
    use std::io::Write;
    let servers = storage::hardcoded();
    let data = &servers[&provider::ProviderName::Mullvad];
    let formatted = match format {
        ServerFormat::Markdown => tune::cli::markdown_servers(data),
        ServerFormat::Json => serde_json::to_string_pretty(data)? + "\n",
        ServerFormat::Summary => format!(
            "mullvad: version {} with {} servers\n",
            data.version,
            data.servers.len()
        ),
    };
    match output {
        Some(path) => std::fs::write(path, formatted).map_err(CliError::Output)?,
        None => std::io::stdout()
            .lock()
            .write_all(formatted.as_bytes())
            .map_err(CliError::Output)?,
    }
    Ok(())
}

fn update_servers(directory: Option<PathBuf>, min_ratio: Option<f64>) -> Result<(), CliError> {
    let env = Env::from_process();
    let min_ratio = min_ratio
        .or(env.parse(&["UPDATER_MIN_RATIO"])?)
        .unwrap_or(0.8);
    if !(0.0..=1.0).contains(&min_ratio) || min_ratio == 0.0 {
        return Err(config::ConfigError::Constraint(
            "update minimum ratio must be in (0, 1]".into(),
        )
        .into());
    }
    let directory = directory.unwrap_or_else(|| {
        PathBuf::from(
            env.get("STORAGE_SERVERS_DIRECTORY_PATH")
                .unwrap_or("/gluetun/servers"),
        )
    });
    let storage = storage::Storage::new(Some(directory))?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(CliError::Runtime)?;
    let count = runtime.block_on(async {
        updater::Updater::new(
            config::UpdaterSettings {
                period: std::time::Duration::ZERO,
                min_ratio,
            },
            storage,
        )?
        .refresh()
        .await
    })?;
    println!("updated Mullvad: {count} relays");
    Ok(())
}

fn healthcheck() -> ExitCode {
    let env = Env::from_process();
    let address = env.get("HEALTH_SERVER_ADDRESS").unwrap_or("127.0.0.1:9999");
    let Some(address) = config::parse_listen_address(address) else {
        eprintln!("error: HEALTH_SERVER_ADDRESS: invalid listening address {address:?}");
        return ExitCode::FAILURE;
    };
    let host = if address.ip().is_unspecified() {
        std::net::SocketAddr::new(std::net::Ipv4Addr::LOCALHOST.into(), address.port())
    } else {
        address
    };
    match health_request(host) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("unhealthy: {err}");
            ExitCode::FAILURE
        }
    }
}

fn health_request(address: std::net::SocketAddr) -> Result<(), String> {
    use std::io::Write;
    use std::time::Duration;
    let timeout = Duration::from_secs(5);
    let mut stream =
        std::net::TcpStream::connect_timeout(&address, timeout).map_err(|e| e.to_string())?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|e| e.to_string())?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|e| e.to_string())?;
    write!(
        stream,
        "GET / HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n"
    )
    .map_err(|e| e.to_string())?;
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .map_err(|e| e.to_string())?;
    let status_line = response.lines().next().unwrap_or_default();
    if status_line.split_whitespace().nth(1) == Some("200") {
        Ok(())
    } else {
        let body = response.split("\r\n\r\n").nth(1).unwrap_or_default().trim();
        Err(format!("{status_line}: {body}"))
    }
}
