use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_rustls::TlsConnector;

use crate::config::Settings;
use crate::firewall::{Firewall, FirewallError};
use crate::health::{Checker, HealthStatus};
use crate::models::Connection;
use crate::pmtud;
use crate::provider::{ConnectionPicker, SelectError, get_connection};
use crate::publicip::PublicIpService;
use crate::routing::{Ipv6Support, Routing};
use crate::storage::Storage;
use crate::wireguard::keys::{KeyError, decode_key};
use crate::wireguard::pq::{self, PqError};
use crate::wireguard::{DEFAULT_FWMARK, DEFAULT_RULE_PRIORITY, Device, DeviceConfig, DeviceError};

const INITIAL_BACKOFF: Duration = Duration::from_secs(15);
const DEFAULT_MTU: u32 = 1320;
const INTERFACE_PLACEHOLDER: &str = "{{VPN_INTERFACE}}";

#[derive(Debug, thiserror::Error)]
pub enum VpnError {
    #[error("selecting connection: {0}")]
    Select(#[from] SelectError),
    #[error("decoding {0} key: {1}")]
    Key(&'static str, #[source] KeyError),
    #[error("configuring firewall: {0}")]
    Firewall(#[from] FirewallError),
    #[error(transparent)]
    Device(#[from] DeviceError),
    #[error("negotiating quantum-resistant tunnel: {0}")]
    Pq(#[from] PqError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Desired {
    Running,
    Restart,
    Stopped,
    Shutdown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tunnel {
    pub interface: String,
    pub connection: Connection,
    pub ipv6: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Status {
    Stopped,
    Starting,
    Running(Tunnel),
    Stopping,
    Crashed,
}

enum Exit {
    Stopped,
    Restart,
    Failed(VpnError),
}

pub struct Vpn {
    pub settings: Arc<Settings>,
    pub routing: Arc<Routing>,
    pub firewall: Arc<Firewall>,
    pub storage: Storage,
    pub public_ip: PublicIpService,
    pub health_status: HealthStatus,
    pub connector: TlsConnector,
    pub ipv6: Ipv6Support,
    pub picker: ConnectionPicker,
}

impl Vpn {
    pub async fn run(
        mut self,
        mut desired: watch::Receiver<Desired>,
        status: watch::Sender<Status>,
        settings: watch::Receiver<Arc<Settings>>,
    ) {
        let mut backoff = INITIAL_BACKOFF;
        loop {
            self.settings = Arc::clone(&settings.borrow());
            if desired.has_changed().is_err() {
                self.health_status.reset();
                return;
            }
            let wanted = *desired.borrow_and_update();
            match wanted {
                Desired::Shutdown => {
                    self.health_status.reset();
                    return;
                }
                Desired::Stopped => {
                    self.health_status.reset();
                    status.send_replace(Status::Stopped);
                    if desired.changed().await.is_err() {
                        return;
                    }
                    continue;
                }
                Desired::Running | Desired::Restart => {}
            }
            self.health_status.reset();
            status.send_replace(Status::Starting);
            let (exit, reached_running) = match self.start().await {
                Ok((device, connection)) => {
                    let exit = self
                        .serve(&device, &connection, &mut desired, &status)
                        .await;
                    let reached_running = matches!(*status.borrow(), Status::Running(_));
                    status.send_replace(Status::Stopping);
                    self.stop(device).await;
                    (exit, reached_running)
                }
                Err(error) => (Exit::Failed(error), false),
            };
            self.health_status.reset();
            if reached_running {
                backoff = INITIAL_BACKOFF;
            }
            match exit {
                Exit::Stopped => self.picker.reset(),
                Exit::Restart => tracing::info!("restarting VPN"),
                Exit::Failed(error) => {
                    status.send_replace(Status::Crashed);
                    tracing::error!(%error, retry_in = ?backoff, "VPN failed");
                    tokio::select! {
                        () = tokio::time::sleep(backoff) => {}
                        () = until_not_running(&mut desired) => { self.picker.reset(); }
                    }
                    backoff = backoff.saturating_mul(2);
                }
            }
        }
    }

    async fn start(&self) -> Result<(Device, Connection), VpnError> {
        let provider = self.settings.provider;
        let connection = get_connection(
            &self.storage.servers(provider),
            &self.settings.selection,
            provider.default_wireguard_port(),
            self.ipv6 == Ipv6Support::Internet,
            &self.picker,
        )?;
        let config = self.device_config(&connection)?;
        self.firewall
            .set_vpn_connection(config.endpoint, &config.interface)
            .await?;
        tracing::info!(
            server = %connection.server_name,
            hostname = %connection.hostname,
            endpoint = %config.endpoint,
            "connecting to VPN server"
        );
        let mut device = match Device::up(self.routing.netlink().clone(), config).await {
            Ok(device) => device,
            Err(error) => {
                if let Err(cleanup) = self.firewall.clear_vpn_connection().await {
                    tracing::warn!(%cleanup, "clearing failed VPN connection allowance");
                }
                return Err(error.into());
            }
        };
        if self.settings.wireguard.quantum_resistant {
            if let Err(error) = pq::negotiate(&mut device).await {
                self.picker.record_failure(&connection);
                device.down().await;
                if let Err(cleanup) = self.firewall.clear_vpn_connection().await {
                    tracing::warn!(%cleanup, "clearing failed VPN connection allowance");
                }
                return Err(error.into());
            }
            tracing::info!("quantum-resistant tunnel established");
        }
        Ok((device, connection))
    }

    fn device_config(&self, connection: &Connection) -> Result<DeviceConfig, VpnError> {
        let wireguard = &self.settings.wireguard;
        let private_key = decode_key(wireguard.private_key.expose())
            .map_err(|error| VpnError::Key("private", error))?;
        let peer_public_key = decode_key(&connection.pubkey)
            .map_err(|error| VpnError::Key("server public", error))?;
        let preshared_key = match wireguard.preshared_key.expose() {
            "" => None,
            encoded => {
                Some(decode_key(encoded).map_err(|error| VpnError::Key("preshared", error))?)
            }
        };
        Ok(DeviceConfig {
            interface: wireguard.interface.clone(),
            private_key,
            peer_public_key,
            preshared_key,
            endpoint: SocketAddr::new(connection.ip, connection.port),
            addresses: wireguard.addresses.clone(),
            allowed_ips: wireguard.allowed_ips.clone(),
            persistent_keepalive: wireguard.persistent_keepalive,
            mtu: if wireguard.mtu == 0 {
                DEFAULT_MTU
            } else {
                wireguard.mtu
            },
            fwmark: DEFAULT_FWMARK,
            rule_priority: DEFAULT_RULE_PRIORITY,
            ipv6: self.ipv6.is_supported(),
        })
    }

    async fn serve(
        &self,
        device: &Device,
        connection: &Connection,
        desired: &mut watch::Receiver<Desired>,
        status: &watch::Sender<Status>,
    ) -> Exit {
        let config = device.config();
        let interface = config.interface.as_str();
        tracing::info!(
            "Wireguard setup is complete. Note Wireguard is a silent protocol and it may or may not \
             work, without giving any error message. Typically i/o timeout errors indicate the \
             Wireguard connection is not working."
        );
        for &port in &self.settings.firewall.vpn_input_ports {
            if let Err(error) = self.firewall.set_allowed_port(port, Some(interface)).await {
                return Exit::Failed(error.into());
            }
        }
        if self.settings.wireguard.mtu == 0 {
            let targets = pmtud::Targets::new(
                &self.settings.pmtud.icmp_addresses,
                &self.settings.pmtud.tcp_addresses,
                config.ipv6,
            );
            let update = pmtud::update_to_max_mtu(
                self.routing.netlink(),
                &self.routing,
                &self.connector,
                interface,
                config.endpoint.is_ipv6(),
                &targets,
            );
            tokio::select! {
                result = update => if let Err(error) = result {
                    tracing::error!(%error, "updating to maximum MTU");
                },
                () = until_not_running(desired) => return Exit::Stopped,
            }
        }
        status.send_replace(Status::Running(Tunnel {
            interface: interface.to_owned(),
            connection: connection.clone(),
            ipv6: config.ipv6,
        }));

        let health = &self.settings.health;
        let mut checker = Checker::new(health, self.connector.clone());
        checker.set_server_ip(health, connection.ip);
        let startup = tokio::select! {
            result = checker.startup() => result,
            () = until_not_running(desired) => return Exit::Stopped,
        };
        self.health_status.set(startup.as_ref().map(|_| ()));
        let mut failing = false;
        if let Err(error) = startup {
            if health.restart_vpn {
                self.picker.record_failure(connection);
                tracing::error!(%error, "healthcheck failed, restarting VPN");
                return Exit::Restart;
            }
            tracing::warn!(%error, "healthcheck failed (ignored)");
            failing = true;
        } else {
            self.picker.record_success();
        }

        let public_ip = self.public_ip.clone();
        let _refresh = AbortOnDrop(tokio::spawn(async move { public_ip.refresh().await }));
        if let Some(template) = &self.settings.vpn_up_command {
            run_command("up", template, interface).await;
        }

        loop {
            let result = tokio::select! {
                result = checker.next_periodic() => result,
                () = until_not_running(desired) => return Exit::Stopped,
            };
            self.health_status.set(result.as_ref().map(|_| ()));
            match result {
                Ok(()) if failing => {
                    self.picker.record_success();
                    tracing::info!("healthcheck passed successfully after previous failure(s)");
                    failing = false;
                }
                Ok(()) => {}
                Err(error) if health.restart_vpn => {
                    self.picker.record_failure(connection);
                    tracing::error!(%error, "healthcheck failed, restarting VPN");
                    return Exit::Restart;
                }
                Err(error) => {
                    tracing::warn!(%error, "healthcheck failed (ignored)");
                    failing = true;
                }
            }
        }
    }

    async fn stop(&self, device: Device) {
        let interface = device.config().interface.clone();
        if let Some(template) = &self.settings.vpn_down_command {
            run_command("down", template, &interface).await;
        }
        for &port in &self.settings.firewall.vpn_input_ports {
            if let Err(error) = self
                .firewall
                .remove_allowed_port_on_interface(port, &interface)
                .await
            {
                tracing::warn!(port, %error, "removing VPN input port");
            }
        }
        self.public_ip.clear();
        device.down().await;
        if let Err(error) = self.firewall.clear_vpn_connection().await {
            tracing::warn!(%error, "clearing VPN connection allowance");
        }
    }
}

struct AbortOnDrop(JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

// A closed sender means the process is shutting down, which also ends the session.
async fn until_not_running(desired: &mut watch::Receiver<Desired>) {
    loop {
        if desired.changed().await.is_err() || *desired.borrow_and_update() != Desired::Running {
            return;
        }
    }
}

// Run through /bin/sh so users can keep gluetun's quoting and chain commands.
async fn run_command(kind: &'static str, template: &str, interface: &str) {
    let command = template.replace(INTERFACE_PLACEHOLDER, interface);
    tracing::info!(kind, %command, "running VPN command");
    match tokio::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(&command)
        .kill_on_drop(true)
        .output()
        .await
    {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            if output.status.success() {
                tracing::info!(kind, stdout = %stdout.trim(), stderr = %stderr.trim(), "VPN command finished");
            } else {
                tracing::error!(kind, status = %output.status, stdout = %stdout.trim(), stderr = %stderr.trim(), "VPN command failed");
            }
        }
        Err(error) => tracing::error!(kind, %error, "starting VPN command"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn until_not_running_ignores_running_updates() {
        let (sender, mut receiver) = watch::channel(Desired::Running);
        let waiter = tokio::spawn(async move { until_not_running(&mut receiver).await });
        sender.send_replace(Desired::Running);
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished());
        sender.send_replace(Desired::Stopped);
        tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("waiter returns")
            .expect("waiter joins");
    }

    #[tokio::test]
    async fn until_not_running_returns_on_closed_sender() {
        let (sender, mut receiver) = watch::channel(Desired::Running);
        drop(sender);
        tokio::time::timeout(Duration::from_secs(1), until_not_running(&mut receiver))
            .await
            .expect("returns when sender is dropped");
    }
}
