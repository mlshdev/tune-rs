use std::io;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use axum::Router;
use axum::http::{StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::get;
use tokio::net::TcpListener;
use tokio::sync::watch;

use crate::config::Settings;
use crate::health::HealthStatus;
use crate::vpn::Status;

fn render(status: &Status, healthy: bool, uptime: u64) -> String {
    let running = u8::from(matches!(status, Status::Running(_)));
    let healthy = u8::from(healthy);
    format!(
        "# HELP tune_vpn_up Whether a WireGuard tunnel is configured.\n\
         # TYPE tune_vpn_up gauge\n\
         tune_vpn_up {running}\n\
         # HELP tune_health_healthy Whether the last VPN health check passed.\n\
         # TYPE tune_health_healthy gauge\n\
         tune_health_healthy {healthy}\n\
         # HELP tune_uptime_seconds Seconds since tune started.\n\
         # TYPE tune_uptime_seconds counter\n\
         tune_uptime_seconds {uptime}\n"
    )
}

#[derive(Debug, PartialEq, Eq)]
struct InterfaceStats {
    rx_bytes: u64,
    tx_bytes: u64,
}

async fn interface_stats(root: &Path, interface: &str) -> io::Result<Option<InterfaceStats>> {
    if interface.is_empty()
        || interface.len() > 15
        || !interface
            .bytes()
            .all(|value| value.is_ascii_alphanumeric() || value == b'_')
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid network interface name",
        ));
    }
    let directory = root.join(interface).join("statistics");
    let result = tokio::try_join!(
        tokio::fs::read_to_string(directory.join("rx_bytes")),
        tokio::fs::read_to_string(directory.join("tx_bytes"))
    );
    let (rx, tx) = match result {
        Ok(values) => values,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let parse = |value: &str| {
        value
            .trim()
            .parse::<u64>()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
    };
    Ok(Some(InterfaceStats {
        rx_bytes: parse(&rx)?,
        tx_bytes: parse(&tx)?,
    }))
}

fn render_traffic(interface: &str, stats: Option<InterfaceStats>) -> String {
    let stats = stats.unwrap_or(InterfaceStats {
        rx_bytes: 0,
        tx_bytes: 0,
    });
    format!(
        "# HELP gluetun_tun_rx_bytes_total Cumulative bytes received over the VPN interface.\n\
         # TYPE gluetun_tun_rx_bytes_total counter\n\
         gluetun_tun_rx_bytes_total{{interface=\"{interface}\"}} {}\n\
         # HELP gluetun_tun_tx_bytes_total Cumulative bytes sent over the VPN interface.\n\
         # TYPE gluetun_tun_tx_bytes_total counter\n\
         gluetun_tun_tx_bytes_total{{interface=\"{interface}\"}} {}\n",
        stats.rx_bytes, stats.tx_bytes,
    )
}

pub async fn serve(
    listener: TcpListener,
    status: watch::Receiver<Status>,
    health: HealthStatus,
    settings: watch::Receiver<Arc<Settings>>,
) -> io::Result<()> {
    let address = listener.local_addr()?;
    let started = Instant::now();
    let app = Router::new()
        .route(
            "/metrics",
            get(move || {
                let status = status.clone();
                let health = health.clone();
                let settings = settings.clone();
                async move {
                    let mut body = render(
                        &status.borrow(),
                        health.is_healthy(),
                        started.elapsed().as_secs(),
                    );
                    let interface = settings.borrow().wireguard.interface.clone();
                    match interface_stats(Path::new("/sys/class/net"), &interface).await {
                        Ok(stats) => body.push_str(&render_traffic(&interface, stats)),
                        Err(error) => {
                            tracing::warn!(%error, %interface, "reading VPN interface statistics")
                        }
                    }
                    (
                        [(
                            header::CONTENT_TYPE,
                            "text/plain; version=0.0.4; charset=utf-8",
                        )],
                        body,
                    )
                        .into_response()
                }
            }),
        )
        .fallback(|| async { StatusCode::NOT_FOUND });
    tracing::info!(%address, "Prometheus metrics listening");
    axum::serve(listener, app).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn reads_linux_sysfs_counters_and_handles_missing_interfaces() {
        let root = Path::new("/sys/class/net");
        let stats = interface_stats(root, "lo").await.expect("sysfs");
        assert!(stats.is_some());
        assert_eq!(
            interface_stats(root, "tune_missing")
                .await
                .expect("missing"),
            None
        );
        assert!(interface_stats(root, "../../secret").await.is_err());
        let rendered = render_traffic(
            "wg0",
            Some(InterfaceStats {
                rx_bytes: 123,
                tx_bytes: 456,
            }),
        );
        assert!(rendered.contains("gluetun_tun_rx_bytes_total{interface=\"wg0\"} 123\n"));
        assert!(rendered.contains("gluetun_tun_tx_bytes_total{interface=\"wg0\"} 456\n"));
        assert!(render_traffic("wg0", None).contains("} 0\n"));
    }

    #[test]
    fn renders_numeric_low_cardinality_metrics() {
        let output = render(&Status::Stopped, false, 19);
        assert!(output.contains("tune_vpn_up 0\n"));
        assert!(output.contains("tune_health_healthy 0\n"));
        assert!(output.contains("tune_uptime_seconds 19\n"));
    }
}
