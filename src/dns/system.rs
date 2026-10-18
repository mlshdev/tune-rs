use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

use crate::config::DnsSettings;

const RESOLV_CONF: &str = "/etc/resolv.conf";

pub struct SystemResolver {
    path: PathBuf,
    original: String,
    installed: String,
}

impl SystemResolver {
    pub fn install(settings: &DnsSettings) -> io::Result<Self> {
        Self::install_at(settings, Path::new(RESOLV_CONF))
    }

    fn install_at(settings: &DnsSettings, path: &Path) -> io::Result<Self> {
        let original = std::fs::read_to_string(path)?;
        let ips: Vec<IpAddr> = if settings.server_enabled {
            let ip = settings.listen_address.ip();
            vec![match ip {
                IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
                IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
                ip => ip,
            }]
        } else {
            settings
                .upstream_plain_addresses
                .iter()
                .map(|address| address.ip())
                .collect()
        };
        let installed = format_resolver(&original, &ips);
        if installed != original
            && let Err(error) = std::fs::write(path, &installed)
        {
            let _ = std::fs::write(path, &original);
            return Err(error);
        }
        tracing::info!(nameservers = ?ips, "system DNS configured");
        Ok(Self {
            path: path.to_path_buf(),
            original,
            installed,
        })
    }

    pub fn restore(self) -> io::Result<()> {
        if self.original != self.installed && std::fs::read_to_string(&self.path)? == self.installed
        {
            std::fs::write(&self.path, self.original)?;
        }
        Ok(())
    }
}

fn format_resolver(original: &str, ips: &[IpAddr]) -> String {
    let mut output = String::new();
    for ip in ips {
        output.push_str(&format!("nameserver {ip}\n"));
    }
    for line in original.lines() {
        let keyword = line.split_whitespace().next().unwrap_or_default();
        if keyword != "nameserver" {
            output.push_str(line);
            output.push('\n');
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retains_search_options_not_old_nameservers() {
        let formatted = format_resolver(
            "nameserver 127.0.0.11\nsearch example.com\noptions ndots:0\n",
            &[IpAddr::V4(Ipv4Addr::LOCALHOST)],
        );
        assert_eq!(
            formatted,
            "nameserver 127.0.0.1\nsearch example.com\noptions ndots:0\n"
        );
    }

    #[test]
    fn restore_leaves_unchanged_resolver_untouched() {
        let path = std::env::temp_dir().join(format!("tune-dns-unchanged-{}", std::process::id()));
        let original = "nameserver 127.0.0.1\n".to_owned();
        std::fs::write(&path, &original).expect("resolver file");
        let timestamp = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1);
        std::fs::File::options()
            .write(true)
            .open(&path)
            .expect("open resolver")
            .set_times(std::fs::FileTimes::new().set_modified(timestamp))
            .expect("set timestamp");
        let resolver = SystemResolver {
            path: path.clone(),
            original: original.clone(),
            installed: original,
        };
        resolver
            .restore()
            .expect("unchanged resolver needs no write");
        assert_eq!(
            std::fs::metadata(&path)
                .expect("metadata")
                .modified()
                .expect("modified"),
            timestamp
        );
        std::fs::remove_file(path).expect("cleanup");
    }
}
