use std::collections::BTreeSet;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use ipnetwork::IpNetwork;
use rtnetlink::packet_route::route::RouteType;
use tokio::sync::Mutex;

use crate::netlink::{Family, Link, Netlink, NetlinkError, Route, Rule, TABLE_LOCAL, TABLE_MAIN};

const INBOUND_TABLE: u32 = 200;
const INBOUND_PRIORITY: u32 = 100;
const OUTBOUND_TABLE: u32 = 199;
const OUTBOUND_PRIORITY: u32 = 99;
const LOCAL_PRIORITY: u32 = 98;
const IPV6_DIAL_TIMEOUT: Duration = Duration::from_secs(1);

type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Debug, thiserror::Error)]
pub enum RoutingError {
    #[error(transparent)]
    Netlink(#[from] NetlinkError),
    #[error("no default route found in {0} routes")]
    NoDefaultRoute(usize),
    #[error("no ethernet link found in {0} links")]
    NoLocalLink(usize),
    #[error("no local subnet found in {0} routes")]
    NoLocalNetwork(usize),
    #[error("link #{0} not found")]
    LinkIndex(u32),
    #[error("link {0} not found")]
    LinkName(String),
    #[error("no {family} address assigned to {interface}")]
    NoAssignedIp { interface: String, family: Family },
    #[error("{action} rule {rule}: {source}")]
    Rule {
        action: &'static str,
        rule: Box<Rule>,
        #[source]
        source: NetlinkError,
    },
    #[error("{action} route {route}: {source}")]
    Route {
        action: &'static str,
        route: Box<Route>,
        #[source]
        source: NetlinkError,
    },
    #[error("firewall: {0}")]
    Firewall(#[source] BoxError),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DefaultRoute {
    pub interface: String,
    pub index: u32,
    pub gateway: Option<IpAddr>,
    pub assigned_ip: IpAddr,
    pub family: Family,
}

impl std::fmt::Display for DefaultRoute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} default route on {}", self.family, self.interface)?;
        if let Some(gateway) = self.gateway {
            write!(f, " via {gateway}")?;
        }
        write!(f, " with assigned IP {}", self.assigned_ip)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalNetwork {
    pub network: IpNetwork,
    pub interface: String,
    pub ip: IpAddr,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Ipv6Support {
    Unsupported,
    Supported,
    Internet,
}

impl Ipv6Support {
    pub fn is_supported(self) -> bool {
        self != Self::Unsupported
    }
}

pub trait OutputGate {
    type Error: std::error::Error + Send + Sync + 'static;

    fn accept_output(
        &self,
        interface: &str,
        destination: SocketAddr,
        remove: bool,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
}

pub fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_private() || ip.is_loopback() || ip.is_link_local(),
        IpAddr::V6(ip) => {
            let first = ip.segments()[0];
            first & 0xfe00 == 0xfc00
                || ip.is_loopback()
                || first & 0xffc0 == 0xfe80
                || (first & 0xff0f) == 0xff02
        }
    }
}

fn is_link_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_link_local() || ip.octets()[..3] == [224, 0, 0],
        IpAddr::V6(ip) => {
            let first = ip.segments()[0];
            first & 0xffc0 == 0xfe80 || (first & 0xff0f) == 0xff02
        }
    }
}

fn host_network(ip: IpAddr) -> IpNetwork {
    IpNetwork::new(ip, Family::of(ip).host_prefix()).expect("host prefix length is valid")
}

fn default_network(family: Family) -> IpNetwork {
    IpNetwork::new(family.unspecified(), 0).expect("prefix length 0 is valid")
}

fn rules_equal(a: &Rule, b: &Rule) -> bool {
    a.source == b.source
        && a.destination == b.destination
        && a.priority == b.priority
        && a.table == b.table
}

pub struct Routing {
    netlink: Netlink,
    outbound_subnets: Mutex<Vec<IpNetwork>>,
}

impl Routing {
    pub fn new(netlink: Netlink) -> Self {
        Self {
            netlink,
            outbound_subnets: Mutex::new(Vec::new()),
        }
    }

    pub fn netlink(&self) -> &Netlink {
        &self.netlink
    }

    async fn link_by_index(&self, index: u32) -> Result<Link, RoutingError> {
        self.netlink
            .link_by_index(index)
            .await?
            .ok_or(RoutingError::LinkIndex(index))
    }

    async fn link_by_name(&self, name: &str) -> Result<Link, RoutingError> {
        self.netlink
            .link_by_name(name)
            .await?
            .ok_or_else(|| RoutingError::LinkName(name.to_owned()))
    }

    pub async fn assigned_ip(&self, link: &Link, family: Family) -> Result<IpAddr, RoutingError> {
        self.netlink
            .addresses(link.index)
            .await?
            .into_iter()
            .map(|network| network.ip())
            .find(|ip| Family::of(*ip) == family)
            .ok_or_else(|| RoutingError::NoAssignedIp {
                interface: link.name.clone(),
                family,
            })
    }

    pub async fn default_routes(&self) -> Result<Vec<DefaultRoute>, RoutingError> {
        let routes = self.netlink.all_routes().await?;
        let mut defaults = Vec::new();
        for route in routes
            .iter()
            .filter(|route| route.table == TABLE_MAIN && route.is_default())
        {
            let Some(index) = route.output_interface else {
                continue;
            };
            if matches!(
                route.kind,
                RouteType::Unreachable | RouteType::Prohibit | RouteType::BlackHole
            ) {
                continue;
            }
            let link = self.link_by_index(index).await?;
            let family = route.gateway.map_or(route.family, Family::of);
            let assigned_ip = self.assigned_ip(&link, family).await?;
            let default = DefaultRoute {
                interface: link.name,
                index,
                gateway: route.gateway,
                assigned_ip,
                family,
            };
            tracing::info!("found {default}");
            defaults.push(default);
        }
        if defaults.is_empty() {
            return Err(RoutingError::NoDefaultRoute(routes.len()));
        }
        Ok(defaults)
    }

    pub async fn local_networks(&self) -> Result<Vec<LocalNetwork>, RoutingError> {
        let links = self.netlink.links().await?;
        let local_links: Vec<&Link> = links.iter().filter(|link| link.ethernet).collect();
        if local_links.is_empty() {
            return Err(RoutingError::NoLocalLink(links.len()));
        }
        for link in &local_links {
            tracing::info!(interface = %link.name, "found local ethernet link");
        }
        let routes = self.netlink.all_routes().await?;
        let mut networks = Vec::new();
        for route in &routes {
            let Some(destination) = route.destination else {
                continue;
            };
            if route.table != TABLE_MAIN
                || route
                    .gateway
                    .is_some_and(|gateway| !gateway.is_unspecified())
                || destination.ip().is_unspecified()
            {
                continue;
            }
            let Some(link) = local_links
                .iter()
                .find(|link| Some(link.index) == route.output_interface)
            else {
                continue;
            };
            let ip = self.assigned_ip(link, route.family).await?;
            tracing::info!(network = %destination, interface = %link.name, "found local network");
            networks.push(LocalNetwork {
                network: destination,
                interface: link.name.clone(),
                ip,
            });
        }
        if networks.is_empty() {
            return Err(RoutingError::NoLocalNetwork(routes.len()));
        }
        Ok(networks)
    }

    pub async fn add_local_rules(&self, networks: &[LocalNetwork]) -> Result<(), RoutingError> {
        for network in networks {
            let mut rule =
                Rule::to_table(Family::of(network.network.ip()), LOCAL_PRIORITY, TABLE_MAIN);
            rule.destination = Some(network.network);
            self.add_rule(&rule).await?;
        }
        Ok(())
    }

    pub async fn remove_local_rules(&self, networks: &[LocalNetwork]) -> Result<(), RoutingError> {
        for network in networks {
            let mut rule =
                Rule::to_table(Family::of(network.network.ip()), LOCAL_PRIORITY, TABLE_MAIN);
            rule.destination = Some(network.network);
            self.delete_rule(&rule).await?;
        }
        Ok(())
    }

    async fn add_rule(&self, rule: &Rule) -> Result<(), RoutingError> {
        let existing = self.netlink.rules(rule.family).await?;
        if existing
            .iter()
            .any(|candidate| rules_equal(candidate, rule))
        {
            return Ok(());
        }
        tracing::debug!("ip rule add {rule}");
        self.netlink
            .rule_add(rule)
            .await
            .map_err(|source| RoutingError::Rule {
                action: "adding",
                rule: Box::new(rule.clone()),
                source,
            })
    }

    async fn delete_rule(&self, rule: &Rule) -> Result<(), RoutingError> {
        let existing = self.netlink.rules(rule.family).await?;
        for candidate in existing
            .iter()
            .filter(|candidate| rules_equal(candidate, rule))
        {
            tracing::debug!("ip rule del {candidate}");
            self.netlink
                .rule_delete(rule)
                .await
                .map_err(|source| RoutingError::Rule {
                    action: "deleting",
                    rule: Box::new(rule.clone()),
                    source,
                })?;
        }
        Ok(())
    }

    fn route_via(destination: IpNetwork, default: &DefaultRoute, table: u32) -> Route {
        let mut route = Route::unicast(Family::of(destination.ip()), table);
        route.destination = Some(destination);
        route.gateway = default.gateway;
        route.output_interface = Some(default.index);
        route
    }

    async fn replace_route(&self, route: &Route) -> Result<(), RoutingError> {
        tracing::debug!("ip route replace {route}");
        self.netlink
            .route_replace(route)
            .await
            .map_err(|source| RoutingError::Route {
                action: "replacing",
                route: Box::new(route.clone()),
                source,
            })
    }

    async fn delete_route(&self, route: &Route) -> Result<(), RoutingError> {
        tracing::debug!("ip route del {route}");
        match self.netlink.route_delete(route).await {
            Err(source) if !source.is_not_found() => Err(RoutingError::Route {
                action: "deleting",
                route: Box::new(route.clone()),
                source,
            }),
            _ => Ok(()),
        }
    }

    pub async fn setup(
        &self,
        defaults: &[DefaultRoute],
        outbound_subnets: &[IpNetwork],
    ) -> Result<(), RoutingError> {
        let result = async {
            self.route_inbound(defaults).await?;
            self.apply_outbound_subnets(outbound_subnets, defaults)
                .await
        }
        .await;
        if let Err(error) = &result {
            tracing::error!(%error, "routing setup failed, reverting");
            if let Err(teardown) = self.teardown(defaults).await {
                tracing::error!(error = %teardown, "cannot revert routing changes");
            }
        }
        result
    }

    pub async fn teardown(&self, defaults: &[DefaultRoute]) -> Result<(), RoutingError> {
        self.unroute_inbound(defaults).await?;
        self.apply_outbound_subnets(&[], defaults).await
    }

    fn inbound_rule(default: &DefaultRoute) -> Rule {
        let mut rule = Rule::to_table(default.family, INBOUND_PRIORITY, INBOUND_TABLE);
        rule.source = Some(host_network(default.assigned_ip));
        rule
    }

    async fn route_inbound(&self, defaults: &[DefaultRoute]) -> Result<(), RoutingError> {
        for default in defaults {
            self.add_rule(&Self::inbound_rule(default)).await?;
        }
        for default in defaults {
            let route = Self::route_via(default_network(default.family), default, INBOUND_TABLE);
            self.replace_route(&route).await?;
        }
        Ok(())
    }

    async fn unroute_inbound(&self, defaults: &[DefaultRoute]) -> Result<(), RoutingError> {
        for default in defaults {
            let route = Self::route_via(default_network(default.family), default, INBOUND_TABLE);
            self.delete_route(&route).await?;
        }
        for default in defaults {
            self.delete_rule(&Self::inbound_rule(default)).await?;
        }
        Ok(())
    }

    pub async fn set_outbound_subnets(&self, subnets: &[IpNetwork]) -> Result<(), RoutingError> {
        let defaults = self.default_routes().await?;
        self.apply_outbound_subnets(subnets, &defaults).await
    }

    async fn apply_outbound_subnets(
        &self,
        subnets: &[IpNetwork],
        defaults: &[DefaultRoute],
    ) -> Result<(), RoutingError> {
        let mut current = self.outbound_subnets.lock().await;
        let old: BTreeSet<IpNetwork> = current.iter().copied().collect();
        let new: BTreeSet<IpNetwork> = subnets.iter().copied().collect();
        for subnet in old.difference(&new) {
            for default in defaults
                .iter()
                .filter(|default| default.family == Family::of(subnet.ip()))
            {
                let route = Self::route_via(*subnet, default, OUTBOUND_TABLE);
                if let Err(error) = self.delete_route(&route).await {
                    tracing::warn!(%error, "cannot remove outdated outbound subnet route");
                }
            }
            let mut rule =
                Rule::to_table(Family::of(subnet.ip()), OUTBOUND_PRIORITY, OUTBOUND_TABLE);
            rule.destination = Some(*subnet);
            if let Err(error) = self.delete_rule(&rule).await {
                tracing::warn!(%error, "cannot remove outdated outbound subnet rule");
            }
            current.retain(|existing| existing != subnet);
        }
        for subnet in new.difference(&old) {
            let family = Family::of(subnet.ip());
            let Some(default) = defaults.iter().find(|default| default.family == family) else {
                tracing::warn!(%subnet, "no {family} default route for outbound subnet, skipping");
                continue;
            };
            tracing::info!(%subnet, "routing outbound subnet");
            self.replace_route(&Self::route_via(*subnet, default, OUTBOUND_TABLE))
                .await?;
            let mut rule = Rule::to_table(family, OUTBOUND_PRIORITY, OUTBOUND_TABLE);
            rule.destination = Some(*subnet);
            self.add_rule(&rule).await?;
            current.push(*subnet);
        }
        Ok(())
    }

    pub async fn ipv6_support<G: OutputGate + Sync>(
        &self,
        check_addresses: &[SocketAddr],
        gate: &G,
    ) -> Result<Ipv6Support, RoutingError> {
        let routes = self.netlink.routes(Family::V6).await?;
        let mut level = Ipv6Support::Unsupported;
        for route in &routes {
            if route
                .destination
                .is_some_and(|destination| destination.ip().is_loopback())
                || matches!(
                    route.kind,
                    RouteType::Unreachable | RouteType::Prohibit | RouteType::BlackHole
                )
            {
                continue;
            }
            let Some(index) = route.output_interface else {
                continue;
            };
            let link = self.link_by_index(index).await?;
            if !route.is_default() {
                tracing::debug!(interface = %link.name, "IPv6 is supported by link");
                level = level.max(Ipv6Support::Supported);
                continue;
            }
            tracing::debug!(interface = %link.name, "IPv6 default route found");
            level = level.max(Ipv6Support::Supported);
            for address in check_addresses.iter().filter(|address| address.is_ipv6()) {
                match dial_through(&link.name, *address, gate).await? {
                    Ok(()) => {
                        tracing::debug!(interface = %link.name, "IPv6 internet is reachable");
                        return Ok(Ipv6Support::Internet);
                    }
                    Err(error) => tracing::debug!(%error, "IPv6 dial failed"),
                }
            }
        }
        if level == Ipv6Support::Unsupported {
            tracing::debug!("no IPv6 route found in {} routes", routes.len());
        }
        Ok(level)
    }

    pub async fn vpn_routes(&self, interface: &str) -> Result<Vec<Route>, RoutingError> {
        let link = self.link_by_name(interface).await?;
        let routes = self.netlink.all_routes().await?;
        Ok(routes
            .into_iter()
            .filter(|route| {
                route.output_interface == Some(link.index) && route.table != TABLE_LOCAL
            })
            .filter(|route| match route.destination {
                None => true,
                Some(destination) if destination.ip().is_unspecified() => true,
                Some(destination) => {
                    !is_link_local(destination.ip()) && !is_private(destination.ip())
                }
            })
            .collect())
    }
}

#[derive(Debug, thiserror::Error)]
#[error("dialing {address} through {interface}: {source}")]
pub struct DialError {
    interface: String,
    address: SocketAddr,
    #[source]
    source: std::io::Error,
}

async fn dial_through<G: OutputGate + Sync>(
    interface: &str,
    address: SocketAddr,
    gate: &G,
) -> Result<Result<(), DialError>, RoutingError> {
    gate.accept_output(interface, address, false)
        .await
        .map_err(|error| RoutingError::Firewall(Box::new(error)))?;
    let dialed = dial_device(interface, address)
        .await
        .map_err(|source| DialError {
            interface: interface.to_owned(),
            address,
            source,
        });
    gate.accept_output(interface, address, true)
        .await
        .map_err(|error| RoutingError::Firewall(Box::new(error)))?;
    Ok(dialed)
}

pub async fn dial_device(interface: &str, address: SocketAddr) -> std::io::Result<()> {
    let domain = socket2::Domain::for_address(address);
    let socket = socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;
    socket.set_nonblocking(true)?;
    socket.bind_device(Some(interface.as_bytes()))?;
    let socket = tokio::net::TcpSocket::from_std_stream(socket.into());
    let stream = tokio::time::timeout(IPV6_DIAL_TIMEOUT, socket.connect(address))
        .await
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::TimedOut))??;
    drop(stream);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_addresses() {
        for ip in [
            "10.0.0.1",
            "172.16.5.4",
            "192.168.1.1",
            "127.0.0.1",
            "169.254.1.1",
            "fd00::1",
            "fe80::1",
            "::1",
        ] {
            assert!(is_private(ip.parse().expect("valid IP")), "{ip}");
        }
        for ip in ["1.1.1.1", "100.64.0.1", "2a07:e340::2", "2001:db8::1"] {
            assert!(!is_private(ip.parse().expect("valid IP")), "{ip}");
        }
    }

    #[test]
    fn rule_equality_ignores_fwmark_and_family_details() {
        let mut a = Rule::to_table(Family::V4, 99, 199);
        a.destination = Some("192.168.0.0/16".parse().expect("valid network"));
        let mut b = a.clone();
        b.fwmark = Some(1);
        assert!(rules_equal(&a, &b));
        b.priority = 98;
        assert!(!rules_equal(&a, &b));
    }
}
