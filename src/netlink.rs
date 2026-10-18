use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use futures::TryStreamExt;
use ipnetwork::IpNetwork;
use rtnetlink::packet_route::AddressFamily;
use rtnetlink::packet_route::address::{AddressAttribute, AddressMessage};
use rtnetlink::packet_route::link::{
    InfoKind, LinkAttribute, LinkFlags, LinkInfo, LinkLayerType, LinkMessage,
};
use rtnetlink::packet_route::route::{
    RouteAddress, RouteAttribute, RouteHeader, RouteMessage, RouteMetric, RouteProtocol,
    RouteScope, RouteType,
};
use rtnetlink::packet_route::rule::{
    RuleAction, RuleAttribute, RuleFlags, RuleHeader, RuleMessage,
};
use rtnetlink::{Handle, IpVersion, LinkUnspec, LinkWireguard, RouteMessageBuilder};

pub const TABLE_MAIN: u32 = RouteHeader::RT_TABLE_MAIN as u32;
pub const TABLE_LOCAL: u32 = 255;

#[derive(Debug, thiserror::Error)]
pub enum NetlinkError {
    #[error("opening netlink socket: {0}")]
    Connect(#[source] std::io::Error),
    #[error("{op}: {source}")]
    Request {
        op: &'static str,
        #[source]
        source: Box<rtnetlink::Error>,
    },
    #[error("link {0} not found")]
    LinkNotFound(String),
    #[error("link {name} exists and is not a {expected} link")]
    LinkKind {
        name: String,
        expected: &'static str,
    },
    #[error("{family} route has {gateway} as gateway")]
    FamilyMismatch { family: Family, gateway: IpAddr },
}

impl NetlinkError {
    fn request(op: &'static str) -> impl FnOnce(rtnetlink::Error) -> Self {
        move |source| Self::Request {
            op,
            source: Box::new(source),
        }
    }

    pub fn errno(&self) -> Option<i32> {
        match self {
            Self::Request { source, .. } => match source.as_ref() {
                rtnetlink::Error::NetlinkError(message) => message.code.map(|code| -code.get()),
                _ => None,
            },
            _ => None,
        }
    }

    pub fn is_exists(&self) -> bool {
        self.errno() == Some(libc::EEXIST)
    }

    pub fn is_not_found(&self) -> bool {
        matches!(
            self.errno(),
            Some(libc::ENOENT | libc::ESRCH | libc::ENODEV)
        )
    }

    pub fn is_permission_denied(&self) -> bool {
        matches!(self.errno(), Some(libc::EACCES | libc::EPERM))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Family {
    V4,
    V6,
}

impl Family {
    pub fn of(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(_) => Self::V4,
            IpAddr::V6(_) => Self::V6,
        }
    }

    pub fn unspecified(self) -> IpAddr {
        match self {
            Self::V4 => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            Self::V6 => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        }
    }

    pub fn host_prefix(self) -> u8 {
        match self {
            Self::V4 => 32,
            Self::V6 => 128,
        }
    }

    fn address_family(self) -> AddressFamily {
        match self {
            Self::V4 => AddressFamily::Inet,
            Self::V6 => AddressFamily::Inet6,
        }
    }

    fn ip_version(self) -> IpVersion {
        match self {
            Self::V4 => IpVersion::V4,
            Self::V6 => IpVersion::V6,
        }
    }

    fn from_address_family(family: AddressFamily) -> Option<Self> {
        match family {
            AddressFamily::Inet => Some(Self::V4),
            AddressFamily::Inet6 => Some(Self::V6),
            _ => None,
        }
    }
}

impl std::fmt::Display for Family {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::V4 => "IPv4",
            Self::V6 => "IPv6",
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Link {
    pub index: u32,
    pub name: String,
    pub ethernet: bool,
    pub kind: Option<InfoKind>,
    pub up: bool,
    pub mtu: Option<u32>,
}

impl Link {
    fn from_message(message: &LinkMessage) -> Self {
        let mut link = Self {
            index: message.header.index,
            name: String::new(),
            ethernet: message.header.link_layer_type == LinkLayerType::Ether,
            kind: None,
            up: message.header.flags.contains(LinkFlags::Up),
            mtu: None,
        };
        for attribute in &message.attributes {
            match attribute {
                LinkAttribute::IfName(name) => link.name.clone_from(name),
                LinkAttribute::Mtu(mtu) => link.mtu = Some(*mtu),
                LinkAttribute::LinkInfo(infos) => {
                    link.kind = infos.iter().find_map(|info| match info {
                        LinkInfo::Kind(kind) => Some(kind.clone()),
                        _ => None,
                    });
                }
                _ => {}
            }
        }
        link
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Route {
    pub family: Family,
    pub table: u32,
    pub destination: Option<IpNetwork>,
    pub source: Option<IpNetwork>,
    pub pref_source: Option<IpAddr>,
    pub gateway: Option<IpAddr>,
    pub output_interface: Option<u32>,
    pub kind: RouteType,
    pub scope: RouteScope,
    pub protocol: RouteProtocol,
    pub priority: Option<u32>,
    pub advmss: Option<u32>,
}

impl Route {
    pub fn unicast(family: Family, table: u32) -> Self {
        Self {
            family,
            table,
            destination: None,
            source: None,
            pref_source: None,
            gateway: None,
            output_interface: None,
            kind: RouteType::Unicast,
            scope: RouteScope::Universe,
            protocol: RouteProtocol::Static,
            priority: None,
            advmss: None,
        }
    }

    pub fn is_default(&self) -> bool {
        self.destination
            .is_none_or(|network| network.prefix() == 0 && network.ip().is_unspecified())
    }

    fn from_message(message: &RouteMessage) -> Option<Self> {
        let family = Family::from_address_family(message.header.address_family)?;
        let mut route = Self {
            family,
            table: u32::from(message.header.table),
            destination: None,
            source: None,
            pref_source: None,
            gateway: None,
            output_interface: None,
            kind: message.header.kind,
            scope: message.header.scope,
            protocol: message.header.protocol,
            priority: None,
            advmss: None,
        };
        for attribute in &message.attributes {
            match attribute {
                RouteAttribute::Table(table) => route.table = *table,
                RouteAttribute::Destination(address) => {
                    route.destination = route_address(address).and_then(|ip| {
                        IpNetwork::new(ip, message.header.destination_prefix_length).ok()
                    });
                }
                RouteAttribute::Source(address) => {
                    route.source = route_address(address).and_then(|ip| {
                        IpNetwork::new(ip, message.header.source_prefix_length).ok()
                    });
                }
                RouteAttribute::PrefSource(address) => route.pref_source = route_address(address),
                RouteAttribute::Gateway(address) => route.gateway = route_address(address),
                RouteAttribute::Oif(index) => route.output_interface = Some(*index),
                RouteAttribute::Priority(priority) => route.priority = Some(*priority),
                RouteAttribute::Metrics(metrics) => {
                    route.advmss = metrics.iter().find_map(|metric| match metric {
                        RouteMetric::Advmss(advmss) => Some(*advmss),
                        _ => None,
                    });
                }
                _ => {}
            }
        }
        Some(route)
    }

    fn to_message(&self) -> Result<RouteMessage, NetlinkError> {
        let mut builder = match self.family {
            Family::V4 => RouteMessageBuilder::<Ipv4Addr>::new().build(),
            Family::V6 => RouteMessageBuilder::<Ipv6Addr>::new().build(),
        };
        let header = &mut builder.header;
        header.kind = self.kind;
        header.scope = self.scope;
        header.protocol = self.protocol;
        match u8::try_from(self.table) {
            Ok(table) => header.table = table,
            Err(_) => {
                header.table = RouteHeader::RT_TABLE_UNSPEC;
                builder.attributes.push(RouteAttribute::Table(self.table));
            }
        }
        if let Some(destination) = self.destination {
            builder.header.destination_prefix_length = destination.prefix();
            builder
                .attributes
                .push(RouteAttribute::Destination(RouteAddress::from(
                    destination.ip(),
                )));
        }
        if let Some(source) = self.source {
            builder.header.source_prefix_length = source.prefix();
            builder
                .attributes
                .push(RouteAttribute::Source(RouteAddress::from(source.ip())));
        }
        if let Some(pref_source) = self.pref_source {
            builder
                .attributes
                .push(RouteAttribute::PrefSource(RouteAddress::from(pref_source)));
        }
        if let Some(gateway) = self.gateway {
            if Family::of(gateway) != self.family {
                return Err(NetlinkError::FamilyMismatch {
                    family: self.family,
                    gateway,
                });
            }
            builder
                .attributes
                .push(RouteAttribute::Gateway(RouteAddress::from(gateway)));
        }
        if let Some(index) = self.output_interface {
            builder.attributes.push(RouteAttribute::Oif(index));
        }
        if let Some(priority) = self.priority {
            builder.attributes.push(RouteAttribute::Priority(priority));
        }
        if let Some(advmss) = self.advmss {
            builder
                .attributes
                .push(RouteAttribute::Metrics(vec![RouteMetric::Advmss(advmss)]));
        }
        Ok(builder)
    }
}

impl std::fmt::Display for Route {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.destination {
            Some(destination) if !self.is_default() => write!(f, "{destination}")?,
            _ => f.write_str("default")?,
        }
        if let Some(gateway) = self.gateway {
            write!(f, " via {gateway}")?;
        }
        if let Some(index) = self.output_interface {
            write!(f, " dev #{index}")?;
        }
        write!(f, " table {}", self.table)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    pub family: Family,
    pub priority: u32,
    pub table: u32,
    pub fwmark: Option<u32>,
    pub source: Option<IpNetwork>,
    pub destination: Option<IpNetwork>,
    pub invert: bool,
}

impl Rule {
    pub fn to_table(family: Family, priority: u32, table: u32) -> Self {
        Self {
            family,
            priority,
            table,
            fwmark: None,
            source: None,
            destination: None,
            invert: false,
        }
    }

    fn from_message(message: &RuleMessage) -> Option<Self> {
        let family = Family::from_address_family(message.header.family)?;
        let mut rule = Self {
            family,
            priority: 0,
            table: u32::from(message.header.table),
            fwmark: None,
            source: None,
            destination: None,
            invert: message.header.flags.contains(RuleFlags::Invert),
        };
        for attribute in &message.attributes {
            match attribute {
                RuleAttribute::Priority(priority) => rule.priority = *priority,
                RuleAttribute::Table(table) => rule.table = *table,
                RuleAttribute::FwMark(mark) => rule.fwmark = Some(*mark),
                RuleAttribute::Source(ip) => {
                    rule.source = IpNetwork::new(*ip, message.header.src_len).ok();
                }
                RuleAttribute::Destination(ip) => {
                    rule.destination = IpNetwork::new(*ip, message.header.dst_len).ok();
                }
                _ => {}
            }
        }
        Some(rule)
    }

    fn to_message(&self) -> RuleMessage {
        let mut message = RuleMessage::default();
        let mut header = RuleHeader {
            family: self.family.address_family(),
            action: RuleAction::ToTable,
            ..RuleHeader::default()
        };
        if self.invert {
            header.flags = RuleFlags::Invert;
        }
        match u8::try_from(self.table) {
            Ok(table) => header.table = table,
            Err(_) => message.attributes.push(RuleAttribute::Table(self.table)),
        }
        message
            .attributes
            .push(RuleAttribute::Priority(self.priority));
        if let Some(mark) = self.fwmark {
            message.attributes.push(RuleAttribute::FwMark(mark));
        }
        if let Some(source) = self.source {
            header.src_len = source.prefix();
            message.attributes.push(RuleAttribute::Source(source.ip()));
        }
        if let Some(destination) = self.destination {
            header.dst_len = destination.prefix();
            message
                .attributes
                .push(RuleAttribute::Destination(destination.ip()));
        }
        message.header = header;
        message
    }
}

impl std::fmt::Display for Rule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: ", self.priority)?;
        if self.invert {
            f.write_str("not ")?;
        }
        match self.source {
            Some(source) => write!(f, "from {source}")?,
            None => f.write_str("from all")?,
        }
        if let Some(destination) = self.destination {
            write!(f, " to {destination}")?;
        }
        if let Some(mark) = self.fwmark {
            write!(f, " fwmark {mark:#x}")?;
        }
        write!(f, " lookup {}", self.table)
    }
}

fn route_address(address: &RouteAddress) -> Option<IpAddr> {
    match address {
        RouteAddress::Inet(ip) => Some(IpAddr::V4(*ip)),
        RouteAddress::Inet6(ip) => Some(IpAddr::V6(*ip)),
        _ => None,
    }
}

fn address_network(message: &AddressMessage) -> Option<IpNetwork> {
    let local = message
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            AddressAttribute::Local(ip) => Some(*ip),
            _ => None,
        });
    let address = message
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            AddressAttribute::Address(ip) => Some(*ip),
            _ => None,
        });
    IpNetwork::new(local.or(address)?, message.header.prefix_len).ok()
}

#[derive(Clone, Debug)]
pub struct Netlink {
    handle: Handle,
}

impl Netlink {
    pub fn connect() -> Result<Self, NetlinkError> {
        let (connection, handle, _) = rtnetlink::new_connection().map_err(NetlinkError::Connect)?;
        tokio::spawn(connection);
        Ok(Self { handle })
    }

    pub async fn links(&self) -> Result<Vec<Link>, NetlinkError> {
        let messages: Vec<LinkMessage> = self
            .handle
            .link()
            .get()
            .execute()
            .try_collect()
            .await
            .map_err(NetlinkError::request("listing links"))?;
        Ok(messages.iter().map(Link::from_message).collect())
    }

    pub async fn link_by_name(&self, name: &str) -> Result<Option<Link>, NetlinkError> {
        let result: Result<Vec<LinkMessage>, _> = self
            .handle
            .link()
            .get()
            .match_name(name.to_owned())
            .execute()
            .try_collect()
            .await;
        match result.map_err(NetlinkError::request("getting link")) {
            Ok(messages) => Ok(messages.first().map(Link::from_message)),
            Err(error) if error.is_not_found() => Ok(None),
            Err(error) => Err(error),
        }
    }

    pub async fn link_by_index(&self, index: u32) -> Result<Option<Link>, NetlinkError> {
        let result: Result<Vec<LinkMessage>, _> = self
            .handle
            .link()
            .get()
            .match_index(index)
            .execute()
            .try_collect()
            .await;
        match result.map_err(NetlinkError::request("getting link")) {
            Ok(messages) => Ok(messages.first().map(Link::from_message)),
            Err(error) if error.is_not_found() => Ok(None),
            Err(error) => Err(error),
        }
    }

    pub async fn link_delete(&self, index: u32) -> Result<(), NetlinkError> {
        self.handle
            .link()
            .del(index)
            .execute()
            .await
            .map_err(NetlinkError::request("deleting link"))
    }

    pub async fn wireguard_add(&self, name: &str, mtu: u32) -> Result<Link, NetlinkError> {
        if let Some(existing) = self.link_by_name(name).await? {
            if existing.kind != Some(InfoKind::Wireguard) {
                return Err(NetlinkError::LinkKind {
                    name: name.to_owned(),
                    expected: "wireguard",
                });
            }
            self.link_delete(existing.index).await?;
        }
        let message = LinkWireguard::new(name).mtu(mtu).build();
        self.handle
            .link()
            .add(message)
            .execute()
            .await
            .map_err(NetlinkError::request("adding wireguard link"))?;
        self.link_by_name(name)
            .await?
            .ok_or_else(|| NetlinkError::LinkNotFound(name.to_owned()))
    }

    pub async fn link_set_up(&self, index: u32) -> Result<(), NetlinkError> {
        let message = LinkUnspec::new_with_index(index).up().build();
        self.link_set(message, "setting link up").await
    }

    pub async fn link_set_down(&self, index: u32) -> Result<(), NetlinkError> {
        let message = LinkUnspec::new_with_index(index).down().build();
        self.link_set(message, "setting link down").await
    }

    pub async fn link_set_mtu(&self, index: u32, mtu: u32) -> Result<(), NetlinkError> {
        let message = LinkUnspec::new_with_index(index).mtu(mtu).build();
        self.link_set(message, "setting link MTU").await
    }

    async fn link_set(&self, message: LinkMessage, op: &'static str) -> Result<(), NetlinkError> {
        self.handle
            .link()
            .set(message)
            .execute()
            .await
            .map_err(NetlinkError::request(op))
    }

    pub async fn addresses(&self, index: u32) -> Result<Vec<IpNetwork>, NetlinkError> {
        let messages: Vec<AddressMessage> = self
            .handle
            .address()
            .get()
            .set_link_index_filter(index)
            .execute()
            .try_collect()
            .await
            .map_err(NetlinkError::request("listing addresses"))?;
        Ok(messages.iter().filter_map(address_network).collect())
    }

    pub async fn address_add(&self, index: u32, network: IpNetwork) -> Result<(), NetlinkError> {
        self.handle
            .address()
            .add(index, network.ip(), network.prefix())
            .replace()
            .execute()
            .await
            .map_err(NetlinkError::request("adding address"))
    }

    pub async fn routes(&self, family: Family) -> Result<Vec<Route>, NetlinkError> {
        let filter = match family {
            Family::V4 => RouteMessageBuilder::<Ipv4Addr>::new().build(),
            Family::V6 => RouteMessageBuilder::<Ipv6Addr>::new().build(),
        };
        let messages: Vec<RouteMessage> = self
            .handle
            .route()
            .get(filter)
            .execute()
            .try_collect()
            .await
            .map_err(NetlinkError::request("listing routes"))?;
        Ok(messages.iter().filter_map(Route::from_message).collect())
    }

    pub async fn all_routes(&self) -> Result<Vec<Route>, NetlinkError> {
        let mut routes = self.routes(Family::V4).await?;
        routes.extend(self.routes(Family::V6).await?);
        Ok(routes)
    }

    pub async fn route_add(&self, route: &Route) -> Result<(), NetlinkError> {
        self.handle
            .route()
            .add(route.to_message()?)
            .execute()
            .await
            .map_err(NetlinkError::request("adding route"))
    }

    pub async fn route_replace(&self, route: &Route) -> Result<(), NetlinkError> {
        self.handle
            .route()
            .add(route.to_message()?)
            .replace()
            .execute()
            .await
            .map_err(NetlinkError::request("replacing route"))
    }

    pub async fn route_delete(&self, route: &Route) -> Result<(), NetlinkError> {
        self.handle
            .route()
            .del(route.to_message()?)
            .execute()
            .await
            .map_err(NetlinkError::request("deleting route"))
    }

    pub async fn rules(&self, family: Family) -> Result<Vec<Rule>, NetlinkError> {
        let messages: Vec<RuleMessage> = self
            .handle
            .rule()
            .get(family.ip_version())
            .execute()
            .try_collect()
            .await
            .map_err(NetlinkError::request("listing rules"))?;
        Ok(messages.iter().filter_map(Rule::from_message).collect())
    }

    pub async fn rule_add(&self, rule: &Rule) -> Result<(), NetlinkError> {
        let mut request = self.handle.rule().add();
        *request.message_mut() = rule.to_message();
        request
            .execute()
            .await
            .map_err(NetlinkError::request("adding rule"))
    }

    pub async fn rule_delete(&self, rule: &Rule) -> Result<(), NetlinkError> {
        self.handle
            .rule()
            .del(rule.to_message())
            .execute()
            .await
            .map_err(NetlinkError::request("deleting rule"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_message_roundtrip() {
        let rule = Rule {
            family: Family::V4,
            priority: 101,
            table: 51820,
            fwmark: Some(51820),
            source: None,
            destination: None,
            invert: true,
        };
        let parsed = Rule::from_message(&rule.to_message()).expect("IPv4 rule");
        assert_eq!(parsed, rule);
    }

    #[test]
    fn route_message_roundtrip() {
        let mut route = Route::unicast(Family::V6, 199);
        route.destination = Some("fd00::/8".parse().expect("valid network"));
        route.gateway = Some("fe80::1".parse().expect("valid address"));
        route.output_interface = Some(3);
        route.advmss = Some(1240);
        let parsed =
            Route::from_message(&route.to_message().expect("valid route")).expect("IPv6 route");
        assert_eq!(parsed, route);
    }

    #[test]
    fn route_rejects_mixed_family_gateway() {
        let mut route = Route::unicast(Family::V4, TABLE_MAIN);
        route.gateway = Some("::1".parse().expect("valid address"));
        assert!(matches!(
            route.to_message(),
            Err(NetlinkError::FamilyMismatch { .. })
        ));
    }

    #[test]
    fn default_route_detection() {
        let mut route = Route::unicast(Family::V4, TABLE_MAIN);
        assert!(route.is_default());
        route.destination = Some("0.0.0.0/0".parse().expect("valid network"));
        assert!(route.is_default());
        route.destination = Some("10.0.0.0/8".parse().expect("valid network"));
        assert!(!route.is_default());
    }
}
