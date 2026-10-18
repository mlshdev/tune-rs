use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CStr, CString};
use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use ipnetwork::{IpNetwork, Ipv6Network};
use nftnl::expr::{
    Bitwise, Cmp, CmpOp, Conntrack, Immediate, InterfaceName, Payload, Register, States,
    TransportHeaderField,
};
use nftnl::{
    Batch, Chain, ChainType, FinalizedBatch, Hook, MsgType, Policy, ProtoFamily, Rule, Table,
    nft_expr,
};
use tokio::sync::Mutex;

use crate::netlink::Family;
use crate::routing::{DefaultRoute, LocalNetwork, OutputGate};

const TABLE_NAME: &CStr = c"tune";
const FILTER_PRIORITY: i32 = 0;
const INBOUND_CONNECTION_MARK: u32 = 0x74756e65;
const NFNL_SUBSYS_CTNETLINK: u16 = 1;
const IPCTNL_MSG_CT_DELETE: u16 = 2;
const NFNETLINK_V0: u8 = 0;
const TCP_FLAGS_OFFSET: u32 = 13;
const TCP_FLAG_RST: u8 = 0x04;
const SOLICITED_NODE_MULTICAST: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 1, 0xff00, 0);
const SOLICITED_NODE_MULTICAST_PREFIX: u8 = 104;

#[derive(Debug, thiserror::Error)]
pub enum FirewallError {
    #[error("interface name {0:?} is not a valid Linux interface name")]
    InterfaceName(String),
    #[error("output allowance mixes IP families: {from} -> {to}")]
    FamilyMismatch { from: IpAddr, to: IpAddr },
    #[error("committing nftables ruleset: {0}")]
    Commit(#[source] io::Error),
    #[error("flushing conntrack table: {0}")]
    Conntrack(#[source] io::Error),
    #[error("netfilter worker task failed: {0}")]
    Worker(#[source] tokio::task::JoinError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Protocol {
    Tcp,
    Udp,
}

impl Protocol {
    const ALL: [Self; 2] = [Self::Tcp, Self::Udp];

    fn number(self) -> u8 {
        match self {
            Self::Tcp => libc::IPPROTO_TCP as u8,
            Self::Udp => libc::IPPROTO_UDP as u8,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct OutputAllowance {
    pub protocol: Protocol,
    pub interface: String,
    pub source: Option<SocketAddr>,
    pub destination: SocketAddr,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct TcpResetDrop {
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub exclude_mark: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct VpnEndpoint {
    endpoint: SocketAddr,
    interface: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ChainKind {
    Input,
    Output,
    Forward,
}

impl ChainKind {
    const ALL: [Self; 3] = [Self::Input, Self::Output, Self::Forward];

    fn name(self) -> &'static CStr {
        match self {
            Self::Input => c"input",
            Self::Output => c"output",
            Self::Forward => c"forward",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Match {
    InputInterface(String),
    OutputInterface(String),
    Source(IpNetwork),
    Destination(IpNetwork),
    Protocol(Protocol),
    SourcePort(u16),
    DestinationPort(u16),
    EstablishedRelated,
    InboundConnection,
    TcpReset,
    MarkNot(u32),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Action {
    Accept,
    AcceptInbound,
    Drop,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RuleSpec {
    chain: ChainKind,
    matches: Vec<Match>,
    action: Action,
}

impl RuleSpec {
    fn new(chain: ChainKind, matches: Vec<Match>, action: Action) -> Self {
        Self {
            chain,
            matches,
            action,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Ruleset {
    drop_policy: bool,
    rules: Vec<RuleSpec>,
}

#[derive(Clone, Debug)]
struct State {
    enabled: bool,
    default_routes: Vec<DefaultRoute>,
    local_networks: Vec<LocalNetwork>,
    vpn: Option<VpnEndpoint>,
    outbound_subnets: Vec<IpNetwork>,
    input_ports: BTreeMap<u16, BTreeSet<Option<String>>>,
    outputs: BTreeSet<OutputAllowance>,
    tcp_reset_drops: BTreeSet<TcpResetDrop>,
}

impl State {
    fn seal(&mut self) {
        self.vpn = None;
        self.outputs.clear();
    }

    fn default_interfaces(&self) -> BTreeSet<&str> {
        self.default_routes
            .iter()
            .map(|route| route.interface.as_str())
            .collect()
    }

    fn outbound_subnet_rules(&self) -> Vec<RuleSpec> {
        let mut rules = Vec::new();
        for subnet in &self.outbound_subnets {
            let family = Family::of(subnet.ip());
            let matching: Vec<&DefaultRoute> = self
                .default_routes
                .iter()
                .filter(|route| route.family == family)
                .collect();
            if matching.is_empty() {
                tracing::warn!(%subnet, %family, "ignoring outbound subnet: no default route of the same IP family");
            }
            for route in matching {
                rules.push(RuleSpec::new(
                    ChainKind::Output,
                    vec![
                        Match::OutputInterface(route.interface.clone()),
                        Match::Source(IpNetwork::from(route.assigned_ip)),
                        Match::Destination(*subnet),
                    ],
                    Action::Accept,
                ));
            }
        }
        rules
    }

    fn tcp_reset_rules(&self) -> Vec<RuleSpec> {
        self.tcp_reset_drops
            .iter()
            .map(|drop| {
                RuleSpec::new(
                    ChainKind::Output,
                    vec![
                        Match::Source(IpNetwork::from(drop.source.ip())),
                        Match::Destination(IpNetwork::from(drop.destination.ip())),
                        Match::Protocol(Protocol::Tcp),
                        Match::SourcePort(drop.source.port()),
                        Match::DestinationPort(drop.destination.port()),
                        Match::TcpReset,
                        Match::MarkNot(drop.exclude_mark),
                    ],
                    Action::Drop,
                )
            })
            .collect()
    }

    fn ruleset(&self) -> Option<Ruleset> {
        if !self.enabled {
            return (!self.tcp_reset_drops.is_empty()).then(|| Ruleset {
                drop_policy: false,
                rules: self.tcp_reset_rules(),
            });
        }

        let mut rules = self.tcp_reset_rules();
        let loopback = "lo".to_owned();
        rules.push(RuleSpec::new(
            ChainKind::Input,
            vec![Match::InputInterface(loopback.clone())],
            Action::Accept,
        ));
        rules.push(RuleSpec::new(
            ChainKind::Output,
            vec![Match::OutputInterface(loopback)],
            Action::Accept,
        ));
        rules.push(RuleSpec::new(
            ChainKind::Output,
            vec![Match::EstablishedRelated, Match::InboundConnection],
            Action::Accept,
        ));
        rules.push(RuleSpec::new(
            ChainKind::Input,
            vec![Match::EstablishedRelated],
            Action::Accept,
        ));

        if let Some(vpn) = &self.vpn {
            for interface in self.default_interfaces() {
                rules.push(RuleSpec::new(
                    ChainKind::Output,
                    vec![
                        Match::OutputInterface(interface.to_owned()),
                        Match::Destination(IpNetwork::from(vpn.endpoint.ip())),
                        Match::Protocol(Protocol::Udp),
                        Match::DestinationPort(vpn.endpoint.port()),
                    ],
                    Action::Accept,
                ));
            }
            rules.push(RuleSpec::new(
                ChainKind::Output,
                vec![Match::OutputInterface(vpn.interface.clone())],
                Action::Accept,
            ));
        }

        let mut local_interfaces = BTreeSet::new();
        for network in &self.local_networks {
            rules.push(RuleSpec::new(
                ChainKind::Output,
                vec![
                    Match::OutputInterface(network.interface.clone()),
                    Match::Source(IpNetwork::from(network.ip)),
                    Match::Destination(network.network),
                ],
                Action::Accept,
            ));
            if local_interfaces.insert(network.interface.as_str()) {
                let multicast = solicited_node_multicast();
                rules.push(RuleSpec::new(
                    ChainKind::Output,
                    vec![
                        Match::OutputInterface(network.interface.clone()),
                        Match::Destination(multicast),
                    ],
                    Action::Accept,
                ));
                rules.push(RuleSpec::new(
                    ChainKind::Input,
                    vec![
                        Match::InputInterface(network.interface.clone()),
                        Match::Destination(multicast),
                    ],
                    Action::Accept,
                ));
            }
        }

        rules.extend(self.outbound_subnet_rules());

        for network in &self.local_networks {
            rules.push(RuleSpec::new(
                ChainKind::Input,
                vec![
                    Match::InputInterface(network.interface.clone()),
                    Match::Destination(network.network),
                ],
                Action::AcceptInbound,
            ));
        }

        for (port, interfaces) in &self.input_ports {
            for interface in interfaces {
                for protocol in Protocol::ALL {
                    let bound: Vec<&str> = match interface {
                        Some(name) => vec![name.as_str()],
                        // Global allowances cover default-route interfaces only:
                        // accepting tunnel-side input would mark companion replies
                        // for clear egress after tunnel loss.
                        None => self.default_interfaces().into_iter().collect(),
                    };
                    for name in bound {
                        let action = if self
                            .vpn
                            .as_ref()
                            .is_some_and(|vpn| vpn.interface.as_str() == name)
                        {
                            // VPN-side input never earns a clear-route reply path;
                            // replies die with the tunnel instead of leaking.
                            Action::Accept
                        } else {
                            Action::AcceptInbound
                        };
                        rules.push(RuleSpec::new(
                            ChainKind::Input,
                            vec![
                                Match::InputInterface(name.to_owned()),
                                Match::Protocol(protocol),
                                Match::DestinationPort(*port),
                            ],
                            action,
                        ));
                    }
                }
            }
        }

        for output in &self.outputs {
            let mut matches = vec![Match::OutputInterface(output.interface.clone())];
            if let Some(source) = output.source {
                matches.push(Match::Source(IpNetwork::from(source.ip())));
            }
            matches.extend([
                Match::Destination(IpNetwork::from(output.destination.ip())),
                Match::Protocol(output.protocol),
            ]);
            if let Some(source) = output.source {
                matches.push(Match::SourcePort(source.port()));
            }
            matches.push(Match::DestinationPort(output.destination.port()));
            rules.push(RuleSpec::new(ChainKind::Output, matches, Action::Accept));
        }

        Some(Ruleset {
            drop_policy: true,
            rules,
        })
    }

    fn remove_input_port(&mut self, port: u16, interface: &str) {
        if let Some(interfaces) = self.input_ports.get_mut(&port) {
            interfaces.remove(&Some(interface.to_owned()));
            if interfaces.is_empty() {
                self.input_ports.remove(&port);
            }
        }
    }
}

#[derive(Debug)]
pub struct Firewall {
    state: Mutex<State>,
}

impl Firewall {
    pub fn new(
        default_routes: Vec<DefaultRoute>,
        local_networks: Vec<LocalNetwork>,
        outbound_subnets: Vec<IpNetwork>,
    ) -> Self {
        Self {
            state: Mutex::new(State {
                enabled: false,
                default_routes,
                local_networks,
                vpn: None,
                outbound_subnets,
                input_ports: BTreeMap::new(),
                outputs: BTreeSet::new(),
                tcp_reset_drops: BTreeSet::new(),
            }),
        }
    }

    async fn update(&self, change: impl FnOnce(&mut State)) -> Result<(), FirewallError> {
        let mut state = self.state.lock().await;
        let mut next = state.clone();
        change(&mut next);
        let flush_conntrack = next.enabled && !state.enabled;
        let (before, after) = (state.ruleset(), next.ruleset());
        if before != after {
            validate(after.as_ref())?;
            tokio::task::spawn_blocking(move || commit(after.as_ref()))
                .await
                .map_err(FirewallError::Worker)?
                .map_err(FirewallError::Commit)?;
        }
        *state = next;
        drop(state);
        if flush_conntrack {
            match tokio::task::spawn_blocking(flush_conntrack_table)
                .await
                .map_err(FirewallError::Worker)?
            {
                Ok(()) => {}
                Err(error) => {
                    tracing::warn!(error = %FirewallError::Conntrack(error), "existing connections were not reset")
                }
            }
        }
        Ok(())
    }

    pub async fn set_enabled(&self, enabled: bool) -> Result<(), FirewallError> {
        tracing::info!(enabled, "setting firewall state");
        self.update(|state| state.enabled = enabled).await
    }

    pub async fn seal(&self) -> Result<(), FirewallError> {
        tracing::info!("retaining firewall kill switch for shared-network containers");
        self.update(State::seal).await
    }

    pub async fn set_vpn_connection(
        &self,
        endpoint: SocketAddr,
        interface: &str,
    ) -> Result<(), FirewallError> {
        tracing::info!(%endpoint, interface, "allowing VPN connection");
        let vpn = VpnEndpoint {
            endpoint,
            interface: interface.to_owned(),
        };
        self.update(|state| state.vpn = Some(vpn)).await
    }

    pub async fn clear_vpn_connection(&self) -> Result<(), FirewallError> {
        self.update(|state| state.vpn = None).await
    }

    pub async fn set_allowed_port(
        &self,
        port: u16,
        interface: Option<&str>,
    ) -> Result<(), FirewallError> {
        if port == 0 {
            return Ok(());
        }
        tracing::info!(
            port,
            interface = interface.unwrap_or("*"),
            "allowing input port"
        );
        let interface = interface.map(str::to_owned);
        self.update(|state| {
            state.input_ports.entry(port).or_default().insert(interface);
        })
        .await
    }

    pub async fn remove_allowed_port(&self, port: u16) -> Result<(), FirewallError> {
        if port == 0 {
            return Ok(());
        }
        tracing::info!(port, "removing allowed input port");
        self.update(|state| {
            state.input_ports.remove(&port);
        })
        .await
    }

    pub async fn remove_allowed_port_on_interface(
        &self,
        port: u16,
        interface: &str,
    ) -> Result<(), FirewallError> {
        if port == 0 {
            return Ok(());
        }
        self.update(|state| state.remove_input_port(port, interface))
            .await
    }

    pub async fn set_outbound_subnets(&self, subnets: Vec<IpNetwork>) -> Result<(), FirewallError> {
        tracing::info!(count = subnets.len(), "setting allowed outbound subnets");
        self.update(|state| state.outbound_subnets = subnets).await
    }

    pub async fn set_output_allowance(
        &self,
        allowance: OutputAllowance,
        remove: bool,
    ) -> Result<(), FirewallError> {
        if let Some(source) = allowance.source
            && source.is_ipv4() != allowance.destination.is_ipv4()
        {
            return Err(FirewallError::FamilyMismatch {
                from: source.ip(),
                to: allowance.destination.ip(),
            });
        }
        self.update(|state| {
            if remove {
                state.outputs.remove(&allowance);
            } else {
                state.outputs.insert(allowance);
            }
        })
        .await
    }

    pub async fn drop_output_tcp_reset(
        &self,
        source: SocketAddr,
        destination: SocketAddr,
        exclude_mark: u32,
    ) -> Result<TcpResetDrop, FirewallError> {
        let drop = TcpResetDrop {
            source,
            destination,
            exclude_mark,
        };
        self.update(|state| {
            state.tcp_reset_drops.insert(drop);
        })
        .await?;
        Ok(drop)
    }

    pub async fn restore_output_tcp_reset(&self, drop: TcpResetDrop) -> Result<(), FirewallError> {
        self.update(|state| {
            state.tcp_reset_drops.remove(&drop);
        })
        .await
    }
}

impl OutputGate for Firewall {
    type Error = FirewallError;

    async fn accept_output(
        &self,
        interface: &str,
        destination: SocketAddr,
        remove: bool,
    ) -> Result<(), FirewallError> {
        let allowance = OutputAllowance {
            protocol: Protocol::Tcp,
            interface: interface.to_owned(),
            source: None,
            destination,
        };
        self.set_output_allowance(allowance, remove).await
    }
}

fn solicited_node_multicast() -> IpNetwork {
    Ipv6Network::new(SOLICITED_NODE_MULTICAST, SOLICITED_NODE_MULTICAST_PREFIX)
        .map(IpNetwork::V6)
        .unwrap_or(IpNetwork::V6(Ipv6Network::from(SOLICITED_NODE_MULTICAST)))
}

fn interface_name(name: &str) -> Result<CString, FirewallError> {
    let valid = !name.is_empty()
        && name.len() < libc::IFNAMSIZ
        && !name.contains(['/', '\0'])
        && !name.contains(char::is_whitespace);
    if !valid {
        return Err(FirewallError::InterfaceName(name.to_owned()));
    }
    CString::new(name).map_err(|_| FirewallError::InterfaceName(name.to_owned()))
}

fn validate(ruleset: Option<&Ruleset>) -> Result<(), FirewallError> {
    for rule in ruleset
        .map(|ruleset| ruleset.rules.as_slice())
        .unwrap_or_default()
    {
        for condition in &rule.matches {
            if let Match::InputInterface(name) | Match::OutputInterface(name) = condition {
                interface_name(name)?;
            }
        }
    }
    Ok(())
}

fn add_network_match(rule: &mut Rule<'_>, network: &IpNetwork, source: bool) {
    let payload = match (network, source) {
        (IpNetwork::V4(_), true) => nft_expr!(payload ipv4 saddr),
        (IpNetwork::V4(_), false) => nft_expr!(payload ipv4 daddr),
        (IpNetwork::V6(_), true) => nft_expr!(payload ipv6 saddr),
        (IpNetwork::V6(_), false) => nft_expr!(payload ipv6 daddr),
    };
    let nfproto = match network {
        IpNetwork::V4(_) => libc::NFPROTO_IPV4 as u8,
        IpNetwork::V6(_) => libc::NFPROTO_IPV6 as u8,
    };
    rule.add_expr(&nft_expr!(meta nfproto));
    rule.add_expr(&nft_expr!(cmp == nfproto));
    rule.add_expr(&payload);
    let full = match network {
        IpNetwork::V4(_) => 32,
        IpNetwork::V6(_) => 128,
    };
    if network.prefix() < full {
        let zero = match network {
            IpNetwork::V4(_) => IpAddr::from([0u8; 4]),
            IpNetwork::V6(_) => IpAddr::from([0u8; 16]),
        };
        rule.add_expr(&Bitwise::new(network.mask(), zero));
    }
    rule.add_expr(&Cmp::new(CmpOp::Eq, network.network()));
}

fn add_match(rule: &mut Rule<'_>, condition: &Match) -> Result<(), FirewallError> {
    match condition {
        Match::InputInterface(name) => {
            rule.add_expr(&nft_expr!(meta iifname));
            rule.add_expr(&Cmp::new(
                CmpOp::Eq,
                InterfaceName::Exact(interface_name(name)?),
            ));
        }
        Match::OutputInterface(name) => {
            rule.add_expr(&nft_expr!(meta oifname));
            rule.add_expr(&Cmp::new(
                CmpOp::Eq,
                InterfaceName::Exact(interface_name(name)?),
            ));
        }
        Match::Source(network) => add_network_match(rule, network, true),
        Match::Destination(network) => add_network_match(rule, network, false),
        Match::Protocol(protocol) => {
            rule.add_expr(&nft_expr!(meta l4proto));
            rule.add_expr(&nft_expr!(cmp == protocol.number()));
        }
        Match::SourcePort(port) => {
            rule.add_expr(&nft_expr!(payload tcp sport));
            rule.add_expr(&nft_expr!(cmp == port.to_be()));
        }
        Match::DestinationPort(port) => {
            rule.add_expr(&nft_expr!(payload tcp dport));
            rule.add_expr(&nft_expr!(cmp == port.to_be()));
        }
        Match::EstablishedRelated => {
            rule.add_expr(&nft_expr!(ct state));
            rule.add_expr(&Bitwise::new(
                (States::ESTABLISHED | States::RELATED).bits(),
                0u32,
            ));
            rule.add_expr(&nft_expr!(cmp != 0u32));
        }
        Match::InboundConnection => {
            rule.add_expr(&Conntrack::Mark { set: false });
            rule.add_expr(&nft_expr!(cmp == INBOUND_CONNECTION_MARK));
        }
        Match::TcpReset => {
            // libnftnl forwards this "bits" field verbatim as NFTA_PAYLOAD_OFFSET/LEN, which are bytes.
            rule.add_expr(&Payload::Transport(TransportHeaderField::Raw {
                offset_bits: TCP_FLAGS_OFFSET,
                length_bits: 1,
            }));
            rule.add_expr(&Bitwise::new(TCP_FLAG_RST, 0u8));
            rule.add_expr(&nft_expr!(cmp != 0u8));
        }
        Match::MarkNot(mark) => {
            rule.add_expr(&nft_expr!(meta mark));
            rule.add_expr(&nft_expr!(cmp != *mark));
        }
    }
    Ok(())
}

fn build(ruleset: Option<&Ruleset>) -> Result<FinalizedBatch, FirewallError> {
    let mut batch = Batch::new();
    let table = Table::new(TABLE_NAME, ProtoFamily::Inet);
    batch.add(&table, MsgType::Add);
    batch.add(&table, MsgType::Del);
    let Some(ruleset) = ruleset else {
        return Ok(batch.finalize());
    };
    batch.add(&table, MsgType::Add);

    let chains: Vec<(ChainKind, Chain<'_>)> = ChainKind::ALL
        .into_iter()
        .map(|kind| {
            let mut chain = Chain::new(kind.name(), &table);
            let (hook, chain_type, priority, policy) = match kind {
                ChainKind::Input => (
                    Hook::In,
                    ChainType::Filter,
                    FILTER_PRIORITY,
                    ruleset.drop_policy,
                ),
                ChainKind::Output => (
                    Hook::Out,
                    ChainType::Filter,
                    FILTER_PRIORITY,
                    ruleset.drop_policy,
                ),
                ChainKind::Forward => (
                    Hook::Forward,
                    ChainType::Filter,
                    FILTER_PRIORITY,
                    ruleset.drop_policy,
                ),
            };
            chain.set_hook(hook, priority);
            chain.set_type(chain_type);
            chain.set_policy(if policy { Policy::Drop } else { Policy::Accept });
            (kind, chain)
        })
        .collect();
    for (_, chain) in &chains {
        batch.add(chain, MsgType::Add);
    }

    for spec in &ruleset.rules {
        let Some((_, chain)) = chains.iter().find(|(kind, _)| *kind == spec.chain) else {
            continue;
        };
        let mut rule = Rule::new(chain);
        for condition in &spec.matches {
            add_match(&mut rule, condition)?;
        }
        match spec.action {
            Action::Accept => rule.add_expr(&nft_expr!(verdict accept)),
            Action::AcceptInbound => {
                // Only replies to accepted inbound connections may bypass the tunnel.
                rule.add_expr(&Immediate::new(INBOUND_CONNECTION_MARK, Register::Reg1));
                rule.add_expr(&Conntrack::Mark { set: true });
                rule.add_expr(&nft_expr!(verdict accept));
            }
            Action::Drop => rule.add_expr(&nft_expr!(verdict drop)),
        }
        batch.add(&rule, MsgType::Add);
    }
    Ok(batch.finalize())
}

fn commit(ruleset: Option<&Ruleset>) -> io::Result<()> {
    let batch = build(ruleset).map_err(io::Error::other)?;
    let socket = mnl::Socket::new(mnl::Bus::Netfilter)?;
    let portid = socket.portid();
    socket.send_all(&batch)?;
    let mut buffer = vec![0; nftnl::nft_nlmsg_maxsize() as usize];
    let mut expected = batch.sequence_numbers();
    while !expected.is_empty() {
        for message in socket.recv(&mut buffer)? {
            let sequence = expected
                .next()
                .ok_or_else(|| io::Error::other("unexpected netfilter acknowledgement"))?;
            mnl::cb_run(message?, sequence, portid)?;
        }
    }
    Ok(())
}

fn flush_conntrack_table() -> io::Result<()> {
    const HEADER_LEN: u32 = 20;
    const SEQUENCE: u32 = 1;
    let socket = mnl::Socket::new(mnl::Bus::Netfilter)?;
    let portid = socket.portid();
    let mut message = Vec::with_capacity(HEADER_LEN as usize);
    message.extend_from_slice(&HEADER_LEN.to_ne_bytes());
    message.extend_from_slice(&((NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_DELETE).to_ne_bytes());
    message.extend_from_slice(&((libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16).to_ne_bytes());
    message.extend_from_slice(&SEQUENCE.to_ne_bytes());
    message.extend_from_slice(&0u32.to_ne_bytes());
    message.extend_from_slice(&[libc::AF_UNSPEC as u8, NFNETLINK_V0, 0, 0]);
    socket.send(&message)?;
    let mut buffer = vec![0; nftnl::nft_nlmsg_maxsize() as usize];
    for reply in socket.recv(&mut buffer)? {
        mnl::cb_run(reply?, SEQUENCE, portid)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> State {
        State {
            enabled: true,
            default_routes: vec![
                DefaultRoute {
                    interface: "eth0".to_owned(),
                    index: 2,
                    gateway: Some("172.17.0.1".parse().expect("valid")),
                    assigned_ip: "172.17.0.2".parse().expect("valid"),
                    family: Family::V4,
                },
                DefaultRoute {
                    interface: "eth0".to_owned(),
                    index: 2,
                    gateway: Some("fd00::1".parse().expect("valid")),
                    assigned_ip: "fd00::2".parse().expect("valid"),
                    family: Family::V6,
                },
            ],
            local_networks: vec![LocalNetwork {
                network: "172.17.0.0/16".parse().expect("valid"),
                interface: "eth0".to_owned(),
                ip: "172.17.0.2".parse().expect("valid"),
            }],
            vpn: Some(VpnEndpoint {
                endpoint: "185.65.134.1:51820".parse().expect("valid"),
                interface: "wg0".to_owned(),
            }),
            outbound_subnets: vec![
                "192.168.1.0/24".parse().expect("valid"),
                "fd12::/64".parse().expect("valid"),
            ],
            input_ports: BTreeMap::new(),
            outputs: BTreeSet::new(),
            tcp_reset_drops: BTreeSet::new(),
        }
    }

    fn contains(ruleset: &Ruleset, chain: ChainKind, matches: &[Match], action: Action) -> bool {
        ruleset
            .rules
            .iter()
            .any(|rule| rule.chain == chain && rule.matches == matches && rule.action == action)
    }

    #[test]
    fn enabled_ruleset_allows_vpn_endpoint_once_per_interface() {
        let ruleset = state().ruleset().expect("enabled ruleset");
        assert!(ruleset.drop_policy);
        let endpoint_rules = ruleset
            .rules
            .iter()
            .filter(|rule| rule.matches.contains(&Match::DestinationPort(51820)))
            .count();
        assert_eq!(endpoint_rules, 1);
        assert!(contains(
            &ruleset,
            ChainKind::Output,
            &[Match::OutputInterface("wg0".to_owned())],
            Action::Accept
        ));
    }

    #[test]
    fn outbound_subnets_match_default_route_family() {
        let ruleset = state().ruleset().expect("enabled ruleset");
        assert!(contains(
            &ruleset,
            ChainKind::Output,
            &[
                Match::OutputInterface("eth0".to_owned()),
                Match::Source("fd00::2/128".parse().expect("valid")),
                Match::Destination("fd12::/64".parse().expect("valid")),
            ],
            Action::Accept
        ));
        assert!(!ruleset.rules.iter().any(|rule| {
            rule.matches
                .contains(&Match::Source("172.17.0.2/32".parse().expect("valid")))
                && rule
                    .matches
                    .contains(&Match::Destination("fd12::/64".parse().expect("valid")))
        }));
    }

    #[test]
    fn disabled_ruleset_only_carries_tcp_reset_drops() {
        let mut state = state();
        state.enabled = false;
        assert_eq!(state.ruleset(), None);
        state.tcp_reset_drops.insert(TcpResetDrop {
            source: "10.64.0.2:40000".parse().expect("valid"),
            destination: "1.1.1.1:443".parse().expect("valid"),
            exclude_mark: 7,
        });
        let ruleset = state.ruleset().expect("tcp reset ruleset");
        assert!(!ruleset.drop_policy);
        assert_eq!(ruleset.rules.len(), 1);
        assert_eq!(ruleset.rules[0].action, Action::Drop);
    }

    #[test]
    fn sealed_firewall_keeps_kill_switch_without_stale_vpn_or_probe_allowances() {
        let mut state = state();
        state.outputs.insert(OutputAllowance {
            protocol: Protocol::Tcp,
            interface: "eth0".into(),
            source: None,
            destination: "203.0.113.1:443".parse().expect("address"),
        });
        state.seal();
        let ruleset = state.ruleset().expect("retained firewall");
        assert!(ruleset.drop_policy);
        assert!(state.vpn.is_none());
        assert!(state.outputs.is_empty());
        assert!(
            !ruleset
                .rules
                .iter()
                .any(|rule| rule.matches.contains(&Match::OutputInterface("wg0".into())))
        );
        for rule in &ruleset.rules {
            if rule.chain == ChainKind::Output && rule.matches.contains(&Match::EstablishedRelated)
            {
                assert!(rule.matches.contains(&Match::InboundConnection));
            }
            if rule.action == Action::AcceptInbound {
                assert_eq!(rule.chain, ChainKind::Input);
            }
        }
        state.enabled = false;
        state.seal();
        assert!(state.ruleset().is_none());
    }

    #[test]
    fn removing_vpn_port_keeps_global_allowance() {
        let mut state = state();
        state
            .input_ports
            .entry(9999)
            .or_default()
            .extend([None, Some("wg0".to_owned())]);
        state.remove_input_port(9999, "wg0");
        assert_eq!(state.input_ports.get(&9999), Some(&BTreeSet::from([None])));
        state.remove_input_port(9999, "wg0");
        assert_eq!(state.input_ports.get(&9999), Some(&BTreeSet::from([None])));
    }

    #[test]
    fn global_input_ports_apply_only_to_default_route_interfaces() {
        let mut state = state();
        state.input_ports.entry(8888).or_default().insert(None);
        let ruleset = state.ruleset().expect("enabled ruleset");
        let port_rules: Vec<&RuleSpec> = ruleset
            .rules
            .iter()
            .filter(|rule| rule.matches.contains(&Match::DestinationPort(8888)))
            .collect();
        assert_eq!(port_rules.len(), Protocol::ALL.len());
        for rule in port_rules {
            assert_eq!(rule.chain, ChainKind::Input);
            assert_eq!(rule.action, Action::AcceptInbound);
            assert!(
                rule.matches
                    .contains(&Match::InputInterface("eth0".to_owned()))
            );
        }
    }

    #[test]
    fn vpn_input_ports_do_not_grant_clear_route_replies() {
        let mut state = state();
        state
            .input_ports
            .entry(8000)
            .or_default()
            .insert(Some("wg0".to_owned()));
        let ruleset = state.ruleset().expect("enabled ruleset");
        let rule = ruleset
            .rules
            .iter()
            .find(|rule| rule.matches.contains(&Match::DestinationPort(8000)))
            .expect("VPN input port rule");
        assert_eq!(rule.chain, ChainKind::Input);
        assert_eq!(rule.action, Action::Accept);
        assert!(!ruleset.rules.iter().any(|rule| {
            rule.action == Action::AcceptInbound
                && rule
                    .matches
                    .contains(&Match::InputInterface("wg0".to_owned()))
        }));
    }

    #[test]
    #[ignore = "needs CAP_NET_ADMIN in a disposable network namespace"]
    fn kernel_accepts_full_ruleset() {
        let mut state = state();
        state.input_ports.entry(8000).or_default().insert(None);
        state.outputs.insert(OutputAllowance {
            protocol: Protocol::Tcp,
            interface: "eth0".to_owned(),
            source: Some("172.17.0.2:40000".parse().expect("valid")),
            destination: "203.0.113.1:443".parse().expect("valid"),
        });
        state.tcp_reset_drops.insert(TcpResetDrop {
            source: "10.64.0.2:40000".parse().expect("valid"),
            destination: "1.1.1.1:443".parse().expect("valid"),
            exclude_mark: 7,
        });
        commit(state.ruleset().as_ref()).expect("kernel accepts ruleset");
        commit(state.ruleset().as_ref()).expect("ruleset replacement is idempotent");
        flush_conntrack_table().expect("conntrack flush");
        commit(None).expect("table removal");
        commit(None).expect("table removal is idempotent");
    }

    #[test]
    fn interface_names_are_validated() {
        assert!(interface_name("wg0").is_ok());
        assert!(interface_name("").is_err());
        assert!(interface_name("a-very-long-interface").is_err());
        assert!(interface_name("bad name").is_err());
    }
}
