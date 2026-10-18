use std::io;
use std::net::IpAddr;
use std::os::fd::AsRawFd;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;

pub const HEADER_LEN: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EchoTypes {
    pub request: u8,
    pub reply: u8,
}

impl EchoTypes {
    pub fn of(target: IpAddr) -> Self {
        match target {
            IpAddr::V4(_) => Self {
                request: 8,
                reply: 0,
            },
            IpAddr::V6(_) => Self {
                request: 128,
                reply: 129,
            },
        }
    }
}

// Unprivileged ping sockets (net.ipv4.ping_group_range) need no NET_RAW, which the container drops.
pub fn ping_socket(target: IpAddr, probe_mtu: bool) -> io::Result<UdpSocket> {
    let (domain, protocol) = match target {
        IpAddr::V4(_) => (Domain::IPV4, Protocol::ICMPV4),
        IpAddr::V6(_) => (Domain::IPV6, Protocol::ICMPV6),
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(protocol))?;
    if probe_mtu {
        set_pmtudisc_probe(&socket, target)?;
    }
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(std::net::UdpSocket::from(socket))
}

pub fn is_not_permitted(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::EPERM | libc::EACCES | libc::EPROTONOSUPPORT)
    )
}

// IP_PMTUDISC_PROBE sets DF and ignores the cached path MTU, so each probe leaves at its exact size.
pub fn set_pmtudisc_probe(socket: &Socket, target: IpAddr) -> io::Result<()> {
    let (level, name, value) = match target {
        IpAddr::V4(_) => (
            libc::IPPROTO_IP,
            libc::IP_MTU_DISCOVER,
            libc::IP_PMTUDISC_PROBE,
        ),
        IpAddr::V6(_) => (
            libc::IPPROTO_IPV6,
            libc::IPV6_MTU_DISCOVER,
            libc::IPV6_PMTUDISC_PROBE,
        ),
    };
    let length = libc::socklen_t::try_from(size_of::<libc::c_int>())
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: the pointer and length describe a live c_int for the duration of the call.
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            level,
            name,
            (&raw const value).cast(),
            length,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

pub fn echo_request(message_type: u8, sequence: u16, payload: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(HEADER_LEN + payload.len());
    packet.extend_from_slice(&[message_type, 0, 0, 0, 0, 0]);
    packet.extend_from_slice(&sequence.to_be_bytes());
    packet.extend_from_slice(payload);
    let checksum = internet_checksum(&packet);
    packet[2..4].copy_from_slice(&checksum.to_be_bytes());
    packet
}

pub fn parse_echo_reply(packet: &[u8], reply_type: u8) -> Option<(u16, &[u8])> {
    (packet.len() >= HEADER_LEN && packet[0] == reply_type && packet[1] == 0).then(|| {
        (
            u16::from_be_bytes([packet[6], packet[7]]),
            &packet[HEADER_LEN..],
        )
    })
}

pub fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = data
        .chunks(2)
        .map(|pair| {
            u32::from(u16::from_be_bytes([
                pair[0],
                pair.get(1).copied().unwrap_or(0),
            ]))
        })
        .sum();
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn echo_request_checksum_verifies() {
        let packet = echo_request(8, 0x1234, b"payload!");
        assert_eq!(internet_checksum(&packet), 0);
        let mut reply = packet.clone();
        reply[0] = 0;
        assert_eq!(
            parse_echo_reply(&reply, 0),
            Some((0x1234, b"payload!".as_slice()))
        );
        assert_eq!(parse_echo_reply(&reply, 129), None);
        assert_eq!(parse_echo_reply(&reply[..4], 0), None);
    }
}
