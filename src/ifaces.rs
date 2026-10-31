use crate::classify::Prefix;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Prefixes of addresses configured on this machine.
pub fn local_prefixes() -> Vec<Prefix> {
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut head) } != 0 || head.is_null() {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut cursor = head;
    while !cursor.is_null() {
        let iface = unsafe { &*cursor };
        if !iface.ifa_addr.is_null() && !iface.ifa_netmask.is_null() {
            if let (Some(addr), Some(mask)) = (read_ip(iface.ifa_addr), read_ip(iface.ifa_netmask))
            {
                out.push(Prefix {
                    addr,
                    prefix_len: leading_ones(mask),
                });
            }
        }
        cursor = iface.ifa_next;
    }
    unsafe { libc::freeifaddrs(head) };
    out
}

fn read_ip(addr: *const libc::sockaddr) -> Option<IpAddr> {
    if addr.is_null() {
        return None;
    }
    let family = unsafe { (*addr).sa_family as i32 };
    if family == libc::AF_INET {
        let v4 = unsafe { &*(addr as *const libc::sockaddr_in) };
        let octets = v4.sin_addr.s_addr.to_ne_bytes();
        return Some(IpAddr::V4(Ipv4Addr::from(octets)));
    }
    if family == libc::AF_INET6 {
        let v6 = unsafe { &*(addr as *const libc::sockaddr_in6) };
        let octets = v6.sin6_addr.s6_addr;
        return Some(IpAddr::V6(Ipv6Addr::from(octets)));
    }
    None
}

fn leading_ones(mask: IpAddr) -> u8 {
    match mask {
        IpAddr::V4(v4) => u32::from(v4).leading_ones() as u8,
        IpAddr::V6(v6) => u128::from(v6).leading_ones() as u8,
    }
}
