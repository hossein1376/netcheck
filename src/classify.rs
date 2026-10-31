use std::net::{IpAddr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    Internet,
    Local,
    Unscoped,
}

#[derive(Debug, Clone, Copy)]
pub struct Prefix {
    pub addr: IpAddr,
    pub prefix_len: u8,
}

const LOCAL_SERVICE_PORTS: [u16; 5] = [68, 137, 138, 1900, 5353];

/// `local_port` is used only when `remote` is missing.
pub fn classify(local_port: Option<u16>, remote: Option<IpAddr>, prefixes: &[Prefix]) -> Scope {
    let Some(ip) = remote else {
        if local_port.is_some_and(|port| LOCAL_SERVICE_PORTS.contains(&port)) {
            return Scope::Local;
        }
        return Scope::Unscoped;
    };
    if is_special_local(ip) || prefixes.iter().any(|prefix| prefix_contains(prefix, ip)) {
        return Scope::Local;
    }
    Scope::Internet
}

fn is_special_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_unspecified()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || is_ula(v6)
                || is_v6_link_local(v6)
                || v6.is_multicast()
                || v6.is_unspecified()
        }
    }
}

fn is_ula(ip: Ipv6Addr) -> bool {
    // fc00::/7
    ip.octets()[0] & 0xfe == 0xfc
}

fn is_v6_link_local(ip: Ipv6Addr) -> bool {
    // fe80::/10
    let o = ip.octets();
    o[0] == 0xfe && o[1] & 0xc0 == 0x80
}

fn prefix_contains(prefix: &Prefix, ip: IpAddr) -> bool {
    match (prefix.addr, ip) {
        (IpAddr::V4(net), IpAddr::V4(ip)) if prefix.prefix_len <= 32 => {
            let bits = prefix.prefix_len;
            let mask = if bits == 0 {
                0
            } else {
                u32::MAX << (32 - bits)
            };
            u32::from(net) & mask == u32::from(ip) & mask
        }
        (IpAddr::V6(net), IpAddr::V6(ip)) if prefix.prefix_len <= 128 => {
            let bits = prefix.prefix_len as usize;
            let full = bits / 8;
            let rem = bits % 8;
            let net = net.octets();
            let ip = ip.octets();
            if net[..full] != ip[..full] {
                return false;
            }
            if rem == 0 {
                return true;
            }
            let mask = 0xffu8 << (8 - rem);
            net[full] & mask == ip[full] & mask
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn v4(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn public_address_is_internet() {
        assert_eq!(classify(Some(40000), Some(v4("1.1.1.1")), &[]), Scope::Internet);
    }

    #[test]
    fn private_and_loopback_are_local() {
        for ip in ["10.1.2.3", "172.16.0.1", "192.168.1.9", "127.0.0.1", "169.254.1.1"] {
            assert_eq!(classify(Some(1), Some(v4(ip)), &[]), Scope::Local, "{ip}");
        }
        let v6: IpAddr = "fd00::1".parse().unwrap();
        assert_eq!(classify(Some(1), Some(v6), &[]), Scope::Local);
        let ll: IpAddr = "fe80::1".parse().unwrap();
        assert_eq!(classify(Some(1), Some(ll), &[]), Scope::Local);
        assert_eq!(
            classify(Some(1), Some(v4("224.0.0.1")), &[]),
            Scope::Local
        );
    }

    #[test]
    fn missing_peer_uses_the_local_port() {
        assert_eq!(classify(Some(5353), None, &[]), Scope::Local);
        assert_eq!(classify(Some(68), None, &[]), Scope::Local);
        assert_eq!(classify(Some(443), None, &[]), Scope::Unscoped);
    }

    #[test]
    fn a_directly_connected_subnet_is_local() {
        let prefixes = [Prefix {
            addr: IpAddr::V4(Ipv4Addr::new(100, 64, 1, 0)),
            prefix_len: 24,
        }];
        assert_eq!(
            classify(Some(1), Some(v4("100.64.1.20")), &prefixes),
            Scope::Local
        );
        assert_eq!(
            classify(Some(1), Some(v4("100.64.2.20")), &prefixes),
            Scope::Internet
        );
    }
}
