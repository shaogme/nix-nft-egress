use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::process::Command;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceIp {
    pub ifname: String,
    pub ip: IpAddr,
    pub prefix: u8,
}

/// Parse a single line from `ip -o addr show scope global`.
pub fn parse_ip_line(line: &str) -> Option<InterfaceIp> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 4 {
        return None;
    }

    let (proto_idx, is_v6) = parts.iter().enumerate().find_map(|(idx, &part)| {
        if part == "inet" {
            Some((idx, false))
        } else if part == "inet6" {
            Some((idx, true))
        } else {
            None
        }
    })?;

    if proto_idx == 0 || proto_idx + 1 >= parts.len() {
        return None;
    }

    let raw_ifname = parts[proto_idx - 1].trim_matches(':');
    let ifname = raw_ifname
        .split('@')
        .next()
        .unwrap_or(raw_ifname)
        .to_string();

    let cidr = parts[proto_idx + 1];
    let (ip_str, prefix_str) = cidr.split_once('/')?;
    let prefix: u8 = prefix_str.parse().ok()?;

    if is_v6 {
        let ip: Ipv6Addr = ip_str.parse().ok()?;
        if ip.is_loopback() {
            return None;
        }
        Some(InterfaceIp {
            ifname,
            ip: IpAddr::V6(ip),
            prefix,
        })
    } else {
        let ip: Ipv4Addr = ip_str.parse().ok()?;
        if ip.is_loopback() {
            return None;
        }
        Some(InterfaceIp {
            ifname,
            ip: IpAddr::V4(ip),
            prefix,
        })
    }
}

/// Retrieve all global IPv4/IPv6 addresses configured on the gateway container's interfaces.
pub fn get_gateway_ips() -> Vec<InterfaceIp> {
    let mut ips = Vec::new();
    for flag in &["-4", "-6"] {
        if let Ok(output) = Command::new("ip")
            .args(["-o", flag, "addr", "show", "scope", "global"])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                if let Some(iface) = parse_ip_line(line)
                    && iface.ifname != "lo"
                {
                    ips.push(iface);
                }
            }
        }
    }
    ips
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefaultRoute {
    pub ifname: String,
    pub gateway: Option<IpAddr>,
}

/// Parse default route line from `ip -o route show default` or `ip -o -6 route show default`.
pub fn parse_default_route_line(line: &str) -> Option<DefaultRoute> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.is_empty() || parts[0] != "default" {
        return None;
    }

    let mut gateway = None;
    let mut ifname = None;

    let mut i = 1;
    while i < parts.len() {
        if parts[i] == "via" && i + 1 < parts.len() {
            gateway = parts[i + 1].parse::<IpAddr>().ok();
            i += 2;
        } else if parts[i] == "dev" && i + 1 < parts.len() {
            let raw_ifname = parts[i + 1].trim_matches(':');
            let clean_name = raw_ifname.split('@').next().unwrap_or(raw_ifname);
            ifname = Some(clean_name.to_string());
            i += 2;
        } else {
            i += 1;
        }
    }

    ifname.map(|name| DefaultRoute {
        ifname: name,
        gateway,
    })
}

/// Retrieve default routes for IPv4 and IPv6 on the gateway container.
pub fn get_default_routes() -> (Option<DefaultRoute>, Option<DefaultRoute>) {
    let mut v4_def = None;
    let mut v6_def = None;

    if let Ok(output) = Command::new("ip")
        .args(["-o", "route", "show", "default"])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if let Some(route) = parse_default_route_line(line) {
                v4_def = Some(route);
                break;
            }
        }
    }

    if let Ok(output) = Command::new("ip")
        .args(["-o", "-6", "route", "show", "default"])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if let Some(route) = parse_default_route_line(line) {
                v6_def = Some(route);
                break;
            }
        }
    }

    (v4_def, v6_def)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ip_line_v4() {
        let line = "2: eth0    inet 172.20.0.2/24 brd 172.20.0.255 scope global eth0\\       valid_lft forever";
        let parsed = parse_ip_line(line).unwrap();
        assert_eq!(parsed.ifname, "eth0");
        assert_eq!(parsed.ip, IpAddr::V4(Ipv4Addr::new(172, 20, 0, 2)));
        assert_eq!(parsed.prefix, 24);
    }

    #[test]
    fn test_parse_ip_line_v6() {
        let line = "2: eth0    inet6 fd00:dead:beef::2/64 scope global \\       valid_lft forever";
        let parsed = parse_ip_line(line).unwrap();
        assert_eq!(parsed.ifname, "eth0");
        assert_eq!(
            parsed.ip,
            IpAddr::V6("fd00:dead:beef::2".parse::<Ipv6Addr>().unwrap())
        );
        assert_eq!(parsed.prefix, 64);
    }

    #[test]
    fn test_parse_default_route_line() {
        let line_v4 = "default via 10.89.1.1 dev eth1 proto static metric 100";
        let r_v4 = parse_default_route_line(line_v4).unwrap();
        assert_eq!(r_v4.ifname, "eth1");
        assert_eq!(r_v4.gateway, Some(IpAddr::V4(Ipv4Addr::new(10, 89, 1, 1))));

        let line_v6 = "default via fd62::1 dev eth1 proto static metric 100";
        let r_v6 = parse_default_route_line(line_v6).unwrap();
        assert_eq!(r_v6.ifname, "eth1");
        assert_eq!(r_v6.gateway, Some("fd62::1".parse().unwrap()));

        let line_no_via = "default dev eth0 proto kernel scope link";
        let r_no_via = parse_default_route_line(line_no_via).unwrap();
        assert_eq!(r_no_via.ifname, "eth0");
        assert_eq!(r_no_via.gateway, None);
    }
}
