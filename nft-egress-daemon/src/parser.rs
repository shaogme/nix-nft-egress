use std::collections::BTreeSet;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct WhitelistEntries {
    pub v4: Vec<String>,
    pub v6: Vec<String>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DetectedDns {
    pub v4: Option<Ipv4Addr>,
    pub v6: Option<Ipv6Addr>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum EntryType {
    V4(String),
    V6(String),
}

/// Zero out host bits for an IPv4 CIDR prefix.
#[must_use]
pub const fn canonicalize_v4(ip: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    if prefix == 0 {
        return Ipv4Addr::UNSPECIFIED;
    }
    if prefix >= 32 {
        return ip;
    }
    let ip_u32 = u32::from_be_bytes(ip.octets());
    let mask = !((1u32 << (32 - prefix)) - 1);
    Ipv4Addr::from_bits(ip_u32 & mask)
}

/// Zero out host bits for an IPv6 CIDR prefix.
#[must_use]
pub const fn canonicalize_v6(ip: Ipv6Addr, prefix: u8) -> Ipv6Addr {
    if prefix == 0 {
        return Ipv6Addr::UNSPECIFIED;
    }
    if prefix >= 128 {
        return ip;
    }
    let ip_u128 = u128::from_be_bytes(ip.octets());
    let mask = !((1u128 << (128 - prefix)) - 1);
    Ipv6Addr::from_bits(ip_u128 & mask)
}

pub fn parse_line(raw_line: &str, strict: bool) -> Result<Option<EntryType>, String> {
    // Strip comments and trim whitespace
    let line = match raw_line.split_once('#') {
        Some((before, _)) => before.trim(),
        None => raw_line.trim(),
    };

    if line.is_empty() {
        return Ok(None);
    }

    if let Some((ip_str, prefix_str)) = line.split_once('/') {
        let ip_str = ip_str.trim();
        let prefix_str = prefix_str.trim();

        let prefix: u8 = prefix_str
            .parse()
            .map_err(|_| format!("Invalid CIDR prefix '{prefix_str}' in '{line}'"))?;

        if let Ok(ipv4) = ip_str.parse::<Ipv4Addr>() {
            if prefix > 32 {
                return Err(format!(
                    "IPv4 CIDR prefix /{prefix} must be <= 32 in '{line}'"
                ));
            }
            let canonical = canonicalize_v4(ipv4, prefix);
            if canonical != ipv4 {
                if strict {
                    return Err(format!(
                        "IPv4 CIDR '{line}' has host bits set, expected '{canonical}/{prefix}'"
                    ));
                }
                eprintln!(
                    "[Gateway] Notice: Canonicalized IPv4 CIDR '{line}' -> '{canonical}/{prefix}'"
                );
            }
            Ok(Some(EntryType::V4(format!("{canonical}/{prefix}"))))
        } else if let Ok(ipv6) = ip_str.parse::<Ipv6Addr>() {
            if prefix > 128 {
                return Err(format!(
                    "IPv6 CIDR prefix /{prefix} must be <= 128 in '{line}'"
                ));
            }
            let canonical = canonicalize_v6(ipv6, prefix);
            if canonical != ipv6 {
                if strict {
                    return Err(format!(
                        "IPv6 CIDR '{line}' has host bits set, expected '{canonical}/{prefix}'"
                    ));
                }
                eprintln!(
                    "[Gateway] Notice: Canonicalized IPv6 CIDR '{line}' -> '{canonical}/{prefix}'"
                );
            }
            Ok(Some(EntryType::V6(format!("{canonical}/{prefix}"))))
        } else {
            Err(format!("Invalid IP address '{ip_str}' in CIDR '{line}'"))
        }
    } else if let Ok(ipv4) = line.parse::<Ipv4Addr>() {
        Ok(Some(EntryType::V4(ipv4.to_string())))
    } else if let Ok(ipv6) = line.parse::<Ipv6Addr>() {
        Ok(Some(EntryType::V6(ipv6.to_string())))
    } else {
        Err(format!("Invalid IP address or CIDR: '{line}'"))
    }
}

pub fn parse_whitelist(content: &str, strict: bool) -> Result<WhitelistEntries, String> {
    let mut v4_set = BTreeSet::new();
    let mut v6_set = BTreeSet::new();

    for (idx, line) in content.lines().enumerate() {
        let line_no = idx + 1;
        match parse_line(line, strict) {
            Ok(Some(EntryType::V4(v4))) => {
                v4_set.insert(v4);
            }
            Ok(Some(EntryType::V6(v6))) => {
                v6_set.insert(v6);
            }
            Ok(None) => {}
            Err(err) => {
                let msg = format!("Line {line_no}: {err}");
                if strict {
                    return Err(msg);
                }
                eprintln!("[Gateway] Warning: Ignored invalid whitelist entry: {msg}");
            }
        }
    }

    Ok(WhitelistEntries {
        v4: v4_set.into_iter().collect(),
        v6: v6_set.into_iter().collect(),
    })
}

/// Parse nameserver entries from resolv.conf format content.
pub fn parse_resolv_conf(content: &str) -> DetectedDns {
    let mut detected = DetectedDns::default();
    for ip in parse_all_nameservers(content) {
        match ip {
            IpAddr::V4(v4) => {
                if detected.v4.is_none() {
                    detected.v4 = Some(v4);
                }
            }
            IpAddr::V6(v6) => {
                if detected.v6.is_none() {
                    detected.v6 = Some(v6);
                }
            }
        }
    }
    detected
}

/// Extract all nameservers from resolv.conf format content in order.
pub fn parse_all_nameservers(content: &str) -> Vec<IpAddr> {
    let mut servers = Vec::new();
    for raw_line in content.lines() {
        let line = match raw_line.split_once('#') {
            Some((before, _)) => before.trim(),
            None => raw_line.trim(),
        };
        let line = match line.split_once(';') {
            Some((before, _)) => before.trim(),
            None => line.trim(),
        };

        let mut parts = line.split_whitespace();
        if parts.next() == Some("nameserver")
            && let Some(server_str) = parts.next()
            && let Ok(ip) = server_str.parse::<IpAddr>()
        {
            servers.push(ip);
        }
    }
    servers
}

/// Read and detect IPv4/IPv6 nameservers from the specified resolv.conf path.
pub fn detect_system_dns(resolv_path: &Path) -> DetectedDns {
    fs::read_to_string(resolv_path).map_or_else(
        |_| DetectedDns::default(),
        |content| parse_resolv_conf(&content),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_resolv_conf() {
        let sample = r"
        # DNS configuration
        search example.com
        nameserver 10.89.5.1 # Gateway container DNS
        nameserver 1.1.1.1   # Secondary
        nameserver 2606:4700:4700::1111 ; IPv6 DNS
        options edns0
        ";
        let detected = parse_resolv_conf(sample);
        assert_eq!(detected.v4, Some(Ipv4Addr::new(10, 89, 5, 1)));
        assert_eq!(
            detected.v6,
            Some("2606:4700:4700::1111".parse::<Ipv6Addr>().unwrap())
        );
    }

    #[test]
    fn test_parse_all_nameservers() {
        let sample = r"
        search dns.podman
        nameserver 10.89.0.1
        nameserver fd26::1
        nameserver 1.1.1.1
        ";
        let all = parse_all_nameservers(sample);
        assert_eq!(all.len(), 3);
        assert_eq!(all[0], IpAddr::V4(Ipv4Addr::new(10, 89, 0, 1)));
        assert_eq!(all[1], IpAddr::V6("fd26::1".parse().unwrap()));
        assert_eq!(all[2], IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
    }

    #[test]
    fn test_parse_resolv_conf_empty() {
        let detected = parse_resolv_conf("# Only comments\nsearch local\n");
        assert_eq!(detected.v4, None);
        assert_eq!(detected.v6, None);
    }

    #[test]
    fn test_valid_entries() {
        let sample = r"
        # Comments and whitespace
        192.168.1.100
        10.0.0.0/8 # Private IPv4 CIDR
        fc00:1234::1
        fd12:3456:789a::/48 # IPv6 CIDR
        ";
        let res = parse_whitelist(sample, true).unwrap();
        assert_eq!(res.v4, vec!["10.0.0.0/8", "192.168.1.100"]);
        assert_eq!(res.v6, vec!["fc00:1234::1", "fd12:3456:789a::/48"]);
    }

    #[test]
    fn test_deduplication() {
        let sample = r"
        192.168.1.100
        192.168.1.100
        10.0.0.0/8
        10.0.0.0/8
        fc00::1
        fc00::1
        ";
        let res = parse_whitelist(sample, true).unwrap();
        assert_eq!(res.v4, vec!["10.0.0.0/8", "192.168.1.100"]);
        assert_eq!(res.v6, vec!["fc00::1"]);
    }

    #[test]
    fn test_cidr_canonicalization_non_strict() {
        let sample = r"
        192.168.1.50/24
        fd12:3456:789a:1::1/48
        ";
        let res = parse_whitelist(sample, false).unwrap();
        assert_eq!(res.v4, vec!["192.168.1.0/24"]);
        assert_eq!(res.v6, vec!["fd12:3456:789a::/48"]);
    }

    #[test]
    fn test_cidr_canonicalization_strict_fails() {
        let sample = "192.168.1.50/24\n";
        let err = parse_whitelist(sample, true).unwrap_err();
        assert!(err.contains("has host bits set"));
    }

    #[test]
    fn test_invalid_entries_non_strict() {
        let sample = "192.168.1.1\ninvalid-ip\n10.0.0.1/99\n::1\n";
        let res = parse_whitelist(sample, false).unwrap();
        assert_eq!(res.v4, vec!["192.168.1.1"]);
        assert_eq!(res.v6, vec!["::1"]);
    }

    #[test]
    fn test_invalid_entries_strict() {
        let sample = "192.168.1.1\ninvalid-ip\n";
        assert!(parse_whitelist(sample, true).is_err());
    }

    #[test]
    fn test_detect_system_dns() {
        let detected = detect_system_dns(Path::new("/nonexistent_path/resolv.conf"));
        assert_eq!(detected.v4, None);
        assert_eq!(detected.v6, None);
    }
}
