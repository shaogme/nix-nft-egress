use crate::parser::WhitelistEntries;
use std::fmt::Write as FmtWrite;
use std::io::Write;
use std::process::{Command, Stdio};

pub fn generate_batch_script(
    family: &str,
    table: &str,
    v4_set: &str,
    v6_set: &str,
    entries: &WhitelistEntries,
) -> String {
    let mut script = String::new();

    // Flush and add v4 elements
    let _ = writeln!(script, "flush set {family} {table} {v4_set}");
    if !entries.v4.is_empty() {
        let _ = writeln!(
            script,
            "add element {family} {table} {v4_set} {{ {} }}",
            entries.v4.join(", ")
        );
    }

    // Flush and add v6 elements
    let _ = writeln!(script, "flush set {family} {table} {v6_set}");
    if !entries.v6.is_empty() {
        let _ = writeln!(
            script,
            "add element {family} {table} {v6_set} {{ {} }}",
            entries.v6.join(", ")
        );
    }

    script
}

pub fn apply_batch(
    family: &str,
    table: &str,
    v4_set: &str,
    v6_set: &str,
    entries: &WhitelistEntries,
) -> Result<(), String> {
    let script = generate_batch_script(family, table, v4_set, v6_set, entries);

    let mut child = Command::new("nft")
        .arg("-f")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to spawn 'nft': {e}"))?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(script.as_bytes())
            .map_err(|e| format!("Failed to write to nft stdin: {e}"))?;
    }

    let output = child
        .wait_with_output()
        .map_err(|e| format!("Failed to wait for nft: {e}"))?;

    if output.status.success() {
        let v4_str = if entries.v4.is_empty() {
            "none".to_string()
        } else {
            entries.v4.join(",")
        };
        let v6_str = if entries.v6.is_empty() {
            "none".to_string()
        } else {
            entries.v6.join(",")
        };
        println!("[Gateway] Whitelist synced: [IPv4: {v4_str}] [IPv6: {v6_str}]");
        Ok(())
    } else {
        let err_msg = String::from_utf8_lossy(&output.stderr).trim().to_string();
        eprintln!("[Gateway] Error applying nftables batch: {err_msg}");
        Err(err_msg)
    }
}

pub fn load_ruleset(rules_path: &str) -> Result<(), String> {
    println!("[Gateway] Loading nftables initial ruleset...");
    let output = Command::new("nft")
        .arg("-f")
        .arg(rules_path)
        .output()
        .map_err(|e| format!("Failed to execute nft: {e}"))?;

    if output.status.success() {
        println!("[Gateway] Ruleset loaded successfully.");
        Ok(())
    } else {
        let err_msg = String::from_utf8_lossy(&output.stderr).trim().to_string();
        eprintln!(
            "[Gateway] Warning: Failed to apply nftables ruleset. Make sure NET_ADMIN capability is granted. Details: {err_msg}"
        );
        Err(err_msg)
    }
}

pub fn apply_ruleset_content(content: &str) -> Result<(), String> {
    println!("[Gateway] Applying nftables ruleset from configuration...");
    let mut child = Command::new("nft")
        .arg("-f")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to spawn 'nft': {e}"))?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(content.as_bytes())
            .map_err(|e| format!("Failed to write ruleset to nft stdin: {e}"))?;
    }

    let output = child
        .wait_with_output()
        .map_err(|e| format!("Failed to wait for nft: {e}"))?;

    if output.status.success() {
        println!("[Gateway] Ruleset loaded successfully from generated configuration.");
        Ok(())
    } else {
        let err_msg = String::from_utf8_lossy(&output.stderr).trim().to_string();
        eprintln!("[Gateway] Warning: Failed to apply generated ruleset: {err_msg}");
        Err(err_msg)
    }
}

pub fn generate_dns_redirect_script(
    family: &str,
    table: &str,
    dns_v4: Option<&str>,
    dns_v6: Option<&str>,
) -> String {
    let mut script = String::new();
    let _ = writeln!(script, "flush chain {family} {table} nat_output");
    let _ = writeln!(script, "flush set {family} {table} dns_upstream_v4");
    let _ = writeln!(script, "flush set {family} {table} dns_upstream_v6");

    if let Some(v4) = dns_v4 {
        let _ = writeln!(
            script,
            "add rule {family} {table} nat_output meta l4proto {{ udp, tcp }} th dport 53 dnat ip to {v4}:53"
        );
        let _ = writeln!(
            script,
            "add element {family} {table} dns_upstream_v4 {{ {v4} }}"
        );
    }

    if let Some(v6) = dns_v6 {
        let _ = writeln!(
            script,
            "add rule {family} {table} nat_output meta l4proto {{ udp, tcp }} th dport 53 dnat ip6 to [{v6}]:53"
        );
        let _ = writeln!(
            script,
            "add element {family} {table} dns_upstream_v6 {{ {v6} }}"
        );
    }

    script
}

pub fn apply_dns_redirect(
    family: &str,
    table: &str,
    dns_v4: Option<&str>,
    dns_v6: Option<&str>,
) -> Result<(), String> {
    let script = generate_dns_redirect_script(family, table, dns_v4, dns_v6);

    let mut child = Command::new("nft")
        .arg("-f")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to spawn 'nft': {e}"))?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(script.as_bytes())
            .map_err(|e| format!("Failed to write to nft stdin: {e}"))?;
    }

    let output = child
        .wait_with_output()
        .map_err(|e| format!("Failed to wait for nft: {e}"))?;

    if output.status.success() {
        let v4_str = dns_v4.unwrap_or("none");
        let v6_str = dns_v6.unwrap_or("none");
        println!("[Gateway] DNS transparent redirect synced: [IPv4: {v4_str}] [IPv6: {v6_str}]");
        Ok(())
    } else {
        let err_msg = String::from_utf8_lossy(&output.stderr).trim().to_string();
        eprintln!("[Gateway] Error applying DNS redirect rules: {err_msg}");
        Err(err_msg)
    }
}

pub fn generate_base_ruleset(
    family: &str,
    table: &str,
    v4_set: &str,
    v6_set: &str,
    dns_v4: Option<&str>,
    dns_v6: Option<&str>,
) -> String {
    let mut script = String::new();
    let _ = writeln!(script, "flush ruleset\n");
    let _ = writeln!(script, "table {family} {table} {{");
    let _ = writeln!(
        script,
        "  set {v4_set} {{\n    type ipv4_addr\n    flags interval\n  }}"
    );
    let _ = writeln!(
        script,
        "  set {v6_set} {{\n    type ipv6_addr\n    flags interval\n  }}"
    );
    let _ = writeln!(
        script,
        "  set dns_upstream_v4 {{\n    type ipv4_addr\n    flags interval\n  }}"
    );
    let _ = writeln!(
        script,
        "  set dns_upstream_v6 {{\n    type ipv6_addr\n    flags interval\n  }}"
    );
    let _ = writeln!(
        script,
        "  set private_v4 {{\n    type ipv4_addr\n    flags interval\n    elements = {{ \n      10.0.0.0/8, \n      172.16.0.0/12, \n      192.168.0.0/16, \n      169.254.0.0/16,\n      100.64.0.0/10,\n      127.0.0.0/8 \n    }}\n  }}"
    );
    let _ = writeln!(
        script,
        "  set private_v6 {{\n    type ipv6_addr\n    flags interval\n    elements = {{ \n      ::1/128,\n      fc00::/7,\n      fe80::/10\n    }}\n  }}"
    );

    let _ = writeln!(
        script,
        "\n  chain nat_output {{\n    type nat hook output priority dstnat; policy accept;"
    );
    if let Some(v4) = dns_v4 {
        let _ = writeln!(
            script,
            "    meta l4proto {{ udp, tcp }} th dport 53 dnat ip to {v4}:53"
        );
    }
    if let Some(v6) = dns_v6 {
        let _ = writeln!(
            script,
            "    meta l4proto {{ udp, tcp }} th dport 53 dnat ip6 to [{v6}]:53"
        );
    }
    let _ = writeln!(script, "  }}");

    let _ = writeln!(
        script,
        "\n  chain nat_postrouting {{\n    type nat hook postrouting priority srcnat; policy accept;\n    oifname != \"lo\" masquerade\n  }}"
    );

    let _ = writeln!(
        script,
        "\n  chain output {{\n    type filter hook output priority 0; policy drop;"
    );
    let _ = writeln!(script, "    oifname \"lo\" accept");
    let _ = writeln!(script, "    ct state established,related accept");
    let _ = writeln!(script, "    meta l4proto ipv6-icmp accept");
    let _ = writeln!(script, "    ip daddr @dns_upstream_v4 th dport 53 accept");
    let _ = writeln!(script, "    ip6 daddr @dns_upstream_v6 th dport 53 accept");
    let _ = writeln!(script, "    ip daddr @{v4_set} accept");
    let _ = writeln!(script, "    ip6 daddr @{v6_set} accept");
    let _ = writeln!(
        script,
        "    ip daddr @private_v4 limit rate 10/minute log prefix \"[ANTI-SSRF DROP-V4]: \""
    );
    let _ = writeln!(script, "    ip daddr @private_v4 drop");
    let _ = writeln!(
        script,
        "    ip6 daddr @private_v6 limit rate 10/minute log prefix \"[ANTI-SSRF DROP-V6]: \""
    );
    let _ = writeln!(script, "    ip6 daddr @private_v6 drop");
    let _ = writeln!(script, "    accept");
    let _ = writeln!(script, "  }}");
    let _ = writeln!(script, "}}");

    if let Some(v4) = dns_v4 {
        let _ = writeln!(
            script,
            "add element {family} {table} dns_upstream_v4 {{ {v4} }}"
        );
    }
    if let Some(v6) = dns_v6 {
        let _ = writeln!(
            script,
            "add element {family} {table} dns_upstream_v6 {{ {v6} }}"
        );
    }

    script
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_batch_script_generation() {
        let entries = WhitelistEntries {
            v4: vec!["1.1.1.1".to_string(), "10.0.0.0/8".to_string()],
            v6: vec!["fe80::1".to_string()],
        };
        let script = generate_batch_script("inet", "filter", "lan_v4", "lan_v6", &entries);
        assert_eq!(
            script,
            "flush set inet filter lan_v4\nadd element inet filter lan_v4 { 1.1.1.1, 10.0.0.0/8 }\nflush set inet filter lan_v6\nadd element inet filter lan_v6 { fe80::1 }\n"
        );
    }

    #[test]
    fn test_batch_script_generation_empty() {
        let entries = WhitelistEntries::default();
        let script = generate_batch_script("inet", "filter", "lan_v4", "lan_v6", &entries);
        assert_eq!(
            script,
            "flush set inet filter lan_v4\nflush set inet filter lan_v6\n"
        );
    }

    #[test]
    fn test_dns_redirect_script_generation() {
        let script = generate_dns_redirect_script(
            "inet",
            "filter",
            Some("8.8.8.8"),
            Some("2001:4860:4860::8888"),
        );
        assert!(script.contains("flush chain inet filter nat_output"));
        assert!(script.contains("dnat ip to 8.8.8.8:53"));
        assert!(script.contains("dnat ip6 to [2001:4860:4860::8888]:53"));
        assert!(script.contains("flush set inet filter dns_upstream_v4"));
        assert!(script.contains("add element inet filter dns_upstream_v4 { 8.8.8.8 }"));
        assert!(script.contains("flush set inet filter dns_upstream_v6"));
        assert!(
            script.contains("add element inet filter dns_upstream_v6 { 2001:4860:4860::8888 }")
        );
    }

    #[test]
    fn test_dns_redirect_script_generation_v4_only() {
        let script = generate_dns_redirect_script("inet", "filter", Some("10.89.5.1"), None);
        assert!(script.contains("flush chain inet filter nat_output"));
        assert!(script.contains("dnat ip to 10.89.5.1:53"));
        assert!(!script.contains("dnat ip6"));
        assert!(script.contains("add element inet filter dns_upstream_v4 { 10.89.5.1 }"));
    }

    #[test]
    fn test_base_ruleset_generation() {
        let ruleset = generate_base_ruleset(
            "inet",
            "filter",
            "lan_v4",
            "lan_v6",
            Some("1.1.1.1"),
            Some("2606:4700:4700::1111"),
        );
        assert!(ruleset.contains("chain nat_output"));
        assert!(ruleset.contains("type nat hook output priority dstnat; policy accept;"));
        assert!(ruleset.contains("dnat ip to 1.1.1.1:53"));
        assert!(ruleset.contains("dnat ip6 to [2606:4700:4700::1111]:53"));
        assert!(ruleset.contains("chain nat_postrouting"));
        assert!(ruleset.contains("type nat hook postrouting priority srcnat; policy accept;"));
        assert!(ruleset.contains("oifname != \"lo\" masquerade"));
        assert!(ruleset.contains("chain output"));
        assert!(ruleset.contains("type filter hook output priority 0; policy drop;"));
        assert!(ruleset.contains("oifname \"lo\" accept"));
        assert!(ruleset.contains("ip daddr @dns_upstream_v4 th dport 53 accept"));
        assert!(ruleset.contains("ip6 daddr @dns_upstream_v6 th dport 53 accept"));
        assert!(ruleset.contains("ip daddr @lan_v4 accept"));
        assert!(ruleset.contains("ip6 daddr @lan_v6 accept"));
        assert!(ruleset.contains("ip daddr @private_v4 drop"));
        assert!(ruleset.contains("ip6 daddr @private_v6 drop"));
    }
}
