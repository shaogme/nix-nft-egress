mod nft;
mod parser;
mod router;
mod signals;
mod watcher;

use std::env;
use std::fs;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, exit};

use nft::{apply_dns_redirect, apply_ruleset_content, generate_base_ruleset, load_ruleset};
use parser::{DetectedDns, detect_system_dns, parse_whitelist};
use signals::register_signals;
use watcher::{DaemonConfig, run_watcher_loop};

fn print_help() {
    println!(
        r"nft-egress-daemon - High performance, atomic nftables egress whitelist gateway daemon

USAGE:
    nft-egress-daemon [SUBCOMMAND | OPTIONS | COMMAND...]

SUBCOMMANDS:
    run                     Run gateway daemon (loads ruleset and monitors whitelist) [default]
    check <FILE>            Validate syntax and structure of a whitelist file

OPTIONS (for 'run' or default mode):
    --rules <PATH>          Path to initial nftables ruleset file to load on startup
    --whitelist <PATH>      Path to whitelist configuration file (default: /etc/nftables/whitelist.txt)
    --family <FAMILY>       nftables table family (default: inet)
    --table <TABLE>         nftables table name (default: filter)
    --v4-set <SET>          IPv4 whitelist set name (default: lan_whitelist_v4)
    --v6-set <SET>          IPv6 whitelist set name (default: lan_whitelist_v6)
    --debounce-ms <MS>      File watch debounce window in milliseconds (default: 150)
    --dns-upstream-v4 <IP>  Upstream IPv4 DNS for transparent redirection, or 'auto' (default: auto)
    --dns-upstream-v6 <IP>  Upstream IPv6 DNS for transparent redirection, or 'auto' (default: auto)
    --resolv-conf <PATH>    Path to resolv.conf for DNS auto-detection (default: /etc/resolv.conf)
    --strict                In 'check' mode, fail on any warning
    --help, -h              Print this help information
    -- <CMD> [ARGS...]      Execute custom command instead of running watcher loop
"
    );
}

fn handle_check(args: &[String]) {
    let mut strict = false;
    let mut file_path: Option<&str> = None;

    for arg in args {
        if arg == "--strict" {
            strict = true;
        } else if arg == "--help" || arg == "-h" {
            println!("Usage: nft-egress-daemon check [--strict] <FILE>");
            return;
        } else if !arg.starts_with('-') && file_path.is_none() {
            file_path = Some(arg);
        }
    }

    let Some(path) = file_path else {
        eprintln!("Error: Missing file path for 'check' command.");
        exit(1);
    };

    println!("Checking whitelist file: {path}");
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error reading '{path}': {e}");
            exit(1);
        }
    };

    match parse_whitelist(&content, strict) {
        Ok(entries) => {
            println!("Validation successful:");
            println!("  IPv4 entries: {}", entries.v4.len());
            for v4 in &entries.v4 {
                println!("    - {v4}");
            }
            println!("  IPv6 entries: {}", entries.v6.len());
            for v6 in &entries.v6 {
                println!("    - {v6}");
            }
        }
        Err(err) => {
            eprintln!("Validation failed: {err}");
            exit(1);
        }
    }
}

fn parse_run_options(args: &[String]) -> (DaemonConfig, Option<(String, Vec<String>)>) {
    let mut config = DaemonConfig::default();
    let mut custom_cmd: Option<(String, Vec<String>)> = None;

    if let Ok(dns_v4_env) = env::var("DNS_UPSTREAM_V4") {
        config.dns_upstream_v4 = dns_v4_env;
    }
    if let Ok(dns_v6_env) = env::var("DNS_UPSTREAM_V6") {
        config.dns_upstream_v6 = dns_v6_env;
    }
    if let Ok(resolv_env) = env::var("RESOLV_CONF_PATH") {
        config.resolv_conf_path = PathBuf::from(resolv_env);
    }

    let mut i = 0usize;
    while i < args.len() {
        let arg = &args[i];
        if arg == "--" {
            if i + 1 < args.len() {
                custom_cmd = Some((args[i + 1].clone(), args[i + 2..].to_vec()));
            }
            break;
        } else if arg == "--rules" && i + 1 < args.len() {
            config.rules_path = Some(PathBuf::from(&args[i + 1]));
            i += 1;
        } else if arg == "--whitelist" && i + 1 < args.len() {
            config.whitelist_path = PathBuf::from(&args[i + 1]);
            i += 1;
        } else if (arg == "--dns-upstream-v4" || arg == "--dns-v4") && i + 1 < args.len() {
            config.dns_upstream_v4.clone_from(&args[i + 1]);
            i += 1;
        } else if (arg == "--dns-upstream-v6" || arg == "--dns-v6") && i + 1 < args.len() {
            config.dns_upstream_v6.clone_from(&args[i + 1]);
            i += 1;
        } else if arg == "--resolv-conf" && i + 1 < args.len() {
            config.resolv_conf_path = PathBuf::from(&args[i + 1]);
            i += 1;
        } else if arg == "--family" && i + 1 < args.len() {
            config.table_family.clone_from(&args[i + 1]);
            i += 1;
        } else if arg == "--table" && i + 1 < args.len() {
            config.table_name.clone_from(&args[i + 1]);
            i += 1;
        } else if arg == "--v4-set" && i + 1 < args.len() {
            config.v4_set.clone_from(&args[i + 1]);
            i += 1;
        } else if arg == "--v6-set" && i + 1 < args.len() {
            config.v6_set.clone_from(&args[i + 1]);
            i += 1;
        } else if arg == "--debounce-ms" && i + 1 < args.len() {
            if let Ok(ms) = args[i + 1].parse::<u64>() {
                config.debounce_ms = ms;
            }
            i += 1;
        } else if !arg.starts_with('-') {
            custom_cmd = Some((arg.clone(), args[i + 1..].to_vec()));
            break;
        } else {
            eprintln!("Unknown argument: {arg}");
            print_help();
            exit(1);
        }
        i += 1;
    }

    (config, custom_cmd)
}

fn detect_auto_dns(config: &DaemonConfig) -> DetectedDns {
    let gw_ips = router::get_gateway_ips();
    let (v4_default, v6_default) = router::get_default_routes();

    // Identify internal subnets: interfaces that do NOT hold the default route.
    let mut internal_subnets = Vec::new();
    for ip_info in &gw_ips {
        let is_external = match ip_info.ip {
            std::net::IpAddr::V4(_) => v4_default
                .as_ref()
                .is_some_and(|d| d.ifname == ip_info.ifname),
            std::net::IpAddr::V6(_) => v6_default
                .as_ref()
                .is_some_and(|d| d.ifname == ip_info.ifname),
        };
        if !is_external {
            internal_subnets.push(ip_info.clone());
        }
    }

    if internal_subnets.is_empty() {
        return detect_system_dns(&config.resolv_conf_path);
    }

    let all_nameservers = fs::read_to_string(&config.resolv_conf_path)
        .map_or_else(|_| Vec::new(), |c| parser::parse_all_nameservers(&c));

    let is_in_internal_subnets = |ip: std::net::IpAddr| -> bool {
        match ip {
            std::net::IpAddr::V4(v4) => internal_subnets.iter().any(|subnet| {
                if let std::net::IpAddr::V4(gw_v4) = subnet.ip {
                    parser::canonicalize_v4(v4, subnet.prefix)
                        == parser::canonicalize_v4(gw_v4, subnet.prefix)
                } else {
                    false
                }
            }),
            std::net::IpAddr::V6(v6) => internal_subnets.iter().any(|subnet| {
                if let std::net::IpAddr::V6(gw_v6) = subnet.ip {
                    parser::canonicalize_v6(v6, subnet.prefix)
                        == parser::canonicalize_v6(gw_v6, subnet.prefix)
                } else {
                    false
                }
            }),
        }
    };

    let mut auto_v4 = None;
    let mut auto_v6 = None;

    for ns in &all_nameservers {
        if is_in_internal_subnets(*ns) {
            println!(
                "[Gateway] Skipping internal bridge nameserver {ns} from {}",
                config.resolv_conf_path.display()
            );
            continue;
        }
        match ns {
            std::net::IpAddr::V4(v4) => {
                if auto_v4.is_none() {
                    auto_v4 = Some(*v4);
                }
            }
            std::net::IpAddr::V6(v6) => {
                if auto_v6.is_none() {
                    auto_v6 = Some(*v6);
                }
            }
        }
    }

    // Fallback: If no external nameserver was parsed, try the default route gateway IP on external interface.
    if auto_v4.is_none()
        && let Some(ref def) = v4_default
        && let Some(std::net::IpAddr::V4(gw_v4)) = def.gateway
    {
        println!("[Gateway] Fallback: Using external default gateway {gw_v4} as upstream DNS IPv4");
        auto_v4 = Some(gw_v4);
    }
    if auto_v6.is_none()
        && let Some(ref def) = v6_default
        && let Some(std::net::IpAddr::V6(gw_v6)) = def.gateway
    {
        println!("[Gateway] Fallback: Using external default gateway {gw_v6} as upstream DNS IPv6");
        auto_v6 = Some(gw_v6);
    }

    DetectedDns {
        v4: auto_v4,
        v6: auto_v6,
    }
}

fn resolve_dns_upstreams(config: &DaemonConfig) -> (Option<String>, Option<String>) {
    let detected = detect_auto_dns(config);

    let eff_v4 = if config.dns_upstream_v4.is_empty()
        || config.dns_upstream_v4.eq_ignore_ascii_case("auto")
    {
        detected.v4.map_or_else(
            || {
                println!(
                    "[Gateway] Notice: No external IPv4 nameserver auto-detected from {}",
                    config.resolv_conf_path.display()
                );
                None
            },
            |v4| {
                println!(
                    "[Gateway] Auto-detected host/gateway DNS IPv4 from {}: {v4}",
                    config.resolv_conf_path.display()
                );
                Some(v4.to_string())
            },
        )
    } else if config.dns_upstream_v4.eq_ignore_ascii_case("off")
        || config.dns_upstream_v4.eq_ignore_ascii_case("none")
        || config.dns_upstream_v4.eq_ignore_ascii_case("disabled")
    {
        println!("[Gateway] Transparent DNS IPv4 redirect disabled by configuration");
        None
    } else {
        println!(
            "[Gateway] Using specified DNS upstream IPv4: {}",
            config.dns_upstream_v4
        );
        Some(config.dns_upstream_v4.clone())
    };

    let eff_v6 = if config.dns_upstream_v6.is_empty()
        || config.dns_upstream_v6.eq_ignore_ascii_case("auto")
    {
        detected.v6.map(|v6| {
            println!(
                "[Gateway] Auto-detected host/gateway DNS IPv6 from {}: {v6}",
                config.resolv_conf_path.display()
            );
            v6.to_string()
        })
    } else if config.dns_upstream_v6.eq_ignore_ascii_case("off")
        || config.dns_upstream_v6.eq_ignore_ascii_case("none")
        || config.dns_upstream_v6.eq_ignore_ascii_case("disabled")
    {
        println!("[Gateway] Transparent DNS IPv6 redirect disabled by configuration");
        None
    } else {
        println!(
            "[Gateway] Using specified DNS upstream IPv6: {}",
            config.dns_upstream_v6
        );
        Some(config.dns_upstream_v6.clone())
    };

    (eff_v4, eff_v6)
}

fn initialize_rules_and_dns(config: &DaemonConfig) {
    let (dns_v4, dns_v6) = resolve_dns_upstreams(config);

    let mut rules_loaded = false;
    if let Some(ref rules) = config.rules_path
        && let Ok(content) = fs::read_to_string(rules)
        && content.contains("hook output")
        && load_ruleset(&rules.to_string_lossy()).is_ok()
    {
        rules_loaded = true;
    } else if let Ok(rules_env) = env::var("NFT_RULES_PATH")
        && Path::new(&rules_env).exists()
        && let Ok(content) = fs::read_to_string(&rules_env)
        && content.contains("hook output")
        && load_ruleset(&rules_env).is_ok()
    {
        rules_loaded = true;
    }

    if rules_loaded {
        if dns_v4.is_some() || dns_v6.is_some() {
            let _ = apply_dns_redirect(
                &config.table_family,
                &config.table_name,
                dns_v4.as_deref(),
                dns_v6.as_deref(),
            );
        }
    } else {
        let base_rules = generate_base_ruleset(
            &config.table_family,
            &config.table_name,
            &config.v4_set,
            &config.v6_set,
            dns_v4.as_deref(),
            dns_v6.as_deref(),
        );
        let _ = apply_ruleset_content(&base_rules);
    }
}

fn execute_command(cmd: &str, child_args: &[String]) -> ! {
    let err = Command::new(cmd).args(child_args).exec();
    eprintln!("[Gateway] Failed to exec '{cmd}': {err}");
    exit(1);
}

fn main() {
    register_signals();

    let raw_args: Vec<String> = env::args().skip(1).collect();

    if raw_args.is_empty() {
        let config = DaemonConfig::default();
        initialize_rules_and_dns(&config);
        println!("[Gateway] Starting whitelist-watcher daemon (Sidecar mode)...");
        if let Err(e) = run_watcher_loop(&config) {
            eprintln!("[Gateway] Watcher error: {e}");
            exit(1);
        }
        return;
    }

    if raw_args.iter().any(|a| a == "--help" || a == "-h") {
        print_help();
        return;
    }

    if raw_args[0] == "check" {
        handle_check(&raw_args[1..]);
        return;
    }

    let (is_direct_exec, args_to_parse) = if raw_args[0] == "run" {
        (false, &raw_args[1..])
    } else if raw_args[0].starts_with('-') {
        (false, &raw_args[..])
    } else {
        (true, &raw_args[..])
    };

    if is_direct_exec {
        let (config, _) = parse_run_options(&[]);
        initialize_rules_and_dns(&config);
        execute_command(&args_to_parse[0], &args_to_parse[1..]);
    }

    let (config, custom_cmd) = parse_run_options(args_to_parse);
    initialize_rules_and_dns(&config);

    if let Some((cmd, child_args)) = custom_cmd {
        execute_command(&cmd, &child_args);
    }

    println!("[Gateway] Starting whitelist-watcher daemon (Sidecar mode)...");
    if let Err(e) = run_watcher_loop(&config) {
        eprintln!("[Gateway] Watcher error: {e}");
        exit(1);
    }
}
