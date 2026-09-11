use inotify::{Inotify, WatchMask};
use std::fs;
use std::io;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::thread::sleep;
use std::time::Duration;

use crate::nft::apply_batch;
use crate::parser::parse_whitelist;
use crate::signals::{check_and_clear_reload, is_shutdown_requested};

#[derive(Debug, Clone)]
pub struct DaemonConfig {
    pub rules_path: Option<PathBuf>,
    pub whitelist_path: PathBuf,
    pub resolv_conf_path: PathBuf,
    pub table_family: String,
    pub table_name: String,
    pub v4_set: String,
    pub v6_set: String,
    pub dns_upstream_v4: String,
    pub dns_upstream_v6: String,
    pub debounce_ms: u64,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            rules_path: None,
            whitelist_path: PathBuf::from("/etc/nftables/whitelist.txt"),
            resolv_conf_path: PathBuf::from("/etc/resolv.conf"),
            table_family: "inet".to_string(),
            table_name: "filter".to_string(),
            v4_set: "lan_whitelist_v4".to_string(),
            v6_set: "lan_whitelist_v6".to_string(),
            dns_upstream_v4: "auto".to_string(),
            dns_upstream_v6: "auto".to_string(),
            debounce_ms: 150,
        }
    }
}

pub fn sync_whitelist(config: &DaemonConfig) {
    if !config.whitelist_path.exists() {
        println!(
            "[Gateway] Whitelist file not found: {}",
            config.whitelist_path.display()
        );
        return;
    }

    match fs::read_to_string(&config.whitelist_path) {
        Ok(content) => match parse_whitelist(&content, false) {
            Ok(entries) => {
                if let Err(e) = apply_batch(
                    &config.table_family,
                    &config.table_name,
                    &config.v4_set,
                    &config.v6_set,
                    &entries,
                ) {
                    eprintln!("[Gateway] Failed to update nftables sets: {e}");
                }
            }
            Err(e) => {
                eprintln!("[Gateway] Failed to parse whitelist: {e}");
            }
        },
        Err(e) => {
            eprintln!(
                "[Gateway] Failed to read whitelist file {}: {e}",
                config.whitelist_path.display()
            );
        }
    }
}

fn drain_inotify_events(inotify: &mut Inotify, buffer: &mut [u8]) {
    while let Ok(events) = inotify.read_events(buffer) {
        let mut count = 0usize;
        for _ in events {
            count += 1;
        }
        if count == 0 {
            break;
        }
    }
}

fn read_and_check_events(
    inotify: &mut Inotify,
    buffer: &mut [u8],
    target_file_name: Option<&str>,
) -> bool {
    let mut matched = false;

    loop {
        match inotify.read_events(buffer) {
            Ok(events) => {
                let mut count = 0usize;
                for event in events {
                    count += 1;
                    if let Some(target) = target_file_name {
                        if let Some(event_name) = event.name {
                            if event_name.to_string_lossy() == target {
                                matched = true;
                            }
                        } else {
                            matched = true;
                        }
                    } else {
                        matched = true;
                    }
                }
                if count == 0 {
                    break;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                break;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => {
                eprintln!("[Gateway] Inotify read error: {e}");
                break;
            }
        }
    }

    matched
}

pub fn run_watcher_loop(config: &DaemonConfig) -> Result<(), Box<dyn std::error::Error>> {
    let parent_dir = config
        .whitelist_path
        .parent()
        .unwrap_or_else(|| Path::new("."));

    if !parent_dir.exists() {
        fs::create_dir_all(parent_dir)?;
    }

    if !config.whitelist_path.exists() {
        let _ = fs::File::create(&config.whitelist_path);
    }

    sync_whitelist(config);

    let mut inotify = Inotify::init()?;
    let fd = inotify.as_raw_fd();

    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
    }

    let watch_mask = WatchMask::CLOSE_WRITE
        | WatchMask::MOVED_TO
        | WatchMask::CREATE
        | WatchMask::MODIFY
        | WatchMask::DELETE;

    let _ = inotify.watches().add(parent_dir, watch_mask);
    if config.whitelist_path.exists() {
        let _ = inotify.watches().add(&config.whitelist_path, watch_mask);
    }

    let target_file_name = config
        .whitelist_path
        .file_name()
        .map(|s| s.to_string_lossy().to_string());

    let mut buffer = [0u8; 4096];

    while !is_shutdown_requested() {
        if check_and_clear_reload() {
            println!("[Gateway] Reload signal received, updating whitelist...");
            sync_whitelist(config);
        }

        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };

        let ret = unsafe { libc::poll(&raw mut pfd, 1, 500) };

        if ret < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            eprintln!("[Gateway] Poll error: {err}");
            sleep(Duration::from_millis(100));
            continue;
        }

        if ret == 0 {
            continue;
        }

        if (pfd.revents & libc::POLLIN) != 0 {
            let need_sync =
                read_and_check_events(&mut inotify, &mut buffer, target_file_name.as_deref());

            if need_sync {
                sleep(Duration::from_millis(config.debounce_ms));
                drain_inotify_events(&mut inotify, &mut buffer);

                if config.whitelist_path.exists() {
                    let _ = inotify.watches().add(&config.whitelist_path, watch_mask);
                }

                sync_whitelist(config);
            }
        }
    }

    println!("[Gateway] Exiting whitelist watcher gracefully...");
    Ok(())
}
