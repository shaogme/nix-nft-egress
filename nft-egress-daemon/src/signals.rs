use std::sync::atomic::{AtomicBool, Ordering};

static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);
static RELOAD_REQUESTED: AtomicBool = AtomicBool::new(false);

extern "C" fn sig_handler(sig: libc::c_int) {
    match sig {
        libc::SIGTERM | libc::SIGINT => {
            SHUTDOWN_REQUESTED.store(true, Ordering::SeqCst);
        }
        libc::SIGHUP => {
            RELOAD_REQUESTED.store(true, Ordering::SeqCst);
        }
        _ => {}
    }
}

pub fn register_signals() {
    unsafe {
        libc::signal(
            libc::SIGTERM,
            sig_handler as *const () as libc::sighandler_t,
        );
        libc::signal(libc::SIGINT, sig_handler as *const () as libc::sighandler_t);
        libc::signal(libc::SIGHUP, sig_handler as *const () as libc::sighandler_t);
    }
}

pub fn is_shutdown_requested() -> bool {
    SHUTDOWN_REQUESTED.load(Ordering::Relaxed)
}

pub fn check_and_clear_reload() -> bool {
    RELOAD_REQUESTED.swap(false, Ordering::Relaxed)
}
