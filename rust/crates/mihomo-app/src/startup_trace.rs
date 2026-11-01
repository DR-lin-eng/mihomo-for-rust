pub fn enabled() -> bool {
    std::env::var_os("MIHOMO_STARTUP_TRACE").is_some()
}

pub fn mark(stage: &str) {
    if enabled() {
        eprintln!("[startup-trace] {stage}");
    }
}
