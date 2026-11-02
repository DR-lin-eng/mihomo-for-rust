use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=MIHOMO_BUILD_TIME");
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_owned());
    let rustc_version = Command::new(&rustc)
        .arg("--version")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|output| output.trim().to_owned())
        .filter(|output| !output.is_empty())
        .unwrap_or_else(|| "rustc unknown".to_owned());
    println!("cargo:rustc-env=MIHOMO_RUSTC_VERSION={rustc_version}");
    let build_time = std::env::var("MIHOMO_BUILD_TIME").unwrap_or_else(|_| "unknown time".to_owned());
    println!("cargo:rustc-env=MIHOMO_BUILD_TIME={build_time}");
}
