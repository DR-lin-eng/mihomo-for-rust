#![cfg(all(test, target_os = "linux"))]

use mihomo_inbound::TunInboundConfig;
use mihomo_tun::{open_linux_tun_device, TunRuntimeSpec};

#[test]
#[ignore = "requires /dev/net/tun, CAP_NET_ADMIN, and iproute2"]
fn open_linux_named_tun_device_smoke() {
    let device_name = format!(
        "mih{:x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos()
    );
    let ipv4 = "198.19.0.1/30";
    let spec = TunRuntimeSpec::new(
        "__top_level_tun__",
        TunInboundConfig {
            device: device_name.clone(),
            mtu: 1400,
            inet4_address: vec![ipv4.into()],
            ..Default::default()
        },
    );

    let file = open_linux_tun_device(&spec).unwrap();

    let link = std::process::Command::new("ip")
        .args(["link", "show", "dev", &device_name])
        .output()
        .unwrap();
    assert!(link.status.success(), "{link:?}");
    let link_stdout = String::from_utf8_lossy(&link.stdout);
    assert!(link_stdout.contains(&device_name), "{link_stdout}");
    assert!(link_stdout.contains("mtu 1400"), "{link_stdout}");

    let addr = std::process::Command::new("ip")
        .args(["-4", "addr", "show", "dev", &device_name])
        .output()
        .unwrap();
    assert!(addr.status.success(), "{addr:?}");
    let addr_stdout = String::from_utf8_lossy(&addr.stdout);
    assert!(addr_stdout.contains(ipv4.split('/').next().unwrap()), "{addr_stdout}");

    drop(file);
    let _ = std::process::Command::new("ip")
        .args(["link", "del", "dev", &device_name])
        .status();
}
