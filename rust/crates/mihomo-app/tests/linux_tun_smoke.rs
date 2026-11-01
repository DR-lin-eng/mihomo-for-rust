#![cfg(all(test, target_os = "linux"))]

use std::fs;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::process::Command as ProcessCommand;
use std::sync::OnceLock;
use std::sync::mpsc;
use std::time::{SystemTime, UNIX_EPOCH};

use mihomo_app::RunningApp;
use mihomo_config::{BootEnvironment, BootOptions, Command};
use mihomo_core::{Metadata, NetworkKind, SessionKind};

fn unique_temp_dir(prefix: &str) -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{nanos}"))
}

fn tun_tcp_trace_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var_os("MIHOMO_TUN_TCP_TRACE").is_some())
}

#[test]
#[ignore = "requires /dev/net/tun, CAP_NET_ADMIN, and iproute2"]
fn start_with_linux_named_tun_device_smoke() {
    let temp = unique_temp_dir("mihomo-app-linux-named-tun");
    fs::create_dir_all(&temp).unwrap();
    let device_name = format!(
        "mih{:x}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .subsec_nanos()
    );
    let ipv4 = "198.19.0.1/30";
    fs::write(
        temp.join("config.yaml"),
        format!(
            r#"
tun:
  enable: true
  device: {device_name}
  mtu: 1400
  inet4-address:
    - {ipv4}
proxies:
  - type: direct
    name: direct-a
rules:
  - MATCH,direct-a
"#,
            device_name = device_name,
            ipv4 = ipv4,
        ),
    )
    .unwrap();

    let options = BootOptions {
        home_dir: Some(temp.to_string_lossy().into_owned()),
        config_file: Some(temp.join("config.yaml").to_string_lossy().into_owned()),
        config_base64: None,
        external_ui: None,
        external_controller: None,
        external_controller_unix: None,
        external_controller_pipe: None,
        secret: None,
        post_up: None,
        post_down: None,
        geodata_mode: false,
        show_version: false,
        test_config: false,
        command: Command::Run,
    };

    let mut app = RunningApp::start(&options, &temp, &BootEnvironment::default()).unwrap();

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

    app.shutdown();
}

#[test]
#[ignore = "requires /dev/net/tun, CAP_NET_ADMIN, iproute2, and real tun routing"]
fn tun_device_proxies_tcp_via_http_outbound_end_to_end() {
    let temp = unique_temp_dir("mihomo-app-linux-tun-http-proxy");
    fs::create_dir_all(&temp).unwrap();
    let device_name = format!(
        "mih{:x}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .subsec_nanos()
    );
    let proxy_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let target_addr = "203.0.113.10:443";
    let target_ip = target_addr.split(':').next().unwrap();
    let (proxy_result_tx, proxy_result_rx) = mpsc::channel();
    let proxy_thread = std::thread::spawn(move || {
        let result = (|| -> Result<(), String> {
            let (mut stream, _) = proxy_listener.accept().map_err(|err| err.to_string())?;
            if tun_tcp_trace_enabled() {
                eprintln!("[tun-http-smoke] accepted proxy connection");
            }
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .map_err(|err| err.to_string())?;
            let mut request = Vec::new();
            let mut buf = [0_u8; 1024];
            loop {
                let read = stream.read(&mut buf).map_err(|err| err.to_string())?;
                if read == 0 {
                    return Err("proxy request closed before headers".to_owned());
                }
                request.extend_from_slice(&buf[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let header_end = request
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .map(|position| position + 4)
                .ok_or_else(|| "missing header terminator".to_owned())?;
            let tail = request[header_end..].to_vec();
            let request_text = String::from_utf8(request).map_err(|err| err.to_string())?;
            if tun_tcp_trace_enabled() {
                eprintln!(
                    "[tun-http-smoke] request-bytes={} tail-bytes={}",
                    request_text.len() + tail.len(),
                    tail.len()
                );
            }
            if !request_text.starts_with(&format!("CONNECT {target_addr} HTTP/1.1\r\n")) {
                return Err(format!("unexpected request: {request_text}"));
            }
            stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .map_err(|err| err.to_string())?;
            stream.flush().map_err(|err| err.to_string())?;

            let mut payload = [0_u8; 1024];
            let mut received = tail;
            while received.len() < b"ping-through-tun".len() {
                let read = stream.read(&mut payload).map_err(|err| err.to_string())?;
                if read == 0 {
                    return Err("proxy payload closed before body".to_owned());
                }
                received.extend_from_slice(&payload[..read]);
            }
            if tun_tcp_trace_enabled() {
                eprintln!(
                    "[tun-http-smoke] received payload bytes={}",
                    received.len()
                );
            }
            if &received[..b"ping-through-tun".len()] != b"ping-through-tun" {
                return Err(format!(
                    "unexpected payload prefix: {:?}",
                    &received[..received.len().min(64)]
                ));
            }
            if tun_tcp_trace_enabled() {
                eprintln!("[tun-http-smoke] sending pong");
            }
            stream
                .write_all(b"pong-through-tun")
                .map_err(|err| err.to_string())?;
            stream.flush().map_err(|err| err.to_string())?;
            stream
                .shutdown(Shutdown::Write)
                .map_err(|err| err.to_string())?;
            Ok(())
        })();
        let _ = proxy_result_tx.send(result.clone());
        result.unwrap();
    });

    fs::write(
        temp.join("config.yaml"),
        format!(
            r#"
mode: rule
tun:
  enable: true
  stack: system
  device: {device_name}
  mtu: 1400
  inet4-address:
    - 198.19.0.1/30
proxies:
  - type: http
    name: edge-http
    server: 127.0.0.1
    port: {proxy_port}
rules:
  - MATCH,edge-http
"#,
            device_name = device_name,
            proxy_port = proxy_addr.port(),
        ),
    )
    .unwrap();

    let options = BootOptions {
        home_dir: Some(temp.to_string_lossy().into_owned()),
        config_file: Some(temp.join("config.yaml").to_string_lossy().into_owned()),
        config_base64: None,
        external_ui: None,
        external_controller: None,
        external_controller_unix: None,
        external_controller_pipe: None,
        secret: None,
        post_up: None,
        post_down: None,
        geodata_mode: false,
        show_version: false,
        test_config: false,
        command: Command::Run,
    };

    let mut app = RunningApp::start(&options, &temp, &BootEnvironment::default()).unwrap();

    let selected = app.runtime_tunnel.selected_target(&Metadata {
        network: NetworkKind::Tcp,
        kind: SessionKind::Tun,
        src_ip: Some("198.19.0.1".parse().unwrap()),
        src_port: Some(40000),
        dst_ip: Some(target_ip.parse().unwrap()),
        dst_port: Some(443),
        inbound_name: "__top_level_tun__".into(),
        ..Metadata::default()
    });
    assert_eq!(selected, "edge-http");

    if tun_tcp_trace_enabled() {
        eprintln!("[tun-http-smoke] selected-target={selected}");
    }

    run_ip_command(["route", "replace", &format!("{target_ip}/32"), "dev", &device_name]);

    let mut client = TcpStream::connect(target_addr).unwrap();
    client
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();
    client
        .set_write_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();
    client.write_all(b"ping-through-tun").unwrap();
    client.flush().unwrap();
    let mut reply = [0_u8; 1024];
    let read = client.read(&mut reply).unwrap_or_else(|err| {
        match proxy_result_rx.recv_timeout(std::time::Duration::from_secs(6)) {
            Ok(result) => panic!("client read failed: {err}; proxy result: {result:?}"),
            Err(wait_err) => panic!("client read failed: {err}; proxy result unavailable: {wait_err}"),
        }
    });
    assert_eq!(&reply[..read], b"pong-through-tun");

    let _ = ProcessCommand::new("ip")
        .args(["route", "del", &format!("{target_ip}/32"), "dev", &device_name])
        .status();
    app.shutdown();
    if let Ok(result) = proxy_result_rx.try_recv() {
        assert!(result.is_ok(), "proxy thread result: {result:?}");
    }
    proxy_thread.join().unwrap();
}

#[test]
#[ignore = "requires /dev/net/tun, CAP_NET_ADMIN, iproute2, and real loopback reroute via tun auto-redirect"]
fn tun_loopback_address_auto_redirect_proxies_local_tcp_via_http_outbound() {
    let temp = unique_temp_dir("mihomo-app-linux-tun-loopback-reroute");
    fs::create_dir_all(&temp).unwrap();
    let device_name = format!(
        "mih{:x}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .subsec_nanos()
    );
    let proxy_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let loopback_target = "198.19.0.9:443";
    let (proxy_result_tx, proxy_result_rx) = mpsc::channel();
    let proxy_thread = std::thread::spawn(move || {
        let result = (|| -> Result<(), String> {
            let (mut stream, _) = proxy_listener.accept().map_err(|err| err.to_string())?;
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .map_err(|err| err.to_string())?;
            let mut request = Vec::new();
            let mut buf = [0_u8; 1024];
            loop {
                let read = stream.read(&mut buf).map_err(|err| err.to_string())?;
                if read == 0 {
                    return Err("proxy request closed before headers".to_owned());
                }
                request.extend_from_slice(&buf[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let request_text = String::from_utf8(request).map_err(|err| err.to_string())?;
            if !request_text.starts_with(&format!("CONNECT {loopback_target} HTTP/1.1\r\n")) {
                return Err(format!("unexpected request: {request_text}"));
            }
            stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .map_err(|err| err.to_string())?;
            stream.flush().map_err(|err| err.to_string())?;
            let mut body = [0_u8; 1024];
            let read = stream.read(&mut body).map_err(|err| err.to_string())?;
            if &body[..read] != b"loopback-ping" {
                return Err(format!("unexpected body: {:?}", &body[..read]));
            }
            stream
                .write_all(b"loopback-pong")
                .map_err(|err| err.to_string())?;
            stream.flush().map_err(|err| err.to_string())?;
            stream
                .shutdown(Shutdown::Write)
                .map_err(|err| err.to_string())?;
            Ok(())
        })();
        let _ = proxy_result_tx.send(result.clone());
        result.unwrap();
    });

    fs::write(
        temp.join("config.yaml"),
        format!(
            r#"
mode: rule
redir-port: 7891
tun:
  enable: true
  stack: system
  device: {device_name}
  mtu: 1400
  inet4-address:
    - 198.19.0.1/30
  auto-route: true
  auto-redirect: true
  loopback-address:
    - 198.19.0.9
proxies:
  - type: http
    name: edge-http
    server: 127.0.0.1
    port: {proxy_port}
rules:
  - MATCH,edge-http
"#,
            device_name = device_name,
            proxy_port = proxy_addr.port(),
        ),
    )
    .unwrap();

    let options = BootOptions {
        home_dir: Some(temp.to_string_lossy().into_owned()),
        config_file: Some(temp.join("config.yaml").to_string_lossy().into_owned()),
        config_base64: None,
        external_ui: None,
        external_controller: None,
        external_controller_unix: None,
        external_controller_pipe: None,
        secret: None,
        post_up: None,
        post_down: None,
        geodata_mode: false,
        show_version: false,
        test_config: false,
        command: Command::Run,
    };

    let mut app = RunningApp::start(&options, &temp, &BootEnvironment::default()).unwrap();

    let mut client = TcpStream::connect(loopback_target).unwrap();
    client
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();
    client
        .set_write_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();
    client.write_all(b"loopback-ping").unwrap();
    client.flush().unwrap();
    let mut reply = [0_u8; 1024];
    let read = client.read(&mut reply).unwrap_or_else(|err| {
        match proxy_result_rx.recv_timeout(std::time::Duration::from_secs(6)) {
            Ok(result) => panic!("client read failed: {err}; proxy result: {result:?}"),
            Err(wait_err) => panic!("client read failed: {err}; proxy result unavailable: {wait_err}"),
        }
    });
    assert_eq!(&reply[..read], b"loopback-pong");

    app.shutdown();
    if let Ok(result) = proxy_result_rx.try_recv() {
        assert!(result.is_ok(), "proxy thread result: {result:?}");
    }
    proxy_thread.join().unwrap();
}

fn run_ip_command<const N: usize>(args: [&str; N]) {
    let output = ProcessCommand::new("ip").args(args).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
