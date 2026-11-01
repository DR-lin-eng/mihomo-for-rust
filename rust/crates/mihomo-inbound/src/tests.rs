use crate::{
    parse_inbound_yaml, InboundDefinition, InboundKind, ShadowSocksInboundConfig,
    SUPPORTED_INBOUNDS, TunStack, TlsInboundConfig, TProxyInboundConfig,
};

#[test]
fn inventory_tracks_listener_parse_surface() {
    assert!(SUPPORTED_INBOUNDS.len() >= 18);
    assert!(SUPPORTED_INBOUNDS.contains(&InboundKind::Tun));
    assert!(SUPPORTED_INBOUNDS.contains(&InboundKind::TProxy));
    assert!(SUPPORTED_INBOUNDS.contains(&InboundKind::ShadowSocks));
    assert!(SUPPORTED_INBOUNDS.contains(&InboundKind::Tuic));
}

#[test]
fn socks_defaults_udp_true_like_listener_parse_go() {
    let parsed = parse_inbound_yaml(
        r#"
type: socks
name: edge
listen: 127.0.0.1
port: "1080"
"#,
    )
    .unwrap();
    let InboundDefinition::Socks(TlsInboundConfig { udp, base, .. }) = parsed else {
        panic!("expected socks config");
    };
    assert!(udp);
    assert_eq!(base.raw_addresses(), vec!["127.0.0.1:1080"]);
}

#[test]
fn socks_accepts_numeric_port_values() {
    let parsed = parse_inbound_yaml(
        r#"
type: socks
name: edge
listen: 127.0.0.1
port: 1080
"#,
    )
    .unwrap();
    let InboundDefinition::Socks(TlsInboundConfig { base, .. }) = parsed else {
        panic!("expected socks config");
    };
    assert_eq!(base.port, "1080");
    assert_eq!(base.raw_addresses(), vec!["127.0.0.1:1080"]);
}

#[test]
fn tproxy_defaults_udp_true_like_listener_parse_go() {
    let parsed = parse_inbound_yaml(
        r#"
type: tproxy
name: edge
listen: 0.0.0.0
port: "7893"
"#,
    )
    .unwrap();
    let InboundDefinition::TProxy(TProxyInboundConfig { udp, .. }) = parsed else {
        panic!("expected tproxy config");
    };
    assert!(udp);
}

#[test]
fn tun_defaults_match_listener_parse_go() {
    let parsed = parse_inbound_yaml(
        r#"
type: tun
name: edge
"#,
    )
    .unwrap();
    let InboundDefinition::Tun(config) = parsed else {
        panic!("expected tun config");
    };
    assert_eq!(config.stack, TunStack::Gvisor);
    assert_eq!(config.dns_hijack, vec!["0.0.0.0:53"]);
    assert_eq!(config.base.raw_addresses(), vec!["0.0.0.0:0"]);
}

#[test]
fn shadowsocks_defaults_udp_false_and_keeps_modeled_fields() {
    let parsed = parse_inbound_yaml(
        r#"
type: shadowsocks
name: edge
listen: 0.0.0.0
port: "8388"
password: secret
cipher: chacha20-ietf-poly1305
simple-obfs:
  enable: true
  mode: http
"#,
    )
    .unwrap();
    let InboundDefinition::ShadowSocks(ShadowSocksInboundConfig {
        udp,
        password,
        cipher,
        simple_obfs,
        ..
    }) = parsed
    else {
        panic!("expected shadowsocks config");
    };
    // Go's shadowsocks listener defaults UDP off (`Udp bool` zero value).
    assert!(!udp);
    assert_eq!(password, "secret");
    assert_eq!(cipher, "chacha20-ietf-poly1305");
    assert!(simple_obfs.enable);
    assert_eq!(simple_obfs.mode, "http");
}

#[test]
fn tunnel_variant_keeps_network_and_target() {
    let parsed = parse_inbound_yaml(
        r#"
type: tunnel
name: edge
listen: 127.0.0.1
port: "9000-9001"
network: [tcp, udp]
target: example.com:443
"#,
    )
    .unwrap();
    let InboundDefinition::Tunnel(config) = parsed else {
        panic!("expected tunnel config");
    };
    assert_eq!(config.network, vec!["tcp", "udp"]);
    assert_eq!(config.target, "example.com:443");
    assert_eq!(
        config.base.raw_addresses(),
        vec!["127.0.0.1:9000", "127.0.0.1:9001"]
    );
}

#[test]
fn tunnel_accepts_numeric_port_values() {
    let parsed = parse_inbound_yaml(
        r#"
type: tunnel
name: edge
listen: 127.0.0.1
port: 9000
target: example.com:443
"#,
    )
    .unwrap();
    let InboundDefinition::Tunnel(config) = parsed else {
        panic!("expected tunnel config");
    };
    assert_eq!(config.base.port, "9000");
    assert_eq!(config.base.raw_addresses(), vec!["127.0.0.1:9000"]);
}
