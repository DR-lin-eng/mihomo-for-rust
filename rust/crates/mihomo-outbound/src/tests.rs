use std::collections::BTreeMap;

use crate::{
    parse_group_yaml, parse_outbound_yaml, parse_provider_yaml, GroupDefinition,
    OutboundDefinition, OutboundGroupKind, OutboundKind, ProviderHealthCheckConfig,
    ProxyProviderVehicleType, ShadowSocksOutboundConfig, SUPPORTED_OUTBOUND_GROUPS,
    SUPPORTED_OUTBOUNDS, WireGuardOutboundConfig,
};

#[test]
fn inventory_tracks_adapter_surface() {
    assert!(SUPPORTED_OUTBOUNDS.len() >= 20);
    assert!(SUPPORTED_OUTBOUNDS.contains(&OutboundKind::WireGuard));
    assert!(SUPPORTED_OUTBOUNDS.contains(&OutboundKind::Tailscale));
    assert!(SUPPORTED_OUTBOUNDS.contains(&OutboundKind::Sudoku));
    assert!(SUPPORTED_OUTBOUNDS.contains(&OutboundKind::TrustTunnel));
}

#[test]
fn inventory_tracks_group_surface() {
    assert_eq!(SUPPORTED_OUTBOUND_GROUPS.len(), 5);
    assert!(SUPPORTED_OUTBOUND_GROUPS.contains(&OutboundGroupKind::Smart));
    assert!(SUPPORTED_OUTBOUND_GROUPS.contains(&OutboundGroupKind::UrlTest));
}

#[test]
fn shadowsocks_proxy_parses_basic_and_smux_fields() {
    let parsed = parse_outbound_yaml(
        r#"
type: ss
name: edge-ss
server: 1.2.3.4
port: 8388
cipher: chacha20-ietf-poly1305
password: secret
tfo: true
smux:
  enabled: true
"#,
    )
    .unwrap();
    let OutboundDefinition::ShadowSocks(ShadowSocksOutboundConfig {
        server,
        port,
        cipher,
        password,
        base,
        ..
    }) = parsed
    else {
        panic!("expected shadowsocks proxy");
    };
    assert_eq!(server, "1.2.3.4");
    assert_eq!(port, 8388);
    assert_eq!(cipher, "chacha20-ietf-poly1305");
    assert_eq!(password, "secret");
    assert!(base.tfo);
    assert!(base.smux.enabled);
}

#[test]
fn direct_proxy_parses_without_server_fields() {
    let parsed = parse_outbound_yaml(
        r#"
type: direct
name: local
interface-name: en0
routing-mark: 10
"#,
    )
    .unwrap();
    let OutboundDefinition::Direct(config) = parsed else {
        panic!("expected direct proxy");
    };
    assert_eq!(config.base.name, "local");
    assert_eq!(config.base.interface_name, "en0");
    assert_eq!(config.base.routing_mark, 10);
}

#[test]
fn wireguard_proxy_keeps_modeled_keys() {
    let parsed = parse_outbound_yaml(
        r#"
type: wireguard
name: wg
server: edge.example.com
port: 51820
private-key: abc
ip: 10.0.0.2/32
ipv6: fd00::2/128
public-key: pub
"#,
    )
    .unwrap();
    let OutboundDefinition::WireGuard(WireGuardOutboundConfig {
        server,
        port,
        private_key,
        ip,
        ipv6,
        public_key,
        ..
    }) = parsed
    else {
        panic!("expected wireguard proxy");
    };
    assert_eq!(server, "edge.example.com");
    assert_eq!(port, 51820);
    assert_eq!(private_key, "abc");
    assert_eq!(ip, "10.0.0.2/32");
    assert_eq!(ipv6, "fd00::2/128");
    assert_eq!(public_key, "pub");
}

#[test]
fn proxy_group_parses_group_common_fields_and_defaults() {
    let parsed = parse_group_yaml(
        r#"
name: auto
type: url-test
proxies: [ss1, ss2, vmess1]
url: https://cp.cloudflare.com/generate_204
interval: 300
"#,
    )
    .unwrap();
    assert_eq!(
        parsed,
        GroupDefinition {
            name: "auto".into(),
            group_type: "url-test".into(),
            proxies: vec!["ss1".into(), "ss2".into(), "vmess1".into()],
            use_providers: vec![],
            url: "https://cp.cloudflare.com/generate_204".into(),
            interval: 300,
            timeout: 0,
            max_failed_times: 0,
            lazy: true,
            disable_udp: false,
            filter: String::new(),
            exclude_filter: String::new(),
            exclude_type: String::new(),
            expected_status: String::new(),
            include_all: false,
            include_all_proxies: false,
            include_all_providers: false,
            hidden: false,
            icon: String::new(),
            strategy: String::new(),
            tolerance: 0,
            extra: BTreeMap::new(),
        }
    );
    assert_eq!(parsed.kind(), Some(OutboundGroupKind::UrlTest));
}

#[test]
fn proxy_group_identifies_smart_as_its_own_group_type() {
    let parsed = parse_group_yaml(
        r#"
name: auto
type: smart
proxies: [ss1, ss2]
strategy: sticky-sessions
uselightgbm: true
collectdata: true
sample-rate: 1.0
"#,
    )
    .unwrap();
    assert_eq!(parsed.group_type, "smart");
    assert_eq!(parsed.strategy, "sticky-sessions");
    assert_eq!(parsed.kind(), Some(OutboundGroupKind::Smart));
    assert_eq!(parsed.extra.get("uselightgbm").and_then(|value| value.as_bool()), Some(true));
    assert_eq!(parsed.extra.get("collectdata").and_then(|value| value.as_bool()), Some(true));
    assert_eq!(parsed.extra.get("sample-rate").and_then(|value| value.as_f64()), Some(1.0));
}

#[test]
fn provider_parses_http_vehicle_health_check_and_override() {
    let parsed = parse_provider_yaml(
        r#"
type: http
url: https://example.com/provider.yaml
interval: 3600
path: ./provider1.yaml
proxy: DIRECT
header:
  User-Agent:
    - Clash/v1.18.0
health-check:
  enable: true
  interval: 600
  url: https://cp.cloudflare.com/generate_204
override:
  udp: true
  interface-name: tailscale0
"#,
    )
    .unwrap();
    assert_eq!(parsed.vehicle_type(), Some(ProxyProviderVehicleType::Http));
    assert_eq!(
        parsed.health_check,
        ProviderHealthCheckConfig {
            enable: true,
            url: "https://cp.cloudflare.com/generate_204".into(),
            interval: 600,
            timeout: 0,
            lazy: true,
            expected_status: String::new(),
        }
    );
    assert!(parsed.override_config.udp);
    assert_eq!(parsed.override_config.interface_name, "tailscale0");
    assert_eq!(
        parsed.header.get("User-Agent"),
        Some(&vec!["Clash/v1.18.0".into()])
    );
}

#[test]
fn expected_status_accepts_numeric_yaml_scalars() {
    let group = parse_group_yaml(
        r#"
name: auto
type: url-test
proxies: [ss1]
expected-status: 204
"#,
    )
    .unwrap();
    assert_eq!(group.expected_status, "204");

    let provider = parse_provider_yaml(
        r#"
type: http
url: https://example.com/provider.yaml
path: ./provider1.yaml
health-check:
  enable: true
  expected-status: 204
"#,
    )
    .unwrap();
    assert_eq!(provider.health_check.expected_status, "204");
}

#[test]
fn provider_parses_inline_payload_as_nested_proxies() {
    let parsed = parse_provider_yaml(
        r#"
type: inline
payload:
  - name: ss1
    type: ss
    server: server
    port: 443
    cipher: chacha20-ietf-poly1305
    password: password
"#,
    )
    .unwrap();
    assert_eq!(parsed.vehicle_type(), Some(ProxyProviderVehicleType::Inline));
    assert_eq!(parsed.payload.len(), 1);
    match &parsed.payload[0] {
        OutboundDefinition::ShadowSocks(config) => {
            assert_eq!(config.base.name, "ss1");
            assert_eq!(config.server, "server");
            assert_eq!(config.port, 443);
        }
        _ => panic!("expected nested shadowsocks proxy"),
    }
}
