use mihomo_outbound::{OutboundDefinition, OutboundKind};
use crate::support_helpers::extra_bool;
use crate::{support_protocols::native_support_gap_for_outbound_impl, ProxySource, RuntimeRegistry};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeSupportGap {
    pub proxy_name: String,
    pub kind: Option<OutboundKind>,
    pub provider_name: String,
    pub reason: String,
}

pub fn detect_native_support_gaps(registry: &RuntimeRegistry) -> Vec<NativeSupportGap> {
    let mut gaps = registry
        .proxy_definitions
        .iter()
        .filter_map(|(name, definition)| {
            let reason = native_support_gap_for_outbound_with_registry(definition, registry)?;
            let registration = registry.proxies.get(name);
            let provider_name = registration
                .and_then(|registration| match &registration.source {
                    ProxySource::ProviderInline { provider } => Some(provider.clone()),
                    _ => None,
                })
                .unwrap_or_default();
            Some(NativeSupportGap {
                proxy_name: name.clone(),
                kind: registration.and_then(|registration| registration.kind),
                provider_name,
                reason,
            })
        })
        .collect::<Vec<_>>();
    gaps.sort_by(|left, right| {
        left.provider_name
            .cmp(&right.provider_name)
            .then_with(|| left.proxy_name.cmp(&right.proxy_name))
            .then_with(|| left.reason.cmp(&right.reason))
    });
    gaps
}

pub fn native_support_gap_for_outbound(definition: &OutboundDefinition) -> Option<String> {
    native_support_gap_for_outbound_impl(definition)
}

pub fn native_support_gap_for_outbound_with_registry(
    definition: &OutboundDefinition,
    registry: &RuntimeRegistry,
) -> Option<String> {
    match definition {
        OutboundDefinition::Tuic(config) => {
            let dialer_proxy = config.base.dialer_proxy.trim();
            if !dialer_proxy.is_empty()
                && tuic_outer_socks5_udp_is_supported(dialer_proxy, registry)
            {
                let shim = OutboundDefinition::Tuic(mihomo_outbound::ServerPortOutboundConfig {
                    base: mihomo_outbound::ProxyBaseConfig {
                        dialer_proxy: String::new(),
                        ..config.base.clone()
                    },
                    server: config.server.clone(),
                    port: config.port,
                    extra: config.extra.clone(),
                });
                native_support_gap_for_outbound_impl(&shim)
            } else {
                native_support_gap_for_outbound_impl(definition)
            }
        }
        OutboundDefinition::Hysteria2(config) => {
            let dialer_proxy = config.base.dialer_proxy.trim();
            if !dialer_proxy.is_empty()
                && outer_socks5_udp_is_supported(dialer_proxy, registry)
            {
                let shim = OutboundDefinition::Hysteria2(mihomo_outbound::ServerPortOutboundConfig {
                    base: mihomo_outbound::ProxyBaseConfig {
                        dialer_proxy: String::new(),
                        ..config.base.clone()
                    },
                    server: config.server.clone(),
                    port: config.port,
                    extra: config.extra.clone(),
                });
                native_support_gap_for_outbound_impl(&shim)
            } else {
                native_support_gap_for_outbound_impl(definition)
            }
        }
        OutboundDefinition::Hysteria(config) => {
            let dialer_proxy = config.base.dialer_proxy.trim();
            if !dialer_proxy.is_empty()
                && outer_socks5_udp_is_supported(dialer_proxy, registry)
            {
                let shim = OutboundDefinition::Hysteria(mihomo_outbound::ServerPortOutboundConfig {
                    base: mihomo_outbound::ProxyBaseConfig {
                        dialer_proxy: String::new(),
                        ..config.base.clone()
                    },
                    server: config.server.clone(),
                    port: config.port,
                    extra: config.extra.clone(),
                });
                native_support_gap_for_outbound_impl(&shim)
            } else {
                native_support_gap_for_outbound_impl(definition)
            }
        }
        OutboundDefinition::TrustTunnel(config) => {
            let dialer_proxy = config.base.dialer_proxy.trim();
            if extra_bool(&config.extra, "quic")
                && !dialer_proxy.is_empty()
                && outer_socks5_udp_is_supported(dialer_proxy, registry)
            {
                let shim = OutboundDefinition::TrustTunnel(mihomo_outbound::ServerPortOutboundConfig {
                    base: mihomo_outbound::ProxyBaseConfig {
                        dialer_proxy: String::new(),
                        ..config.base.clone()
                    },
                    server: config.server.clone(),
                    port: config.port,
                    extra: config.extra.clone(),
                });
                native_support_gap_for_outbound_impl(&shim)
            } else {
                native_support_gap_for_outbound_impl(definition)
            }
        }
        OutboundDefinition::WireGuard(config) => {
            let dialer_proxy = config.base.dialer_proxy.trim();
            if !dialer_proxy.is_empty() && outer_socks5_udp_is_supported(dialer_proxy, registry) {
                let shim = OutboundDefinition::WireGuard(mihomo_outbound::WireGuardOutboundConfig {
                    base: mihomo_outbound::ProxyBaseConfig {
                        dialer_proxy: String::new(),
                        ..config.base.clone()
                    },
                    server: config.server.clone(),
                    port: config.port,
                    private_key: config.private_key.clone(),
                    ip: config.ip.clone(),
                    ipv6: config.ipv6.clone(),
                    public_key: config.public_key.clone(),
                    extra: config.extra.clone(),
                });
                native_support_gap_for_outbound_impl(&shim)
            } else {
                native_support_gap_for_outbound_impl(definition)
            }
        }
        OutboundDefinition::OpenVpn(config) => {
            let dialer_proxy = config.base.dialer_proxy.trim();
            let proto = crate::support_helpers::extra_string(&config.extra, "proto");
            let normalized_proto = match proto.trim().to_ascii_lowercase().as_str() {
                "" | "udp" | "udp4" => "udp",
                "tcp" | "tcp-client" | "tcp4" | "tcp4-client" => "tcp",
                _ => "other",
            };
            if normalized_proto == "udp"
                && !dialer_proxy.is_empty()
                && outer_socks5_udp_is_supported(dialer_proxy, registry)
            {
                let shim = OutboundDefinition::OpenVpn(mihomo_outbound::ServerPortOutboundConfig {
                    base: mihomo_outbound::ProxyBaseConfig {
                        dialer_proxy: String::new(),
                        ..config.base.clone()
                    },
                    server: config.server.clone(),
                    port: config.port,
                    extra: config.extra.clone(),
                });
                native_support_gap_for_outbound_impl(&shim)
            } else {
                native_support_gap_for_outbound_impl(definition)
            }
        }
        OutboundDefinition::Masque(config) => {
            let dialer_proxy = config.base.dialer_proxy.trim();
            let network = crate::support_helpers::extra_string(&config.extra, "network");
            if network.trim() == "h2"
                && !dialer_proxy.is_empty()
                && outer_socks5_udp_is_supported(dialer_proxy, registry)
            {
                let shim = OutboundDefinition::Masque(mihomo_outbound::ServerPortOutboundConfig {
                    base: mihomo_outbound::ProxyBaseConfig {
                        dialer_proxy: String::new(),
                        ..config.base.clone()
                    },
                    server: config.server.clone(),
                    port: config.port,
                    extra: config.extra.clone(),
                });
                native_support_gap_for_outbound_impl(&shim)
            } else {
                native_support_gap_for_outbound_impl(definition)
            }
        }
        _ => native_support_gap_for_outbound_impl(definition),
    }
}

fn tuic_outer_socks5_udp_is_supported(
    dialer_proxy: &str,
    registry: &RuntimeRegistry,
) -> bool {
    outer_socks5_udp_is_supported(dialer_proxy, registry)
}

fn outer_socks5_udp_is_supported(
    dialer_proxy: &str,
    registry: &RuntimeRegistry,
) -> bool {
    let Some(definition) = registry.proxy_definitions.get(dialer_proxy) else {
        return false;
    };
    match definition {
        OutboundDefinition::Socks5(config) => {
            crate::execution::outbound_supports_udp(definition)
                && config.base.dialer_proxy.trim().is_empty()
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use mihomo_config::parse_runtime_config_document;

    use crate::{build_runtime_registry, detect_native_support_gaps};

    use super::native_support_gap_for_outbound;

    #[test]
    fn support_gap_marks_protocols_without_native_runtime() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: tuic
    name: edge-tuic
    server: 1.2.3.4
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    password: secret
  - type: wireguard
    name: edge-wg
    server: 1.2.3.4
    port: 51820
    private-key: abc
    ip: 10.0.0.2/32
    public-key: pub
"#,
        )
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let gaps = detect_native_support_gaps(&registry);
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0].proxy_name, "edge-wg");
        assert!(gaps[0].reason.contains("wireguard"));
    }

    #[test]
    fn support_gap_marks_vless_flow_and_reality_features() {
        // VLESS + flow + reality over a non-tcp network is still a gap; the
        // plain-tcp reality happy path is served natively now.
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: vless
    name: vision
    server: 1.2.3.4
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    flow: xtls-rprx-vision
  - type: vless
    name: reality
    server: 1.2.3.4
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    network: grpc
    reality-opts:
      public-key: abc
      short-id: def
"#,
        )
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let gaps = detect_native_support_gaps(&registry);
        assert_eq!(gaps.len(), 2);
        assert!(gaps.iter().any(|gap| gap.reason.contains("flow=xtls-rprx-vision")));
        assert!(gaps.iter().any(|gap| gap.reason.contains("reality-opts")));
    }

    #[test]
    fn support_gap_keeps_vless_vision_without_reality_on_legacy_path() {
        let definition = parse_runtime_config_document(
            r#"
proxies:
  - type: vless
    name: vision
    server: 1.2.3.4
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    flow: xtls-rprx-vision
"#,
        )
        .unwrap()
        .proxies
        .into_iter()
        .next()
        .unwrap();
        let reason = native_support_gap_for_outbound(&definition).unwrap();
        assert!(reason.contains("flow=xtls-rprx-vision"));
    }

    #[test]
    fn support_gap_allows_vless_vision_reality_tcp_and_udp() {
        let definition = parse_runtime_config_document(
            r#"
proxies:
  - type: vless
    name: vision-reality
    server: 127.0.0.1
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    udp: true
    xudp: true
    flow: xtls-rprx-vision
    reality-opts:
      public-key: qHR1BC0xPz5Z1HR1BC0xPz5Z1HR1BC0xPz5Z1HR1BC0
      short-id: abcd
"#,
        )
        .unwrap()
        .proxies
        .into_iter()
        .next()
        .unwrap();
        assert!(native_support_gap_for_outbound(&definition).is_none());
        assert!(crate::outbound_udp_support_gap(&definition).is_none());
    }

    #[test]
    fn support_gap_allows_vless_vision_tls_tcp_without_reality() {
        let definition = parse_runtime_config_document(
            r#"
proxies:
  - type: vless
    name: vision
    server: 1.2.3.4
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    flow: xtls-rprx-vision
"#,
        )
        .unwrap()
        .proxies
        .into_iter()
        .next()
        .unwrap();
        assert!(native_support_gap_for_outbound(&definition).is_none());
    }

    #[test]
    fn support_gap_allows_vless_vision_tls_h2_without_reality() {
        let definition = parse_runtime_config_document(
            r#"
proxies:
  - type: vless
    name: vision
    server: 1.2.3.4
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    network: h2
    flow: xtls-rprx-vision
"#,
        )
        .unwrap()
        .proxies
        .into_iter()
        .next()
        .unwrap();
        assert!(native_support_gap_for_outbound(&definition).is_none());
    }

    #[test]
    fn support_gap_allows_vless_vision_tls_grpc_without_reality() {
        let definition = parse_runtime_config_document(
            r#"
proxies:
  - type: vless
    name: vision
    server: 1.2.3.4
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    network: grpc
    flow: xtls-rprx-vision
"#,
        )
        .unwrap()
        .proxies
        .into_iter()
        .next()
        .unwrap();
        assert!(native_support_gap_for_outbound(&definition).is_none());
    }

    #[test]
    fn support_gap_allows_vless_vision_tls_ws_without_reality() {
        let definition = parse_runtime_config_document(
            r#"
proxies:
  - type: vless
    name: vision
    server: 1.2.3.4
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    network: ws
    flow: xtls-rprx-vision
"#,
        )
        .unwrap()
        .proxies
        .into_iter()
        .next()
        .unwrap();
        assert!(native_support_gap_for_outbound(&definition).is_none());
    }

    #[test]
    fn support_gap_allows_vless_vision_tls_http_without_reality() {
        let definition = parse_runtime_config_document(
            r#"
proxies:
  - type: vless
    name: vision
    server: 1.2.3.4
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    network: http
    flow: xtls-rprx-vision
"#,
        )
        .unwrap()
        .proxies
        .into_iter()
        .next()
        .unwrap();
        assert!(native_support_gap_for_outbound(&definition).is_none());
    }

    #[test]
    fn support_gap_allows_vmess_xhttp_auto_mode() {
        let definition = parse_runtime_config_document(
            r#"
proxies:
  - type: vmess
    name: vmess-xhttp
    server: 1.2.3.4
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    servername: localhost
    skip-cert-verify: true
    alpn: [h2]
    network: xhttp
    xhttp-opts:
      path: /vmxa
      host: localhost
      mode: auto
"#,
        )
        .unwrap()
        .proxies
        .into_iter()
        .next()
        .unwrap();
        assert!(native_support_gap_for_outbound(&definition).is_none());
    }

    #[test]
    fn support_gap_marks_non_salamander_hysteria2_obfs_feature() {
        let definition = parse_runtime_config_document(
            r#"
proxies:
  - type: hysteria2
    name: hy2
    server: 1.2.3.4
    port: 443
    password: secret
    obfs: custom-obfs
    obfs-password: hidden
"#,
        )
        .unwrap()
        .proxies
        .into_iter()
        .next()
        .unwrap();
        let gap = native_support_gap_for_outbound(&definition).unwrap();
        assert!(gap.contains("obfs=custom-obfs"));
    }

    #[test]
    fn support_gap_allows_salamander_hysteria2_obfs_feature() {
        let definition = parse_runtime_config_document(
            r#"
proxies:
  - type: hysteria2
    name: hy2
    server: 1.2.3.4
    port: 443
    password: secret
    obfs: salamander
    obfs-password: hidden
"#,
        )
        .unwrap()
        .proxies
        .into_iter()
        .next()
        .unwrap();
        assert!(native_support_gap_for_outbound(&definition).is_none());
    }

    #[test]
    fn support_gap_allows_plain_hysteria_feature() {
        let definition = parse_runtime_config_document(
            r#"
proxies:
  - type: hysteria
    name: hy
    server: 1.2.3.4
    port: 443
    auth-str: secret
    up: 10 Mbps
    down: 50 Mbps
"#,
        )
        .unwrap()
        .proxies
        .into_iter()
        .next()
        .unwrap();
        assert!(native_support_gap_for_outbound(&definition).is_none());
    }

    #[test]
    fn support_gap_marks_non_udp_hysteria_protocol() {
        let definition = parse_runtime_config_document(
            r#"
proxies:
  - type: hysteria
    name: hy
    server: 1.2.3.4
    port: 443
    auth-str: secret
    protocol: faketcp
    up: 10 Mbps
    down: 50 Mbps
"#,
        )
        .unwrap()
        .proxies
        .into_iter()
        .next()
        .unwrap();
        let gap = native_support_gap_for_outbound(&definition).unwrap();
        assert!(gap.contains("protocol=faketcp"));
    }

    #[test]
    fn support_gap_allows_hysteria_obfs_feature() {
        let definition = parse_runtime_config_document(
            r#"
proxies:
  - type: hysteria
    name: hy
    server: 1.2.3.4
    port: 443
    auth-str: secret
    obfs: demo
    up: 10 Mbps
    down: 50 Mbps
"#,
        )
        .unwrap()
        .proxies
        .into_iter()
        .next()
        .unwrap();
        assert!(native_support_gap_for_outbound(&definition).is_none());
    }

    #[test]
    fn support_gap_marks_hysteria2_dialer_proxy_feature() {
        let definition = parse_runtime_config_document(
            r#"
proxies:
  - type: hysteria2
    name: hy2
    server: 1.2.3.4
    port: 443
    password: secret
    dialer-proxy: chain
"#,
        )
        .unwrap()
        .proxies
        .into_iter()
        .next()
        .unwrap();
        let gap = native_support_gap_for_outbound(&definition).unwrap();
        assert!(gap.contains("dialer-proxy"));
    }

    #[test]
    fn support_gap_allows_hysteria2_realm_happy_path() {
        let definition = parse_runtime_config_document(
            r#"
proxies:
  - type: hysteria2
    name: hy2
    server: 1.2.3.4
    port: 443
    password: secret
    realm-opts:
      enable: true
      server-url: https://realm.example.com
      realm-id: alpha
      stun-servers:
        - 1.1.1.1:3478
"#,
        )
        .unwrap()
        .proxies
        .into_iter()
        .next()
        .unwrap();
        assert!(native_support_gap_for_outbound(&definition).is_none());
    }

    #[test]
    fn support_gap_allows_hysteria2_realm_proxy_feature() {
        let definition = parse_runtime_config_document(
            r#"
proxies:
  - type: hysteria2
    name: hy2
    server: 1.2.3.4
    port: 443
    password: secret
    realm-opts:
      enable: true
      server-url: https://realm.example.com
      realm-id: alpha
      stun-servers:
        - 1.1.1.1:3478
      proxy: socks5://127.0.0.1:1080
"#,
        )
        .unwrap()
        .proxies
        .into_iter()
        .next()
        .unwrap();
        assert!(native_support_gap_for_outbound(&definition).is_none());
    }

    #[test]
    fn support_gap_allows_hysteria2_realm_proxy_name_feature() {
        let definition = parse_runtime_config_document(
            r#"
proxies:
  - type: hysteria2
    name: hy2
    server: 1.2.3.4
    port: 443
    password: secret
    realm-opts:
      enable: true
      server-url: https://realm.example.com
      realm-id: alpha
      stun-servers:
        - 1.1.1.1:3478
      proxy: outer-socks
"#,
        )
        .unwrap()
        .proxies
        .into_iter()
        .next()
        .unwrap();
        assert!(native_support_gap_for_outbound(&definition).is_none());
    }

    #[test]
    fn support_gap_marks_hysteria_dialer_proxy_feature() {
        let definition = parse_runtime_config_document(
            r#"
proxies:
  - type: hysteria
    name: hy
    server: 1.2.3.4
    port: 443
    auth-str: secret
    up: 10 Mbps
    down: 50 Mbps
    dialer-proxy: chain
"#,
        )
        .unwrap()
        .proxies
        .into_iter()
        .next()
        .unwrap();
        let gap = native_support_gap_for_outbound(&definition).unwrap();
        assert!(gap.contains("dialer-proxy"));
    }

    #[test]
    fn support_gap_allows_ssh_proxy_in_default_native_build() {
        let definition = parse_runtime_config_document(
            r#"
proxies:
  - type: ssh
    name: ssh-hop
    server: 1.2.3.4
    port: 22
    username: demo
    password: secret
"#,
        )
        .unwrap()
        .proxies
        .into_iter()
        .next()
        .unwrap();
        assert!(native_support_gap_for_outbound(&definition).is_none());
    }

    #[test]
    fn support_gap_allows_tuic_v5_tcp_happy_path() {
        let definition = parse_runtime_config_document(
            r#"
proxies:
  - type: tuic
    name: edge-tuic
    server: 1.2.3.4
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    password: secret
    alpn: [h3]
"#,
        )
        .unwrap()
        .proxies
        .into_iter()
        .next()
        .unwrap();
        assert!(native_support_gap_for_outbound(&definition).is_none());
    }

    #[test]
    fn support_gap_allows_anytls_default_tls_happy_path() {
        let definition = parse_runtime_config_document(
            r#"
proxies:
  - type: anytls
    name: anytls-hop
    server: anytls.example.com
    port: 443
    password: secret
"#,
        )
        .unwrap()
        .proxies
        .into_iter()
        .next()
        .unwrap();
        assert!(native_support_gap_for_outbound(&definition).is_none());
    }

    #[test]
    fn support_gap_allows_trojan_default_tls_happy_path() {
        let definition = parse_runtime_config_document(
            r#"
proxies:
  - type: trojan
    name: trojan-hop
    server: 1.2.3.4
    port: 443
    password: secret
"#,
        )
        .unwrap()
        .proxies
        .into_iter()
        .next()
        .unwrap();
        assert!(native_support_gap_for_outbound(&definition).is_none());
    }

    #[test]
    fn support_gap_allows_trojan_h2_and_xhttp_happy_paths() {
        let h2_definition = parse_runtime_config_document(
            r#"
proxies:
  - type: trojan
    name: trojan-h2
    server: trojan.example.com
    port: 443
    password: secret
    network: h2
    h2-opts:
      host: [localhost]
      path: /trh2
"#,
        )
        .unwrap()
        .proxies
        .into_iter()
        .next()
        .unwrap();
        assert!(native_support_gap_for_outbound(&h2_definition).is_none());

        let xhttp_definition = parse_runtime_config_document(
            r#"
proxies:
  - type: trojan
    name: trojan-xhttp
    server: trojan.example.com
    port: 443
    password: secret
    network: xhttp
    xhttp-opts:
      host: localhost
      path: /trx
      mode: stream-one
"#,
        )
        .unwrap()
        .proxies
        .into_iter()
        .next()
        .unwrap();
        assert!(native_support_gap_for_outbound(&xhttp_definition).is_none());
    }

    #[test]
    fn support_gap_marks_tuic_udp_feature() {
        let definition = parse_runtime_config_document(
            r#"
proxies:
  - type: tuic
    name: edge-tuic
    server: 1.2.3.4
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    password: secret
    udp: true
"#,
        )
        .unwrap()
        .proxies
        .into_iter()
        .next()
        .unwrap();
        assert!(native_support_gap_for_outbound(&definition).is_none());
    }

    #[test]
    fn support_gap_marks_tuic_v4_token_mode() {
        let definition = parse_runtime_config_document(
            r#"
proxies:
  - type: tuic
    name: edge-tuic
    server: 1.2.3.4
    port: 443
    token: secret
"#,
        )
        .unwrap()
        .proxies
        .into_iter()
        .next()
        .unwrap();
        assert!(native_support_gap_for_outbound(&definition).is_none());
    }

    #[test]
    fn support_gap_marks_vmess_xhttp_download_transport_overrides() {
        let definition = parse_runtime_config_document(
            r#"
proxies:
  - type: vmess
    name: vmess-xhttp
    server: 1.2.3.4
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    network: xhttp
    xhttp-opts:
      mode: stream-up
      download-settings:
        host: download.example.com
        reality-opts:
          public-key: abc
"#,
        )
        .unwrap()
        .proxies
        .into_iter()
        .next()
        .unwrap();
        let gap = native_support_gap_for_outbound(&definition).unwrap();
        assert!(gap.contains("download-settings transport overrides"));
    }

    #[test]
    fn support_gap_allows_vmess_xhttp_verified_download_transport_overrides() {
        let definition = parse_runtime_config_document(
            r#"
proxies:
  - type: vmess
    name: vmess-xhttp
    server: 1.2.3.4
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    servername: localhost
    skip-cert-verify: true
    alpn: [h2]
    network: xhttp
    xhttp-opts:
      mode: stream-up
      download-settings:
        server: 127.0.0.1
        port: 8443
        tls: true
        servername: localhost
        skip-cert-verify: true
        fingerprint: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
        host: download.local
        path: /vxdf
"#,
        )
        .unwrap()
        .proxies
        .into_iter()
        .next()
        .unwrap();
        assert!(native_support_gap_for_outbound(&definition).is_none());
    }

    #[test]
    fn support_gap_allows_sudoku_ws_http_mask_over_dialer_proxy() {
        let definition = parse_runtime_config_document(
            r#"
proxies:
  - type: socks5
    name: outer
    server: 127.0.0.1
    port: 1080
  - type: sudoku
    name: edge-sudoku
    server: sudoku.example.com
    port: 443
    key: secret-seed
    aead-method: aes-128-gcm
    table-type: prefer_ascii
    padding-min: 12
    http-mask: true
    http-mask-mode: ws
    dialer-proxy: outer
"#,
        )
        .unwrap()
        .proxies
        .into_iter()
        .nth(1)
        .unwrap();
        assert!(native_support_gap_for_outbound(&definition).is_none());
    }

    #[test]
    fn support_gap_allows_sudoku_stream_like_http_mask_over_dialer_proxy() {
        for mode in ["stream", "poll", "auto"] {
            let definition = parse_runtime_config_document(
                &format!(
                    r#"
proxies:
  - type: socks5
    name: outer
    server: 127.0.0.1
    port: 1080
  - type: sudoku
    name: edge-sudoku
    server: sudoku.example.com
    port: 443
    key: secret-seed
    aead-method: aes-128-gcm
    table-type: prefer_ascii
    padding-min: 12
    http-mask: true
    http-mask-mode: {mode}
    dialer-proxy: outer
"#,
                    mode = mode
                ),
            )
            .unwrap()
            .proxies
            .into_iter()
            .nth(1)
            .unwrap();
            assert!(
                native_support_gap_for_outbound(&definition).is_none(),
                "{mode}"
            );
        }
    }

    #[test]
    fn support_gap_allows_trusttunnel_quic_feature() {
        let definition = parse_runtime_config_document(
            r#"
proxies:
  - type: trusttunnel
    name: tt
    server: 1.2.3.4
    port: 443
    username: demo
    password: secret
    tls: true
    quic: true
"#,
        )
        .unwrap()
        .proxies
        .into_iter()
        .next()
        .unwrap();
        let gap = native_support_gap_for_outbound(&definition);
        assert_eq!(gap, None);
    }

    #[test]
    fn support_gap_marks_trusttunnel_quic_dialer_proxy_feature() {
        let definition = parse_runtime_config_document(
            r#"
proxies:
  - type: trusttunnel
    name: tt
    server: 1.2.3.4
    port: 443
    username: demo
    password: secret
    tls: true
    quic: true
    dialer-proxy: chain
"#,
        )
        .unwrap()
        .proxies
        .into_iter()
        .next()
        .unwrap();
        let gap = native_support_gap_for_outbound(&definition).unwrap();
        assert!(gap.contains("dialer-proxy"));
    }

    #[test]
    fn support_gap_marks_shadowsocks_unsupported_plugin_feature() {
        let definition = parse_runtime_config_document(
            r#"
proxies:
  - type: ss
    name: ss-plugin
    server: 1.2.3.4
    port: 443
    cipher: aes-128-gcm
    password: secret
    plugin: shadow-tls
"#,
        )
        .unwrap()
        .proxies
        .into_iter()
        .next()
        .unwrap();
        let gap = native_support_gap_for_outbound(&definition).unwrap();
        assert!(gap.contains("plugin=shadow-tls"));
    }

    #[test]
    fn support_gap_allows_shadowsocks_v2ray_plugin_over_dialer_proxy() {
        let definition = parse_runtime_config_document(
            r#"
proxies:
  - type: ss
    name: ss-plugin
    server: 1.2.3.4
    port: 443
    cipher: aes-128-gcm
    password: secret
    dialer-proxy: outer-http
    plugin: v2ray-plugin
    plugin-opts:
      mode: websocket
      host: ws.example.com
      path: /shadow
"#,
        )
        .unwrap()
        .proxies
        .into_iter()
        .next()
        .unwrap();
        assert!(native_support_gap_for_outbound(&definition).is_none());
    }

    #[test]
    fn support_gap_allows_shadowsocks_gost_plugin_over_dialer_proxy() {
        let definition = parse_runtime_config_document(
            r#"
proxies:
  - type: ss
    name: ss-plugin
    server: 1.2.3.4
    port: 443
    cipher: aes-128-gcm
    password: secret
    dialer-proxy: outer-http
    plugin: gost-plugin
    plugin-opts:
      mode: websocket
      host: ws.example.com
      path: /shadow
      mux: true
"#,
        )
        .unwrap()
        .proxies
        .into_iter()
        .next()
        .unwrap();
        assert!(native_support_gap_for_outbound(&definition).is_none());
    }

    #[test]
    fn support_gap_allows_wireguard_single_peer_happy_path() {
        let definition = parse_runtime_config_document(
            r#"
proxies:
  - type: wireguard
    name: edge-wg
    server: 1.2.3.4
    port: 51820
    private-key: cHJpdmF0ZS1rZXktMzItYnl0ZXMtcHJpdmF0ZS1rZXk=
    public-key: cHVibGljLWtleS0zMi1ieXRlcy1wdWJsaWMta2V5LQ==
    ip: 10.0.0.2/32
    allowed-ips:
      - 0.0.0.0/0
"#,
        )
        .unwrap()
        .proxies
        .into_iter()
        .next()
        .unwrap();
        assert!(native_support_gap_for_outbound(&definition).is_none());
    }

    #[test]
    fn support_gap_allows_wireguard_multi_peer_happy_path() {
        let multi_peer = parse_runtime_config_document(
            r#"
proxies:
  - type: wireguard
    name: edge-wg
    private-key: cHJpdmF0ZS1rZXktMzItYnl0ZXMtcHJpdmF0ZS1rZXk=
    ip: 10.0.0.2/32
    peers:
      - server: 1.2.3.4
        port: 51820
        public-key: cHVibGljLWtleS0zMi1ieXRlcy1wdWJsaWMta2V5LQ==
        allowed-ips: [0.0.0.0/0]
      - server: 5.6.7.8
        port: 51821
        public-key: cHVibGljLWtleS0zMi1ieXRlcy1wdWJsaWMta2V5LQ==
        allowed-ips: [10.0.0.0/8]
"#,
        )
        .unwrap()
        .proxies
        .into_iter()
        .next()
        .unwrap();
        assert!(native_support_gap_for_outbound(&multi_peer).is_none());

        let missing_peer_allowed_ips = parse_runtime_config_document(
            r#"
proxies:
  - type: wireguard
    name: edge-wg
    private-key: cHJpdmF0ZS1rZXktMzItYnl0ZXMtcHJpdmF0ZS1rZXk=
    ip: 10.0.0.2/32
    peers:
      - server: 1.2.3.4
        port: 51820
        public-key: cHVibGljLWtleS0zMi1ieXRlcy1wdWJsaWMta2V5LQ==
"#,
        )
        .unwrap()
        .proxies
        .into_iter()
        .next()
        .unwrap();
        let gap = native_support_gap_for_outbound(&missing_peer_allowed_ips).unwrap();
        assert!(gap.contains("peer 0 allowed-ips"));

        let missing_peer_public_key = parse_runtime_config_document(
            r#"
proxies:
  - type: wireguard
    name: edge-wg
    private-key: cHJpdmF0ZS1rZXktMzItYnl0ZXMtcHJpdmF0ZS1rZXk=
    ip: 10.0.0.2/32
    peers:
      - server: 1.2.3.4
        port: 51820
        allowed-ips: [0.0.0.0/0]
"#,
        )
        .unwrap()
        .proxies
        .into_iter()
        .next()
        .unwrap();
        let gap = native_support_gap_for_outbound(&missing_peer_public_key).unwrap();
        assert!(gap.contains("peer 0 public-key"));

        let missing_allowed_ips = parse_runtime_config_document(
            r#"
proxies:
  - type: wireguard
    name: edge-wg
    server: 1.2.3.4
    port: 51820
    private-key: cHJpdmF0ZS1rZXktMzItYnl0ZXMtcHJpdmF0ZS1rZXk=
    public-key: cHVibGljLWtleS0zMi1ieXRlcy1wdWJsaWMta2V5LQ==
    ip: 10.0.0.2/32
"#,
        )
        .unwrap()
        .proxies
        .into_iter()
        .next()
        .unwrap();
        let gap = native_support_gap_for_outbound(&missing_allowed_ips).unwrap();
        assert!(gap.contains("allowed-ips"));
    }

    #[test]
    fn support_gap_allows_wireguard_workers_field() {
        let definition = parse_runtime_config_document(
            r#"
proxies:
  - type: wireguard
    name: edge-wg
    server: 1.2.3.4
    port: 51820
    private-key: cHJpdmF0ZS1rZXktMzItYnl0ZXMtcHJpdmF0ZS1rZXk=
    public-key: cHVibGljLWtleS0zMi1ieXRlcy1wdWJsaWMta2V5LQ==
    ip: 10.0.0.2/32
    allowed-ips: [0.0.0.0/0]
    workers: 4
"#,
        )
        .unwrap()
        .proxies
        .into_iter()
        .next()
        .unwrap();
        assert!(native_support_gap_for_outbound(&definition).is_none());
    }

    #[test]
    fn support_gap_marks_wireguard_unimplemented_top_level_fields() {
        let definition = parse_runtime_config_document(
            r#"
proxies:
  - type: wireguard
    name: edge-wg
    server: 1.2.3.4
    port: 51820
    private-key: cHJpdmF0ZS1rZXktMzItYnl0ZXMtcHJpdmF0ZS1rZXk=
    public-key: cHVibGljLWtleS0zMi1ieXRlcy1wdWJsaWMta2V5LQ==
    ip: 10.0.0.2/32
    allowed-ips: [0.0.0.0/0]
    reserved: [209, 98, 59]
"#,
        )
        .unwrap()
        .proxies
        .into_iter()
        .next()
        .unwrap();
        let gap = native_support_gap_for_outbound(&definition).unwrap();
        assert!(gap.contains("reserved"));

        let definition = parse_runtime_config_document(
            r#"
proxies:
  - type: wireguard
    name: edge-wg
    server: 1.2.3.4
    port: 51820
    private-key: cHJpdmF0ZS1rZXktMzItYnl0ZXMtcHJpdmF0ZS1rZXk=
    public-key: cHVibGljLWtleS0zMi1ieXRlcy1wdWJsaWMta2V5LQ==
    ip: 10.0.0.2/32
    allowed-ips: [0.0.0.0/0]
    remote-dns-resolve: true
"#,
        )
        .unwrap()
        .proxies
        .into_iter()
        .next()
        .unwrap();
        let gap = native_support_gap_for_outbound(&definition).unwrap();
        assert!(gap.contains("explicit dns servers"));

        let definition = parse_runtime_config_document(
            r#"
proxies:
  - type: wireguard
    name: edge-wg
    server: 1.2.3.4
    port: 51820
    private-key: cHJpdmF0ZS1rZXktMzItYnl0ZXMtcHJpdmF0ZS1rZXk=
    public-key: cHVibGljLWtleS0zMi1ieXRlcy1wdWJsaWMta2V5LQ==
    ip: 10.0.0.2/32
    allowed-ips: [0.0.0.0/0]
    dns: [1.1.1.1]
"#,
        )
        .unwrap()
        .proxies
        .into_iter()
        .next()
        .unwrap();
        assert_eq!(native_support_gap_for_outbound(&definition), None);

        let definition = parse_runtime_config_document(
            r#"
proxies:
  - type: wireguard
    name: edge-wg
    server: 1.2.3.4
    port: 51820
    private-key: cHJpdmF0ZS1rZXktMzItYnl0ZXMtcHJpdmF0ZS1rZXk=
    public-key: cHVibGljLWtleS0zMi1ieXRlcy1wdWJsaWMta2V5LQ==
    ip: 10.0.0.2/32
    allowed-ips: [0.0.0.0/0]
    refresh-server-ip-interval: 60
"#,
        )
        .unwrap()
        .proxies
        .into_iter()
        .next()
        .unwrap();
        let gap = native_support_gap_for_outbound(&definition).unwrap();
        assert!(gap.contains("refresh-server-ip-interval"));

        let definition = parse_runtime_config_document(
            r#"
proxies:
  - type: openvpn
    name: edge-ovpn
    server: 1.2.3.4
    port: 1194
    proto: udp
    dev: tun
    cipher: AES-128-GCM
    auth: SHA256
    username: demo
    password: secret
    ca: demo
    tls-crypt: demo
    remote-dns-resolve: true
"#,
        )
        .unwrap()
        .proxies
        .into_iter()
        .next()
        .unwrap();
        let gap = native_support_gap_for_outbound(&definition).unwrap();
        assert!(gap.contains("explicit dns servers"));

        let definition = parse_runtime_config_document(
            r#"
proxies:
  - type: openvpn
    name: edge-ovpn
    server: 1.2.3.4
    port: 1194
    proto: udp
    dev: tun
    cipher: AES-128-GCM
    auth: SHA256
    username: demo
    password: secret
    ca: demo
    tls-crypt: demo
    dns: [1.1.1.1]
"#,
        )
        .unwrap()
        .proxies
        .into_iter()
        .next()
        .unwrap();
        assert_eq!(native_support_gap_for_outbound(&definition), None);

    }

    #[test]
    fn support_gap_marks_wireguard_dialer_proxy_feature() {
        let definition = parse_runtime_config_document(
            r#"
proxies:
  - type: wireguard
    name: edge-wg
    server: 1.2.3.4
    port: 51820
    private-key: cHJpdmF0ZS1rZXktMzItYnl0ZXMtcHJpdmF0ZS1rZXk=
    public-key: cHVibGljLWtleS0zMi1ieXRlcy1wdWJsaWMta2V5LQ==
    ip: 10.0.0.2/32
    allowed-ips: [0.0.0.0/0]
    dialer-proxy: chain
"#,
        )
        .unwrap()
        .proxies
        .into_iter()
        .next()
        .unwrap();
        let gap = native_support_gap_for_outbound(&definition).unwrap();
        assert!(gap.contains("dialer-proxy"));
    }

    #[test]
    fn support_gap_allows_wireguard_over_outer_socks5_udp_with_registry() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: socks5
    name: outer-socks
    server: 127.0.0.1
    port: 1080
    udp: true
  - type: wireguard
    name: edge-wg
    server: 1.2.3.4
    port: 51820
    private-key: cHJpdmF0ZS1rZXktMzItYnl0ZXMtcHJpdmF0ZS1rZXk=
    public-key: cHVibGljLWtleS0zMi1ieXRlcy1wdWJsaWMta2V5LQ==
    ip: 10.0.0.2/32
    allowed-ips: [0.0.0.0/0]
    dialer-proxy: outer-socks
"#,
        )
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let definition = document
            .proxies
            .iter()
            .find(|definition| definition.name() == "edge-wg")
            .unwrap();
        assert!(
            super::native_support_gap_for_outbound_with_registry(definition, &registry).is_none()
        );
    }

    #[test]
    fn support_gap_marks_wireguard_unimplemented_peer_fields() {
        let definition = parse_runtime_config_document(
            r#"
proxies:
  - type: wireguard
    name: edge-wg
    private-key: cHJpdmF0ZS1rZXktMzItYnl0ZXMtcHJpdmF0ZS1rZXk=
    ip: 10.0.0.2/32
    peers:
      - server: 1.2.3.4
        port: 51820
        public-key: cHVibGljLWtleS0zMi1ieXRlcy1wdWJsaWMta2V5LQ==
        pre-shared-key: cHJlLXNoYXJlZC1rZXktMzItYnl0ZXMtc2hhcmVkIQ==
        allowed-ips: [0.0.0.0/0]
"#,
        )
        .unwrap()
        .proxies
        .into_iter()
        .next()
        .unwrap();
        let gap = native_support_gap_for_outbound(&definition).unwrap();
        assert!(gap.contains("peer 0 pre-shared-key"));

        let definition = parse_runtime_config_document(
            r#"
proxies:
  - type: wireguard
    name: edge-wg
    private-key: cHJpdmF0ZS1rZXktMzItYnl0ZXMtcHJpdmF0ZS1rZXk=
    ip: 10.0.0.2/32
    peers:
      - server: 1.2.3.4
        port: 51820
        public-key: cHVibGljLWtleS0zMi1ieXRlcy1wdWJsaWMta2V5LQ==
        reserved: [209, 98, 59]
        allowed-ips: [0.0.0.0/0]
"#,
        )
        .unwrap()
        .proxies
        .into_iter()
        .next()
        .unwrap();
        let gap = native_support_gap_for_outbound(&definition).unwrap();
        assert!(gap.contains("peer 0 reserved"));
    }

    #[test]
    fn support_gap_allows_openvpn_happy_path() {
        let definition = parse_runtime_config_document(
            r#"
proxies:
  - type: openvpn
    name: edge-ovpn
    server: 1.2.3.4
    port: 1194
    proto: udp
    dev: tun
    cipher: AES-128-GCM
    auth: SHA256
    ca: |
      -----BEGIN CERTIFICATE-----
      MIIBhTCCASugAwIBAgIUJfQ1G3QW9W5JmM6z7Q9M9Q0Y0KowCgYIKoZIzj0EAwIw
      EzERMA8GA1UEAwwIb3Zwbi10ZXN0MB4XDTI2MDEwMTAwMDAwMFoXDTM2MDEwMTAw
      MDAwMFowEzERMA8GA1UEAwwIb3Zwbi10ZXN0MFkwEwYHKoZIzj0CAQYIKoZIzj0D
      AQcDQgAEw2P9GQHk8r2m2mG4Xv8Jw6fD3F2rM4bJ2GQzj1f5aH3m3M5Q0n+uC2oVv
      lB3w0dQ4G9F1sY4E6oQhXg4nW8v+9qNTMFEwHQYDVR0OBBYEFDs6x9h1gY0fD7kL
      8K1kzv6dY8hGMB8GA1UdIwQYMBaAFDs6x9h1gY0fD7kL8K1kzv6dY8hGMA8GA1Ud
      EwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIhAKZ9ZpD5jN7s3QXcY5z9V4sL
      pG7bXz1wGx9K2V8nM2mTAiA4r0v9dZ7g6Y8Eo4Jt2kP7Z8M6dX1qZ3cN5uV1bH6g
      -----END CERTIFICATE-----
    tls-crypt: |
      -----BEGIN OpenVPN Static key V1-----
      11111111111111111111111111111111
      11111111111111111111111111111111
      11111111111111111111111111111111
      11111111111111111111111111111111
      11111111111111111111111111111111
      11111111111111111111111111111111
      11111111111111111111111111111111
      11111111111111111111111111111111
      11111111111111111111111111111111
      11111111111111111111111111111111
      11111111111111111111111111111111
      11111111111111111111111111111111
      11111111111111111111111111111111
      11111111111111111111111111111111
      11111111111111111111111111111111
      11111111111111111111111111111111
      -----END OpenVPN Static key V1-----
    username: demo
    password: secret
"#,
        )
        .unwrap()
        .proxies
        .into_iter()
        .next()
        .unwrap();
        assert!(native_support_gap_for_outbound(&definition).is_none());
    }

    #[test]
    fn support_gap_marks_openvpn_dialer_proxy_feature() {
        let definition = parse_runtime_config_document(
            r#"
proxies:
  - type: openvpn
    name: edge-ovpn
    server: 1.2.3.4
    port: 1194
    proto: udp
    dev: tun
    cipher: AES-128-GCM
    auth: SHA256
    username: demo
    password: secret
    ca: demo
    tls-crypt: demo
    dialer-proxy: chain
"#,
        )
        .unwrap()
        .proxies
        .into_iter()
        .next()
        .unwrap();
        let gap = native_support_gap_for_outbound(&definition).unwrap();
        assert!(gap.contains("dialer-proxy"));
    }

    #[test]
    fn support_gap_allows_openvpn_tcp_dialer_proxy_feature() {
        let definition = parse_runtime_config_document(
            r#"
proxies:
  - type: openvpn
    name: edge-ovpn
    server: 1.2.3.4
    port: 1194
    proto: tcp
    dev: tun
    cipher: AES-128-GCM
    auth: SHA256
    username: demo
    password: secret
    ca: demo
    tls-crypt: demo
    dialer-proxy: chain
"#,
        )
        .unwrap()
        .proxies
        .into_iter()
        .next()
        .unwrap();
        assert!(native_support_gap_for_outbound(&definition).is_none());
    }

    #[test]
    fn support_gap_allows_openvpn_tcp_client_cert_dialer_proxy_feature() {
        let definition = parse_runtime_config_document(
            r#"
proxies:
  - type: openvpn
    name: edge-ovpn
    server: 1.2.3.4
    port: 1194
    proto: tcp
    dev: tun
    cipher: AES-128-GCM
    auth: SHA256
    ca: demo
    cert: demo-cert
    key: demo-key
    tls-crypt: demo
    dialer-proxy: chain
"#,
        )
        .unwrap()
        .proxies
        .into_iter()
        .next()
        .unwrap();
        assert!(native_support_gap_for_outbound(&definition).is_none());
    }

    #[test]
    fn support_gap_allows_openvpn_udp_over_outer_socks5_with_registry() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: socks5
    name: outer-socks
    server: 127.0.0.1
    port: 1080
    udp: true
  - type: openvpn
    name: edge-ovpn
    server: 1.2.3.4
    port: 1194
    proto: udp
    dev: tun
    cipher: AES-128-GCM
    auth: SHA256
    username: demo
    password: secret
    ca: demo
    tls-crypt: demo
    dialer-proxy: outer-socks
"#,
        )
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let definition = document
            .proxies
            .iter()
            .find(|definition| definition.name() == "edge-ovpn")
            .unwrap();
        assert!(
            super::native_support_gap_for_outbound_with_registry(definition, &registry).is_none()
        );
    }

    #[test]
    fn support_gap_allows_masque_h2_over_outer_socks5_with_registry() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: socks5
    name: outer-socks
    server: 127.0.0.1
    port: 1080
    udp: true
  - type: masque
    name: edge-masque
    server: masque.example.com
    port: 443
    private-key: key
    public-key: pub
    ip: 10.10.0.2/32
    network: h2
    dialer-proxy: outer-socks
"#,
        )
        .unwrap();
        let registry = build_runtime_registry(&document).unwrap();
        let definition = document
            .proxies
            .iter()
            .find(|definition| definition.name() == "edge-masque")
            .unwrap();
        assert!(
            super::native_support_gap_for_outbound_with_registry(definition, &registry).is_none()
        );
    }

    #[test]
    fn support_gap_allows_openvpn_remote_cert_tls_server() {
        let definition = parse_runtime_config_document(
            r#"
proxies:
  - type: openvpn
    name: edge-ovpn
    server: 1.2.3.4
    port: 1194
    proto: udp
    dev: tun
    cipher: AES-128-GCM
    auth: SHA256
    ca: test-ca
    tls-crypt: test-key
    username: demo
    password: secret
    remote-cert-tls: server
"#,
        )
        .unwrap()
        .proxies
        .into_iter()
        .next()
        .unwrap();
        assert!(native_support_gap_for_outbound(&definition).is_none());
    }

    #[test]
    fn support_gap_rejects_openvpn_unsupported_shape() {
        let definition = parse_runtime_config_document(
            r#"
proxies:
  - type: openvpn
    name: edge-ovpn
    server: 1.2.3.4
    port: 1194
    proto: sctp
    dev: tap
"#,
        )
        .unwrap()
        .proxies
        .into_iter()
        .next()
        .unwrap();
        let gap = native_support_gap_for_outbound(&definition).unwrap();
        assert!(gap.contains("dev=tap") || gap.contains("proto=sctp"));

        let remote_cert_tls = parse_runtime_config_document(
            r#"
proxies:
  - type: openvpn
    name: edge-ovpn
    server: 1.2.3.4
    port: 1194
    proto: udp
    dev: tun
    cipher: AES-128-GCM
    auth: SHA256
    ca: test-ca
    tls-crypt: test-key
    username: demo
    password: secret
    remote-cert-tls: client
"#,
        )
        .unwrap()
        .proxies
        .into_iter()
        .next()
        .unwrap();
        let gap = native_support_gap_for_outbound(&remote_cert_tls).unwrap();
        assert!(gap.contains("remote-cert-tls=client"));
    }
}
