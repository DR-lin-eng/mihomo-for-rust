use std::collections::BTreeMap;

use mihomo_config::RuntimeConfigDocument;
use mihomo_runtime::NativeSupportGap;

use super::common::surface_support_gap;

pub(super) fn listener_surface_support_gaps(
    document: &RuntimeConfigDocument,
) -> Vec<NativeSupportGap> {
    let mut gaps = Vec::new();
    if document.redir_port != 0 && !listener_redir_is_supported() {
        gaps.push(surface_support_gap(
            "__top_level_redir__",
            "top-level redir listener is not yet served by the native Rust app",
        ));
    }
    if document.tproxy_port != 0
        && !listener_tproxy_is_supported(&mihomo_inbound::TProxyInboundConfig::default())
    {
        gaps.push(surface_support_gap(
            "__top_level_tproxy__",
            "top-level tproxy listener is not yet served by the native Rust app",
        ));
    }
    if document.tun.enable {
        for reason in tun_inbound_support_gap_reasons(&document.tun.config) {
            gaps.push(surface_support_gap("__top_level_tun__", reason));
        }
    }
    if !document.shadow_socks_config.trim().is_empty()
        && !top_level_shadowsocks_config_is_supported(document)
    {
        gaps.push(surface_support_gap(
            "__top_level_shadowsocks__",
            "top-level shadowsocks inbound is not yet served by the native Rust app",
        ));
    }
    if !document.vmess_config.trim().is_empty() && !top_level_vmess_config_is_supported(document) {
        gaps.push(surface_support_gap(
            "__top_level_vmess__",
            "top-level vmess inbound is not yet served by the native Rust app",
        ));
    }
    if document.tuic_server.enable && !top_level_tuic_server_is_supported(document) {
        gaps.push(surface_support_gap(
            "__top_level_tuic__",
            "top-level tuic server is not yet served by the native Rust app",
        ));
    }
    for listener in &document.listeners {
        match listener {
            mihomo_inbound::InboundDefinition::Http(config)
                if plain_http_listener_surface_is_supported(config) => {}
            mihomo_inbound::InboundDefinition::Socks(config)
                if plain_tls_listener_surface_is_supported(config) => {}
            mihomo_inbound::InboundDefinition::Mixed(config)
                if plain_tls_listener_surface_is_supported(config) => {}
            mihomo_inbound::InboundDefinition::Tunnel(_) => {}
            mihomo_inbound::InboundDefinition::Sudoku(config)
                if listener_sudoku_is_supported(config) => {}
            mihomo_inbound::InboundDefinition::Vless(config)
                if listener_vless_network_is_supported(config) => {}
            mihomo_inbound::InboundDefinition::Vmess(config)
                if listener_vmess_network_is_supported(config) => {}
            mihomo_inbound::InboundDefinition::ShadowSocks(config)
                if listener_shadowsocks_is_supported(config) => {}
            mihomo_inbound::InboundDefinition::Trojan(config)
                if listener_trojan_is_supported(config) => {}
            mihomo_inbound::InboundDefinition::Tuic(config)
                if listener_tuic_is_supported(config) => {}
            mihomo_inbound::InboundDefinition::Hysteria2(config)
                if listener_hy2_is_supported(config) => {}
            mihomo_inbound::InboundDefinition::Hysteria2Realm(config)
                if listener_hy2_realm_is_supported(config) => {}
            mihomo_inbound::InboundDefinition::AnyTls(config)
                if listener_anytls_is_supported(config) => {}
            mihomo_inbound::InboundDefinition::TrustTunnel(config)
                if listener_trusttunnel_is_supported(config) => {}
            mihomo_inbound::InboundDefinition::Redir(_) if listener_redir_is_supported() => {}
            mihomo_inbound::InboundDefinition::Tun(config) if tun_inbound_is_supported(config) => {}
            mihomo_inbound::InboundDefinition::TProxy(config)
                if listener_tproxy_is_supported(config) => {}
            mihomo_inbound::InboundDefinition::Tun(config) => {
                let reasons = tun_inbound_support_gap_reasons(config);
                if reasons.is_empty() {
                    gaps.push(surface_support_gap(
                        &format!("listener:{}", config.base.name),
                        "listener type=tun is not yet served by the native Rust app",
                    ));
                } else {
                    for reason in reasons {
                        gaps.push(surface_support_gap(
                            &format!("listener:{}", config.base.name),
                            reason,
                        ));
                    }
                }
            }
            other => gaps.push(surface_support_gap(
                &format!("listener:{}", other.base().name),
                &format!(
                    "listener type={} is not yet served by the native Rust app",
                    other.kind().as_str()
                ),
            )),
        }
    }
    gaps
}
