pub(super) fn config_exposes_udp_surface(document: &RuntimeConfigDocument) -> bool {
    if document.tun.enable {
        return true;
    }
    if !document.shadow_socks_config.trim().is_empty()
        || !document.vmess_config.trim().is_empty()
        || document.tuic_server.enable
    {
        return true;
    }
    if document.socks_port != 0
        || document.mixed_port != 0
        || document.redir_port != 0
        || document.tproxy_port != 0
    {
        return true;
    }
    document.listeners.iter().any(|listener| match listener {
        mihomo_inbound::InboundDefinition::Socks(config) => config.udp,
        mihomo_inbound::InboundDefinition::Mixed(config) => config.udp,
        mihomo_inbound::InboundDefinition::Redir(_) => true,
        mihomo_inbound::InboundDefinition::TProxy(config) => config.udp,
        mihomo_inbound::InboundDefinition::Tun(_) => true,
        mihomo_inbound::InboundDefinition::Tunnel(config) => {
            tunnel_network_supports_udp(&config.network)
        }
        mihomo_inbound::InboundDefinition::ShadowSocks(config) => config.udp,
        mihomo_inbound::InboundDefinition::Vmess(config) => vmess_listener_supports_udp(config),
        mihomo_inbound::InboundDefinition::Vless(config) => vless_listener_supports_udp(config),
        mihomo_inbound::InboundDefinition::Trojan(config) => {
            generic_listener_supports_udp(config, "tcp")
        }
        mihomo_inbound::InboundDefinition::AnyTls(config) => {
            generic_listener_supports_udp(config, "tcp")
        }
        mihomo_inbound::InboundDefinition::TrustTunnel(config) => {
            generic_listener_supports_udp(config, "tcp")
        }
        mihomo_inbound::InboundDefinition::Sudoku(config) => {
            generic_listener_supports_udp(config, "tcp")
        }
        mihomo_inbound::InboundDefinition::Hysteria2(_) => true,
        mihomo_inbound::InboundDefinition::Tuic(_) => true,
        _ => false,
    })
}
