pub(super) fn build_udp_listener_configs(
    document: &RuntimeConfigDocument,
) -> Result<Vec<ManagedUdpListenerConfig>, ListenerServiceError> {
    let mut listeners = Vec::new();
    if document.redir_port != 0 {
        let address = top_level_bind_address(document, document.redir_port);
        listeners.push(ManagedUdpListenerConfig {
            name: "__top_level_redir__".into(),
            address: address.clone(),
            handler: ManagedUdpListenerHandler::Redir(mihomo_inbound::RedirInboundConfig {
                base: base_from_address("__top_level_redir__", &address),
                ..mihomo_inbound::RedirInboundConfig::default()
            }),
        });
    }
    if document.tproxy_port != 0 {
        let address = top_level_bind_address(document, document.tproxy_port);
        listeners.push(ManagedUdpListenerConfig {
            name: "__top_level_tproxy__".into(),
            address: address.clone(),
            handler: ManagedUdpListenerHandler::TProxy(TProxyInboundConfig {
                base: base_from_address("__top_level_tproxy__", &address),
                udp: true,
                ..TProxyInboundConfig::default()
            }),
        });
    }
    if !document.shadow_socks_config.trim().is_empty() {
        let (config, addresses) = top_level_shadowsocks_listener_config(document)?;
        for address in addresses {
            listeners.push(ManagedUdpListenerConfig {
                name: config.base.name.clone(),
                address,
                handler: ManagedUdpListenerHandler::ShadowSocks(config.clone()),
            });
        }
    }
    for listener in &document.listeners {
        match listener {
            InboundDefinition::Tunnel(config) => {
                if !tunnel_network_supports_udp(&config.network) {
                    continue;
                }
                for address in config.base.raw_addresses() {
                    listeners.push(ManagedUdpListenerConfig {
                        name: config.base.name.clone(),
                        address,
                        handler: ManagedUdpListenerHandler::Tunnel(config.clone()),
                    });
                }
            }
            InboundDefinition::ShadowSocks(config) if config.udp => {
                let Ok(config) = ShadowSocksListenerConfig::try_from_inbound(config) else {
                    continue;
                };
                for address in config.base.raw_addresses() {
                    listeners.push(ManagedUdpListenerConfig {
                        name: config.base.name.clone(),
                        address,
                        handler: ManagedUdpListenerHandler::ShadowSocks(config.clone()),
                    });
                }
            }
            InboundDefinition::Redir(config) => {
                for address in config.base.raw_addresses() {
                    listeners.push(ManagedUdpListenerConfig {
                        name: config.base.name.clone(),
                        address,
                        handler: ManagedUdpListenerHandler::Redir(config.clone()),
                    });
                }
            }
            InboundDefinition::TProxy(config) if config.udp => {
                for address in config.base.raw_addresses() {
                    listeners.push(ManagedUdpListenerConfig {
                        name: config.base.name.clone(),
                        address,
                        handler: ManagedUdpListenerHandler::TProxy(config.clone()),
                    });
                }
            }
            _ => {}
        }
    }
    Ok(listeners)
}
