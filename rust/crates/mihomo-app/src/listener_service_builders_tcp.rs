pub(super) fn build_tcp_listener_configs(
    document: &RuntimeConfigDocument,
) -> Result<Vec<ManagedTcpListenerConfig>, ListenerServiceError> {
    let mut listeners = Vec::new();
    let auth_users = parse_authentication_users(&document.authentication);

    if document.port != 0 {
        let address = top_level_bind_address(document, document.port);
        listeners.push(ManagedTcpListenerConfig {
            name: "__top_level_http__".into(),
            address: address.clone(),
            handler: ManagedTcpListenerHandler::Http(HttpInboundConfig {
                base: base_from_address("__top_level_http__", &address),
                users: auth_users.clone(),
                ..HttpInboundConfig::default()
            }),
        });
    }
    if document.socks_port != 0 {
        let address = top_level_bind_address(document, document.socks_port);
        listeners.push(ManagedTcpListenerConfig {
            name: "__top_level_socks__".into(),
            address: address.clone(),
            handler: ManagedTcpListenerHandler::Socks(TlsInboundConfig {
                udp: true,
                base: base_from_address("__top_level_socks__", &address),
                users: auth_users.clone(),
                ..TlsInboundConfig::default()
            }),
        });
    }
    if document.mixed_port != 0 {
        let address = top_level_bind_address(document, document.mixed_port);
        listeners.push(ManagedTcpListenerConfig {
            name: "__top_level_mixed__".into(),
            address: address.clone(),
            handler: ManagedTcpListenerHandler::Mixed(TlsInboundConfig {
                udp: true,
                base: base_from_address("__top_level_mixed__", &address),
                users: auth_users,
                ..TlsInboundConfig::default()
            }),
        });
    }
    if document.redir_port != 0 {
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        {
            return Err(ListenerServiceError::Rule(
                "tproxy udp listener is only implemented on Linux/Android".to_owned(),
            ));
        }
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            let address = if !document.ebpf.auto_redir.is_empty() && document.ipv6 && document.allow_lan && (document.bind_address.is_empty() || document.bind_address=="*") {
                format!("[::]:{}",document.redir_port)
            } else {top_level_bind_address(document, document.redir_port)};
            listeners.push(ManagedTcpListenerConfig {
                name: "__top_level_redir__".into(),
                address: address.clone(),
                handler: ManagedTcpListenerHandler::Redir(mihomo_inbound::RedirInboundConfig {
                    base: base_from_address("__top_level_redir__", &address),
                    ..mihomo_inbound::RedirInboundConfig::default()
                }),
            });
        }
    }
    if document.tproxy_port != 0 {
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        {
            return Err(ListenerServiceError::Rule(
                "tproxy listener is only implemented on Linux/Android".to_owned(),
            ));
        }
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            let address = top_level_bind_address(document, document.tproxy_port);
            listeners.push(ManagedTcpListenerConfig {
                name: "__top_level_tproxy__".into(),
                address: address.clone(),
                handler: ManagedTcpListenerHandler::TProxy(TProxyInboundConfig {
                    base: base_from_address("__top_level_tproxy__", &address),
                    udp: false,
                    ..TProxyInboundConfig::default()
                }),
            });
        }
    }
    if !document.vmess_config.trim().is_empty() {
        let (config, addresses) = top_level_vmess_listener_config(document)?;
        for address in addresses {
            listeners.push(ManagedTcpListenerConfig {
                name: config.base.name.clone(),
                address,
                handler: ManagedTcpListenerHandler::Vmess(config.clone()),
            });
        }
    }
    if !document.shadow_socks_config.trim().is_empty() {
        let (config, addresses) = top_level_shadowsocks_listener_config(document)?;
        for address in addresses {
            listeners.push(ManagedTcpListenerConfig {
                name: config.base.name.clone(),
                address,
                handler: ManagedTcpListenerHandler::ShadowSocks(config.clone()),
            });
        }
    }

    for listener in &document.listeners {
        match listener {
            InboundDefinition::Http(config) => {
                for address in config.base.raw_addresses() {
                    listeners.push(ManagedTcpListenerConfig {
                        name: config.base.name.clone(),
                        address,
                        handler: ManagedTcpListenerHandler::Http(config.clone()),
                    });
                }
            }
            InboundDefinition::Socks(config) => {
                for address in config.base.raw_addresses() {
                    listeners.push(ManagedTcpListenerConfig {
                        name: config.base.name.clone(),
                        address,
                        handler: ManagedTcpListenerHandler::Socks(config.clone()),
                    });
                }
            }
            InboundDefinition::Mixed(config) => {
                for address in config.base.raw_addresses() {
                    listeners.push(ManagedTcpListenerConfig {
                        name: config.base.name.clone(),
                        address,
                        handler: ManagedTcpListenerHandler::Mixed(config.clone()),
                    });
                }
            }
            InboundDefinition::Tunnel(config) => {
                for address in config.base.raw_addresses() {
                    listeners.push(ManagedTcpListenerConfig {
                        name: config.base.name.clone(),
                        address,
                        handler: ManagedTcpListenerHandler::Tunnel(config.clone()),
                    });
                }
            }
            InboundDefinition::Redir(config) => {
                for address in config.base.raw_addresses() {
                    listeners.push(ManagedTcpListenerConfig {
                        name: config.base.name.clone(),
                        address,
                        handler: ManagedTcpListenerHandler::Redir(config.clone()),
                    });
                }
            }
            InboundDefinition::TProxy(config) => {
                for address in config.base.raw_addresses() {
                    listeners.push(ManagedTcpListenerConfig {
                        name: config.base.name.clone(),
                        address,
                        handler: ManagedTcpListenerHandler::TProxy(config.clone()),
                    });
                }
            }
            InboundDefinition::ShadowSocks(config) => {
                let config = ShadowSocksListenerConfig::try_from_inbound(config)?;
                for address in config.base.raw_addresses() {
                    listeners.push(ManagedTcpListenerConfig {
                        name: config.base.name.clone(),
                        address,
                        handler: ManagedTcpListenerHandler::ShadowSocks(config.clone()),
                    });
                }
            }
            InboundDefinition::Trojan(config) => {
                let config = TrojanListenerConfig::try_from_generic(config)?;
                for address in config.base.raw_addresses() {
                    listeners.push(ManagedTcpListenerConfig {
                        name: config.base.name.clone(),
                        address,
                        handler: ManagedTcpListenerHandler::Trojan(config.clone()),
                    });
                }
            }
            InboundDefinition::AnyTls(config) => {
                let config = AnyTlsListenerConfig::try_from_generic(config)?;
                for address in config.base.raw_addresses() {
                    listeners.push(ManagedTcpListenerConfig {
                        name: config.base.name.clone(),
                        address,
                        handler: ManagedTcpListenerHandler::AnyTls(config.clone()),
                    });
                }
            }
            InboundDefinition::Hysteria2Realm(config) => {
                let config = hy2_realm_inbound::Hy2RealmListenerConfig::try_from_generic(config)
                    .map_err(ListenerServiceError::Rule)?;
                let server =
                    hy2_realm_inbound::Hy2RealmServer::new(&config).map_err(ListenerServiceError::Io)?;
                for address in config.base.raw_addresses() {
                    listeners.push(ManagedTcpListenerConfig {
                        name: config.base.name.clone(),
                        address,
                        handler: ManagedTcpListenerHandler::Hy2Realm(
                            config.clone(),
                            server.clone(),
                        ),
                    });
                }
            }
            InboundDefinition::TrustTunnel(config) => {
                let config = TrustTunnelListenerConfig::try_from_generic(config)?;
                for address in config.base.raw_addresses() {
                    listeners.push(ManagedTcpListenerConfig {
                        name: config.base.name.clone(),
                        address,
                        handler: ManagedTcpListenerHandler::TrustTunnel(config.clone()),
                    });
                }
            }
            InboundDefinition::Sudoku(config) => {
                let config = SudokuInboundConfig::try_from_generic(config)?;
                for address in config.base.raw_addresses() {
                    listeners.push(ManagedTcpListenerConfig {
                        name: config.base.name.clone(),
                        address,
                        handler: ManagedTcpListenerHandler::Sudoku(config.clone()),
                    });
                }
            }
            InboundDefinition::Vmess(config) => {
                let config = VmessInboundConfig::try_from_generic(config)?;
                for address in config.base.raw_addresses() {
                    listeners.push(ManagedTcpListenerConfig {
                        name: config.base.name.clone(),
                        address,
                        handler: ManagedTcpListenerHandler::Vmess(config.clone()),
                    });
                }
            }
            InboundDefinition::Vless(config) => {
                let config = VlessInboundConfig::try_from_generic(config)?;
                for address in config.base.raw_addresses() {
                    listeners.push(ManagedTcpListenerConfig {
                        name: config.base.name.clone(),
                        address,
                        handler: ManagedTcpListenerHandler::Vless(config.clone()),
                    });
                }
            }
            _ => {}
        }
    }

    Ok(listeners)
}
