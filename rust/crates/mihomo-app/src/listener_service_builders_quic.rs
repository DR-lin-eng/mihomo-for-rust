pub(super) fn build_quic_listener_configs(
    document: &RuntimeConfigDocument,
) -> Result<Vec<ManagedQuicListenerConfig>, ListenerServiceError> {
    let mut listeners = Vec::new();
    if document.tuic_server.enable {
        if document.tuic_server.listen.trim().is_empty() {
            return Err(ListenerServiceError::Rule(
                "top-level tuic-server requires listen".to_owned(),
            ));
        }
        let config = tuic_inbound::TuicListenerConfig::from_top_level(&document.tuic_server)
            .map_err(ListenerServiceError::Rule)?;
        listeners.push(ManagedQuicListenerConfig {
            name: config.base.name.clone(),
            address: document.tuic_server.listen.clone(),
            handler: ManagedQuicListenerHandler::Tuic(config),
        });
    }
    for listener in &document.listeners {
        match listener {
            InboundDefinition::Tuic(config) => {
                let config = tuic_inbound::TuicListenerConfig::try_from_generic(config)
                    .map_err(ListenerServiceError::Rule)?;
                for address in config.base.raw_addresses() {
                    listeners.push(ManagedQuicListenerConfig {
                        name: config.base.name.clone(),
                        address,
                        handler: ManagedQuicListenerHandler::Tuic(config.clone()),
                    });
                }
            }
            InboundDefinition::Hysteria2(config) => {
                let config = hy2_inbound::Hy2ListenerConfig::try_from_generic(config)
                    .map_err(ListenerServiceError::Rule)?;
                for address in config.base.raw_addresses() {
                    listeners.push(ManagedQuicListenerConfig {
                        name: config.base.name.clone(),
                        address,
                        handler: ManagedQuicListenerHandler::Hy2(config.clone()),
                    });
                }
            }
            _ => {}
        }
    }
    Ok(listeners)
}
