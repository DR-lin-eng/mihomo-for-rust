use mihomo_runtime::{
    outbound_udp_support_gap, NativeSupportGap, ProxySource, RuntimeRegistry,
};

pub(super) fn udp_runtime_support_gaps(registry: &RuntimeRegistry) -> Vec<NativeSupportGap> {
    registry
        .proxy_definitions
        .iter()
        .filter_map(|(name, definition)| {
            // HTTP CONNECT deliberately has no UDP capability in Clash. Its
            // presence must not prevent TCP/DNS listeners or the API starting.
            if matches!(definition, mihomo_outbound::OutboundDefinition::Http(_)) { return None; }
            let reason = outbound_udp_support_gap(definition)?;
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
        .collect()
}
