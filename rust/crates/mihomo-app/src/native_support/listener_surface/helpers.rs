fn extra_string_listener(extra: &BTreeMap<String, serde_yaml::Value>, key: &str) -> String {
    extra
        .get(key)
        .and_then(serde_yaml::Value::as_str)
        .map(str::trim)
        .unwrap_or_default()
        .to_owned()
}

fn normalize_client_auth_type_listener(raw: &str) -> Result<Option<()>, String> {
    match raw.trim() {
        "" => Ok(None),
        "request" | "require-any" | "verify-if-given" | "verify" | "require-and-verify"
        | "require" => Ok(Some(())),
        other => Err(other.to_owned()),
    }
}

fn shared_tls_listener_surface_is_supported(config: &mihomo_inbound::GenericInboundConfig) -> bool {
    let certificate = extra_string_listener(&config.extra, "certificate");
    let private_key = extra_string_listener(&config.extra, "private-key");
    let client_auth_type = extra_string_listener(&config.extra, "client-auth-type");
    let client_auth_cert = extra_string_listener(&config.extra, "client-auth-cert");
    let tls_enabled = !certificate.trim().is_empty() || !private_key.trim().is_empty();

    if certificate.trim().is_empty() != private_key.trim().is_empty() {
        return false;
    }
    if !extra_string_listener(&config.extra, "ech-key").trim().is_empty() {
        return false;
    }
    if config.extra.contains_key("reality-config") {
        return false;
    }
    match normalize_client_auth_type_listener(&client_auth_type) {
        Ok(None) => tls_enabled || client_auth_cert.trim().is_empty(),
        Ok(Some(_)) => tls_enabled && !client_auth_cert.trim().is_empty(),
        Err(_) => false,
    }
}

fn vmess_listener_auth_is_supported(config: &mihomo_inbound::GenericInboundConfig) -> bool {
    config
        .extra
        .get("users")
        .and_then(serde_yaml::Value::as_sequence)
        .is_some_and(|users| {
            users
                .iter()
                .filter_map(serde_yaml::Value::as_mapping)
                .any(|user| {
                    user.get(serde_yaml::Value::String("uuid".to_owned()))
                        .and_then(serde_yaml::Value::as_str)
                        .is_some_and(|uuid| !uuid.trim().is_empty())
                })
        })
}

fn vless_listener_auth_is_supported(config: &mihomo_inbound::GenericInboundConfig) -> bool {
    if !extra_string_listener(&config.extra, "decryption").trim().is_empty() {
        return false;
    }
    config
        .extra
        .get("users")
        .and_then(serde_yaml::Value::as_sequence)
        .is_some_and(|users| {
            users
                .iter()
                .filter_map(serde_yaml::Value::as_mapping)
                .any(|user| {
                    user.get(serde_yaml::Value::String("uuid".to_owned()))
                        .and_then(serde_yaml::Value::as_str)
                        .is_some_and(|uuid| !uuid.trim().is_empty())
                })
        })
}

fn non_empty_or_listener(value: String, fallback: &str) -> String {
    if value.trim().is_empty() {
        fallback.to_owned()
    } else {
        value
    }
}

fn generic_listener_from_http_inbound(
    config: &mihomo_inbound::HttpInboundConfig,
) -> mihomo_inbound::GenericInboundConfig {
    let mut extra = config.extra.clone();
    if !config.certificate.trim().is_empty() {
        extra.insert(
            "certificate".to_owned(),
            serde_yaml::Value::String(config.certificate.clone()),
        );
    }
    if !config.private_key.trim().is_empty() {
        extra.insert(
            "private-key".to_owned(),
            serde_yaml::Value::String(config.private_key.clone()),
        );
    }
    if !config.client_auth_type.trim().is_empty() {
        extra.insert(
            "client-auth-type".to_owned(),
            serde_yaml::Value::String(config.client_auth_type.clone()),
        );
    }
    if !config.client_auth_cert.trim().is_empty() {
        extra.insert(
            "client-auth-cert".to_owned(),
            serde_yaml::Value::String(config.client_auth_cert.clone()),
        );
    }
    if !config.ech_key.trim().is_empty() {
        extra.insert(
            "ech-key".to_owned(),
            serde_yaml::Value::String(config.ech_key.clone()),
        );
    }
    if config.reality_config != mihomo_inbound::RealityConfig::default() {
        extra.insert(
            "reality-config".to_owned(),
            serde_yaml::to_value(&config.reality_config).unwrap_or(serde_yaml::Value::Null),
        );
    }
    mihomo_inbound::GenericInboundConfig {
        base: config.base.clone(),
        extra,
    }
}

fn generic_listener_from_tls_inbound(
    config: &mihomo_inbound::TlsInboundConfig,
) -> mihomo_inbound::GenericInboundConfig {
    let mut extra = config.extra.clone();
    if !config.certificate.trim().is_empty() {
        extra.insert(
            "certificate".to_owned(),
            serde_yaml::Value::String(config.certificate.clone()),
        );
    }
    if !config.private_key.trim().is_empty() {
        extra.insert(
            "private-key".to_owned(),
            serde_yaml::Value::String(config.private_key.clone()),
        );
    }
    if !config.client_auth_type.trim().is_empty() {
        extra.insert(
            "client-auth-type".to_owned(),
            serde_yaml::Value::String(config.client_auth_type.clone()),
        );
    }
    if !config.client_auth_cert.trim().is_empty() {
        extra.insert(
            "client-auth-cert".to_owned(),
            serde_yaml::Value::String(config.client_auth_cert.clone()),
        );
    }
    if !config.ech_key.trim().is_empty() {
        extra.insert(
            "ech-key".to_owned(),
            serde_yaml::Value::String(config.ech_key.clone()),
        );
    }
    if config.reality_config != mihomo_inbound::RealityConfig::default() {
        extra.insert(
            "reality-config".to_owned(),
            serde_yaml::to_value(&config.reality_config).unwrap_or(serde_yaml::Value::Null),
        );
    }
    mihomo_inbound::GenericInboundConfig {
        base: config.base.clone(),
        extra,
    }
}

fn tunnel_network_supports_udp(networks: &[String]) -> bool {
    networks.is_empty()
        || networks.iter().any(|network| {
            let network = network.trim().to_ascii_lowercase();
            network == "udp" || network == "all"
        })
}

fn generic_listener_supports_udp(
    config: &mihomo_inbound::GenericInboundConfig,
    default_network: &str,
) -> bool {
    matches!(
        non_empty_or_listener(extra_string_listener(&config.extra, "network"), default_network)
            .to_ascii_lowercase()
            .as_str(),
        "tcp" | "ws" | "grpc" | "h2" | "http" | "xhttp"
    )
}

fn vmess_listener_supports_udp(config: &mihomo_inbound::GenericInboundConfig) -> bool {
    generic_listener_supports_udp(config, "tcp")
}

fn vless_listener_supports_udp(config: &mihomo_inbound::GenericInboundConfig) -> bool {
    generic_listener_supports_udp(config, "tcp")
}
