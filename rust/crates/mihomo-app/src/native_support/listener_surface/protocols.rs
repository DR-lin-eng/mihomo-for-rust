fn listener_vless_network_is_supported(config: &mihomo_inbound::GenericInboundConfig) -> bool {
    let network = non_empty_or_listener(extra_string_listener(&config.extra, "network"), "tcp");
    // REALITY inbound: plain TCP with a complete reality-config block
    // (private-key + server-names + dest); regular TLS fields must be absent.
    if config.extra.get("reality-config").is_some() {
        if network != "tcp" {
            return false;
        }
        let mapping_ok = config
            .extra
            .get("reality-config")
            .and_then(serde_yaml::Value::as_mapping)
            .map(|mapping| {
                let required = ["private-key", "server-names", "dest"];
                required.iter().all(|key| {
                    mapping
                        .get(serde_yaml::Value::String((*key).to_owned()))
                        .map(|value| match value {
                            serde_yaml::Value::String(text) => !text.trim().is_empty(),
                            serde_yaml::Value::Sequence(items) => !items.is_empty(),
                            _ => false,
                        })
                        .unwrap_or(false)
                })
            })
            .unwrap_or(false);
        let no_plain_tls = extra_string_listener(&config.extra, "certificate").trim().is_empty()
            && extra_string_listener(&config.extra, "private-key").trim().is_empty();
        return mapping_ok
            && no_plain_tls
            && vless_listener_auth_is_supported(config);
    }
    let transport_ok = match network.as_str() {
        "tcp" | "ws" | "h2" | "grpc" | "http" => true,
        "xhttp" => listener_xhttp_mode_is_supported(config),
        _ => false,
    };
    transport_ok
        && shared_tls_listener_surface_is_supported(config)
        && vless_listener_auth_is_supported(config)
}

fn plain_http_listener_surface_is_supported(config: &mihomo_inbound::HttpInboundConfig) -> bool {
    let generic = generic_listener_from_http_inbound(config);
    shared_tls_listener_surface_is_supported(&generic)
}

fn plain_tls_listener_surface_is_supported(config: &mihomo_inbound::TlsInboundConfig) -> bool {
    let generic = generic_listener_from_tls_inbound(config);
    shared_tls_listener_surface_is_supported(&generic)
}

fn listener_shadowsocks_is_supported(config: &mihomo_inbound::ShadowSocksInboundConfig) -> bool {
    let cipher = config.cipher.trim().to_ascii_uppercase();
    if matches!(
        cipher.as_str(),
        "2022-BLAKE3-AES-128-GCM"
            | "2022-BLAKE3-AES-256-GCM"
            | "2022-BLAKE3-CHACHA20-POLY1305"
    ) {
        // SIP022 TCP + UDP, single PSK, no obfs.
        return !config.simple_obfs.enable
            && config.shadow_tls.is_empty()
            && config.kcp_tun.is_empty()
            && config.mux_option.is_empty();
    }
    (!config.simple_obfs.enable || matches!(config.simple_obfs.mode.trim(), "http" | "tls"))
        && config.shadow_tls.is_empty()
        && config.kcp_tun.is_empty()
        && config.mux_option.is_empty()
        && matches!(
            config.cipher.trim().to_ascii_uppercase().as_str(),
            "AEAD_AES_128_GCM"
                | "AES-128-GCM"
                | "AEAD_AES_192_GCM"
                | "AES-192-GCM"
                | "AEAD_AES_256_GCM"
                | "AES-256-GCM"
                | "AEAD_CHACHA20_POLY1305"
                | "CHACHA20-IETF-POLY1305"
        )
}

fn listener_vmess_network_is_supported(config: &mihomo_inbound::GenericInboundConfig) -> bool {
    let network = non_empty_or_listener(extra_string_listener(&config.extra, "network"), "tcp");
    let transport_ok = match network.as_str() {
        "tcp" | "ws" | "h2" | "grpc" | "http" => true,
        "xhttp" => listener_xhttp_mode_is_supported(config),
        _ => false,
    };
    transport_ok
        && shared_tls_listener_surface_is_supported(config)
        && vmess_listener_auth_is_supported(config)
}

fn listener_trojan_is_supported(config: &mihomo_inbound::GenericInboundConfig) -> bool {
    let network = non_empty_or_listener(extra_string_listener(&config.extra, "network"), "tcp");
    listener_auth_users_present(config) || !extra_string_listener(&config.extra, "password").trim().is_empty()
        && shared_tls_listener_surface_is_supported(config)
        && match network.as_str() {
            "tcp" | "ws" | "http" | "grpc" | "h2" => true,
            "xhttp" => listener_xhttp_mode_is_supported(config),
            _ => false,
        }
}

/// Matches the listener builders: Go-style `users` collections or legacy flat
/// password fields both satisfy the authentication surface.
fn listener_auth_users_present(config: &mihomo_inbound::GenericInboundConfig) -> bool {
    if let Some(mapping) = config
        .extra
        .get("users")
        .and_then(serde_yaml::Value::as_mapping)
    {
        return !mapping.is_empty();
    }
    if let Some(entries) = config
        .extra
        .get("users")
        .and_then(serde_yaml::Value::as_sequence)
    {
        return entries.iter().any(|entry| {
            entry
                .as_mapping()
                .and_then(|mapping| {
                    mapping.get(serde_yaml::Value::String("password".to_owned()))
                })
                .and_then(serde_yaml::Value::as_str)
                .map(str::trim)
                .map(|password| !password.is_empty())
                .unwrap_or(false)
        });
    }
    false
}

fn listener_sudoku_is_supported(config: &mihomo_inbound::GenericInboundConfig) -> bool {
    let key = extra_string_listener(&config.extra, "key");
    if key.trim().is_empty() {
        return false;
    }

    let http_mask_enabled = sudoku_listener_http_mask_enabled(config);
    let http_mask_mode = sudoku_listener_http_mask_mode(config);
    let tls_enabled = !extra_string_listener(&config.extra, "certificate").trim().is_empty()
        || !extra_string_listener(&config.extra, "private-key").trim().is_empty();

    if !http_mask_enabled {
        return if tls_enabled {
            shared_tls_listener_surface_is_supported(config)
        } else {
            extra_string_listener(&config.extra, "client-auth-type")
                .trim()
                .is_empty()
                && extra_string_listener(&config.extra, "client-auth-cert")
                    .trim()
                    .is_empty()
                && extra_string_listener(&config.extra, "ech-key").trim().is_empty()
                && !config.extra.contains_key("reality-config")
        };
    }

    if matches!(http_mask_mode.as_str(), "stream" | "poll" | "ws")
        && sudoku_listener_http_mask_tls_enabled(config)
    {
        return shared_tls_listener_surface_is_supported(config);
    }

    !tls_enabled
        && extra_string_listener(&config.extra, "client-auth-type")
            .trim()
            .is_empty()
        && extra_string_listener(&config.extra, "client-auth-cert")
            .trim()
            .is_empty()
        && extra_string_listener(&config.extra, "ech-key").trim().is_empty()
        && !config.extra.contains_key("reality-config")
}

fn listener_xhttp_mode_is_supported(config: &mihomo_inbound::GenericInboundConfig) -> bool {
    matches!(
        normalized_listener_xhttp_mode(config).as_str(),
        "stream-one" | "stream-up" | "packet-up"
    )
}

fn normalized_listener_xhttp_mode(config: &mihomo_inbound::GenericInboundConfig) -> String {
    let mode = config
        .extra
        .get("xhttp-opts")
        .and_then(serde_yaml::Value::as_mapping)
        .and_then(|mapping| mapping.get(&serde_yaml::Value::String("mode".to_owned())))
        .and_then(serde_yaml::Value::as_str)
        .map(str::trim)
        .unwrap_or_default();
    if mode.is_empty() || mode == "auto" {
        "packet-up".to_owned()
    } else {
        mode.to_owned()
    }
}

fn sudoku_listener_http_mask_enabled(config: &mihomo_inbound::GenericInboundConfig) -> bool {
    if config.extra.contains_key("http-mask") {
        return config
            .extra
            .get("http-mask")
            .and_then(serde_yaml::Value::as_bool)
            .unwrap_or(false);
    }
    if config.extra.contains_key("disable-http-mask") {
        return !config
            .extra
            .get("disable-http-mask")
            .and_then(serde_yaml::Value::as_bool)
            .unwrap_or(false);
    }
    if let Some(mapping) = config
        .extra
        .get("httpmask")
        .and_then(serde_yaml::Value::as_mapping)
    {
        if let Some(disable) = mapping
            .get(serde_yaml::Value::String("disable".to_owned()))
            .and_then(serde_yaml::Value::as_bool)
        {
            return !disable;
        }
        return true;
    }
    false
}

fn sudoku_listener_http_mask_mode(config: &mihomo_inbound::GenericInboundConfig) -> String {
    let flat = extra_string_listener(&config.extra, "http-mask-mode");
    if !flat.trim().is_empty() {
        return flat;
    }
    config
        .extra
        .get("httpmask")
        .and_then(serde_yaml::Value::as_mapping)
        .and_then(|mapping| mapping.get(serde_yaml::Value::String("mode".to_owned())))
        .and_then(serde_yaml::Value::as_str)
        .map(str::trim)
        .unwrap_or("legacy")
        .to_owned()
}

fn sudoku_listener_http_mask_tls_enabled(config: &mihomo_inbound::GenericInboundConfig) -> bool {
    if config.extra.contains_key("http-mask-tls") {
        return config
            .extra
            .get("http-mask-tls")
            .and_then(serde_yaml::Value::as_bool)
            .unwrap_or(false);
    }
    config
        .extra
        .get("httpmask")
        .and_then(serde_yaml::Value::as_mapping)
        .and_then(|mapping| mapping.get(serde_yaml::Value::String("tls".to_owned())))
        .and_then(serde_yaml::Value::as_bool)
        .unwrap_or(false)
}

fn listener_anytls_is_supported(config: &mihomo_inbound::GenericInboundConfig) -> bool {
    (listener_auth_users_present(config)
        || !extra_string_listener(&config.extra, "password").trim().is_empty())
        && !extra_string_listener(&config.extra, "certificate")
            .trim()
            .is_empty()
        && !extra_string_listener(&config.extra, "private-key")
            .trim()
            .is_empty()
        && shared_tls_listener_surface_is_supported(config)
}

fn listener_trusttunnel_is_supported(config: &mihomo_inbound::GenericInboundConfig) -> bool {
    (listener_auth_users_present(config)
        || (!extra_string_listener(&config.extra, "username").trim().is_empty()
            && !extra_string_listener(&config.extra, "password").trim().is_empty()))
        && !extra_string_listener(&config.extra, "certificate")
            .trim()
            .is_empty()
        && !extra_string_listener(&config.extra, "private-key")
            .trim()
            .is_empty()
        && shared_tls_listener_surface_is_supported(config)
}

fn listener_tuic_is_supported(config: &mihomo_inbound::GenericInboundConfig) -> bool {
    let client_auth_type = extra_string_listener(&config.extra, "client-auth-type");
    let client_auth_cert = extra_string_listener(&config.extra, "client-auth-cert");
    let client_auth_ok = match normalize_client_auth_type_listener(&client_auth_type) {
        Ok(None) => client_auth_cert.trim().is_empty(),
        Ok(Some(_)) => !client_auth_cert.trim().is_empty(),
        Err(_) => false,
    };
    (!extra_string_listener(&config.extra, "certificate")
        .trim()
        .is_empty()
        && !extra_string_listener(&config.extra, "private-key")
            .trim()
            .is_empty())
        && extra_string_listener(&config.extra, "ech-key").trim().is_empty()
        && client_auth_ok
        && (!extra_string_listener(&config.extra, "token").trim().is_empty()
            || config
                .extra
                .get("users")
                .and_then(serde_yaml::Value::as_mapping)
                .is_some_and(|users| !users.is_empty()))
}

fn listener_hy2_is_supported(config: &mihomo_inbound::GenericInboundConfig) -> bool {
    let client_auth_type = extra_string_listener(&config.extra, "client-auth-type");
    let client_auth_cert = extra_string_listener(&config.extra, "client-auth-cert");
    let client_auth_ok = match normalize_client_auth_type_listener(&client_auth_type) {
        Ok(None) => client_auth_cert.trim().is_empty(),
        Ok(Some(_)) => !client_auth_cert.trim().is_empty(),
        Err(_) => false,
    };
    !extra_string_listener(&config.extra, "certificate")
        .trim()
        .is_empty()
        && !extra_string_listener(&config.extra, "private-key")
            .trim()
            .is_empty()
        && config
            .extra
            .get("users")
            .and_then(serde_yaml::Value::as_mapping)
            .is_some_and(|users| !users.is_empty())
        && matches!(
            extra_string_listener(&config.extra, "obfs").trim(),
            "" | "salamander"
        )
        && client_auth_ok
        && extra_string_listener(&config.extra, "ech-key").trim().is_empty()
}

fn listener_hy2_realm_is_supported(config: &mihomo_inbound::GenericInboundConfig) -> bool {
    !extra_string_listener(&config.extra, "token").trim().is_empty()
        && {
            let certificate = extra_string_listener(&config.extra, "certificate");
            let private_key = extra_string_listener(&config.extra, "private-key");
            (certificate.trim().is_empty() && private_key.trim().is_empty())
                || (!certificate.trim().is_empty() && !private_key.trim().is_empty())
        }
        && extra_string_listener(&config.extra, "ech-key").trim().is_empty()
        && normalize_client_auth_type_listener(
            &extra_string_listener(&config.extra, "client-auth-type"),
        )
        .is_ok()
        && !config.extra.contains_key("reality-config")
}

fn listener_redir_is_supported() -> bool {
    cfg!(any(target_os = "linux", target_os = "android"))
}

fn listener_tproxy_is_supported(_config: &mihomo_inbound::TProxyInboundConfig) -> bool {
    cfg!(any(target_os = "linux", target_os = "android"))
}

fn tun_inbound_support_gap_reasons(
    config: &mihomo_inbound::TunInboundConfig,
) -> Vec<&'static str> {
    #[cfg(target_os = "linux")]
    {
        let mut reasons = Vec::new();
        match config.stack {
            mihomo_inbound::TunStack::System => {}
            mihomo_inbound::TunStack::Mixed => {
                if !(config.auto_route && config.auto_redirect) {
                    reasons.push(
                        "tun stack `mixed` is only partially served by the native Rust app: the current Rust path requires Linux `auto-route` + `auto-redirect` so TCP can stay on the transparent listener path while UDP continues through the TUN packet relay",
                    );
                }
            }
            mihomo_inbound::TunStack::Gvisor => {
                // The gvisor stack runs on the smoltcp passive TCP bridge:
                // user-space TCP termination without auto-route/redirect.
                // UDP goes through the TUN packet relay (DirectRelay).
            }
            mihomo_inbound::TunStack::Unknown(_) => {
                reasons.push(
                    "tun stack values other than `system` are not yet served by the native Rust app",
                );
            }
        }
        if !config.include_package.is_empty()
            || !config.exclude_package.is_empty()
            || !config.include_android_user.is_empty()
        {
            reasons.push(
                "tun Android package and user filters are not yet served by the native Rust app",
            );
        }
        if !config.include_mac_address.is_empty() || !config.exclude_mac_address.is_empty() {
            reasons.push("tun MAC address filters are not yet served by the native Rust app");
        }
        if config.gso || config.gso_max_size > 0 {
            reasons.push("tun GSO options are not yet served by the native Rust app");
        }
        if config.recvmsgx || config.sendmsgx {
            reasons.push("tun recvmsgx/sendmsgx options are not yet served by the native Rust app");
        }
        if config.auto_redirect_output_mark != 0 {
            reasons.push(
                "tun auto-redirect-output-mark still lacks full native parity: the Rust app now emits Linux iptables/ip rule command-layer mark-mode setup and applies a global routing mark, but it still lacks Go-equivalent nftables output routing and loopback reroute behavior",
            );
        }
        if config.auto_redirect_iproute2_fallback_rule_index > 0 {
            reasons.push(
                "tun auto-redirect-iproute2-fallback-rule-index still lacks full native parity: the Rust app now emits the Linux fallback ip rule, but it still lacks the rest of the Go mark-mode model around nftables output routing and loopback reroute",
            );
        }
        if !config.loopback_address.is_empty() {
            if config.auto_redirect {
                reasons.push(
                    "tun loopback-address still lacks full native parity: the Rust app now performs a minimal TCP loopback bounce after TUN ingress and emits Linux output-mark, conntrack-mark, and prerouting-mark rules for configured loopback targets, but it still lacks the upstream nftables loopback reroute model and the full Go system-stack semantics",
                );
            } else {
                reasons.push(
                    "tun loopback-address still lacks full native parity: the Rust app now performs only a minimal TCP loopback bounce after TUN ingress, but it still lacks the Linux reroute command layer and the full Go system-stack semantics",
                );
            }
        }
        reasons
    }
    #[cfg(not(target_os = "linux"))]
    {
        if config.file_descriptor > 0 {
            Vec::new()
        } else {
            vec!["top-level tun listener is not yet served by the native Rust app"]
        }
    }
}

fn tun_inbound_is_supported(config: &mihomo_inbound::TunInboundConfig) -> bool {
    tun_inbound_support_gap_reasons(config).is_empty()
}

fn top_level_vmess_config_is_supported(document: &RuntimeConfigDocument) -> bool {
    let raw = document.vmess_config.trim();
    if raw.is_empty() {
        return false;
    }
    let Some(value) = raw.strip_prefix("vmess://") else {
        return false;
    };
    let Some((credentials, hosts)) = value.split_once('@') else {
        return false;
    };
    let Some((_username, uuid)) = credentials.split_once(':') else {
        return false;
    };
    !uuid.trim().is_empty() && !hosts.trim().is_empty()
}

fn top_level_shadowsocks_config_is_supported(document: &RuntimeConfigDocument) -> bool {
    let raw = document.shadow_socks_config.trim();
    if raw.is_empty() {
        return false;
    }
    let Some(value) = raw.strip_prefix("ss://") else {
        return false;
    };
    let Some((credentials, hosts)) = value.split_once('@') else {
        return false;
    };
    let Some((cipher, password)) = credentials.split_once(':') else {
        return false;
    };
    !cipher.trim().is_empty() && !password.trim().is_empty() && !hosts.trim().is_empty()
}

fn top_level_tuic_server_is_supported(document: &RuntimeConfigDocument) -> bool {
    let config = &document.tuic_server;
    let client_auth_ok = match normalize_client_auth_type_listener(&config.client_auth_type) {
        Ok(None) => config.client_auth_cert.trim().is_empty(),
        Ok(Some(_)) => !config.client_auth_cert.trim().is_empty(),
        Err(_) => false,
    };
    config.enable
        && !config.listen.trim().is_empty()
        && !config.certificate.trim().is_empty()
        && !config.private_key.trim().is_empty()
        && (!config.token.is_empty() || !config.users.is_empty())
        && client_auth_ok
        && config.ech_key.trim().is_empty()
}
