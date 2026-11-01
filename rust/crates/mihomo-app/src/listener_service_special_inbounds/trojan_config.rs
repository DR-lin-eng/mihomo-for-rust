impl TrojanListenerConfig {
    pub(in crate::listener_service) fn try_from_generic(
        config: &GenericInboundConfig,
    ) -> Result<Self, ListenerServiceError> {
        let mut users = Vec::new();
        if let Some(entries) = config
            .extra
            .get("users")
            .and_then(serde_yaml::Value::as_sequence)
        {
            for entry in entries {
                let Some(mapping) = entry.as_mapping() else {
                    return Err(ListenerServiceError::Rule(
                        "trojan listener users entry must be a mapping".to_owned(),
                    ));
                };
                let password = mapping
                    .get(serde_yaml::Value::String("password".to_owned()))
                    .and_then(serde_yaml::Value::as_str)
                    .unwrap_or_default()
                    .trim()
                    .to_owned();
                if password.is_empty() {
                    return Err(ListenerServiceError::Rule(
                        "trojan listener user requires password".to_owned(),
                    ));
                }
                let username = mapping
                    .get(serde_yaml::Value::String("username".to_owned()))
                    .and_then(serde_yaml::Value::as_str)
                    .unwrap_or_default()
                    .trim()
                    .to_owned();
                users.push(ListenerAuthUser { username, password });
            }
        }
        let legacy_password = extra_string(&config.extra, "password");
        if !legacy_password.trim().is_empty()
            && !users
                .iter()
                .any(|user| user.password == legacy_password)
        {
            users.push(ListenerAuthUser {
                username: String::new(),
                password: legacy_password,
            });
        }
        if users.is_empty() {
            return Err(ListenerServiceError::Rule(
                "trojan listener requires password or users".to_owned(),
            ));
        }
        let password_keys = Arc::new(
            users
                .iter()
                .map(|user| (trojan_password_key(&user.password), user.username.clone()))
                .collect::<BTreeMap<String, String>>(),
        );
        let shadowsocks = parse_trojan_shadowsocks_options(&config.extra)?;
        let network = non_empty_or(extra_string(&config.extra, "network"), "tcp");
        if network != "tcp"
            && network != "ws"
            && network != "http"
            && network != "grpc"
            && network != "h2"
            && network != "xhttp"
            && !network.is_empty()
        {
            return Err(ListenerServiceError::Rule(format!(
                "trojan listener inbound network is not implemented yet: {network}"
            )));
        }

        let ws_path = if network == "ws" {
            non_empty_or(nested_string(&config.extra, "ws-opts", "path"), "/")
        } else {
            String::new()
        };
        let grpc_service_name = if network == "grpc" {
            non_empty_or(
                nested_string(&config.extra, "grpc-opts", "grpc-service-name"),
                "GunService",
            )
        } else {
            String::new()
        };
        let http = if network == "http" {
            build_trojan_http_options(&config.extra)
        } else {
            HttpStreamOptions::default()
        };
        let h2_hosts = if network == "h2" {
            config
                .extra
                .get("h2-opts")
                .and_then(serde_yaml::Value::as_mapping)
                .and_then(|mapping| mapping.get(&serde_yaml::Value::String("host".to_owned())))
                .and_then(serde_yaml::Value::as_sequence)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(serde_yaml::Value::as_str)
                        .map(str::to_owned)
                        .filter(|value| !value.trim().is_empty())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        let h2_path = if network == "h2" {
            config
                .extra
                .get("h2-opts")
                .and_then(serde_yaml::Value::as_mapping)
                .and_then(|mapping| mapping.get(&serde_yaml::Value::String("path".to_owned())))
                .and_then(serde_yaml::Value::as_str)
                .map(str::to_owned)
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| "/".to_owned())
        } else {
            String::new()
        };
        let xhttp = if network == "xhttp" {
            xhttp_options(&config.extra)
        } else {
            XHttpOptions::default()
        };
        let certificate = extra_string(&config.extra, "certificate");
        let private_key = extra_string(&config.extra, "private-key");
        if certificate.trim().is_empty() != private_key.trim().is_empty() {
            return Err(ListenerServiceError::Rule(
                "trojan listener requires both certificate and private-key when either is set"
                    .to_owned(),
            ));
        }
        let tls_config = if certificate.trim().is_empty() && private_key.trim().is_empty() {
            None
        } else {
            Some(Arc::new(build_server_tls_config(
                &certificate,
                &private_key,
                &network,
                &extra_string(&config.extra, "client-auth-type"),
                &extra_string(&config.extra, "client-auth-cert"),
                &extra_string(&config.extra, "ech-key"),
                config.extra.get("reality-config").is_some(),
            )?))
        };
        Ok(Self {
            base: config.base.clone(),
            password_keys,
            shadowsocks,
            network,
            ws_path,
            grpc_service_name,
            http,
            h2_hosts,
            h2_path,
            xhttp,
            xhttp_sessions: Arc::new(Mutex::new(HashMap::new())),
            tls_config,
        })
    }
}

fn build_trojan_http_options(
    extra: &BTreeMap<String, serde_yaml::Value>,
) -> HttpStreamOptions {
    let host = nested_string_list_or_single(extra, "http-opts", "host", Vec::new());
    let path = nested_string_list_or_single(
        extra,
        "http-opts",
        "path",
        vec!["/".to_owned()],
    );
    let method = non_empty_or(nested_string(extra, "http-opts", "method"), "GET");
    let headers = nested_string_map_list(extra, "http-opts", "headers");
    HttpStreamOptions {
        host,
        path,
        method,
        headers,
    }
}

fn nested_string_list_or_single(
    extra: &BTreeMap<String, serde_yaml::Value>,
    parent: &str,
    key: &str,
    default: Vec<String>,
) -> Vec<String> {
    let values = extra
        .get(parent)
        .and_then(serde_yaml::Value::as_mapping)
        .and_then(|mapping| mapping.get(&serde_yaml::Value::String(key.to_owned())))
        .and_then(serde_yaml::Value::as_sequence)
        .map(|items| {
            items
                .iter()
                .filter_map(serde_yaml::Value::as_str)
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if !values.is_empty() {
        return values;
    }

    let single = nested_string(extra, parent, key);
    if single.trim().is_empty() {
        default
    } else {
        vec![single]
    }
}
