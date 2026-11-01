pub(super) fn bind_ephemeral(host: &str) -> String {
    if host.is_empty() {
        "0.0.0.0:0".to_owned()
    } else if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:0")
    } else {
        format!("{host}:0")
    }
}

fn tunnel_network_supports_udp(networks: &[String]) -> bool {
    if networks.is_empty() {
        return true;
    }
    networks.iter().any(|network| {
        let network = network.trim().to_ascii_lowercase();
        network == "udp" || network == "all"
    })
}

fn parse_authentication_users(values: &[String]) -> Vec<AuthUser> {
    values
        .iter()
        .filter_map(|value| {
            let (username, password) = value.split_once(':')?;
            Some(AuthUser {
                username: username.to_owned(),
                password: password.to_owned(),
            })
        })
        .collect()
}

fn top_level_bind_address(document: &RuntimeConfigDocument, port: u16) -> String {
    if document.allow_lan {
        if document.bind_address.is_empty() || document.bind_address == "*" {
            format!("0.0.0.0:{port}")
        } else {
            format!("{}:{port}", document.bind_address)
        }
    } else {
        format!("127.0.0.1:{port}")
    }
}

fn base_from_address(name: &str, address: &str) -> BaseInboundConfig {
    let (listen, port) = address.rsplit_once(':').unwrap_or((address, "0"));
    BaseInboundConfig {
        name: name.to_owned(),
        listen: listen.to_owned(),
        port: port.to_owned(),
        ..BaseInboundConfig::default()
    }
}

fn top_level_vmess_listener_config(
    document: &RuntimeConfigDocument,
) -> Result<(VmessInboundConfig, Vec<String>), ListenerServiceError> {
    let (listen, _username, uuid) = parse_top_level_vmess_config(&document.vmess_config)?;
    let addresses = top_level_listen_addresses(&listen)?;
    let base = BaseInboundConfig {
        name: "__top_level_vmess__".to_owned(),
        listen: String::new(),
        port: String::new(),
        ..BaseInboundConfig::default()
    };
    Ok((
        VmessInboundConfig {
            base,
            uuids: vec![uuid],
            network: "tcp".to_owned(),
            ws_path: String::new(),
            grpc_service_name: String::new(),
            http: mihomo_transport::HttpStreamOptions::default(),
            h2_hosts: Vec::new(),
            h2_path: String::new(),
            xhttp: XHttpOptions::default(),
            xhttp_sessions: Arc::new(Mutex::new(HashMap::new())),
            tls_config: None,
        },
        addresses,
    ))
}

fn top_level_shadowsocks_listener_config(
    document: &RuntimeConfigDocument,
) -> Result<(ShadowSocksListenerConfig, Vec<String>), ListenerServiceError> {
    let (listen, cipher, password) =
        parse_top_level_shadowsocks_config(&document.shadow_socks_config)?;
    let addresses = top_level_listen_addresses(&listen)?;
    let base = BaseInboundConfig {
        name: "__top_level_shadowsocks__".to_owned(),
        listen: String::new(),
        port: String::new(),
        ..BaseInboundConfig::default()
    };
    Ok((
        ShadowSocksListenerConfig {
            base,
            password,
            cipher,
            obfs_mode: String::new(),
        },
        addresses,
    ))
}

fn parse_top_level_vmess_config(
    raw: &str,
) -> Result<(String, String, String), ListenerServiceError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(ListenerServiceError::Rule(
            "top-level vmess-config is empty".to_owned(),
        ));
    }
    let value = trimmed
        .strip_prefix("vmess://")
        .ok_or_else(|| {
            ListenerServiceError::Rule(
                "top-level vmess-config must use vmess:// scheme".to_owned(),
            )
        })?;
    let (credentials, hosts) = value.split_once('@').ok_or_else(|| {
        ListenerServiceError::Rule(
            "top-level vmess-config must include credentials and listen address".to_owned(),
        )
    })?;
    let (username, uuid) = credentials.split_once(':').ok_or_else(|| {
        ListenerServiceError::Rule(
            "top-level vmess-config must use vmess://username:uuid@host:port format".to_owned(),
        )
    })?;
    if username.trim().is_empty() {
        return Err(ListenerServiceError::Rule(
            "top-level vmess-config requires username".to_owned(),
        ));
    }
    let listen = hosts.trim().to_owned();
    if listen.is_empty() {
        return Err(ListenerServiceError::Rule(
            "top-level vmess-config requires listen address".to_owned(),
        ));
    }
    for address in listen.split(',') {
        if address.trim().is_empty() || normalize_listener_address(address.trim()).is_none() {
            return Err(ListenerServiceError::Rule(format!(
                "top-level vmess-config has invalid listen address: {address}"
            )));
        }
    }
    Ok((listen, username.trim().to_owned(), uuid.trim().to_owned()))
}

fn parse_top_level_shadowsocks_config(
    raw: &str,
) -> Result<(String, String, String), ListenerServiceError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(ListenerServiceError::Rule(
            "top-level ss-config is empty".to_owned(),
        ));
    }
    let value = trimmed.strip_prefix("ss://").ok_or_else(|| {
        ListenerServiceError::Rule("top-level ss-config must use ss:// scheme".to_owned())
    })?;
    let (credentials, hosts) = value.split_once('@').ok_or_else(|| {
        ListenerServiceError::Rule(
            "top-level ss-config must include credentials and listen address".to_owned(),
        )
    })?;
    let (cipher, password) = credentials.split_once(':').ok_or_else(|| {
        ListenerServiceError::Rule(
            "top-level ss-config must use ss://cipher:password@host:port format".to_owned(),
        )
    })?;
    let listen = hosts.trim().to_owned();
    if cipher.trim().is_empty() || password.trim().is_empty() || listen.is_empty() {
        return Err(ListenerServiceError::Rule(
            "top-level ss-config requires cipher, password, and listen address".to_owned(),
        ));
    }
    for address in listen.split(',') {
        if address.trim().is_empty() || normalize_listener_address(address.trim()).is_none() {
            return Err(ListenerServiceError::Rule(format!(
                "top-level ss-config has invalid listen address: {address}"
            )));
        }
    }
    Ok((listen, cipher.trim().to_owned(), password.trim().to_owned()))
}

fn top_level_listen_addresses(addresses: &str) -> Result<Vec<String>, ListenerServiceError> {
    addresses
        .split(',')
        .map(|address| {
            normalize_listener_address(address.trim()).ok_or_else(|| {
                ListenerServiceError::Rule(format!(
                    "invalid top-level listen address: {}",
                    address.trim()
                ))
            })
        })
        .collect()
}

fn normalize_listener_address(address: &str) -> Option<String> {
    if address.is_empty() {
        return None;
    }
    let socket = address.parse::<SocketAddr>().ok()?;
    Some(match socket {
        SocketAddr::V4(addr) => addr.to_string(),
        SocketAddr::V6(addr) => format!("[{}]:{}", addr.ip(), addr.port()),
    })
}
