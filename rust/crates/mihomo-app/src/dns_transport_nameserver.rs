struct ParsedTunnelNameserver {
    transport: TunnelDnsTransport,
    special_proxy: String,
}

enum TunnelDnsTransport {
    Udp(SocketAddr),
    Tcp(SocketAddr),
    Tls {
        endpoint: SocketAddr,
        server_name: String,
    },
    Http(Url),
    Https(Url),
    Quic {
        endpoints: Vec<SocketAddr>,
        server_name: String,
    },
}

fn parse_tunnel_nameserver_with_runtime(
    raw: &str,
    default_special_proxy: &str,
    mut runtime: Option<&mut DnsRuntime>,
) -> Result<ParsedTunnelNameserver, DnsError> {
    let raw = raw.trim();
    let (endpoint, fragment) = raw
        .split_once('#')
        .map_or((raw, ""), |(left, right)| (left.trim(), right.trim()));
    if endpoint.is_empty() {
        return Err(DnsError::UnsupportedNameserver(raw.to_owned()));
    }
    let special_proxy = if fragment.is_empty() {
        default_special_proxy.to_owned()
    } else if fragment.eq_ignore_ascii_case("RULES") {
        "RULES".to_owned()
    } else if !fragment.contains('=') && !fragment.contains('&') {
        // Proxy/group names may contain Unicode and spaces.
        url::form_urlencoded::parse(format!("name={fragment}").as_bytes())
            .next()
            .map(|(_, value)| value.into_owned())
            .unwrap_or_default()
    } else {
        return Err(DnsError::UnsupportedNameserver(raw.to_owned()));
    };
    let lower = endpoint.to_ascii_lowercase();
    let transport = if let Some(value) = endpoint.strip_prefix("udp://") {
        TunnelDnsTransport::Udp(
            resolve_dns_endpoint(value, 53, runtime.as_deref_mut())?
                .into_iter()
                .next()
                .ok_or_else(|| DnsError::ResolveFailed(value.into()))?,
        )
    } else if let Some(value) = endpoint.strip_prefix("tcp://") {
        TunnelDnsTransport::Tcp(
            resolve_dns_endpoint(value, 53, runtime.as_deref_mut())?
                .into_iter()
                .next()
                .ok_or_else(|| DnsError::ResolveFailed(value.into()))?,
        )
    } else if let Some(value) = endpoint.strip_prefix("tls://") {
        let endpoint_addr = resolve_dns_endpoint(value, 853, runtime.as_deref_mut())?
            .into_iter()
            .next()
            .ok_or_else(|| DnsError::ResolveFailed(value.into()))?;
        let server_name = host_part(value).to_owned();
        TunnelDnsTransport::Tls {
            endpoint: endpoint_addr,
            server_name,
        }
    } else if lower.starts_with("http://") {
        TunnelDnsTransport::Http(
            Url::parse(endpoint).map_err(|_| DnsError::UnsupportedNameserver(raw.to_owned()))?,
        )
    } else if lower.starts_with("https://") {
        TunnelDnsTransport::Https(
            Url::parse(endpoint).map_err(|_| DnsError::UnsupportedNameserver(raw.to_owned()))?,
        )
    } else if let Some(value) = endpoint.strip_prefix("quic://") {
        let endpoints = resolve_dns_endpoint(value, 853, runtime.as_deref_mut())?;
        let server_name = host_part(value).to_owned();
        TunnelDnsTransport::Quic {
            endpoints,
            server_name,
        }
    } else if lower.starts_with("quic://")
        || lower.starts_with("system")
        || lower.starts_with("rcode://")
        || lower.starts_with("dhcp://")
        || lower.starts_with("ts://")
        || lower.starts_with("tailscale://")
    {
        return Err(DnsError::UnsupportedNameserver(raw.to_owned()));
    } else {
        TunnelDnsTransport::Udp(
            resolve_dns_endpoint(endpoint, 53, runtime.as_deref_mut())?
                .into_iter()
                .next()
                .ok_or_else(|| DnsError::ResolveFailed(endpoint.into()))?,
        )
    };
    Ok(ParsedTunnelNameserver {
        transport,
        special_proxy,
    })
}

fn resolve_dns_endpoint(
    raw: &str,
    default_port: u16,
    runtime: Option<&mut DnsRuntime>,
) -> Result<Vec<SocketAddr>, DnsError> {
    if let Ok(addr) = raw.parse::<SocketAddr>() {
        return Ok(vec![addr]);
    }
    if let Ok(ip) = raw.trim_matches(['[', ']']).parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, default_port)]);
    }
    let url = Url::parse(&format!("tcp://{raw}"))
        .map_err(|_| DnsError::UnsupportedNameserver(raw.into()))?;
    let host = url
        .host_str()
        .ok_or_else(|| DnsError::UnsupportedNameserver(raw.into()))?;
    let port = url.port().unwrap_or(default_port);
    let runtime = runtime
        .ok_or_else(|| DnsError::ResolveFailed(format!("no bootstrap resolver for {host}")))?;
    Ok(runtime
        .resolve_nameserver_host(host)?
        .into_iter()
        .map(|ip| SocketAddr::new(ip, port))
        .collect())
}

fn host_part(raw: &str) -> &str {
    let raw = raw.trim();
    if let Some(rest) = raw.strip_prefix('[') {
        return rest.split_once(']').map(|(host, _)| host).unwrap_or(raw);
    }
    raw.rsplit_once(':').map(|(host, _)| host).unwrap_or(raw)
}
