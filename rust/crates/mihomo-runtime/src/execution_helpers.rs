use std::collections::BTreeMap;

use mihomo_outbound::ProxyBaseConfig;
use mihomo_transport::{
    BasicAuth as TransportBasicAuth, GrpcOptions as TransportGrpcOptions,
    Http2Options as TransportHttp2Options, HttpStreamOptions as TransportHttpStreamOptions,
    SocketOptions as TransportSocketOptions, TlsOptions as TransportTlsOptions,
    TrojanShadowsocksOptions as TransportTrojanShadowsocksOptions,
    WebsocketOptions as TransportWebsocketOptions, WireGuardPeerTransportOptions,
    XHttpOptions as TransportXHttpOptions,
};
use serde_yaml::Value;

use crate::execution::{BasicAuth, SocketOptions, TlsOptions, WireGuardPeerHopSpec};

pub(super) fn socket_options(base: &ProxyBaseConfig) -> SocketOptions {
    SocketOptions {
        tfo: base.tfo,
        mptcp: base.mptcp,
        interface_name: base.interface_name.clone(),
        routing_mark: base.routing_mark,
        ip_version: base.ip_version.clone(),
        smux_enabled: base.smux.enabled,
    }
}

pub(super) fn transport_socket_options(socket: &SocketOptions) -> TransportSocketOptions {
    TransportSocketOptions {
        tfo: socket.tfo,
        mptcp: socket.mptcp,
        interface_name: socket.interface_name.clone(),
        routing_mark: socket.routing_mark,
        ip_version: socket.ip_version.clone(),
        smux_enabled: socket.smux_enabled,
    }
}

pub(super) fn tls_options(extra: &BTreeMap<String, Value>, sni_key: &str) -> TlsOptions {
    TlsOptions {
        enabled: value_as_bool(extra, "tls"),
        sni: value_as_string(extra, sni_key)
            .or_else(|| value_as_string(extra, "servername"))
            .unwrap_or_default(),
        skip_cert_verify: value_as_bool(extra, "skip-cert-verify"),
        fingerprint: value_as_string(extra, "fingerprint").unwrap_or_default(),
        certificate: value_as_string(extra, "certificate").unwrap_or_default(),
        private_key: value_as_string(extra, "private-key").unwrap_or_default(),
    }
}

pub(super) fn transport_tls_options(tls: &TlsOptions) -> TransportTlsOptions {
    TransportTlsOptions {
        enabled: tls.enabled,
        sni: tls.sni.clone(),
        skip_cert_verify: tls.skip_cert_verify,
        fingerprint: tls.fingerprint.clone(),
        certificate: tls.certificate.clone(),
        private_key: tls.private_key.clone(),
    }
}

pub(super) fn basic_auth(
    extra: &BTreeMap<String, Value>,
    user_key: &str,
    pass_key: &str,
) -> Option<BasicAuth> {
    let username = value_as_string(extra, user_key)?;
    let password = value_as_string(extra, pass_key).unwrap_or_default();
    Some(BasicAuth { username, password })
}

pub(super) fn transport_basic_auth(auth: &Option<BasicAuth>) -> Option<TransportBasicAuth> {
    auth.as_ref().map(|auth| TransportBasicAuth {
        username: auth.username.clone(),
        password: auth.password.clone(),
    })
}

pub(super) fn string_map(extra: &BTreeMap<String, Value>, key: &str) -> BTreeMap<String, String> {
    let Some(value) = extra.get(key) else {
        return BTreeMap::new();
    };
    let Some(map) = value.as_mapping() else {
        return BTreeMap::new();
    };
    map.iter()
        .filter_map(|(key, value)| {
            let key = key.as_str()?.to_owned();
            let value = value.as_str().map(|text| text.to_owned()).or_else(|| {
                value.as_sequence().and_then(|sequence| {
                    sequence
                        .first()
                        .and_then(|first| first.as_str())
                        .map(|text| text.to_owned())
                })
            })?;
            Some((key, value))
        })
        .collect()
}

pub(super) fn nested_string_map(
    extra: &BTreeMap<String, Value>,
    outer_key: &str,
    inner_key: &str,
) -> BTreeMap<String, String> {
    let Some(value) = extra.get(outer_key) else {
        return BTreeMap::new();
    };
    let Some(map) = value.as_mapping() else {
        return BTreeMap::new();
    };
    let Some(value) = map.get(Value::String(inner_key.to_owned())) else {
        return BTreeMap::new();
    };
    let Some(inner) = value.as_mapping() else {
        return BTreeMap::new();
    };
    inner
        .iter()
        .filter_map(|(key, value)| Some((key.as_str()?.to_owned(), value.as_str()?.to_owned())))
        .collect()
}

pub(super) fn value_as_string(extra: &BTreeMap<String, Value>, key: &str) -> Option<String> {
    extra.get(key).and_then(|value| value.as_str()).map(ToOwned::to_owned)
}

pub(super) fn string_list(extra: &BTreeMap<String, Value>, key: &str) -> Vec<String> {
    extra
        .get(key)
        .and_then(|value| value.as_sequence())
        .map(|sequence| {
            sequence
                .iter()
                .filter_map(|value| value.as_str().map(ToOwned::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

pub(super) fn value_as_bool(extra: &BTreeMap<String, Value>, key: &str) -> bool {
    extra.get(key).and_then(|value| value.as_bool()).unwrap_or(false)
}

pub(super) fn value_as_bool_with_default(
    extra: &BTreeMap<String, Value>,
    key: &str,
    default: bool,
) -> bool {
    extra.get(key).and_then(|value| value.as_bool()).unwrap_or(default)
}

fn nested_optional_bool(
    extra: &BTreeMap<String, Value>,
    outer_key: &str,
    inner_key: &str,
) -> Option<bool> {
    let value = extra.get(outer_key)?;
    let map = value.as_mapping()?;
    map.get(Value::String(inner_key.to_owned()))
        .and_then(|value| value.as_bool())
}

pub(super) fn sudoku_http_mask_enabled(extra: &BTreeMap<String, Value>) -> bool {
    if extra.contains_key("http-mask") {
        return value_as_bool_with_default(extra, "http-mask", true);
    }
    if extra.contains_key("httpmask") {
        return !nested_optional_bool(extra, "httpmask", "disable").unwrap_or(false);
    }
    false
}

pub(super) fn sudoku_http_mask_mode(extra: &BTreeMap<String, Value>) -> Option<String> {
    value_as_string(extra, "http-mask-mode")
        .or_else(|| nested_value_as_string(extra, "httpmask", "mode"))
}

pub(super) fn sudoku_http_mask_tls(extra: &BTreeMap<String, Value>) -> bool {
    if extra.contains_key("http-mask-tls") {
        return value_as_bool(extra, "http-mask-tls");
    }
    nested_optional_bool(extra, "httpmask", "tls").unwrap_or(false)
}

pub(super) fn sudoku_http_mask_host(extra: &BTreeMap<String, Value>) -> Option<String> {
    value_as_string(extra, "http-mask-host")
        .or_else(|| nested_value_as_string(extra, "httpmask", "host"))
}

pub(super) fn sudoku_http_mask_path_root(extra: &BTreeMap<String, Value>) -> Option<String> {
    value_as_string(extra, "path-root")
        .or_else(|| nested_value_as_string(extra, "httpmask", "path-root"))
}

fn value_as_i32(extra: &BTreeMap<String, Value>, key: &str) -> Option<i32> {
    extra
        .get(key)
        .and_then(|value| value.as_i64())
        .and_then(|value| i32::try_from(value).ok())
}

pub(super) fn value_as_u16(extra: &BTreeMap<String, Value>, key: &str) -> Option<u16> {
    extra
        .get(key)
        .and_then(|value| value.as_u64())
        .and_then(|value| u16::try_from(value).ok())
}

pub(super) fn value_as_u32(extra: &BTreeMap<String, Value>, key: &str) -> Option<u32> {
    extra
        .get(key)
        .and_then(|value| value.as_u64())
        .and_then(|value| u32::try_from(value).ok())
}

pub(super) fn value_as_u64(extra: &BTreeMap<String, Value>, key: &str) -> Option<u64> {
    extra.get(key).and_then(|value| value.as_u64())
}

pub(super) fn resolve_padding_min(
    extra: &BTreeMap<String, Value>,
    default_min: i32,
    default_max: i32,
) -> i32 {
    let mut min = value_as_i32(extra, "padding-min").unwrap_or(default_min);
    let max = value_as_i32(extra, "padding-max").unwrap_or(default_max);
    if !extra.contains_key("padding-min") && extra.contains_key("padding-max") && max < min {
        min = max;
    }
    min
}

pub(super) fn resolve_padding_max(
    extra: &BTreeMap<String, Value>,
    default_min: i32,
    default_max: i32,
) -> i32 {
    let min = value_as_i32(extra, "padding-min").unwrap_or(default_min);
    let mut max = value_as_i32(extra, "padding-max").unwrap_or(default_max);
    if !extra.contains_key("padding-max") && extra.contains_key("padding-min") && max < min {
        max = min;
    }
    max
}

pub(super) fn value_as_u8(extra: &BTreeMap<String, Value>, key: &str) -> Option<u8> {
    extra
        .get(key)
        .and_then(|value| value.as_u64())
        .and_then(|value| u8::try_from(value).ok())
}

pub(super) fn nested_value_as_string(
    extra: &BTreeMap<String, Value>,
    outer_key: &str,
    inner_key: &str,
) -> Option<String> {
    extra
        .get(outer_key)
        .and_then(|value| value.as_mapping())
        .and_then(|mapping| mapping.get(Value::String(inner_key.to_owned())))
        .and_then(|value| value.as_str())
        .map(ToOwned::to_owned)
}

pub(super) fn nested_value_as_bool(
    extra: &BTreeMap<String, Value>,
    outer_key: &str,
    inner_key: &str,
) -> bool {
    extra
        .get(outer_key)
        .and_then(|value| value.as_mapping())
        .and_then(|mapping| mapping.get(Value::String(inner_key.to_owned())))
        .and_then(|value| value.as_bool())
        .unwrap_or(false)
}

pub(super) fn nested_value_as_u64(
    extra: &BTreeMap<String, Value>,
    outer_key: &str,
    inner_key: &str,
) -> Option<u64> {
    extra
        .get(outer_key)
        .and_then(|value| value.as_mapping())
        .and_then(|mapping| mapping.get(Value::String(inner_key.to_owned())))
        .and_then(|value| value.as_u64())
}

pub(super) fn nested_value_as_bool_with_default(
    extra: &BTreeMap<String, Value>,
    outer_key: &str,
    inner_key: &str,
    default: bool,
) -> bool {
    extra
        .get(outer_key)
        .and_then(|value| value.as_mapping())
        .and_then(|mapping| mapping.get(Value::String(inner_key.to_owned())))
        .and_then(|value| value.as_bool())
        .unwrap_or(default)
}

fn nested_value_as_i32(
    extra: &BTreeMap<String, Value>,
    outer_key: &str,
    inner_key: &str,
) -> Option<i32> {
    extra
        .get(outer_key)
        .and_then(|value| value.as_mapping())
        .and_then(|mapping| mapping.get(Value::String(inner_key.to_owned())))
        .and_then(|value| value.as_i64())
        .and_then(|value| i32::try_from(value).ok())
}

pub(super) fn websocket_options(extra: &BTreeMap<String, Value>) -> TransportWebsocketOptions {
    TransportWebsocketOptions {
        path: nested_value_as_string(extra, "ws-opts", "path").unwrap_or_default(),
        headers: nested_string_map(extra, "ws-opts", "headers"),
        max_early_data: nested_value_as_i32(extra, "ws-opts", "max-early-data").unwrap_or(0),
        early_data_header_name: nested_value_as_string(
            extra,
            "ws-opts",
            "early-data-header-name",
        )
        .unwrap_or_default(),
        v2ray_http_upgrade: nested_value_as_bool(extra, "ws-opts", "v2ray-http-upgrade"),
        v2ray_http_upgrade_fast_open: nested_value_as_bool(
            extra,
            "ws-opts",
            "v2ray-http-upgrade-fast-open",
        ),
    }
}

pub(super) fn shadowsocks_plugin_websocket_options(
    plugin: &str,
    extra: &BTreeMap<String, Value>,
) -> TransportWebsocketOptions {
    let plugin = plugin.trim().to_ascii_lowercase();
    if plugin != "v2ray-plugin" && plugin != "gost-plugin" {
        return TransportWebsocketOptions::default();
    }
    let mut headers = nested_string_map(extra, "plugin-opts", "headers");
    let plugin_host = nested_value_as_string(extra, "plugin-opts", "host")
        .unwrap_or_else(|| "bing.com".to_owned());
    if !plugin_host.trim().is_empty()
        && !headers.keys().any(|name| name.eq_ignore_ascii_case("host"))
    {
        headers.insert("Host".to_owned(), plugin_host);
    }
    TransportWebsocketOptions {
        path: nested_value_as_string(extra, "plugin-opts", "path").unwrap_or_default(),
        headers,
        max_early_data: 0,
        early_data_header_name: String::new(),
        v2ray_http_upgrade: nested_value_as_bool(extra, "plugin-opts", "v2ray-http-upgrade"),
        v2ray_http_upgrade_fast_open: nested_value_as_bool(
            extra,
            "plugin-opts",
            "v2ray-http-upgrade-fast-open",
        ),
    }
}

pub(super) fn shadowsocks_plugin_tls_options(
    plugin: &str,
    extra: &BTreeMap<String, Value>,
) -> TlsOptions {
    let plugin = plugin.trim().to_ascii_lowercase();
    if plugin != "v2ray-plugin" && plugin != "gost-plugin" {
        return TlsOptions {
            enabled: false,
            sni: String::new(),
            skip_cert_verify: false,
            fingerprint: String::new(),
            certificate: String::new(),
            private_key: String::new(),
        };
    }
    let enabled = nested_value_as_bool(extra, "plugin-opts", "tls");
    let mut sni = String::new();
    if enabled {
        sni = nested_string_map(extra, "plugin-opts", "headers")
            .into_iter()
            .find(|(name, value)| name.eq_ignore_ascii_case("host") && !value.trim().is_empty())
            .map(|(_, value)| value)
            .unwrap_or_else(|| {
                nested_value_as_string(extra, "plugin-opts", "host")
                    .unwrap_or_else(|| "bing.com".to_owned())
            });
    }
    TlsOptions {
        enabled,
        sni,
        skip_cert_verify: nested_value_as_bool(extra, "plugin-opts", "skip-cert-verify"),
        fingerprint: nested_value_as_string(extra, "plugin-opts", "fingerprint")
            .unwrap_or_default(),
        certificate: nested_value_as_string(extra, "plugin-opts", "certificate")
            .unwrap_or_default(),
        private_key: nested_value_as_string(extra, "plugin-opts", "private-key")
            .unwrap_or_default(),
    }
}

pub(super) fn shadowsocks_plugin_mux(plugin: &str, extra: &BTreeMap<String, Value>) -> bool {
    let plugin = plugin.trim().to_ascii_lowercase();
    if plugin != "v2ray-plugin" && plugin != "gost-plugin" {
        return false;
    }
    nested_value_as_bool_with_default(extra, "plugin-opts", "mux", true)
}

pub(super) fn nested_string_list(
    extra: &BTreeMap<String, Value>,
    outer_key: &str,
    inner_key: &str,
) -> Vec<String> {
    extra
        .get(outer_key)
        .and_then(|value| value.as_mapping())
        .and_then(|mapping| mapping.get(Value::String(inner_key.to_owned())))
        .and_then(|value| value.as_sequence())
        .map(|sequence| {
            sequence
                .iter()
                .filter_map(|value| value.as_str().map(ToOwned::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

pub(super) fn nested_string_map_list(
    extra: &BTreeMap<String, Value>,
    outer_key: &str,
    inner_key: &str,
) -> BTreeMap<String, Vec<String>> {
    let Some(value) = extra.get(outer_key) else {
        return BTreeMap::new();
    };
    let Some(map) = value.as_mapping() else {
        return BTreeMap::new();
    };
    let Some(value) = map.get(Value::String(inner_key.to_owned())) else {
        return BTreeMap::new();
    };
    let Some(inner) = value.as_mapping() else {
        return BTreeMap::new();
    };
    inner
        .iter()
        .filter_map(|(key, value)| {
            let key = key.as_str()?.to_owned();
            let values = if let Some(text) = value.as_str() {
                vec![text.to_owned()]
            } else {
                value
                    .as_sequence()
                    .map(|sequence| {
                        sequence
                            .iter()
                            .filter_map(|value| value.as_str().map(ToOwned::to_owned))
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default()
            };
            Some((key, values))
        })
        .collect()
}

pub(super) fn http_options(
    extra: &BTreeMap<String, Value>,
    default_host: &str,
) -> TransportHttpStreamOptions {
    let host = nested_string_list(extra, "http-opts", "host");
    let mut path = nested_string_list(extra, "http-opts", "path");
    if path.is_empty() {
        if let Some(single_path) = nested_value_as_string(extra, "http-opts", "path") {
            path.push(single_path);
        }
    }
    TransportHttpStreamOptions {
        method: nested_value_as_string(extra, "http-opts", "method").unwrap_or_default(),
        host: if host.is_empty() {
            vec![default_host.to_owned()]
        } else {
            host
        },
        path,
        headers: nested_string_map_list(extra, "http-opts", "headers"),
    }
}

pub(super) fn h2_options(
    extra: &BTreeMap<String, Value>,
    default_host: &str,
) -> TransportHttp2Options {
    let mut host = nested_string_list(extra, "h2-opts", "host");
    if host.is_empty() {
        if let Some(single_host) = nested_value_as_string(extra, "h2-opts", "host") {
            host.push(single_host);
        }
    }
    TransportHttp2Options {
        host: if host.is_empty() {
            vec![default_host.to_owned()]
        } else {
            host
        },
        path: nested_value_as_string(extra, "h2-opts", "path").unwrap_or_default(),
    }
}

pub(super) fn grpc_options(extra: &BTreeMap<String, Value>) -> TransportGrpcOptions {
    TransportGrpcOptions {
        service_name: nested_value_as_string(extra, "grpc-opts", "grpc-service-name")
            .unwrap_or_default(),
        user_agent: nested_value_as_string(extra, "grpc-opts", "grpc-user-agent")
            .unwrap_or_default(),
        ping_interval: nested_value_as_i32(extra, "grpc-opts", "ping-interval").unwrap_or(0),
        max_connections: nested_value_as_i32(extra, "grpc-opts", "max-connections")
            .unwrap_or(0),
        min_streams: nested_value_as_i32(extra, "grpc-opts", "min-streams").unwrap_or(0),
        max_streams: nested_value_as_i32(extra, "grpc-opts", "max-streams").unwrap_or(0),
    }
}

pub(super) fn trojan_shadowsocks_options(
    extra: &BTreeMap<String, Value>,
) -> TransportTrojanShadowsocksOptions {
    TransportTrojanShadowsocksOptions {
        enabled: nested_value_as_bool(extra, "ss-opts", "enabled"),
        method: nested_value_as_string(extra, "ss-opts", "method").unwrap_or_default(),
        password: nested_value_as_string(extra, "ss-opts", "password").unwrap_or_default(),
    }
}

pub(super) fn xhttp_options(
    extra: &BTreeMap<String, Value>,
    default_host: &str,
) -> TransportXHttpOptions {
    TransportXHttpOptions {
        host: nested_value_as_string(extra, "xhttp-opts", "host")
            .unwrap_or_else(|| default_host.to_owned()),
        path: nested_value_as_string(extra, "xhttp-opts", "path").unwrap_or_default(),
        mode: nested_value_as_string(extra, "xhttp-opts", "mode").unwrap_or_default(),
        headers: nested_string_map(extra, "xhttp-opts", "headers"),
        uplink_http_method: nested_value_as_string(extra, "xhttp-opts", "uplink-http-method")
            .unwrap_or_default(),
        session_placement: nested_value_as_string(extra, "xhttp-opts", "session-placement")
            .unwrap_or_default(),
        session_key: nested_value_as_string(extra, "xhttp-opts", "session-key")
            .unwrap_or_default(),
        seq_placement: nested_value_as_string(extra, "xhttp-opts", "seq-placement")
            .unwrap_or_default(),
        seq_key: nested_value_as_string(extra, "xhttp-opts", "seq-key").unwrap_or_default(),
        uplink_data_placement: nested_value_as_string(
            extra,
            "xhttp-opts",
            "uplink-data-placement",
        )
        .unwrap_or_default(),
        uplink_data_key: nested_value_as_string(extra, "xhttp-opts", "uplink-data-key")
            .unwrap_or_default(),
        uplink_chunk_size: nested_value_as_string(extra, "xhttp-opts", "uplink-chunk-size")
            .unwrap_or_default(),
        sc_max_each_post_bytes: nested_value_as_string(
            extra,
            "xhttp-opts",
            "sc-max-each-post-bytes",
        )
        .unwrap_or_default(),
        sc_min_posts_interval_ms: nested_value_as_string(
            extra,
            "xhttp-opts",
            "sc-min-posts-interval-ms",
        )
        .unwrap_or_default(),
        no_grpc_header: nested_value_as_bool(extra, "xhttp-opts", "no-grpc-header"),
        xpadding_bytes: nested_value_as_string(extra, "xhttp-opts", "x-padding-bytes")
            .unwrap_or_default(),
        xpadding_obfs_mode: nested_value_as_bool(extra, "xhttp-opts", "x-padding-obfs-mode"),
        xpadding_key: nested_value_as_string(extra, "xhttp-opts", "x-padding-key")
            .unwrap_or_default(),
        xpadding_header: nested_value_as_string(extra, "xhttp-opts", "x-padding-header")
            .unwrap_or_default(),
        xpadding_placement: nested_value_as_string(extra, "xhttp-opts", "x-padding-placement")
            .unwrap_or_default(),
        xpadding_method: nested_value_as_string(extra, "xhttp-opts", "x-padding-method")
            .unwrap_or_default(),
        has_reuse_settings: nested_value_exists(extra, "xhttp-opts", "reuse-settings"),
        has_download_settings: nested_value_exists(extra, "xhttp-opts", "download-settings"),
        download_host: doubly_nested_value_as_string(extra, "xhttp-opts", "download-settings", "host")
            .unwrap_or_default(),
        download_path: doubly_nested_value_as_string(extra, "xhttp-opts", "download-settings", "path")
            .unwrap_or_default(),
        download_headers: doubly_nested_string_map(extra, "xhttp-opts", "download-settings", "headers"),
        download_server: doubly_nested_value_as_string(
            extra,
            "xhttp-opts",
            "download-settings",
            "server",
        )
        .unwrap_or_default(),
        download_port: doubly_nested_value_as_u16(extra, "xhttp-opts", "download-settings", "port")
            .unwrap_or(0),
        has_download_port: doubly_nested_value_exists(extra, "xhttp-opts", "download-settings", "port"),
        download_tls: doubly_nested_value_as_bool(extra, "xhttp-opts", "download-settings", "tls")
            .unwrap_or(false),
        has_download_tls: doubly_nested_value_exists(extra, "xhttp-opts", "download-settings", "tls"),
        download_sni: doubly_nested_value_as_string(
            extra,
            "xhttp-opts",
            "download-settings",
            "servername",
        )
        .unwrap_or_default(),
        download_skip_cert_verify: doubly_nested_value_as_bool(
            extra,
            "xhttp-opts",
            "download-settings",
            "skip-cert-verify",
        )
        .unwrap_or(false),
        has_download_skip_cert_verify: doubly_nested_value_exists(
            extra,
            "xhttp-opts",
            "download-settings",
            "skip-cert-verify",
        ),
        download_alpn: doubly_nested_string_list(extra, "xhttp-opts", "download-settings", "alpn"),
        download_fingerprint: doubly_nested_value_as_string(
            extra,
            "xhttp-opts",
            "download-settings",
            "fingerprint",
        )
        .unwrap_or_default(),
        download_certificate: doubly_nested_value_as_string(
            extra,
            "xhttp-opts",
            "download-settings",
            "certificate",
        )
        .unwrap_or_default(),
        download_private_key: doubly_nested_value_as_string(
            extra,
            "xhttp-opts",
            "download-settings",
            "private-key",
        )
        .unwrap_or_default(),
        has_download_reuse_settings: doubly_nested_value_exists(
            extra,
            "xhttp-opts",
            "download-settings",
            "reuse-settings",
        ),
        has_download_transport_overrides: [
            "ech-opts",
            "reality-opts",
            "client-fingerprint",
        ]
        .iter()
        .any(|key| doubly_nested_value_exists(extra, "xhttp-opts", "download-settings", key)),
    }
}

pub(super) fn wireguard_peer_specs(
    config: &mihomo_outbound::WireGuardOutboundConfig,
) -> Vec<WireGuardPeerHopSpec> {
    if let Some(peers) = config.extra.get("peers").and_then(Value::as_sequence) {
        let peers = peers
            .iter()
            .filter_map(Value::as_mapping)
            .map(|peer| WireGuardPeerHopSpec {
                server: mapping_value_as_string(peer, "server").unwrap_or_default(),
                port: mapping_value_as_u16(peer, "port").unwrap_or(0),
                public_key: mapping_value_as_string(peer, "public-key").unwrap_or_default(),
                allowed_ips: mapping_value_as_string_list(peer, "allowed-ips"),
                persistent_keepalive: mapping_value_as_u16(peer, "persistent-keepalive")
                    .unwrap_or(0),
            })
            .collect::<Vec<_>>();
        if !peers.is_empty() {
            return peers;
        }
    }

    vec![WireGuardPeerHopSpec {
        server: config.server.clone(),
        port: config.port,
        public_key: config.public_key.clone(),
        allowed_ips: string_list(&config.extra, "allowed-ips"),
        persistent_keepalive: value_as_u16(&config.extra, "persistent-keepalive").unwrap_or(0),
    }]
}

pub(super) fn transport_wireguard_peers(
    peers: &[WireGuardPeerHopSpec],
) -> Vec<WireGuardPeerTransportOptions> {
    peers
        .iter()
        .map(|peer| WireGuardPeerTransportOptions {
            server: peer.server.clone(),
            port: peer.port,
            public_key: peer.public_key.clone(),
            allowed_ips: peer.allowed_ips.clone(),
            persistent_keepalive: peer.persistent_keepalive,
        })
        .collect()
}

fn mapping_value_as_string(mapping: &serde_yaml::Mapping, key: &str) -> Option<String> {
    mapping
        .get(Value::String(key.to_owned()))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn mapping_value_as_u16(mapping: &serde_yaml::Mapping, key: &str) -> Option<u16> {
    mapping
        .get(Value::String(key.to_owned()))
        .and_then(Value::as_u64)
        .and_then(|value| u16::try_from(value).ok())
}

fn mapping_value_as_string_list(mapping: &serde_yaml::Mapping, key: &str) -> Vec<String> {
    mapping
        .get(Value::String(key.to_owned()))
        .and_then(Value::as_sequence)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn nested_value_exists(extra: &BTreeMap<String, Value>, outer_key: &str, inner_key: &str) -> bool {
    extra
        .get(outer_key)
        .and_then(|value| value.as_mapping())
        .is_some_and(|mapping| mapping.contains_key(Value::String(inner_key.to_owned())))
}

fn doubly_nested_value_as_string(
    extra: &BTreeMap<String, Value>,
    outer_key: &str,
    middle_key: &str,
    inner_key: &str,
) -> Option<String> {
    extra
        .get(outer_key)
        .and_then(|value| value.as_mapping())
        .and_then(|mapping| mapping.get(Value::String(middle_key.to_owned())))
        .and_then(|value| value.as_mapping())
        .and_then(|mapping| mapping.get(Value::String(inner_key.to_owned())))
        .and_then(|value| value.as_str().map(ToOwned::to_owned))
}

fn doubly_nested_value_as_u16(
    extra: &BTreeMap<String, Value>,
    outer_key: &str,
    middle_key: &str,
    inner_key: &str,
) -> Option<u16> {
    extra
        .get(outer_key)
        .and_then(|value| value.as_mapping())
        .and_then(|mapping| mapping.get(Value::String(middle_key.to_owned())))
        .and_then(|value| value.as_mapping())
        .and_then(|mapping| mapping.get(Value::String(inner_key.to_owned())))
        .and_then(|value| value.as_i64())
        .and_then(|value| u16::try_from(value).ok())
}

fn doubly_nested_value_as_bool(
    extra: &BTreeMap<String, Value>,
    outer_key: &str,
    middle_key: &str,
    inner_key: &str,
) -> Option<bool> {
    extra
        .get(outer_key)
        .and_then(|value| value.as_mapping())
        .and_then(|mapping| mapping.get(Value::String(middle_key.to_owned())))
        .and_then(|value| value.as_mapping())
        .and_then(|mapping| mapping.get(Value::String(inner_key.to_owned())))
        .and_then(|value| value.as_bool())
}

fn doubly_nested_string_map(
    extra: &BTreeMap<String, Value>,
    outer_key: &str,
    middle_key: &str,
    inner_key: &str,
) -> BTreeMap<String, String> {
    extra
        .get(outer_key)
        .and_then(|value| value.as_mapping())
        .and_then(|mapping| mapping.get(Value::String(middle_key.to_owned())))
        .and_then(|value| value.as_mapping())
        .and_then(|mapping| mapping.get(Value::String(inner_key.to_owned())))
        .and_then(|value| value.as_mapping())
        .map(|mapping| {
            mapping
                .iter()
                .filter_map(|(key, value)| Some((key.as_str()?.to_owned(), value.as_str()?.to_owned())))
                .collect()
        })
        .unwrap_or_default()
}

fn doubly_nested_string_list(
    extra: &BTreeMap<String, Value>,
    outer_key: &str,
    middle_key: &str,
    inner_key: &str,
) -> Vec<String> {
    extra
        .get(outer_key)
        .and_then(|value| value.as_mapping())
        .and_then(|mapping| mapping.get(Value::String(middle_key.to_owned())))
        .and_then(|value| value.as_mapping())
        .and_then(|mapping| mapping.get(Value::String(inner_key.to_owned())))
        .and_then(|value| value.as_sequence())
        .map(|sequence| {
            sequence
                .iter()
                .filter_map(|value| value.as_str().map(ToOwned::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

fn doubly_nested_value_exists(
    extra: &BTreeMap<String, Value>,
    outer_key: &str,
    middle_key: &str,
    inner_key: &str,
) -> bool {
    extra
        .get(outer_key)
        .and_then(|value| value.as_mapping())
        .and_then(|mapping| mapping.get(Value::String(middle_key.to_owned())))
        .and_then(|value| value.as_mapping())
        .is_some_and(|mapping| mapping.contains_key(Value::String(inner_key.to_owned())))
}
