use std::collections::BTreeMap;
use std::io;

use base64::Engine as _;
use mihomo_core::BoxedTcpStream;
use mihomo_runtime::ListenerRuntimeError;
use mihomo_transport::XHttpOptions;

use crate::listener_service_support::{
    doubly_nested_bool, doubly_nested_string, doubly_nested_string_list,
    doubly_nested_string_map, doubly_nested_u16, doubly_nested_value_exists,
    nested_optional_bool, nested_string, nested_string_map, nested_value_exists,
    prefix_tcp_stream,
};

pub(in crate::listener_service) fn xhttp_options(
    extra: &BTreeMap<String, serde_yaml::Value>,
) -> XHttpOptions {
    let mode = nested_string(extra, "xhttp-opts", "mode");
    let normalized_mode = if mode.trim().is_empty() || mode.trim() == "auto" {
        "packet-up".to_owned()
    } else {
        mode
    };
    XHttpOptions {
        host: nested_string(extra, "xhttp-opts", "host"),
        path: nested_string(extra, "xhttp-opts", "path"),
        mode: normalized_mode,
        headers: nested_string_map(extra, "xhttp-opts", "headers"),
        uplink_http_method: nested_string(extra, "xhttp-opts", "uplink-http-method"),
        session_placement: nested_string(extra, "xhttp-opts", "session-placement"),
        session_key: nested_string(extra, "xhttp-opts", "session-key"),
        seq_placement: nested_string(extra, "xhttp-opts", "seq-placement"),
        seq_key: nested_string(extra, "xhttp-opts", "seq-key"),
        uplink_data_placement: nested_string(extra, "xhttp-opts", "uplink-data-placement"),
        uplink_data_key: nested_string(extra, "xhttp-opts", "uplink-data-key"),
        uplink_chunk_size: nested_string(extra, "xhttp-opts", "uplink-chunk-size"),
        sc_max_each_post_bytes: nested_string(extra, "xhttp-opts", "sc-max-each-post-bytes"),
        sc_min_posts_interval_ms: nested_string(extra, "xhttp-opts", "sc-min-posts-interval-ms"),
        no_grpc_header: nested_optional_bool(extra, "xhttp-opts", "no-grpc-header")
            .unwrap_or(false),
        xpadding_bytes: nested_string(extra, "xhttp-opts", "x-padding-bytes"),
        xpadding_obfs_mode: nested_optional_bool(extra, "xhttp-opts", "x-padding-obfs-mode")
            .unwrap_or(false),
        xpadding_key: nested_string(extra, "xhttp-opts", "x-padding-key"),
        xpadding_header: nested_string(extra, "xhttp-opts", "x-padding-header"),
        xpadding_placement: nested_string(extra, "xhttp-opts", "x-padding-placement"),
        xpadding_method: nested_string(extra, "xhttp-opts", "x-padding-method"),
        has_reuse_settings: nested_value_exists(extra, "xhttp-opts", "reuse-settings"),
        has_download_settings: nested_value_exists(extra, "xhttp-opts", "download-settings"),
        download_host: doubly_nested_string(extra, "xhttp-opts", "download-settings", "host"),
        download_path: doubly_nested_string(extra, "xhttp-opts", "download-settings", "path"),
        download_headers: doubly_nested_string_map(
            extra,
            "xhttp-opts",
            "download-settings",
            "headers",
        ),
        download_server: doubly_nested_string(extra, "xhttp-opts", "download-settings", "server"),
        download_port: doubly_nested_u16(extra, "xhttp-opts", "download-settings", "port")
            .unwrap_or(0),
        has_download_port: doubly_nested_value_exists(
            extra,
            "xhttp-opts",
            "download-settings",
            "port",
        ),
        download_tls: doubly_nested_bool(extra, "xhttp-opts", "download-settings", "tls")
            .unwrap_or(false),
        has_download_tls: doubly_nested_value_exists(
            extra,
            "xhttp-opts",
            "download-settings",
            "tls",
        ),
        download_sni: doubly_nested_string(
            extra,
            "xhttp-opts",
            "download-settings",
            "servername",
        ),
        download_skip_cert_verify: doubly_nested_bool(
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
        download_fingerprint: doubly_nested_string(
            extra,
            "xhttp-opts",
            "download-settings",
            "fingerprint",
        ),
        download_certificate: doubly_nested_string(
            extra,
            "xhttp-opts",
            "download-settings",
            "certificate",
        ),
        download_private_key: doubly_nested_string(
            extra,
            "xhttp-opts",
            "download-settings",
            "private-key",
        ),
        has_download_reuse_settings: doubly_nested_value_exists(
            extra,
            "xhttp-opts",
            "download-settings",
            "reuse-settings",
        ),
        has_download_transport_overrides: [
            "server",
            "port",
            "tls",
            "servername",
            "skip-cert-verify",
            "alpn",
            "fingerprint",
            "certificate",
            "private-key",
        ]
        .iter()
        .any(|key| doubly_nested_value_exists(extra, "xhttp-opts", "download-settings", key)),
    }
}

pub(in crate::listener_service) fn normalize_xhttp_path(path: &str) -> String {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        "/".to_owned()
    } else if trimmed.starts_with('/') {
        format!("{trimmed}/").replace("//", "/")
    } else {
        format!("/{trimmed}/")
    }
}

pub(in crate::listener_service) fn normalized_xhttp_mode(options: &XHttpOptions) -> &str {
    let mode = options.mode.trim();
    if mode.is_empty() || mode == "auto" {
        "packet-up"
    } else {
        mode
    }
}

pub(in crate::listener_service) fn normalized_xhttp_session_placement(
    options: &XHttpOptions,
) -> &str {
    let placement = options.session_placement.trim();
    if placement.is_empty() {
        "path"
    } else {
        placement
    }
}

pub(in crate::listener_service) fn normalized_xhttp_seq_placement(
    options: &XHttpOptions,
) -> &str {
    let placement = options.seq_placement.trim();
    if placement.is_empty() {
        "path"
    } else {
        placement
    }
}

pub(in crate::listener_service) fn normalized_xhttp_session_key(
    options: &XHttpOptions,
) -> String {
    let key = options.session_key.trim();
    if !key.is_empty() {
        return key.to_owned();
    }
    match normalized_xhttp_session_placement(options) {
        "header" => "X-Session".to_owned(),
        "query" | "cookie" => "x_session".to_owned(),
        _ => String::new(),
    }
}

pub(in crate::listener_service) fn normalized_xhttp_seq_key(options: &XHttpOptions) -> String {
    let key = options.seq_key.trim();
    if !key.is_empty() {
        return key.to_owned();
    }
    match normalized_xhttp_seq_placement(options) {
        "header" => "X-Seq".to_owned(),
        "query" | "cookie" => "x_seq".to_owned(),
        _ => String::new(),
    }
}

pub(in crate::listener_service) fn normalized_xhttp_uplink_data_placement(
    options: &XHttpOptions,
) -> &str {
    let placement = options.uplink_data_placement.trim();
    if placement.is_empty() || placement == "auto" {
        "body"
    } else {
        placement
    }
}

pub(in crate::listener_service) fn xhttp_uses_path_session(options: &XHttpOptions) -> bool {
    normalized_xhttp_session_placement(options) == "path"
}

pub(in crate::listener_service) fn xhttp_uses_path_seq(options: &XHttpOptions) -> bool {
    normalized_xhttp_seq_placement(options) == "path"
}

pub(in crate::listener_service) fn xhttp_download_authority(options: &XHttpOptions) -> &str {
    if !options.download_host.trim().is_empty() {
        &options.download_host
    } else {
        &options.host
    }
}

pub(in crate::listener_service) fn xhttp_download_path(options: &XHttpOptions) -> String {
    if !options.download_path.trim().is_empty() {
        normalize_xhttp_path(&options.download_path)
    } else {
        normalize_xhttp_path(&options.path)
    }
}

pub(in crate::listener_service) fn xhttp_download_headers(
    options: &XHttpOptions,
) -> BTreeMap<String, String> {
    if options.download_headers.is_empty() {
        options.headers.clone()
    } else {
        options.download_headers.clone()
    }
}

pub(in crate::listener_service) fn split_request_path(path: &str) -> (&str, Option<&str>) {
    if let Some((path, query)) = path.split_once('?') {
        (path, Some(query))
    } else {
        (path, None)
    }
}

pub(in crate::listener_service) fn parse_query_string(
    query: Option<&str>,
) -> BTreeMap<String, String> {
    query
        .unwrap_or_default()
        .split('&')
        .filter(|part| !part.is_empty())
        .map(|part| {
            let (key, value) = part.split_once('=').unwrap_or((part, ""));
            (key.to_owned(), value.to_owned())
        })
        .collect()
}

pub(in crate::listener_service) fn request_header_value(
    headers: &BTreeMap<String, String>,
    key: &str,
) -> Option<String> {
    headers
        .iter()
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(key))
        .map(|(_, value)| value.clone())
}

pub(in crate::listener_service) fn parse_cookie_header(
    headers: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    request_header_value(headers, "cookie")
        .unwrap_or_default()
        .split(';')
        .filter_map(|part| {
            let trimmed = part.trim();
            let (key, value) = trimmed.split_once('=')?;
            Some((key.trim().to_owned(), value.trim().to_owned()))
        })
        .collect()
}

pub(in crate::listener_service) fn validate_expected_headers(
    headers: &BTreeMap<String, String>,
    expected: &BTreeMap<String, String>,
    label: &str,
) -> Result<(), ListenerRuntimeError> {
    for (key, expected_value) in expected {
        let actual = request_header_value(headers, key).ok_or_else(|| {
            ListenerRuntimeError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("missing xhttp {label} header: {key}"),
            ))
        })?;
        if actual != *expected_value {
            return Err(ListenerRuntimeError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "unexpected xhttp {label} header: key={key}, expected={expected_value}, got={actual}",
                ),
            )));
        }
    }
    Ok(())
}

pub(in crate::listener_service) fn take_xhttp_meta_from_request(
    headers: &BTreeMap<String, String>,
    query: &BTreeMap<String, String>,
    cookies: &BTreeMap<String, String>,
    path_segments: &mut Vec<&str>,
    placement: &str,
    key: &str,
    label: &str,
) -> Result<String, ListenerRuntimeError> {
    let value = match placement {
        "path" => path_segments.first().copied().map(str::to_owned),
        "query" => query.get(key).cloned(),
        "header" => request_header_value(headers, key),
        "cookie" => cookies.get(key).cloned(),
        other => {
            return Err(ListenerRuntimeError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsupported xhttp {label} placement: {other}"),
            )))
        }
    }
    .ok_or_else(|| {
        ListenerRuntimeError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("missing xhttp {label}"),
        ))
    })?;
    if placement == "path" {
        path_segments.remove(0);
    }
    Ok(value)
}

pub(in crate::listener_service) fn collect_xhttp_uplink_prefix(
    headers: &BTreeMap<String, String>,
    cookies: &BTreeMap<String, String>,
    options: &XHttpOptions,
) -> Result<Vec<u8>, ListenerRuntimeError> {
    let key = options.uplink_data_key.trim();
    let placement = normalized_xhttp_uplink_data_placement(options);
    let mut encoded = String::new();
    match placement {
        "body" => return Ok(Vec::new()),
        "header" => {
            for index in 0.. {
                let header_name = format!("{key}-{index}");
                let Some(chunk) = request_header_value(headers, &header_name) else {
                    break;
                };
                encoded.push_str(&chunk);
            }
        }
        "cookie" => {
            for index in 0.. {
                let cookie_name = format!("{key}_{index}");
                let Some(chunk) = cookies.get(&cookie_name) else {
                    break;
                };
                encoded.push_str(chunk);
            }
        }
        other => {
            return Err(ListenerRuntimeError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsupported xhttp uplink-data placement: {other}"),
            )))
        }
    }
    if encoded.is_empty() {
        return Ok(Vec::new());
    }
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|err| {
            ListenerRuntimeError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid xhttp uplink data: {err}"),
            ))
        })
}

pub(in crate::listener_service) fn maybe_prefix_xhttp_stream(
    stream: BoxedTcpStream,
    prefix: Vec<u8>,
) -> BoxedTcpStream {
    prefix_tcp_stream(stream, prefix)
}
