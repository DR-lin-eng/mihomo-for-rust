use std::io::{self, Read, Write};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use mihomo_core::{BoxedTcpStream, TcpStream};
use rand::{Rng, RngCore};

use std::collections::BTreeMap;

use base64::Engine;

use crate::{h2_stream, TlsOptions, TransportError, TransportTarget};

const BASE62_CHARSET: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct XHttpOptions {
    pub host: String,
    pub path: String,
    pub mode: String,
    pub headers: BTreeMap<String, String>,
    pub uplink_http_method: String,
    pub session_placement: String,
    pub session_key: String,
    pub seq_placement: String,
    pub seq_key: String,
    pub uplink_data_placement: String,
    pub uplink_data_key: String,
    pub uplink_chunk_size: String,
    pub sc_max_each_post_bytes: String,
    pub sc_min_posts_interval_ms: String,
    pub no_grpc_header: bool,
    pub xpadding_bytes: String,
    pub xpadding_obfs_mode: bool,
    pub xpadding_key: String,
    pub xpadding_header: String,
    pub xpadding_placement: String,
    pub xpadding_method: String,
    pub has_reuse_settings: bool,
    pub has_download_settings: bool,
    pub download_host: String,
    pub download_path: String,
    pub download_headers: BTreeMap<String, String>,
    pub download_server: String,
    pub download_port: u16,
    pub has_download_port: bool,
    pub download_tls: bool,
    pub has_download_tls: bool,
    pub download_sni: String,
    pub download_skip_cert_verify: bool,
    pub has_download_skip_cert_verify: bool,
    pub download_alpn: Vec<String>,
    pub download_fingerprint: String,
    pub download_certificate: String,
    pub download_private_key: String,
    pub has_download_reuse_settings: bool,
    pub has_download_transport_overrides: bool,
}

pub(crate) fn wrap_tls_stream(
    stream: BoxedTcpStream,
    proxy: &TransportTarget,
    tls: &TlsOptions,
    alpn: &[String],
    options: &XHttpOptions,
) -> Result<BoxedTcpStream, TransportError> {
    wrap_stream_internal(stream, proxy, tls.clone(), alpn, options)
}

pub(crate) fn wrap_stream(
    stream: BoxedTcpStream,
    proxy: &TransportTarget,
    options: &XHttpOptions,
) -> Result<BoxedTcpStream, TransportError> {
    wrap_stream_internal(stream, proxy, TlsOptions::default(), &[], options)
}

fn wrap_stream_internal(
    stream: BoxedTcpStream,
    proxy: &TransportTarget,
    tls: TlsOptions,
    alpn: &[String],
    options: &XHttpOptions,
) -> Result<BoxedTcpStream, TransportError> {
    if !alpn.is_empty() && !alpn.iter().any(|value| value == "h2") {
        return Err(TransportError::UnsupportedFeature {
            proxy: proxy.authority(),
            feature: format!("xhttp alpn={}", alpn.join(",")),
        });
    }

    validate_options(proxy, options)?;

    let mode = effective_mode(options);
    if mode != "stream-one" && mode != "stream-up" && mode != "packet-up" {
        return Err(TransportError::UnsupportedFeature {
            proxy: proxy.authority(),
            feature: format!("xhttp mode={mode}"),
        });
    }

    let authority = if options.host.trim().is_empty() {
        proxy.host.clone()
    } else {
        options.host.clone()
    };
    let path = normalize_path(&options.path);
    let method = if options.uplink_http_method.trim().is_empty() {
        "POST".to_owned()
    } else {
        options.uplink_http_method.clone()
    };
    let headers = options
        .headers
        .iter()
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect::<Vec<_>>();
    let download_authority = if options.download_host.trim().is_empty() {
        authority.clone()
    } else {
        options.download_host.clone()
    };
    let download_target = resolved_download_target(proxy, options);
    let download_tls = resolved_download_tls(&tls, &download_target, options);
    let download_alpn = resolved_download_alpn(alpn, options);
    let download_path = if options.download_path.trim().is_empty() {
        path.clone()
    } else {
        normalize_path(&options.download_path)
    };
    let download_headers = if options.download_headers.is_empty() {
        headers.clone()
    } else {
        options
            .download_headers
            .iter()
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect::<Vec<_>>()
    };
    let meta_options = XHttpOptions {
        session_placement: options.session_placement.clone(),
        session_key: options.session_key.clone(),
        seq_placement: options.seq_placement.clone(),
        seq_key: options.seq_key.clone(),
        uplink_data_placement: options.uplink_data_placement.clone(),
        uplink_data_key: options.uplink_data_key.clone(),
        uplink_chunk_size: options.uplink_chunk_size.clone(),
        ..Default::default()
    };
    let alpn = if alpn.is_empty() {
        vec!["h2".to_owned()]
    } else {
        alpn.to_vec()
    };

    if mode == "stream-one" {
        let mut headers = headers;
        maybe_set_stream_content_type(&mut headers, options);
        let request = request_options_with_meta(
            authority,
            path,
            method,
            headers,
            options,
            None,
            None,
        );
        h2_wrap_stream_with_request(stream, proxy, &tls, &alpn, request)
    } else if mode == "stream-up" {
        wrap_tls_stream_up(
            stream,
            proxy,
            &tls,
            &alpn,
            authority,
            path,
            method,
            headers,
            proxy.clone(),
            download_authority,
            download_path,
            download_headers,
            download_target,
            download_tls,
            download_alpn,
            meta_options,
        )
    } else {
        wrap_tls_packet_up(
            stream,
            proxy,
            &tls,
            &alpn,
            authority,
            path,
            method,
            headers,
            proxy.clone(),
            download_authority,
            download_path,
            download_headers,
            download_target,
            download_tls,
            download_alpn,
            meta_options,
        )
    }
}

fn h2_wrap_stream_with_request(
    stream: BoxedTcpStream,
    proxy: &TransportTarget,
    tls: &TlsOptions,
    alpn: &[String],
    request: h2_stream::H2RequestOptions,
) -> Result<BoxedTcpStream, TransportError> {
    if tls.enabled {
        h2_stream::wrap_tls_stream_with_request(stream, proxy, tls, alpn, request)
    } else {
        h2_stream::wrap_stream_with_request(stream, request)
    }
}

fn normalize_path(path: &str) -> String {
    let trimmed = path.trim();
    let mut normalized = if trimmed.is_empty() {
        "/".to_owned()
    } else if trimmed.starts_with('/') {
        trimmed.to_owned()
    } else {
        format!("/{trimmed}")
    };
    if !normalized.ends_with('/') {
        normalized.push('/');
    }
    normalized
}

fn normalized_mode(mode: &str) -> &str {
    let trimmed = mode.trim();
    if trimmed.is_empty() {
        "auto"
    } else {
        trimmed
    }
}

fn effective_mode(options: &XHttpOptions) -> &str {
    match normalized_mode(&options.mode) {
        // Rust 侧当前还没有 xhttp reality，因此 auto/空 mode 按上游无 reality 分支收敛到 packet-up。
        "auto" => "packet-up",
        other => other,
    }
}

fn validate_options(proxy: &TransportTarget, options: &XHttpOptions) -> Result<(), TransportError> {
    let _ = normalized_xpadding_bytes(options).map_err(|_| TransportError::UnsupportedFeature {
        proxy: proxy.authority(),
        feature: format!("xhttp x-padding-bytes={}", options.xpadding_bytes.trim()),
    })?;
    if options.xpadding_obfs_mode {
        validate_supported_placement(
            proxy,
            "x-padding-placement",
            options.xpadding_placement.trim(),
            &["header", "queryInHeader", "query", "cookie"],
        )?;
        let method = normalized_xpadding_method(options);
        if method != "repeat-x" && method != "tokenish" {
            return Err(TransportError::UnsupportedFeature {
                proxy: proxy.authority(),
                feature: format!("xhttp x-padding-method={method}"),
            });
        }
    }
    if options.has_download_settings && effective_mode(options) == "stream-one" {
        return Err(TransportError::UnsupportedFeature {
            proxy: proxy.authority(),
            feature: "xhttp download-settings with mode=stream-one".to_owned(),
        });
    }
    if options.has_download_transport_overrides {
        return Err(TransportError::UnsupportedFeature {
            proxy: proxy.authority(),
            feature: "xhttp download-settings transport overrides".to_owned(),
        });
    }
    let _ = normalized_sc_max_each_post_bytes(options).map_err(|_| TransportError::UnsupportedFeature {
        proxy: proxy.authority(),
        feature: format!(
            "xhttp sc-max-each-post-bytes={}",
            options.sc_max_each_post_bytes.trim()
        ),
    })?;
    let _ = normalized_sc_min_posts_interval_ms(options).map_err(|_| TransportError::UnsupportedFeature {
        proxy: proxy.authority(),
        feature: format!(
            "xhttp sc-min-posts-interval-ms={}",
            options.sc_min_posts_interval_ms.trim()
        ),
    })?;
    validate_supported_placement(
        proxy,
        "session-placement",
        options.session_placement.trim(),
        &["path", "query", "header", "cookie"],
    )?;
    validate_supported_placement(
        proxy,
        "seq-placement",
        options.seq_placement.trim(),
        &["path", "query", "header", "cookie"],
    )?;
    validate_supported_placement(
        proxy,
        "uplink-data-placement",
        options.uplink_data_placement.trim(),
        &["body", "header", "cookie", "auto"],
    )?;
    match normalized_uplink_data_placement(options) {
        "header" | "cookie" => {
            let _ = normalized_uplink_chunk_size(options).map_err(|_| {
                TransportError::UnsupportedFeature {
                    proxy: proxy.authority(),
                    feature: format!("xhttp uplink-chunk-size={}", options.uplink_chunk_size.trim()),
                }
            })?;
        }
        _ => {}
    }
    Ok(())
}

fn validate_supported_placement(
    proxy: &TransportTarget,
    name: &str,
    value: &str,
    allowed: &[&str],
) -> Result<(), TransportError> {
    if value.is_empty() || allowed.iter().any(|candidate| *candidate == value) {
        return Ok(());
    }
    Err(TransportError::UnsupportedFeature {
        proxy: proxy.authority(),
        feature: format!("xhttp {name}={value}"),
    })
}

fn resolved_download_target(proxy: &TransportTarget, options: &XHttpOptions) -> TransportTarget {
    let host = if options.download_server.trim().is_empty() {
        proxy.host.clone()
    } else {
        options.download_server.clone()
    };
    let port = if options.has_download_port {
        options.download_port
    } else {
        proxy.port
    };
    TransportTarget::new(host, port)
}

fn resolved_download_tls(base: &TlsOptions, target: &TransportTarget, options: &XHttpOptions) -> TlsOptions {
    TlsOptions {
        enabled: if options.has_download_tls {
            options.download_tls
        } else {
            base.enabled
        },
        sni: if !options.download_sni.trim().is_empty() {
            options.download_sni.clone()
        } else if !base.sni.trim().is_empty() {
            base.sni.clone()
        } else {
            target.host.clone()
        },
        skip_cert_verify: if options.has_download_skip_cert_verify {
            options.download_skip_cert_verify
        } else {
            base.skip_cert_verify
        },
        fingerprint: if !options.download_fingerprint.trim().is_empty() {
            options.download_fingerprint.clone()
        } else {
            base.fingerprint.clone()
        },
        certificate: if !options.download_certificate.trim().is_empty() {
            options.download_certificate.clone()
        } else {
            base.certificate.clone()
        },
        private_key: if !options.download_private_key.trim().is_empty() {
            options.download_private_key.clone()
        } else {
            base.private_key.clone()
        },
    }
}

fn resolved_download_alpn(base: &[String], options: &XHttpOptions) -> Vec<String> {
    if options.download_alpn.is_empty() {
        if base.is_empty() {
            vec!["h2".to_owned()]
        } else {
            base.to_vec()
        }
    } else {
        options.download_alpn.clone()
    }
}

fn normalized_session_placement(options: &XHttpOptions) -> &str {
    let placement = options.session_placement.trim();
    if placement.is_empty() {
        "path"
    } else {
        placement
    }
}

fn normalized_seq_placement(options: &XHttpOptions) -> &str {
    let placement = options.seq_placement.trim();
    if placement.is_empty() {
        "path"
    } else {
        placement
    }
}

fn normalized_session_key(options: &XHttpOptions) -> String {
    let key = options.session_key.trim();
    if !key.is_empty() {
        return key.to_owned();
    }
    match normalized_session_placement(options) {
        "header" => "X-Session".to_owned(),
        "query" | "cookie" => "x_session".to_owned(),
        _ => String::new(),
    }
}

fn normalized_seq_key(options: &XHttpOptions) -> String {
    let key = options.seq_key.trim();
    if !key.is_empty() {
        return key.to_owned();
    }
    match normalized_seq_placement(options) {
        "header" => "X-Seq".to_owned(),
        "query" | "cookie" => "x_seq".to_owned(),
        _ => String::new(),
    }
}

fn normalized_uplink_data_placement(options: &XHttpOptions) -> &str {
    let placement = options.uplink_data_placement.trim();
    if placement.is_empty() || placement == "auto" {
        "body"
    } else {
        placement
    }
}

fn normalized_xpadding_method(options: &XHttpOptions) -> &str {
    let method = options.xpadding_method.trim();
    if method.is_empty() {
        "repeat-x"
    } else {
        method
    }
}

fn normalized_xpadding_bytes(options: &XHttpOptions) -> Result<(usize, usize), TransportError> {
    let value = options.xpadding_bytes.trim();
    let parsed = if value.is_empty() {
        (100, 1000)
    } else if let Some((min, max)) = value.split_once('-') {
        let min = min.trim().parse::<usize>().map_err(|_| TransportError::UnsupportedFeature {
            proxy: options.host.clone(),
            feature: format!("xhttp x-padding-bytes={value}"),
        })?;
        let max = max.trim().parse::<usize>().map_err(|_| TransportError::UnsupportedFeature {
            proxy: options.host.clone(),
            feature: format!("xhttp x-padding-bytes={value}"),
        })?;
        if max < min {
            return Err(TransportError::UnsupportedFeature {
                proxy: options.host.clone(),
                feature: format!("xhttp x-padding-bytes={value}"),
            });
        }
        (min, max)
    } else {
        let parsed = value.parse::<usize>().map_err(|_| TransportError::UnsupportedFeature {
            proxy: options.host.clone(),
            feature: format!("xhttp x-padding-bytes={value}"),
        })?;
        (parsed, parsed)
    };
    Ok(parsed)
}

fn apply_xpadding(
    authority: &str,
    path: &mut String,
    headers: &mut Vec<(String, String)>,
    options: &XHttpOptions,
) -> Result<(), TransportError> {
    let (min, max) = normalized_xpadding_bytes(options)?;
    let length = if min == max {
        min
    } else {
        rand::thread_rng().gen_range(min..=max)
    };
    let padding = generate_padding(normalized_xpadding_method(options), length);
    if options.xpadding_obfs_mode {
        let placement = options.xpadding_placement.trim();
        let placement = if placement.is_empty() { "queryInHeader" } else { placement };
        let key = if options.xpadding_key.trim().is_empty() {
            "x_padding"
        } else {
            options.xpadding_key.trim()
        };
        let header = if options.xpadding_header.trim().is_empty() {
            "referer".to_owned()
        } else {
            options.xpadding_header.trim().to_ascii_lowercase()
        };
        match placement {
            "header" => set_header(headers, &header, &padding),
            "queryInHeader" => {
                let mut padded = path.clone();
                set_query_param(&mut padded, key, &padding);
                set_header(headers, &header, &format!("https://{authority}{padded}"));
            }
            "query" => append_query_param(path, key, &padding),
            "cookie" => append_cookie(headers, key, &padding),
            _ => {}
        }
    } else {
        let mut padded = path.clone();
        append_query_param(&mut padded, "x_padding", &padding);
        set_header(headers, "Referer", &format!("https://{authority}{padded}"));
    }
    Ok(())
}

fn generate_padding(method: &str, length: usize) -> String {
    match method {
        "tokenish" => generate_tokenish_padding(length),
        _ => "X".repeat(length),
    }
}

fn generate_tokenish_padding(length: usize) -> String {
    if length == 0 {
        return String::new();
    }
    let mut out = String::with_capacity(length);
    let mut rng = rand::thread_rng();
    for _ in 0..length {
        let index = rng.gen_range(0..BASE62_CHARSET.len());
        out.push(BASE62_CHARSET[index] as char);
    }
    out
}

fn normalized_uplink_chunk_size(options: &XHttpOptions) -> Result<usize, TransportError> {
    let placement = normalized_uplink_data_placement(options);
    let default_max = match placement {
        "cookie" => 3 * 1024,
        "header" => 4 * 1024,
        _ => return Ok(0),
    };
    let value = options.uplink_chunk_size.trim();
    if value.is_empty() {
        return Ok(default_max);
    }
    let max = if let Some((_, max)) = value.split_once('-') {
        max.trim()
    } else {
        value
    };
    max.parse::<usize>()
        .map(|parsed| parsed.max(64))
        .map_err(|_| TransportError::UnsupportedFeature {
            proxy: options.host.clone(),
            feature: format!("xhttp uplink-chunk-size={value}"),
        })
}

fn normalized_sc_max_each_post_bytes(options: &XHttpOptions) -> Result<usize, TransportError> {
    let (min, max) = parse_positive_range_usize(&options.sc_max_each_post_bytes, (1_000_000, 1_000_000))?;
    if min == max {
        Ok(min)
    } else {
        Ok(rand::thread_rng().gen_range(min..=max))
    }
}

fn normalized_sc_min_posts_interval_ms(options: &XHttpOptions) -> Result<(u64, u64), TransportError> {
    parse_positive_range_u64(&options.sc_min_posts_interval_ms, (30, 30))
}

fn parse_positive_range_usize(value: &str, default: (usize, usize)) -> Result<(usize, usize), TransportError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(default);
    }
    if let Some((min, max)) = trimmed.split_once('-') {
        let min = min.trim().parse::<usize>().map_err(|_| TransportError::InvalidPlan(trimmed.to_owned()))?;
        let max = max.trim().parse::<usize>().map_err(|_| TransportError::InvalidPlan(trimmed.to_owned()))?;
        if min == 0 || max < min {
            return Err(TransportError::InvalidPlan(trimmed.to_owned()));
        }
        Ok((min, max))
    } else {
        let parsed = trimmed.parse::<usize>().map_err(|_| TransportError::InvalidPlan(trimmed.to_owned()))?;
        if parsed == 0 {
            return Err(TransportError::InvalidPlan(trimmed.to_owned()));
        }
        Ok((parsed, parsed))
    }
}

fn parse_positive_range_u64(value: &str, default: (u64, u64)) -> Result<(u64, u64), TransportError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(default);
    }
    if let Some((min, max)) = trimmed.split_once('-') {
        let min = min.trim().parse::<u64>().map_err(|_| TransportError::InvalidPlan(trimmed.to_owned()))?;
        let max = max.trim().parse::<u64>().map_err(|_| TransportError::InvalidPlan(trimmed.to_owned()))?;
        if min == 0 || max < min {
            return Err(TransportError::InvalidPlan(trimmed.to_owned()));
        }
        Ok((min, max))
    } else {
        let parsed = trimmed.parse::<u64>().map_err(|_| TransportError::InvalidPlan(trimmed.to_owned()))?;
        if parsed == 0 {
            return Err(TransportError::InvalidPlan(trimmed.to_owned()));
        }
        Ok((parsed, parsed))
    }
}

fn request_options_with_meta(
    authority: String,
    mut path: String,
    method: String,
    mut headers: Vec<(String, String)>,
    options: &XHttpOptions,
    session_id: Option<&str>,
    seq: Option<&str>,
) -> h2_stream::H2RequestOptions {
    let _ = apply_xpadding(&authority, &mut path, &mut headers, options);
    if let Some(session_id) = session_id {
        apply_meta(
            &mut path,
            &mut headers,
            normalized_session_placement(options),
            &normalized_session_key(options),
            session_id,
        );
    }
    if let Some(seq) = seq {
        apply_meta(
            &mut path,
            &mut headers,
            normalized_seq_placement(options),
            &normalized_seq_key(options),
            seq,
        );
    }
    h2_stream::H2RequestOptions {
        authority,
        path,
        method,
        headers,
    }
}

fn request_options_with_payload(
    authority: String,
    path: String,
    method: String,
    headers: Vec<(String, String)>,
    options: &XHttpOptions,
    session_id: &str,
    seq: &str,
    payload: &[u8],
) -> Result<(h2_stream::H2RequestOptions, bool), TransportError> {
    let mut request = request_options_with_meta(
        authority.clone(),
        path,
        method,
        headers,
        options,
        Some(session_id),
        Some(seq),
    );
    match normalized_uplink_data_placement(options) {
        "body" => Ok((request, true)),
        "header" => {
            let key = options.uplink_data_key.trim();
            let chunk_size = normalized_uplink_chunk_size(options)?;
            for (index, chunk) in payload_chunks(payload, chunk_size).into_iter().enumerate() {
                set_header(&mut request.headers, &format!("{key}-{index}"), &chunk);
            }
            Ok((request, false))
        }
        "cookie" => {
            let key = options.uplink_data_key.trim();
            let chunk_size = normalized_uplink_chunk_size(options)?;
            for (index, chunk) in payload_chunks(payload, chunk_size).into_iter().enumerate() {
                append_cookie(&mut request.headers, &format!("{key}_{index}"), &chunk);
            }
            Ok((request, false))
        }
        other => Err(TransportError::UnsupportedFeature {
            proxy: authority,
            feature: format!("xhttp uplink-data-placement={other}"),
        }),
    }
}

fn payload_chunks(payload: &[u8], chunk_size: usize) -> Vec<String> {
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload);
    if encoded.is_empty() {
        return Vec::new();
    }
    encoded
        .as_bytes()
        .chunks(chunk_size)
        .map(|chunk| String::from_utf8(chunk.to_vec()).expect("base64 payload should be utf-8"))
        .collect()
}

fn apply_meta(
    path: &mut String,
    headers: &mut Vec<(String, String)>,
    placement: &str,
    key: &str,
    value: &str,
) {
    match placement {
        "path" => {
            if !path.ends_with('/') {
                path.push('/');
            }
            path.push_str(value);
        }
        "query" => append_query_param(path, key, value),
        "header" => set_header(headers, key, value),
        "cookie" => append_cookie(headers, key, value),
        _ => {}
    }
}

fn append_query_param(path: &mut String, key: &str, value: &str) {
    if path.contains('?') {
        path.push('&');
    } else {
        path.push('?');
    }
    path.push_str(key);
    path.push('=');
    path.push_str(value);
}

fn set_query_param(path: &mut String, key: &str, value: &str) {
    if let Some((prefix, _)) = path.split_once('?') {
        *path = prefix.to_owned();
    }
    path.push('?');
    path.push_str(key);
    path.push('=');
    path.push_str(value);
}

fn set_header(headers: &mut Vec<(String, String)>, key: &str, value: &str) {
    if let Some((_, existing)) = headers
        .iter_mut()
        .find(|(name, _)| name.eq_ignore_ascii_case(key))
    {
        *existing = value.to_owned();
    } else {
        headers.push((key.to_owned(), value.to_owned()));
    }
}

fn append_cookie(headers: &mut Vec<(String, String)>, key: &str, value: &str) {
    if let Some((_, existing)) = headers
        .iter_mut()
        .find(|(name, _)| name.eq_ignore_ascii_case("cookie"))
    {
        if !existing.is_empty() {
            existing.push_str("; ");
        }
        existing.push_str(key);
        existing.push('=');
        existing.push_str(value);
    } else {
        headers.push(("cookie".to_owned(), format!("{key}={value}")));
    }
}

fn maybe_set_stream_content_type(headers: &mut Vec<(String, String)>, options: &XHttpOptions) {
    if !options.no_grpc_header {
        set_header(headers, "content-type", "application/grpc");
    }
}

fn wrap_tls_stream_up(
    first_stream: BoxedTcpStream,
    proxy: &TransportTarget,
    tls: &TlsOptions,
    alpn: &[String],
    authority: String,
    path: String,
    method: String,
    headers: Vec<(String, String)>,
    upload_target: TransportTarget,
    download_authority: String,
    download_path: String,
    download_headers: Vec<(String, String)>,
    download_target: TransportTarget,
    download_tls: TlsOptions,
    download_alpn: Vec<String>,
    meta_options: XHttpOptions,
) -> Result<BoxedTcpStream, TransportError> {
    let session_id = random_session_id();
    let mut initial_stream = Some(first_stream);
    let same_download_target = download_target == upload_target
        && download_tls == *tls
        && download_alpn.as_slice() == alpn;
    let download_request = request_options_with_meta(
        download_authority,
        download_path,
        "GET".to_owned(),
        download_headers,
        &meta_options,
        Some(&session_id),
        None,
    );
    let download_stream = if same_download_target {
        h2_wrap_stream_with_request(initial_stream.take().unwrap(), proxy, tls, alpn, download_request)?
    } else {
        let tcp = std::net::TcpStream::connect(download_target.authority()).map_err(TransportError::from)?;
        if download_tls.enabled {
            h2_stream::wrap_tls_stream_with_request(
                Box::new(tcp),
                &download_target,
                &download_tls,
                &download_alpn,
                download_request,
            )?
        } else {
            h2_stream::wrap_stream_with_request(Box::new(tcp), download_request)?
        }
    };

    let mut upload_headers = headers;
    maybe_set_stream_content_type(&mut upload_headers, &meta_options);
    let upload_request = request_options_with_meta(
        authority,
        path,
        method,
        upload_headers,
        &meta_options,
        Some(&session_id),
        None,
    );
    let upload_stream = if same_download_target {
        let upload_tcp = std::net::TcpStream::connect(proxy.authority()).map_err(TransportError::from)?;
        h2_wrap_stream_with_request(Box::new(upload_tcp), proxy, tls, alpn, upload_request)?
    } else {
        h2_wrap_stream_with_request(initial_stream.take().unwrap(), proxy, tls, alpn, upload_request)?
    };

    Ok(Box::new(SplitStream {
        reader: download_stream,
        writer: upload_stream,
    }))
}

fn random_session_id() -> String {
    let mut bytes = [0_u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(b"0123456789abcdef"[(byte >> 4) as usize]));
        out.push(char::from(b"0123456789abcdef"[(byte & 0x0f) as usize]));
    }
    out
}

struct SplitStream {
    reader: BoxedTcpStream,
    writer: BoxedTcpStream,
}

impl Read for SplitStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.reader.read(buf)
    }
}

fn wrap_tls_packet_up(
    first_stream: BoxedTcpStream,
    proxy: &TransportTarget,
    tls: &TlsOptions,
    alpn: &[String],
    authority: String,
    path: String,
    method: String,
    headers: Vec<(String, String)>,
    upload_target: TransportTarget,
    download_authority: String,
    download_path: String,
    download_headers: Vec<(String, String)>,
    download_target: TransportTarget,
    download_tls: TlsOptions,
    download_alpn: Vec<String>,
    meta_options: XHttpOptions,
) -> Result<BoxedTcpStream, TransportError> {
    let session_id = random_session_id();
    let mut initial_stream = Some(first_stream);
    let same_download_target = download_target == upload_target
        && download_tls == *tls
        && download_alpn.as_slice() == alpn;
    let download_request = request_options_with_meta(
        download_authority,
        download_path,
        "GET".to_owned(),
        download_headers,
        &meta_options,
        Some(&session_id),
        None,
    );
    let download_stream = if same_download_target {
        h2_wrap_stream_with_request(initial_stream.take().unwrap(), proxy, tls, alpn, download_request)?
    } else {
        let tcp = std::net::TcpStream::connect(download_target.authority()).map_err(TransportError::from)?;
        if download_tls.enabled {
            h2_stream::wrap_tls_stream_with_request(
                Box::new(tcp),
                &download_target,
                &download_tls,
                &download_alpn,
                download_request,
            )?
        } else {
            h2_stream::wrap_stream_with_request(Box::new(tcp), download_request)?
        }
    };

    let sc_max_each_post_bytes = normalized_sc_max_each_post_bytes(&meta_options)?;
    let sc_min_posts_interval_ms = normalized_sc_min_posts_interval_ms(&meta_options)?;

    Ok(Box::new(PacketUpStream {
        reader: download_stream,
        writer: PacketUpWriter {
            inner: Arc::new(PacketUpWriterInner {
                proxy: proxy.clone(),
                tls: tls.clone(),
                alpn: alpn.to_vec(),
                authority,
                path,
                method,
                headers,
                session_id,
                session_placement: meta_options.session_placement,
                session_key: meta_options.session_key,
                seq_placement: meta_options.seq_placement,
                seq_key: meta_options.seq_key,
                uplink_data_placement: meta_options.uplink_data_placement.clone(),
                uplink_data_key: meta_options.uplink_data_key.clone(),
                uplink_chunk_size: meta_options.uplink_chunk_size.clone(),
                sc_max_each_post_bytes,
                sc_min_posts_interval_ms,
                state: Mutex::new(PacketUpWriterState {
                    initial_stream: if same_download_target { None } else { initial_stream.take() },
                    next_seq: 0,
                    buffer: Vec::new(),
                    flush_error: None,
                    timer_armed: false,
                    timer_generation: 0,
                    closed: false,
                }),
            }),
        },
    }))
}

struct PacketUpStream {
    reader: BoxedTcpStream,
    writer: PacketUpWriter,
}

impl Read for PacketUpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.reader.read(buf)
    }
}

impl Write for PacketUpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.writer.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl TcpStream for PacketUpStream {
    fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "xhttp packet-up stream does not support cloning",
        ))
    }

    fn shutdown_write(&mut self) -> io::Result<()> {
        self.writer.close()
    }

    fn shutdown_all(&mut self) -> io::Result<()> {
        self.writer.close()?;
        self.reader.shutdown_all()
    }
}

struct PacketUpWriter {
    inner: Arc<PacketUpWriterInner>,
}

struct PacketUpWriterInner {
    proxy: TransportTarget,
    tls: TlsOptions,
    alpn: Vec<String>,
    authority: String,
    path: String,
    method: String,
    headers: Vec<(String, String)>,
    session_id: String,
    session_placement: String,
    session_key: String,
    seq_placement: String,
    seq_key: String,
    uplink_data_placement: String,
    uplink_data_key: String,
    uplink_chunk_size: String,
    sc_max_each_post_bytes: usize,
    sc_min_posts_interval_ms: (u64, u64),
    state: Mutex<PacketUpWriterState>,
}

struct PacketUpWriterState {
    initial_stream: Option<BoxedTcpStream>,
    next_seq: u64,
    buffer: Vec<u8>,
    flush_error: Option<String>,
    timer_armed: bool,
    timer_generation: u64,
    closed: bool,
}

struct FlushJob {
    seq: String,
    payload: Vec<u8>,
    base_stream: Option<BoxedTcpStream>,
}

impl PacketUpWriterInner {
    fn timer_delay(&self) -> Duration {
        let (min, max) = self.sc_min_posts_interval_ms;
        let millis = if min == max {
            min
        } else {
            rand::thread_rng().gen_range(min..=max)
        };
        Duration::from_millis(millis)
    }

    fn build_job_locked(state: &mut PacketUpWriterState) -> Option<FlushJob> {
        if state.buffer.is_empty() {
            return None;
        }
        let seq = state.next_seq.to_string();
        state.next_seq = state
            .next_seq
            .checked_add(1)
            .expect("xhttp seq should not overflow");
        Some(FlushJob {
            seq,
            payload: std::mem::take(&mut state.buffer),
            base_stream: state.initial_stream.take(),
        })
    }

    fn remember_error(&self, err: &io::Error) {
        let mut state = self.state.lock().unwrap();
        if state.flush_error.is_none() {
            state.flush_error = Some(err.to_string());
        }
    }

    fn send_job(&self, job: FlushJob) -> io::Result<usize> {
        let meta_options = XHttpOptions {
            session_placement: self.session_placement.clone(),
            session_key: self.session_key.clone(),
            seq_placement: self.seq_placement.clone(),
            seq_key: self.seq_key.clone(),
            uplink_data_placement: self.uplink_data_placement.clone(),
            uplink_data_key: self.uplink_data_key.clone(),
            uplink_chunk_size: self.uplink_chunk_size.clone(),
            ..Default::default()
        };
        let (request, write_body) = request_options_with_payload(
            self.authority.clone(),
            self.path.clone(),
            self.method.clone(),
            self.headers.clone(),
            &meta_options,
            &self.session_id,
            &job.seq,
            &job.payload,
        )
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
        let base_stream = if let Some(stream) = job.base_stream {
            stream
        } else {
            Box::new(std::net::TcpStream::connect(self.proxy.authority())?)
        };
        let mut upload_stream =
            h2_wrap_stream_with_request(base_stream, &self.proxy, &self.tls, &self.alpn, request)
                .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
        if write_body {
            upload_stream.write_all(&job.payload)?;
        }
        upload_stream.shutdown_write()?;
        let mut discard = Vec::new();
        upload_stream.read_to_end(&mut discard)?;
        Ok(job.payload.len())
    }

    fn spawn_timer(self: &Arc<Self>, generation: u64, delay: Duration) {
        let inner = Arc::clone(self);
        thread::spawn(move || {
            thread::sleep(delay);
            let job = {
                let mut state = inner.state.lock().unwrap();
                if state.closed || !state.timer_armed || state.timer_generation != generation {
                    return;
                }
                state.timer_armed = false;
                Self::build_job_locked(&mut state)
            };
            if let Some(job) = job {
                if let Err(err) = inner.send_job(job) {
                    inner.remember_error(&err);
                }
            }
        });
    }
}

impl PacketUpWriter {
    fn close(&self) -> io::Result<()> {
        let pending = {
            let mut state = self.inner.state.lock().unwrap();
            if let Some(err) = &state.flush_error {
                return Err(io::Error::new(io::ErrorKind::Other, err.clone()));
            }
            if state.closed {
                return Ok(());
            }
            state.closed = true;
            state.timer_armed = false;
            state.timer_generation = state.timer_generation.wrapping_add(1);
            PacketUpWriterInner::build_job_locked(&mut state)
        };
        if let Some(job) = pending {
            if let Err(err) = self.inner.send_job(job) {
                self.inner.remember_error(&err);
                return Err(err);
            }
        }
        Ok(())
    }
}

impl Write for PacketUpWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut offset = 0;
        while offset < buf.len() {
            let mut pending = None;
            {
                let mut state = self.inner.state.lock().unwrap();
                if state.closed {
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "xhttp packet-up writer is closed",
                    ));
                }
                if let Some(err) = &state.flush_error {
                    return Err(io::Error::new(io::ErrorKind::Other, err.clone()));
                }
                let capacity = self
                    .inner
                    .sc_max_each_post_bytes
                    .saturating_sub(state.buffer.len());
                let append = capacity.min(buf.len() - offset);
                state.buffer.extend_from_slice(&buf[offset..offset + append]);
                offset += append;
                if state.buffer.len() >= self.inner.sc_max_each_post_bytes {
                    state.timer_armed = false;
                    state.timer_generation = state.timer_generation.wrapping_add(1);
                    pending = PacketUpWriterInner::build_job_locked(&mut state);
                } else if !state.timer_armed {
                    state.timer_armed = true;
                    state.timer_generation = state.timer_generation.wrapping_add(1);
                    let generation = state.timer_generation;
                    self.inner.spawn_timer(generation, self.inner.timer_delay());
                }
            }
            if let Some(job) = pending {
                if let Err(err) = self.inner.send_job(job) {
                    self.inner.remember_error(&err);
                    return Err(err);
                }
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Write for SplitStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.writer.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

impl TcpStream for SplitStream {
    fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "xhttp split stream does not support cloning",
        ))
    }

    fn shutdown_write(&mut self) -> io::Result<()> {
        self.writer.shutdown_write()
    }

    fn shutdown_all(&mut self) -> io::Result<()> {
        self.writer.shutdown_write()?;
        self.reader.shutdown_all()
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use std::collections::BTreeMap;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream as StdTcpStream};
    use std::sync::Arc;
    use std::thread;

    use rcgen::generate_simple_self_signed;
    use rustls::{Certificate, PrivateKey, ServerConfig};

    use crate::h2_stream;
    use super::{
        effective_mode, payload_chunks, request_options_with_meta, request_options_with_payload,
        resolved_download_tls, validate_options, wrap_tls_packet_up, TlsOptions, XHttpOptions,
    };
    use crate::{TransportError, TransportTarget};

    fn test_proxy() -> TransportTarget {
        TransportTarget::new("xhttp.example.com", 443)
    }

    fn build_tls_server_config() -> Arc<ServerConfig> {
        let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_der = cert.cert.der().to_vec();
        let key_der = cert.key_pair.serialize_der();
        Arc::new(
            ServerConfig::builder()
                .with_safe_defaults()
                .with_no_client_auth()
                .with_single_cert(vec![Certificate(cert_der)], PrivateKey(key_der))
                .unwrap(),
        )
    }

    #[test]
    fn effective_mode_defaults_auto_to_packet_up() {
        assert_eq!(effective_mode(&XHttpOptions::default()), "packet-up");
        assert_eq!(
            effective_mode(&XHttpOptions {
                mode: "auto".into(),
                ..Default::default()
            }),
            "packet-up"
        );
        assert_eq!(
            effective_mode(&XHttpOptions {
                mode: "stream-up".into(),
                ..Default::default()
            }),
            "stream-up"
        );
    }

    #[test]
    fn validate_options_accepts_current_supported_subset() {
        validate_options(
            &test_proxy(),
            &XHttpOptions {
                mode: "packet-up".into(),
                session_placement: "path".into(),
                seq_placement: "path".into(),
                uplink_data_placement: "body".into(),
                ..Default::default()
            },
        )
        .unwrap();
        validate_options(
            &test_proxy(),
            &XHttpOptions {
                mode: "packet-up".into(),
                has_download_settings: true,
                download_host: "download.example.com".into(),
                download_path: "/download".into(),
                download_headers: BTreeMap::from([("X-Download".into(), "yes".into())]),
                ..Default::default()
            },
        )
        .unwrap();
        validate_options(
            &test_proxy(),
            &XHttpOptions {
                mode: "packet-up".into(),
                session_placement: "query".into(),
                session_key: "sid".into(),
                seq_placement: "header".into(),
                seq_key: "X-Seq-Custom".into(),
                uplink_data_placement: "header".into(),
                uplink_data_key: "x-data".into(),
                ..Default::default()
            },
        )
        .unwrap();
        validate_options(
            &test_proxy(),
            &XHttpOptions {
                mode: "packet-up".into(),
                uplink_data_placement: "auto".into(),
                ..Default::default()
            },
        )
        .unwrap();
        validate_options(
            &test_proxy(),
            &XHttpOptions {
                mode: "packet-up".into(),
                sc_max_each_post_bytes: "8".into(),
                sc_min_posts_interval_ms: "15-30".into(),
                ..Default::default()
            },
        )
        .unwrap();
        validate_options(
            &test_proxy(),
            &XHttpOptions {
                mode: "packet-up".into(),
                xpadding_bytes: "10-20".into(),
                ..Default::default()
            },
        )
        .unwrap();
        validate_options(
            &test_proxy(),
            &XHttpOptions {
                mode: "packet-up".into(),
                xpadding_obfs_mode: true,
                xpadding_placement: "queryInHeader".into(),
                xpadding_key: "pad".into(),
                xpadding_header: "Referer".into(),
                xpadding_method: "repeat-x".into(),
                ..Default::default()
            },
        )
        .unwrap();
        validate_options(
            &test_proxy(),
            &XHttpOptions {
                mode: "packet-up".into(),
                xpadding_obfs_mode: true,
                xpadding_placement: "queryInHeader".into(),
                xpadding_key: "pad".into(),
                xpadding_header: "Referer".into(),
                xpadding_method: "tokenish".into(),
                ..Default::default()
            },
        )
        .unwrap();
        validate_options(
            &test_proxy(),
            &XHttpOptions {
                mode: "packet-up".into(),
                has_reuse_settings: true,
                ..Default::default()
            },
        )
        .unwrap();
        validate_options(
            &test_proxy(),
            &XHttpOptions {
                mode: "packet-up".into(),
                has_download_settings: true,
                has_download_reuse_settings: true,
                ..Default::default()
            },
        )
        .unwrap();
    }

    #[test]
    fn validate_options_rejects_unsupported_subfeatures() {
        for (feature, options) in [
            (
                "xhttp download-settings with mode=stream-one",
                XHttpOptions {
                    has_download_settings: true,
                    mode: "stream-one".into(),
                    ..Default::default()
                },
            ),
            (
                "xhttp download-settings transport overrides",
                XHttpOptions {
                    has_download_settings: true,
                    has_download_transport_overrides: true,
                    mode: "packet-up".into(),
                    ..Default::default()
                },
            ),
            (
                "xhttp x-padding-method=unsupported",
                XHttpOptions {
                    xpadding_obfs_mode: true,
                    xpadding_method: "unsupported".into(),
                    xpadding_placement: "queryInHeader".into(),
                    ..Default::default()
                },
            ),
            (
                "xhttp x-padding-placement=body",
                XHttpOptions {
                    xpadding_obfs_mode: true,
                    xpadding_placement: "body".into(),
                    ..Default::default()
                },
            ),
        ] {
            match validate_options(&test_proxy(), &options).unwrap_err() {
                TransportError::UnsupportedFeature {
                    proxy: _,
                    feature: actual,
                } => assert_eq!(actual, feature),
                other => panic!("expected unsupported feature, got {other:?}"),
            }
        }
    }

    #[test]
    fn resolved_download_tls_overrides_download_fingerprint() {
        let base = TlsOptions {
            enabled: true,
            sni: "upload.local".into(),
            skip_cert_verify: false,
            fingerprint: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            certificate: String::new(),
            private_key: String::new(),
        };
        let target = TransportTarget::new("download.example.com", 443);
        let resolved = resolved_download_tls(
            &base,
            &target,
            &XHttpOptions {
                download_fingerprint:
                    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
                ..Default::default()
            },
        );
        assert_eq!(
            resolved.fingerprint,
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        );
    }

    #[test]
    fn request_options_with_meta_supports_query_placement() {
        let request = request_options_with_meta(
            "upload.local".into(),
            "/xhttp/".into(),
            "POST".into(),
            Vec::new(),
            &XHttpOptions {
                session_placement: "query".into(),
                session_key: "sid".into(),
                seq_placement: "query".into(),
                seq_key: "n".into(),
                ..Default::default()
            },
            Some("abc123"),
            Some("7"),
        );
        assert_eq!(request.path, "/xhttp/?sid=abc123&n=7");
    }

    #[test]
    fn request_options_with_meta_supports_header_and_cookie_placements() {
        let request = request_options_with_meta(
            "upload.local".into(),
            "/xhttp/".into(),
            "POST".into(),
            Vec::new(),
            &XHttpOptions {
                session_placement: "header".into(),
                session_key: "X-Session-Custom".into(),
                seq_placement: "cookie".into(),
                seq_key: "seq_cookie".into(),
                ..Default::default()
            },
            Some("abc123"),
            Some("7"),
        );
        assert_eq!(request.path, "/xhttp/");
        assert_eq!(
            request
                .headers
                .iter()
                .find(|(name, _)| name == "X-Session-Custom")
                .map(|(_, value)| value.as_str()),
            Some("abc123")
        );
        assert_eq!(
            request
                .headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("cookie"))
                .map(|(_, value)| value.as_str()),
            Some("seq_cookie=7")
        );
    }

    #[test]
    fn request_options_with_payload_supports_header_placement() {
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"ping");
        let (request, write_body) = request_options_with_payload(
            "upload.local".into(),
            "/xhttp/".into(),
            "POST".into(),
            Vec::new(),
            &XHttpOptions {
                uplink_data_placement: "header".into(),
                uplink_data_key: "x-data".into(),
                ..Default::default()
            },
            "abc123",
            "7",
            b"ping",
        )
        .unwrap();
        assert!(!write_body);
        assert_eq!(
            request
                .headers
                .iter()
                .find(|(name, _)| name == "x-data-0")
                .map(|(_, value)| value.as_str()),
            Some(encoded.as_str())
        );
    }

    #[test]
    fn request_options_with_payload_supports_empty_header_key() {
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"ping");
        let (request, write_body) = request_options_with_payload(
            "upload.local".into(),
            "/xhttp/".into(),
            "POST".into(),
            Vec::new(),
            &XHttpOptions {
                uplink_data_placement: "header".into(),
                ..Default::default()
            },
            "abc123",
            "7",
            b"ping",
        )
        .unwrap();
        assert!(!write_body);
        assert_eq!(
            request
                .headers
                .iter()
                .find(|(name, _)| name == "-0")
                .map(|(_, value)| value.as_str()),
            Some(encoded.as_str())
        );
    }

    #[test]
    fn request_options_with_payload_supports_cookie_placement() {
        let (request, write_body) = request_options_with_payload(
            "upload.local".into(),
            "/xhttp/".into(),
            "POST".into(),
            Vec::new(),
            &XHttpOptions {
                uplink_data_placement: "cookie".into(),
                uplink_data_key: "x_data".into(),
                ..Default::default()
            },
            "abc123",
            "7",
            b"ping",
        )
        .unwrap();
        assert!(!write_body);
        assert_eq!(
            request
                .headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("cookie"))
                .map(|(_, value)| value.as_str()),
            Some("x_data_0=cGluZw")
        );
    }

    #[test]
    fn request_options_with_payload_supports_empty_cookie_key() {
        let (request, write_body) = request_options_with_payload(
            "upload.local".into(),
            "/xhttp/".into(),
            "POST".into(),
            Vec::new(),
            &XHttpOptions {
                uplink_data_placement: "cookie".into(),
                ..Default::default()
            },
            "abc123",
            "7",
            b"ping",
        )
        .unwrap();
        assert!(!write_body);
        assert_eq!(
            request
                .headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("cookie"))
                .map(|(_, value)| value.as_str()),
            Some("_0=cGluZw")
        );
    }

    #[test]
    fn request_options_with_payload_treats_auto_as_body() {
        let (request, write_body) = request_options_with_payload(
            "upload.local".into(),
            "/xhttp/".into(),
            "POST".into(),
            Vec::new(),
            &XHttpOptions {
                uplink_data_placement: "auto".into(),
                ..Default::default()
            },
            "abc123",
            "7",
            b"ping",
        )
        .unwrap();
        assert!(write_body);
        assert!(request
            .headers
            .iter()
            .all(|(name, _)| !name.starts_with("x-data-") && !name.eq_ignore_ascii_case("cookie")));
    }

    #[test]
    fn request_options_with_meta_applies_default_xpadding_referer() {
        let request = request_options_with_meta(
            "upload.local".into(),
            "/xhttp/".into(),
            "POST".into(),
            Vec::new(),
            &XHttpOptions {
                xpadding_bytes: "8".into(),
                ..Default::default()
            },
            Some("abc123"),
            None,
        );
        let referer = request
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("referer"))
            .map(|(_, value)| value.as_str())
            .unwrap();
        assert!(referer.starts_with("https://upload.local/xhttp/?x_padding="));
        assert_eq!(request.path, "/xhttp/abc123");
    }

    #[test]
    fn request_options_with_meta_applies_obfs_query_in_header_padding() {
        let request = request_options_with_meta(
            "upload.local".into(),
            "/xhttp/".into(),
            "POST".into(),
            Vec::new(),
            &XHttpOptions {
                xpadding_bytes: "8".into(),
                xpadding_obfs_mode: true,
                xpadding_placement: "queryInHeader".into(),
                xpadding_key: "pad".into(),
                xpadding_header: "X-Pad".into(),
                ..Default::default()
            },
            None,
            None,
        );
        let pad = request
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("x-pad"))
            .map(|(_, value)| value.as_str())
            .unwrap();
        assert!(pad.starts_with("https://upload.local/xhttp/?pad="));
    }

    #[test]
    fn request_options_with_meta_query_in_header_overwrites_existing_query() {
        let request = request_options_with_meta(
            "upload.local".into(),
            "/xhttp/?foo=bar".into(),
            "POST".into(),
            Vec::new(),
            &XHttpOptions {
                xpadding_bytes: "8".into(),
                xpadding_obfs_mode: true,
                xpadding_placement: "queryInHeader".into(),
                xpadding_key: "pad".into(),
                xpadding_header: "X-Pad".into(),
                ..Default::default()
            },
            None,
            None,
        );
        let pad = request
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("x-pad"))
            .map(|(_, value)| value.as_str())
            .unwrap();
        assert!(pad.starts_with("https://upload.local/xhttp/?pad="));
        assert!(!pad.contains("foo=bar"));
    }

    #[test]
    fn request_options_with_meta_applies_tokenish_header_padding() {
        let request = request_options_with_meta(
            "upload.local".into(),
            "/xhttp/".into(),
            "POST".into(),
            Vec::new(),
            &XHttpOptions {
                xpadding_bytes: "12".into(),
                xpadding_obfs_mode: true,
                xpadding_placement: "header".into(),
                xpadding_header: "X-Pad".into(),
                xpadding_method: "tokenish".into(),
                ..Default::default()
            },
            None,
            None,
        );
        let pad = request
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("x-pad"))
            .map(|(_, value)| value.as_str())
            .unwrap();
        assert_eq!(pad.len(), 12);
        assert!(pad.chars().all(|ch| ch.is_ascii_alphanumeric()));
    }

    #[test]
    fn payload_chunks_split_encoded_data_by_chunk_size() {
        let chunks = payload_chunks(b"abcdefgh", 4);
        assert_eq!(
            chunks.concat(),
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"abcdefgh")
        );
        assert!(chunks.iter().all(|chunk| chunk.len() <= 4));
    }

    #[test]
    fn packet_up_writer_respects_sc_max_each_post_bytes() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let worker = thread::spawn(move || {
            let (download_stream, _) = listener.accept().unwrap();
            let (download_request, mut download_stream) =
                h2_stream::accept_tls_server_stream(Box::new(download_stream), tls_config.clone()).unwrap();
            assert_eq!(download_request.method, "GET");
            assert!(download_request.path.starts_with("/xhttp/"));

            let mut payloads = Vec::new();
            for index in 0..3 {
                let (upload_stream, _) = listener.accept().unwrap();
                let (upload_request, mut upload_stream) =
                    h2_stream::accept_tls_server_stream(Box::new(upload_stream), tls_config.clone()).unwrap();
                assert_eq!(upload_request.method, "POST");
                assert_eq!(upload_request.path, format!("{}/{}", download_request.path, index));
                let mut body = Vec::new();
                upload_stream.read_to_end(&mut body).unwrap();
                upload_stream.shutdown_all().unwrap();
                payloads.push(body);
            }

            download_stream.write_all(b"ok").unwrap();
            download_stream.shutdown_write().unwrap();
            payloads
        });

        let stream = Box::new(StdTcpStream::connect(listen_addr).unwrap());
        let proxy = TransportTarget::new("127.0.0.1", listen_addr.port());
        let tls = TlsOptions {
            enabled: true,
            sni: "localhost".into(),
            skip_cert_verify: true,
            fingerprint: String::new(),
            certificate: String::new(),
            private_key: String::new(),
        };
        let mut stream = wrap_tls_packet_up(
            stream,
            &proxy,
            &tls,
            &["h2".to_owned()],
            "localhost".into(),
            "/xhttp/".into(),
            "POST".into(),
            Vec::new(),
            proxy.clone(),
            "localhost".into(),
            "/xhttp/".into(),
            Vec::new(),
            proxy.clone(),
            tls.clone(),
            vec!["h2".to_owned()],
            XHttpOptions {
                mode: "packet-up".into(),
                sc_max_each_post_bytes: "3".into(),
                sc_min_posts_interval_ms: "1000".into(),
                ..Default::default()
            },
        )
        .unwrap();
        stream.write_all(b"abcdefg").unwrap();
        stream.shutdown_write().unwrap();
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"ok");

        let payloads = worker.join().unwrap();
        assert_eq!(payloads, vec![b"abc".to_vec(), b"def".to_vec(), b"g".to_vec()]);
    }
}
