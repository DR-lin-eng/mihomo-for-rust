use std::collections::BTreeMap;
use std::io;
use std::net::TcpStream as NetTcpStream;
use std::sync::Arc;
use std::time::Instant;
use std::time::{SystemTime, UNIX_EPOCH};

use mihomo_core::Metadata;
use mihomo_transport::TransportTarget;
use url::Url;

use crate::{CandidateState, RuntimeTunnel};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HealthCheckResult {
    pub name: String,
    pub alive: bool,
    pub delay_ms: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HealthCheckError {
    InvalidUrl(String),
    InvalidExpectedStatus(String),
    ProxyNotFound(String),
    Request(io::ErrorKind, String),
}

impl std::fmt::Display for HealthCheckError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidUrl(url) => write!(f, "invalid health-check url: {url}"),
            Self::InvalidExpectedStatus(value) => {
                write!(f, "invalid expected status: {value}")
            }
            Self::ProxyNotFound(name) => write!(f, "proxy not found: {name}"),
            Self::Request(_, message) => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for HealthCheckError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProxyHealthSnapshot {
    pub alive: bool,
    pub history: Vec<DelayHistorySnapshot>,
    pub extra: BTreeMap<String, ProxyUrlHealthSnapshot>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProxyUrlHealthSnapshot {
    pub alive: bool,
    pub history: Vec<DelayHistorySnapshot>,
    pub last_error: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DelayHistorySnapshot {
    pub time_unix_ms: u64,
    pub delay_ms: u16,
}

#[derive(Clone, Debug)]
pub(crate) struct ProxyHealthState {
    pub(crate) alive: bool,
    pub(crate) history: Vec<DelayHistorySnapshot>,
    pub(crate) extra: BTreeMap<String, ProxyUrlHealthSnapshot>,
}

pub fn run_proxy_health_check(
    tunnel: &RuntimeTunnel,
    proxy_name: &str,
    url: &str,
    expected_status: &str,
) -> Result<HealthCheckResult, HealthCheckError> {
    run_proxy_health_check_with_timeout(tunnel, proxy_name, url, expected_status, None)
}

pub fn run_proxy_health_check_with_timeout(
    tunnel: &RuntimeTunnel,
    proxy_name: &str,
    url: &str,
    expected_status: &str,
    timeout_ms: Option<u64>,
) -> Result<HealthCheckResult, HealthCheckError> {
    let registry = tunnel.registry_snapshot();
    if !registry.proxies.contains_key(proxy_name) {
        return Err(HealthCheckError::ProxyNotFound(proxy_name.to_owned()));
    }

    let parsed = Url::parse(url).map_err(|_| HealthCheckError::InvalidUrl(url.to_owned()))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| HealthCheckError::InvalidUrl(url.to_owned()))?;
    let scheme = parsed.scheme();
    let port = parsed
        .port_or_known_default()
        .unwrap_or_else(|| if scheme == "https" { 443 } else { 80 });
    let path = {
        let mut path = parsed.path().to_owned();
        if let Some(query) = parsed.query() {
            path.push('?');
            path.push_str(query);
        }
        if path.is_empty() {
            "/".to_owned()
        } else {
            path
        }
    };

    let metadata = Metadata {
        host: Some(host.to_owned()),
        dst_port: Some(port),
        special_proxy: proxy_name.to_owned(),
        ..Metadata::default()
    };

    let start = Instant::now();
    let (mut upstream, _) = tunnel
        .connect_tcp_with_system_dialer_with_timeout(&metadata, timeout_ms)
        .map_err(|err| {
            mark_proxy_unhealthy(tunnel, proxy_name, url, &err.to_string());
            HealthCheckError::Request(io::ErrorKind::Other, err.to_string())
        })?;
    apply_stream_timeout(&mut *upstream, timeout_ms);
    if scheme == "https" {
        let tls = mihomo_transport::TlsOptions {
            enabled: true,
            sni: host.to_owned(),
            skip_cert_verify: false,
            fingerprint: String::new(),
            certificate: String::new(),
            private_key: String::new(),
        };
        let target = TransportTarget::new(host.to_owned(), port);
        upstream = mihomo_transport::wrap_tls_proxy_stream(upstream, target, &tls, &[])
            .map_err(|err| {
                mark_proxy_unhealthy(tunnel, proxy_name, url, &err.to_string());
                HealthCheckError::Request(io::ErrorKind::Other, err.to_string())
            })?;
        apply_stream_timeout(&mut *upstream, timeout_ms);
    }

    let request = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    upstream
        .write_all(request.as_bytes())
        .and_then(|_| upstream.flush())
        .map_err(|err| {
            mark_proxy_unhealthy(tunnel, proxy_name, url, &err.to_string());
            HealthCheckError::Request(err.kind(), err.to_string())
        })?;

    let (headers, _) = read_http_response_head(&mut *upstream)
        .map_err(|err| {
            mark_proxy_unhealthy(tunnel, proxy_name, url, &err.to_string());
            HealthCheckError::Request(err.kind(), err.to_string())
        })?;
    let status = parse_http_status_code(&headers)
        .ok_or_else(|| {
            mark_proxy_unhealthy(tunnel, proxy_name, url, "invalid http status");
            HealthCheckError::Request(io::ErrorKind::InvalidData, "invalid http status".into())
        })?;
    let expected = parse_expected_status(expected_status)?;
    if !expected.contains(&status) {
        let err = HealthCheckError::Request(
            io::ErrorKind::InvalidData,
            format!("unexpected http status: {status}"),
        );
        mark_proxy_unhealthy(tunnel, proxy_name, url, &err.to_string());
        return Err(err);
    }

    let delay_ms = start.elapsed().as_millis().min(u128::from(u16::MAX)) as u16;
    let result = HealthCheckResult {
        name: proxy_name.to_owned(),
        alive: true,
        delay_ms,
    };
    tunnel.set_candidate_state(CandidateState {
        name: proxy_name.to_owned(),
        alive: true,
        last_delay_ms: delay_ms,
        supports_udp: tunnel
            .registry_snapshot()
            .proxy_definitions
            .get(proxy_name)
            .map(crate::outbound_supports_udp)
            .unwrap_or(true),
    });
    tunnel.record_proxy_health(proxy_name, url, true, delay_ms, "");
    Ok(result)
}

pub fn run_provider_healthcheck_with_timeout(
    tunnel: Arc<RuntimeTunnel>,
    proxy_names: &[String],
    url: &str,
    expected_status: &str,
    timeout_ms: Option<u64>,
) {
    let max_parallel = 10usize;
    let mut active = Vec::new();
    for proxy_name in proxy_names {
        let proxy_name = proxy_name.clone();
        let url = url.to_owned();
        let expected_status = expected_status.to_owned();
        let tunnel = Arc::clone(&tunnel);
        active.push(std::thread::spawn(move || {
            let _ = run_proxy_health_check_with_timeout(
                tunnel.as_ref(),
                &proxy_name,
                &url,
                &expected_status,
                timeout_ms,
            );
        }));
        if active.len() >= max_parallel {
            for handle in active.drain(..) {
                let _ = handle.join();
            }
        }
    }
    for handle in active {
        let _ = handle.join();
    }
}

fn parse_expected_status(value: &str) -> Result<Vec<u16>, HealthCheckError> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed == "*" {
        return Ok((200..=299).collect());
    }

    let mut statuses = Vec::new();
    for part in trimmed.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((start, end)) = part.split_once('-') {
            let start = start
                .trim()
                .parse::<u16>()
                .map_err(|_| HealthCheckError::InvalidExpectedStatus(value.to_owned()))?;
            let end = end
                .trim()
                .parse::<u16>()
                .map_err(|_| HealthCheckError::InvalidExpectedStatus(value.to_owned()))?;
            if start > end {
                return Err(HealthCheckError::InvalidExpectedStatus(value.to_owned()));
            }
            statuses.extend(start..=end);
        } else {
            statuses.push(
                part.parse::<u16>()
                    .map_err(|_| HealthCheckError::InvalidExpectedStatus(value.to_owned()))?,
            );
        }
    }
    if statuses.is_empty() {
        return Err(HealthCheckError::InvalidExpectedStatus(value.to_owned()));
    }
    Ok(statuses)
}

fn read_http_response_head(stream: &mut dyn io::Read) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let mut response = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "http response ended before headers were complete",
            ));
        }
        response.extend_from_slice(&chunk[..read]);
        if let Some(split) = response
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
        {
            let header_end = split + 4;
            return Ok((
                response[..header_end].to_vec(),
                response[header_end..].to_vec(),
            ));
        }
    }
}

fn parse_http_status_code(headers: &[u8]) -> Option<u16> {
    let line = std::str::from_utf8(headers).ok()?.lines().next()?;
    line.split_whitespace().nth(1)?.parse::<u16>().ok()
}

pub(crate) fn record_health_state(
    states: &mut BTreeMap<String, ProxyHealthState>,
    name: &str,
    url: &str,
    alive: bool,
    delay_ms: u16,
    last_error: &str,
) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let record = DelayHistorySnapshot {
        time_unix_ms: now,
        delay_ms,
    };
    let state = states.entry(name.to_owned()).or_insert_with(|| ProxyHealthState {
        alive,
        history: Vec::new(),
        extra: BTreeMap::new(),
    });
    state.alive = alive;
    push_history(&mut state.history, record.clone());
    let url_state = state
        .extra
        .entry(url.to_owned())
        .or_insert_with(|| ProxyUrlHealthSnapshot {
            alive,
            history: Vec::new(),
            last_error: String::new(),
        });
    url_state.alive = alive;
    url_state.last_error = last_error.to_owned();
    push_history(&mut url_state.history, record);
}

fn push_history(history: &mut Vec<DelayHistorySnapshot>, record: DelayHistorySnapshot) {
    history.push(record);
    const MAX: usize = 10;
    if history.len() > MAX {
        let overflow = history.len() - MAX;
        history.drain(0..overflow);
    }
}

fn mark_proxy_unhealthy(tunnel: &RuntimeTunnel, proxy_name: &str, url: &str, last_error: &str) {
    tunnel.set_candidate_state(CandidateState {
        name: proxy_name.to_owned(),
        alive: false,
        last_delay_ms: u16::MAX,
        supports_udp: tunnel
            .registry_snapshot()
            .proxy_definitions
            .get(proxy_name)
            .map(crate::outbound_supports_udp)
            .unwrap_or(true),
    });
    tunnel.record_proxy_health(proxy_name, url, false, 0, last_error);
}

fn apply_stream_timeout(stream: &mut dyn mihomo_core::TcpStream, timeout_ms: Option<u64>) {
    let Some(timeout_ms) = timeout_ms.filter(|value| *value > 0) else {
        return;
    };
    let timeout = std::time::Duration::from_millis(timeout_ms.max(1));
    let any = stream as &mut dyn std::any::Any;
    if let Some(net) = any.downcast_mut::<NetTcpStream>() {
        let _ = net.set_read_timeout(Some(timeout));
        let _ = net.set_write_timeout(Some(timeout));
        return;
    }
    if let Some(boxed) = any.downcast_mut::<mihomo_core::BoxedTcpStream>() {
        apply_stream_timeout(boxed.as_mut(), Some(timeout_ms));
    }
}
