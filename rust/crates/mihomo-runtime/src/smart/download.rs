use super::*;
use crate::RuntimeTunnel;
use mihomo_core::Metadata;
use mihomo_transport::{TlsOptions, TransportTarget};
use std::io::{self, Read, Write};

/// Fetch on the configured routing path and follow the release server redirects.
pub(crate) fn fetch_model(tunnel: &RuntimeTunnel, raw: &str) -> io::Result<Vec<u8>> {
    let mut url = url::Url::parse(raw).map_err(io::Error::other)?;
    for _ in 0..6 {
        if !matches!(url.scheme(), "http" | "https") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "model URL must use HTTP or HTTPS",
            ));
        }
        let host = url
            .host_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing model URL host"))?
            .to_owned();
        let port = url.port_or_known_default().unwrap();
        let metadata = Metadata {
            host: Some(host.clone()),
            dst_port: Some(port),
            ..Default::default()
        };
        let (mut stream, _) = tunnel
            .connect_tcp_with_system_dialer_with_timeout(&metadata, Some(15000))
            .map_err(io::Error::other)?;
        if url.scheme() == "https" {
            stream = mihomo_transport::wrap_tls_proxy_stream(
                stream,
                TransportTarget::new(host.clone(), port),
                &TlsOptions {
                    enabled: true,
                    sni: host.clone(),
                    skip_cert_verify: false,
                    fingerprint: String::new(),
                    certificate: String::new(),
                    private_key: String::new(),
                },
                &[],
            )
            .map_err(io::Error::other)?;
        }
        let mut target = url.path().to_owned();
        if target.is_empty() {
            target.push('/');
        }
        if let Some(query) = url.query() {
            target.push('?');
            target.push_str(query);
        }
        let authority =
            if (url.scheme() == "https" && port == 443) || (url.scheme() == "http" && port == 80) {
                host
            } else {
                format!("{host}:{port}")
            };
        write!(stream,"GET {target} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: mihomo-rust-smart\r\nAccept: */*\r\nConnection: close\r\n\r\n")?;
        stream.flush()?;
        let mut raw_head = Vec::new();
        let mut byte = [0u8; 1];
        while !raw_head.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte)?;
            raw_head.push(byte[0]);
            if raw_head.len() > 65536 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "model response headers too large",
                ));
            }
        }
        let head = String::from_utf8_lossy(&raw_head);
        let mut lines = head.lines();
        let status = lines
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|v| v.parse::<u16>().ok())
            .unwrap_or(0);
        let headers = lines
            .filter_map(|line| line.split_once(':'))
            .map(|(k, v)| (k.to_ascii_lowercase(), v.trim().to_owned()))
            .collect::<BTreeMap<_, _>>();
        if matches!(status, 301 | 302 | 303 | 307 | 308) {
            let location = headers.get("location").ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "model redirect has no Location")
            })?;
            url = url.join(location).map_err(io::Error::other)?;
            continue;
        }
        if status != 200 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("model download returned HTTP {status}"),
            ));
        }
        let limit = 64 * 1024 * 1024usize;
        let mut body = Vec::new();
        if headers
            .get("transfer-encoding")
            .is_some_and(|v| v.eq_ignore_ascii_case("chunked"))
        {
            loop {
                let mut line = Vec::new();
                while !line.ends_with(b"\r\n") {
                    stream.read_exact(&mut byte)?;
                    line.push(byte[0]);
                    if line.len() > 1024 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "model chunk header too large",
                        ));
                    }
                }
                let text = std::str::from_utf8(&line).map_err(io::Error::other)?;
                let size = usize::from_str_radix(text.trim().split(';').next().unwrap(), 16)
                    .map_err(io::Error::other)?;
                if size == 0 {
                    break;
                }
                if size > limit.saturating_sub(body.len()) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "model exceeds 64 MiB",
                    ));
                }
                let start = body.len();
                body.resize(start + size, 0);
                stream.read_exact(&mut body[start..])?;
                let mut end = [0; 2];
                stream.read_exact(&mut end)?;
                if end != *b"\r\n" {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid model chunk terminator",
                    ));
                }
            }
        } else if let Some(size) = headers.get("content-length") {
            let size = size.parse::<usize>().map_err(io::Error::other)?;
            if size > limit {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "model exceeds 64 MiB",
                ));
            }
            body.resize(size, 0);
            stream.read_exact(&mut body)?;
        } else {
            stream.take(limit as u64 + 1).read_to_end(&mut body)?;
            if body.len() > limit {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "model exceeds 64 MiB",
                ));
            }
        }
        return Ok(body);
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "too many model redirects",
    ))
}
