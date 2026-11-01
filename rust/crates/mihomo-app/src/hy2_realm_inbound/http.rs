#[derive(Default, serde::Deserialize)]
struct AddressesBody {
    addresses: Vec<String>,
}

#[derive(Default, serde::Deserialize)]
struct HeartbeatBody {
    addresses: Option<Vec<String>>,
}

#[derive(Default, serde::Deserialize)]
struct ConnectBody {
    addresses: Vec<String>,
    nonce: String,
    obfs: String,
}

#[derive(Default)]
struct SimpleHttpRequest {
    method: String,
    target: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

struct SimpleHttpResponse {
    status_code: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

fn parse_http_request(stream: &mut dyn Read) -> io::Result<SimpleHttpRequest> {
    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line)? == 0 {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "empty request"));
    }
    let request_line = request_line.trim_end_matches(['\r', '\n']);
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing method"))?
        .to_owned();
    let target = parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing target"))?
        .to_owned();
    let version = parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing version"))?;
    if !version.starts_with("HTTP/1.") {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "unsupported version"));
    }

    let mut headers = BTreeMap::new();
    loop {
        let mut line = String::new();
        let bytes = reader.read_line(&mut line)?;
        if bytes == 0 {
            break;
        }
        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            break;
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid header line"))?;
        headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
    }
    let content_length = headers
        .get("content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or_default()
        .min(MAX_REQUEST_BODY_BYTES);
    let mut body = vec![0; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body)?;
    }

    Ok(SimpleHttpRequest {
        method,
        target,
        headers,
        body,
    })
}

fn write_http_response(stream: &mut dyn Write, response: SimpleHttpResponse) -> io::Result<()> {
    let reason = match response.status_code {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "OK",
    };
    write!(stream, "HTTP/1.1 {} {}\r\n", response.status_code, reason)?;
    for (name, value) in response.headers {
        write!(stream, "{name}: {value}\r\n")?;
    }
    write!(stream, "Content-Length: {}\r\nConnection: close\r\n\r\n", response.body.len())?;
    stream.write_all(&response.body)?;
    stream.flush()
}

fn split_target(target: &str) -> (&str, &str) {
    target
        .split_once('?')
        .map(|(path, query)| (path, query))
        .unwrap_or((target, ""))
}

fn json_error(code: &str, message: &str) -> String {
    serde_json::json!({
        "error": code,
        "message": message,
    })
    .to_string()
}

fn json_response<T: Serialize>(status_code: u16, value: &T) -> SimpleHttpResponse {
    SimpleHttpResponse {
        status_code,
        headers: vec![("Content-Type".to_owned(), "application/json".to_owned())],
        body: serde_json::to_vec(value).unwrap_or_else(|_| b"{}".to_vec()),
    }
}

fn http_response(status_code: u16, body: &str) -> SimpleHttpResponse {
    let headers = if body.trim_start().starts_with('{') {
        vec![("Content-Type".to_owned(), "application/json".to_owned())]
    } else {
        Vec::new()
    };
    SimpleHttpResponse {
        status_code,
        headers,
        body: body.as_bytes().to_vec(),
    }
}

fn bearer_token(request: &SimpleHttpRequest) -> String {
    request
        .headers
        .get("authorization")
        .and_then(|value| value.strip_prefix("Bearer "))
        .unwrap_or_default()
        .to_owned()
}

fn peer_ip_from_request(request: &SimpleHttpRequest, proxy_header: &str) -> String {
    if !proxy_header.trim().is_empty() {
        if let Some(value) = request.headers.get(&proxy_header.to_ascii_lowercase()) {
            let value = value.split(',').next().unwrap_or_default().trim();
            if !value.is_empty() {
                return value.to_owned();
            }
        }
    }
    "127.0.0.1".to_owned()
}

fn validate_addresses(addresses: &[String]) -> Result<(), String> {
    if addresses.is_empty() {
        return Err("at least one address required".to_owned());
    }
    if addresses.len() > MAX_ADDRESSES {
        return Err(format!("too many addresses (max {MAX_ADDRESSES})"));
    }
    for address in addresses {
        address
            .parse::<SocketAddr>()
            .map_err(|_| format!("invalid address: {address}"))?;
    }
    Ok(())
}

fn validate_hex_field(name: &str, value: &str, length: usize) -> Result<(), String> {
    if value.len() != length {
        return Err(format!("{name} must be {length} hex characters"));
    }
    hex::decode(value).map_err(|_| format!("{name} must be valid hex"))?;
    Ok(())
}

fn hex_token() -> String {
    let mut bytes = [0_u8; 16];
    getrandom::getrandom(&mut bytes).ok();
    hex::encode(bytes)
}
