fn exchange_http_over_stream(
    stream: &mut dyn ReadWrite,
    request_target: &str,
    host_header: &str,
    payload: &[u8],
) -> Result<Vec<u8>, DnsError> {
    let request = format!(
        "POST {request_target} HTTP/1.1\r\nHost: {host_header}\r\nAccept: application/dns-message\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        payload.len()
    );
    stream.write_all(request.as_bytes())?;
    stream.write_all(payload)?;
    stream.flush()?;
    read_http_response_body_from_stream(stream)
}

fn exchange_dns_payload_over_stream(
    stream: &mut dyn ReadWrite,
    payload: &[u8],
) -> Result<Vec<u8>, DnsError> {
    let length = u16::try_from(payload.len())
        .map_err(|_| DnsError::DnsProtocol("dns tcp query too large".to_owned()))?;
    stream.write_all(&length.to_be_bytes())?;
    stream.write_all(payload)?;
    stream.flush()?;

    let mut header = [0_u8; 2];
    stream.read_exact(&mut header)?;
    let response_len = u16::from_be_bytes(header) as usize;
    let mut response = vec![0_u8; response_len];
    stream.read_exact(&mut response)?;
    Ok(response)
}

trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}

fn read_http_response_body_from_stream(stream: &mut dyn Read) -> Result<Vec<u8>, DnsError> {
    let mut response = Vec::new();
    let mut buf = [0_u8; 1024];
    let header_end = loop {
        let read = stream.read(&mut buf)?;
        if read == 0 {
            return Err(DnsError::DnsProtocol(
                "http response ended before headers were complete".to_owned(),
            ));
        }
        response.extend_from_slice(&buf[..read]);
        if let Some(position) = response
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
        {
            break position + 4;
        }
    };

    let headers = response[..header_end].to_vec();
    let header_text = String::from_utf8_lossy(&headers);
    let mut lines = header_text.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| DnsError::DnsProtocol("http response missing status line".to_owned()))?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| DnsError::DnsProtocol("http response missing status code".to_owned()))?;
    if status != "200" {
        return Err(DnsError::DnsProtocol(format!(
            "http upstream returned status {status}"
        )));
    }

    let mut content_length = None;
    let mut chunked = false;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim().to_ascii_lowercase();
            let value = value.trim().to_ascii_lowercase();
            if name == "content-length" {
                content_length = value.parse::<usize>().ok();
            } else if name == "transfer-encoding" && value.contains("chunked") {
                chunked = true;
            }
        }
    }

    let mut body = response[header_end..].to_vec();
    if let Some(length) = content_length {
        while body.len() < length {
            let read = stream.read(&mut buf)?;
            if read == 0 {
                return Err(DnsError::DnsProtocol(
                    "http response body shorter than content-length".to_owned(),
                ));
            }
            body.extend_from_slice(&buf[..read]);
        }
        return Ok(body[..length].to_vec());
    }

    if chunked {
        loop {
            let read = stream.read(&mut buf)?;
            if read == 0 {
                break;
            }
            body.extend_from_slice(&buf[..read]);
        }
        return decode_chunked_body(&body);
    }

    loop {
        let read = stream.read(&mut buf)?;
        if read == 0 {
            break;
        }
        body.extend_from_slice(&buf[..read]);
    }
    Ok(body)
}

fn decode_chunked_body(body: &[u8]) -> Result<Vec<u8>, DnsError> {
    let mut cursor = 0;
    let mut decoded = Vec::new();
    loop {
        let line_end = body[cursor..]
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or_else(|| DnsError::DnsProtocol("chunked body missing size line".to_owned()))?;
        let size_text = std::str::from_utf8(&body[cursor..cursor + line_end])
            .map_err(|_| DnsError::DnsProtocol("chunk size is not utf-8".to_owned()))?;
        let size = usize::from_str_radix(size_text.trim(), 16)
            .map_err(|_| DnsError::DnsProtocol("invalid chunk size".to_owned()))?;
        cursor += line_end + 2;
        if size == 0 {
            break;
        }
        if body.len() < cursor + size + 2 {
            return Err(DnsError::DnsProtocol("chunk body truncated".to_owned()));
        }
        decoded.extend_from_slice(&body[cursor..cursor + size]);
        cursor += size + 2;
    }
    Ok(decoded)
}
