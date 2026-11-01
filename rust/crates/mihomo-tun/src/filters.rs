use std::net::SocketAddr;

pub(crate) fn allows_value(include: &[String], exclude: &[String], value: &str) -> bool {
    if !include.is_empty() && !include.iter().any(|item| item == value) {
        return false;
    }
    !exclude.iter().any(|item| item == value)
}

pub(crate) fn uid_in_range(uid: u32, raw: &str) -> bool {
    let Some((start, end)) = raw.split_once(':') else {
        return false;
    };
    let Ok(start) = start.trim().parse::<u32>() else {
        return false;
    };
    let Ok(end) = end.trim().parse::<u32>() else {
        return false;
    };
    start <= uid && uid <= end
}

pub(crate) fn dns_hijack_matches(entry: &str, destination: SocketAddr) -> bool {
    let raw = entry
        .trim()
        .strip_prefix("udp://")
        .or_else(|| entry.trim().strip_prefix("tcp://"))
        .unwrap_or(entry.trim());
    let Some((host, port)) = raw.rsplit_once(':') else {
        return false;
    };
    let Ok(port) = port.trim().parse::<u16>() else {
        return false;
    };
    if port != destination.port() {
        return false;
    }
    let host = host.trim();
    host == "*"
        || host.eq_ignore_ascii_case("any")
        || host == "0.0.0.0"
        || host == "::"
        || host == destination.ip().to_string()
}
