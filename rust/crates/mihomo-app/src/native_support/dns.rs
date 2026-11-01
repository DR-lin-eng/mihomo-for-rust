use mihomo_config::RuntimeConfigDocument;
use mihomo_runtime::NativeSupportGap;

use super::common::surface_support_gap;

pub(super) fn dns_runtime_support_gaps(document: &RuntimeConfigDocument) -> Vec<NativeSupportGap> {
    if !document.dns.enable {
        return Vec::new();
    }

    let mut gaps = Vec::new();
    if !document.dns.proxy_server_nameserver_policy.is_empty()
        && document.dns.proxy_server_nameserver.is_empty()
    {
        gaps.push(surface_support_gap(
            "dns.proxy-server-nameserver-policy",
            "dns proxy-server-nameserver-policy requires proxy-server-nameserver for the native Rust dns runtime",
        ));
    }
    collect_dns_nameserver_gaps(&mut gaps, "dns.nameserver", &document.dns.nameserver);
    collect_dns_nameserver_gaps(&mut gaps, "dns.fallback", &document.dns.fallback);
    collect_dns_nameserver_gaps(
        &mut gaps,
        "dns.default-nameserver",
        &document.dns.default_nameserver,
    );
    collect_dns_nameserver_gaps(
        &mut gaps,
        "dns.proxy-server-nameserver",
        &document.dns.proxy_server_nameserver,
    );
    collect_dns_nameserver_gaps(
        &mut gaps,
        "dns.direct-nameserver",
        &document.dns.direct_nameserver,
    );
    for (pattern, values) in &document.dns.nameserver_policy {
        collect_dns_nameserver_gaps(
            &mut gaps,
            &format!("dns.nameserver-policy[{pattern}]"),
            &values.values,
        );
    }
    for (pattern, values) in &document.dns.proxy_server_nameserver_policy {
        collect_dns_nameserver_gaps(
            &mut gaps,
            &format!("dns.proxy-server-nameserver-policy[{pattern}]"),
            &values.values,
        );
    }
    gaps
}

fn collect_dns_nameserver_gaps(gaps: &mut Vec<NativeSupportGap>, field: &str, servers: &[String]) {
    for server in servers {
        if let Some(reason) = dns_nameserver_support_gap(server) {
            gaps.push(surface_support_gap(field, &reason));
        }
    }
}

fn dns_nameserver_support_gap(server: &str) -> Option<String> {
    let raw = server.trim();
    if raw.is_empty() {
        return None;
    }

    let (endpoint, fragment) = raw
        .split_once('#')
        .map_or((raw, ""), |(left, right)| (left.trim(), right.trim()));
    if !fragment.is_empty() {
        if fragment.eq_ignore_ascii_case("RULES")
            || (!fragment.contains('=') && !fragment.contains('&'))
        {
            let lower = endpoint.to_ascii_lowercase();
            let tunnel_udp_style = !lower.starts_with("system")
                && !lower.starts_with("rcode://")
                && !lower.starts_with("dhcp://")
                && !lower.starts_with("ts://")
                && !lower.starts_with("tailscale://");
            let tunnel_tcp_style = lower.starts_with("tcp://")
                || lower.starts_with("tls://")
                || lower.starts_with("http://")
                || lower.starts_with("https://")
                || lower.starts_with("quic://");
            if tunnel_udp_style || tunnel_tcp_style {
                return None;
            }
        }
        return Some(format!(
            "dns nameserver `{raw}` uses fragment options or proxy routing that are not yet supported by the native Rust dns runtime"
        ));
    }

    let lower = endpoint.to_ascii_lowercase();
    if lower.starts_with("dhcp://")
        || lower.starts_with("ts://")
        || lower.starts_with("tailscale://")
    {
        return Some(format!(
            "dns nameserver `{raw}` uses a protocol or transport that is not yet supported by the native Rust dns runtime"
        ));
    }

    None
}
