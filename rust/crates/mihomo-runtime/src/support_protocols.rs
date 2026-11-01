use mihomo_outbound::OutboundDefinition;
use serde_yaml::Value;

use crate::support_helpers::*;

pub(crate) fn native_support_gap_for_outbound_impl(
    definition: &OutboundDefinition,
) -> Option<String> {
    let dialer_proxy = definition.dialer_proxy().trim();
    match definition {
        OutboundDefinition::Hysteria(config) => hysteria_support_gap(config),
        OutboundDefinition::WireGuard(config) => wireguard_support_gap(config),
        OutboundDefinition::Tuic(config) => tuic_support_gap(config, dialer_proxy),
        OutboundDefinition::Mieru(_) => unsupported_protocol_reason("mieru"),
        OutboundDefinition::Masque(config) => masque_support_gap(config, dialer_proxy),
        OutboundDefinition::OpenVpn(config) => openvpn_support_gap(config),
        OutboundDefinition::Tailscale(_) => unsupported_protocol_reason("tailscale"),
        OutboundDefinition::Hysteria2(config) => {
            if !dialer_proxy.is_empty() {
                return Some(
                    "hysteria2 over dialer-proxy is not yet supported in the native Rust runtime"
                        .to_owned(),
                );
            }
            let obfs = extra_string(&config.extra, "obfs");
            if !obfs.is_empty() && obfs != "salamander" {
                return Some(format!(
                    "hysteria2 obfs={} is not yet supported in the native Rust runtime",
                    obfs
                ));
            }
            let realm = nested_map(&config.extra, "realm-opts");
            if nested_mapping_bool(realm, "enable") {
                if nested_mapping_string(realm, "realm-id").trim().is_empty() {
                    return Some(
                        "hysteria2 realm-opts requires realm-id in the native Rust runtime"
                            .to_owned(),
                    );
                }
                if !nested_mapping_contains(realm, "stun-servers")
                    || nested_map_has_no_entries(realm, "stun-servers")
                {
                    return Some(
                        "hysteria2 realm-opts requires stun-servers in the native Rust runtime"
                            .to_owned(),
                    );
                }
            }
            None
        }
        OutboundDefinition::ShadowSocks(config) => shadowsocks_support_gap(config, dialer_proxy),
        OutboundDefinition::ShadowSocksR(config) => shadowsocksr_support_gap(config),
        OutboundDefinition::Snell(config) => snell_support_gap(config),
        OutboundDefinition::Trojan(config) => trojan_support_gap(config),
        OutboundDefinition::TrustTunnel(config) => trusttunnel_support_gap(config),
        OutboundDefinition::Sudoku(config) => sudoku_support_gap(config, dialer_proxy),
        OutboundDefinition::Vless(config) => {
            let flow = extra_string(&config.extra, "flow");
            let network = extra_string(&config.extra, "network");
            let tls = extra_bool(&config.extra, "tls");
            let has_reality = config.extra.contains_key("reality-opts");
            // REALITY supports plain TCP with optional Vision framing.
            let reality_happy_path = has_reality
                && (flow.is_empty() || (flow == "xtls-rprx-vision" && tls))
                && (network.is_empty() || network == "tcp");
            let native_vision_happy_path = flow == "xtls-rprx-vision"
                && !has_reality
                && tls
                && (network.is_empty()
                    || network == "tcp"
                    || network == "h2"
                    || network == "grpc"
                    || network == "ws"
                    || network == "http");
            if !flow.is_empty() && !native_vision_happy_path && !reality_happy_path {
                return Some(format!(
                    "vless flow={} is not yet supported in the native Rust runtime",
                    flow
                ));
            }
            if has_reality && !reality_happy_path {
                return Some(
                    "vless reality-opts requires plain tcp with an empty flow or xtls-rprx-vision"
                        .to_owned(),
                );
            }
            let encryption = extra_string(&config.extra, "encryption");
            if !encryption.is_empty() && encryption != "none" {
                return Some(format!(
                    "vless encryption={} is not yet supported in the native Rust runtime",
                    encryption
                ));
            }
            if network == "xhttp" {
                let xhttp = nested_map(&config.extra, "xhttp-opts");
                if let Some(reason) = xhttp_support_gap(xhttp, "vless") {
                    return Some(reason);
                }
            }
            None
        }
        OutboundDefinition::Vmess(config) => vmess_support_gap(config),
        _ => None,
    }
}

fn nested_map_has_no_entries(mapping: Option<&serde_yaml::Mapping>, key: &str) -> bool {
    mapping
        .and_then(|mapping| mapping.get(Value::String(key.to_owned())))
        .and_then(Value::as_sequence)
        .is_none_or(|entries| entries.is_empty())
}

fn hysteria_support_gap(
    config: &mihomo_outbound::ServerPortOutboundConfig,
) -> Option<String> {
    if !config.base.dialer_proxy.trim().is_empty() {
        return Some(
            "hysteria over dialer-proxy is not yet supported in the native Rust runtime"
                .to_owned(),
        );
    }
    let protocol = extra_string(&config.extra, "protocol");
    let obfs_protocol = extra_string(&config.extra, "obfs-protocol");
    let effective_protocol = if obfs_protocol.is_empty() {
        protocol
    } else {
        obfs_protocol
    };
    if !effective_protocol.is_empty() && effective_protocol != "udp" {
        return Some(format!(
            "hysteria protocol={} is not yet supported in the native Rust runtime",
            effective_protocol
        ));
    }
    None
}

fn wireguard_support_gap(
    config: &mihomo_outbound::WireGuardOutboundConfig,
) -> Option<String> {
    if !config.base.dialer_proxy.trim().is_empty() {
        return Some(
            "wireguard over dialer-proxy is not yet supported in the native Rust runtime"
                .to_owned(),
        );
    }
    let peers = nested_sequence(&config.extra, "peers");
    let multi_peer = !peers.is_empty();
    if !multi_peer && config.server.trim().is_empty() {
        return Some("wireguard server is required for the native Rust runtime".to_owned());
    }
    if !multi_peer && config.port == 0 {
        return Some("wireguard port is required for the native Rust runtime".to_owned());
    }
    if config.private_key.trim().is_empty() {
        return Some("wireguard private-key is required for the native Rust runtime".to_owned());
    }
    if !multi_peer && config.public_key.trim().is_empty() {
        return Some("wireguard public-key is required for the native Rust runtime".to_owned());
    }
    if config.ip.trim().is_empty() && config.ipv6.trim().is_empty() {
        return Some("wireguard requires ip and/or ipv6 for the native Rust runtime".to_owned());
    }

    if !extra_string(&config.extra, "pre-shared-key").is_empty() {
        return Some(
            "wireguard pre-shared-key is not yet supported in the native Rust runtime".to_owned(),
        );
    }
    if nested_map(&config.extra, "amnezia-wg-option")
        .is_some_and(|mapping| !mapping.is_empty())
    {
        return Some(
            "wireguard amnezia-wg-option is not yet supported in the native Rust runtime"
                .to_owned(),
        );
    }
    if config.extra.contains_key("reserved") {
        return Some("wireguard reserved is not yet supported in the native Rust runtime".to_owned());
    }
    let remote_dns_resolve = extra_bool(&config.extra, "remote-dns-resolve");
    let dns = string_list(&config.extra, "dns");
    if remote_dns_resolve && dns.is_empty() {
        return Some(
            "wireguard remote-dns-resolve currently requires explicit dns servers in the native Rust runtime"
                .to_owned(),
        );
    }
    if !dns.is_empty()
        && dns.iter().any(|server| {
            let endpoint = server.split('#').next().unwrap_or(server).trim();
            !endpoint.is_empty()
                && endpoint.strip_prefix("udp://").unwrap_or(endpoint).contains("://")
        })
    {
        return Some(
            "wireguard dns currently supports udp nameservers only in the native Rust runtime"
                .to_owned(),
        );
    }
    if extra_u64(&config.extra, "refresh-server-ip-interval") != 0 {
        return Some(
            "wireguard refresh-server-ip-interval is not yet supported in the native Rust runtime"
                .to_owned(),
        );
    }
    if multi_peer {
        for (index, peer) in peers.iter().filter_map(Value::as_mapping).enumerate() {
            let server = peer
                .get(Value::String("server".to_owned()))
                .and_then(Value::as_str)
                .map(str::trim)
                .unwrap_or_default();
            if server.is_empty() {
                return Some(format!(
                    "wireguard peer {index} server is required for the native Rust runtime"
                ));
            }
            let port = peer
                .get(Value::String("port".to_owned()))
                .and_then(Value::as_u64)
                .unwrap_or(0);
            if port == 0 {
                return Some(format!(
                    "wireguard peer {index} port is required for the native Rust runtime"
                ));
            }
            let public_key = peer
                .get(Value::String("public-key".to_owned()))
                .and_then(Value::as_str)
                .map(str::trim)
                .unwrap_or_default();
            if public_key.is_empty() {
                return Some(format!(
                    "wireguard peer {index} public-key is required for the native Rust runtime"
                ));
            }
            if peer.contains_key(Value::String("pre-shared-key".to_owned())) {
                return Some(format!(
                    "wireguard peer {index} pre-shared-key is not yet supported in the native Rust runtime"
                ));
            }
            if peer.contains_key(Value::String("reserved".to_owned())) {
                return Some(format!(
                    "wireguard peer {index} reserved is not yet supported in the native Rust runtime"
                ));
            }
            let allowed_ips = peer
                .get(Value::String("allowed-ips".to_owned()))
                .and_then(Value::as_sequence)
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            if allowed_ips.is_empty() {
                return Some(format!(
                    "wireguard peer {index} allowed-ips is required for the native Rust runtime"
                ));
            }
        }
    } else {
        let allowed_ips = string_list(&config.extra, "allowed-ips");
        if allowed_ips.is_empty() {
            return Some("wireguard allowed-ips is required for the native Rust runtime".to_owned());
        }
    }
    None
}

fn openvpn_support_gap(
    config: &mihomo_outbound::ServerPortOutboundConfig,
) -> Option<String> {
    let proto = extra_string(&config.extra, "proto").to_ascii_lowercase();
    let normalized_proto = if proto.is_empty() || proto == "udp4" {
        "udp"
    } else if matches!(proto.as_str(), "tcp-client" | "tcp4" | "tcp4-client") {
        "tcp"
    } else {
        proto.as_str()
    };
    if !config.base.dialer_proxy.trim().is_empty() && normalized_proto != "tcp" {
        return Some(
            "openvpn over dialer-proxy currently requires proto=tcp in the native Rust runtime"
                .to_owned(),
        );
    }
    if config.server.trim().is_empty() {
        return Some("openvpn server is required for the native Rust runtime".to_owned());
    }
    if config.port == 0 {
        return Some("openvpn port is required for the native Rust runtime".to_owned());
    }

    let dev = extra_string(&config.extra, "dev");
    if !dev.is_empty() && dev != "tun" {
        return Some(format!(
            "openvpn dev={} is not yet supported in the native Rust runtime",
            dev
        ));
    }

    if !proto.is_empty()
        && !matches!(
            proto.as_str(),
            "udp" | "udp4" | "tcp" | "tcp-client" | "tcp4" | "tcp4-client"
        )
    {
        return Some(format!(
            "openvpn proto={} is not yet supported in the native Rust runtime",
            proto
        ));
    }

    let cipher = extra_string(&config.extra, "cipher").to_ascii_uppercase();
    if !cipher.is_empty() && cipher != "AES-128-GCM" && cipher != "AES-256-GCM" {
        return Some(format!(
            "openvpn cipher={} is not yet supported in the native Rust runtime",
            cipher
        ));
    }

    let auth = extra_string(&config.extra, "auth").to_ascii_uppercase();
    if !auth.is_empty() && auth != "SHA256" {
        return Some(format!(
            "openvpn auth={} is not yet supported in the native Rust runtime",
            auth
        ));
    }

    if extra_string(&config.extra, "ca").trim().is_empty() {
        return Some("openvpn ca is required for the native Rust runtime".to_owned());
    }
    if extra_string(&config.extra, "tls-crypt").trim().is_empty() {
        return Some("openvpn tls-crypt is required for the native Rust runtime".to_owned());
    }

    let cert = extra_string(&config.extra, "cert");
    let key = extra_string(&config.extra, "key");
    let username = extra_string(&config.extra, "username");
    if cert.trim().is_empty() || key.trim().is_empty() {
        if username.trim().is_empty() {
            return Some(
                "openvpn requires cert+key or username/password in the native Rust runtime"
                    .to_owned(),
            );
        }
    }

    let remote_cert_tls = extra_string(&config.extra, "remote-cert-tls");
    if !remote_cert_tls.trim().is_empty() && remote_cert_tls.trim() != "server" {
        return Some(format!(
            "openvpn remote-cert-tls={} is not yet supported in the native Rust runtime",
            remote_cert_tls.trim()
        ));
    }

    let remote_dns_resolve = extra_bool(&config.extra, "remote-dns-resolve");
    let dns = string_list(&config.extra, "dns");
    if remote_dns_resolve && dns.is_empty() {
        return Some(
            "openvpn remote-dns-resolve currently requires explicit dns servers in the native Rust runtime"
                .to_owned(),
        );
    }
    if !dns.is_empty()
        && dns.iter().any(|server| {
            let endpoint = server.split('#').next().unwrap_or(server).trim();
            !endpoint.is_empty()
                && endpoint.strip_prefix("udp://").unwrap_or(endpoint).contains("://")
        })
    {
        return Some(
            "openvpn dns currently supports udp nameservers only in the native Rust runtime"
                .to_owned(),
        );
    }

    None
}

fn masque_support_gap(
    config: &mihomo_outbound::ServerPortOutboundConfig,
    dialer_proxy: &str,
) -> Option<String> {
    if extra_string(&config.extra, "private-key").trim().is_empty() {
        return Some("masque private-key is required for the native Rust runtime".to_owned());
    }
    if extra_string(&config.extra, "public-key").trim().is_empty() {
        return Some("masque public-key is required for the native Rust runtime".to_owned());
    }
    if extra_string(&config.extra, "ip").trim().is_empty()
        && extra_string(&config.extra, "ipv6").trim().is_empty()
    {
        return Some("masque requires ip and/or ipv6 for the native Rust runtime".to_owned());
    }
    let network = extra_string(&config.extra, "network");
    if network != "h2" {
        return Some(format!(
            "masque network={} is not yet supported in the native Rust runtime",
            if network.trim().is_empty() { "<default>" } else { network.as_str() }
        ));
    }
    if !dialer_proxy.is_empty() && network != "h2" {
        return Some(
            "masque over dialer-proxy is currently supported only with network=h2 in the native Rust runtime"
                .to_owned(),
        );
    }
    let remote_dns_resolve = extra_bool(&config.extra, "remote-dns-resolve");
    let dns = string_list(&config.extra, "dns");
    if remote_dns_resolve && dns.is_empty() {
        return Some(
            "masque remote-dns-resolve currently requires explicit dns servers in the native Rust runtime"
                .to_owned(),
        );
    }
    if !dns.is_empty()
        && dns.iter().any(|server| {
            let endpoint = server.split('#').next().unwrap_or(server).trim();
            !endpoint.is_empty()
                && endpoint.strip_prefix("udp://").unwrap_or(endpoint).contains("://")
        })
    {
        return Some(
            "masque dns currently supports udp nameservers only in the native Rust runtime"
                .to_owned(),
        );
    }
    None
}

fn shadowsocks_support_gap(
    config: &mihomo_outbound::ShadowSocksOutboundConfig,
    _dialer_proxy: &str,
) -> Option<String> {
    let cipher = config.cipher.trim().to_ascii_uppercase();
    let is_2022 = matches!(
        cipher.as_str(),
        "2022-BLAKE3-AES-128-GCM"
            | "2022-BLAKE3-AES-256-GCM"
            | "2022-BLAKE3-CHACHA20-POLY1305"
    );
    if !is_2022
        && !matches!(
            cipher.as_str(),
            "AEAD_AES_128_GCM"
                | "AES-128-GCM"
                | "AEAD_AES_192_GCM"
                | "AES-192-GCM"
                | "AEAD_AES_256_GCM"
                | "AES-256-GCM"
                | "AEAD_CHACHA20_POLY1305"
                | "CHACHA20-IETF-POLY1305"
        )
    {
        return Some(format!(
            "shadowsocks cipher={} is not yet supported in the native Rust runtime",
            config.cipher.trim()
        ));
    }
    let plugin = extra_string(&config.extra, "plugin").to_ascii_lowercase();
    if is_2022 && !plugin.is_empty() {
        return Some(format!(
            "shadowsocks 2022 cipher with plugin={plugin} is not yet supported in the native Rust runtime"
        ));
    }
    match plugin.as_str() {
        "" => None,
        "obfs" => {
            let mode = nested_string(&config.extra, "plugin-opts", "mode");
            if mode != "tls" && mode != "http" {
                return Some(format!(
                    "shadowsocks plugin=obfs mode={} is not yet supported in the native Rust runtime",
                    mode
                ));
            }
            None
        }
        "v2ray-plugin" | "gost-plugin" => None,
        _ => Some(format!(
            "shadowsocks plugin={} is not yet supported in the native Rust runtime",
            plugin
        )),
    }
}

fn shadowsocksr_support_gap(
    config: &mihomo_outbound::ServerPortOutboundConfig,
) -> Option<String> {
    let cipher = extra_string(&config.extra, "cipher");
    if !matches!(
        cipher.as_str(),
        "" | "dummy" | "none" | "aes-128-cfb" | "aes-192-cfb" | "aes-256-cfb"
    ) {
        return Some(format!(
            "ssr cipher={} is not yet supported in the native Rust runtime",
            cipher
        ));
    }
    let obfs = extra_string(&config.extra, "obfs");
    if !matches!(obfs.as_str(), "" | "plain" | "http_simple" | "http_post") {
        return Some(format!(
            "ssr obfs={} is not yet supported in the native Rust runtime",
            obfs
        ));
    }
    let protocol = extra_string(&config.extra, "protocol");
    if !matches!(protocol.as_str(), "" | "origin") {
        return Some(format!(
            "ssr protocol={} is not yet supported in the native Rust runtime",
            protocol
        ));
    }
    None
}

fn snell_support_gap(
    config: &mihomo_outbound::ServerPortOutboundConfig,
) -> Option<String> {
    let obfs_mode = nested_string(&config.extra, "obfs-opts", "mode");
    if !matches!(obfs_mode.as_str(), "" | "http" | "tls") {
        return Some(format!(
            "snell obfs={} is not yet supported in the native Rust runtime",
            obfs_mode
        ));
    }
    None
}

fn trojan_support_gap(
    config: &mihomo_outbound::ServerPortOutboundConfig,
) -> Option<String> {
    let network = extra_string(&config.extra, "network");
    if !matches!(network.as_str(), "" | "tcp" | "ws" | "http" | "grpc" | "h2" | "xhttp") {
        return Some(format!(
            "trojan network={} is not yet supported in the native Rust runtime",
            network
        ));
    }
    None
}

fn trusttunnel_support_gap(
    config: &mihomo_outbound::ServerPortOutboundConfig,
) -> Option<String> {
    if extra_bool(&config.extra, "quic") && !config.base.dialer_proxy.trim().is_empty() {
        return Some(
            "trusttunnel quic over dialer-proxy is not yet supported in the native Rust runtime"
                .to_owned(),
        );
    }
    None
}

fn tuic_support_gap(
    config: &mihomo_outbound::ServerPortOutboundConfig,
    dialer_proxy: &str,
) -> Option<String> {
    if !dialer_proxy.is_empty() {
        return Some("tuic over dialer-proxy is not yet supported in the native Rust runtime".to_owned());
    }
    let token = extra_string(&config.extra, "token");
    if token.is_empty() {
        let uuid = extra_string(&config.extra, "uuid");
        if uuid.is_empty() {
            return Some("tuic requires uuid in the native Rust runtime".to_owned());
        }
        let password = extra_string(&config.extra, "password");
        if password.is_empty() {
            return Some("tuic requires password in the native Rust runtime".to_owned());
        }
    }
    None
}

fn sudoku_support_gap(
    config: &mihomo_outbound::ServerPortOutboundConfig,
    dialer_proxy: &str,
) -> Option<String> {
    if dialer_proxy.is_empty() {
        return None;
    }
    let _ = config;
    None
}

fn vmess_support_gap(
    config: &mihomo_outbound::ServerPortOutboundConfig,
) -> Option<String> {
    let network = extra_string(&config.extra, "network");
    if !matches!(
        network.as_str(),
        "" | "tcp" | "ws" | "grpc" | "http" | "h2" | "xhttp"
    ) {
        return Some(format!(
            "vmess network={} is not yet supported in the native Rust runtime",
            network
        ));
    }
    let cipher = extra_string(&config.extra, "cipher");
    if !matches!(
        cipher.as_str(),
        "" | "auto" | "none" | "zero" | "aes-128-cfb" | "aes-128-gcm" | "chacha20-poly1305"
    ) {
        return Some(format!(
            "vmess cipher={} is not yet supported in the native Rust runtime",
            cipher
        ));
    }
    if network == "xhttp" {
        let xhttp = nested_map(&config.extra, "xhttp-opts");
        if let Some(reason) = xhttp_support_gap(xhttp, "vmess") {
            return Some(reason);
        }
    }
    None
}

fn xhttp_support_gap(
    xhttp: Option<&serde_yaml::Mapping>,
    protocol: &str,
) -> Option<String> {
    let mode = nested_mapping_string(xhttp, "mode");
    let normalized_mode = if mode.is_empty() || mode == "auto" {
        "packet-up"
    } else {
        mode.as_str()
    };
    if !matches!(normalized_mode, "stream-one" | "stream-up" | "packet-up") {
        return Some(format!(
            "{protocol} xhttp mode={} is not yet supported in the native Rust runtime",
            normalized_mode
        ));
    }
    let xpadding_obfs_mode = nested_mapping_bool(xhttp, "x-padding-obfs-mode");
    if xpadding_obfs_mode {
        let placement = nested_mapping_string(xhttp, "x-padding-placement");
        if !matches!(placement.as_str(), "" | "header" | "queryInHeader" | "query" | "cookie")
        {
            return Some(format!(
                "{protocol} xhttp x-padding-placement={} is not yet supported in the native Rust runtime",
                placement
            ));
        }
        let method = nested_mapping_string(xhttp, "x-padding-method");
        if !matches!(method.as_str(), "" | "repeat-x" | "tokenish") {
            return Some(format!(
                "{protocol} xhttp x-padding-method={} is not yet supported in the native Rust runtime",
                method
            ));
        }
    }
    let session_placement = nested_mapping_string(xhttp, "session-placement");
    if !matches!(session_placement.as_str(), "" | "path" | "query" | "header" | "cookie") {
        return Some(format!(
            "{protocol} xhttp session-placement={} is not yet supported in the native Rust runtime",
            session_placement
        ));
    }
    let seq_placement = nested_mapping_string(xhttp, "seq-placement");
    if !matches!(seq_placement.as_str(), "" | "path" | "query" | "header" | "cookie") {
        return Some(format!(
            "{protocol} xhttp seq-placement={} is not yet supported in the native Rust runtime",
            seq_placement
        ));
    }
    let uplink_data_placement = nested_mapping_string(xhttp, "uplink-data-placement");
    if !matches!(
        uplink_data_placement.as_str(),
        "" | "body" | "header" | "cookie" | "auto"
    ) {
        return Some(format!(
            "{protocol} xhttp uplink-data-placement={} is not yet supported in the native Rust runtime",
            uplink_data_placement
        ));
    }
    let has_download_settings = nested_mapping_contains(xhttp, "download-settings");
    if has_download_settings && normalized_mode == "stream-one" {
        return Some(format!(
            "{protocol} xhttp download-settings with mode=stream-one is not yet supported in the native Rust runtime"
        ));
    }
    let download = nested_mapping_map(xhttp, "download-settings");
    let has_unsupported_download_transport_overrides =
        ["ech-opts", "reality-opts", "client-fingerprint"]
            .iter()
            .any(|key| nested_mapping_contains(download, key));
    if has_unsupported_download_transport_overrides {
        return Some(format!(
            "{protocol} xhttp download-settings transport overrides are not yet supported in the native Rust runtime"
        ));
    }
    None
}

#[cfg(test)]
mod tests {
    use mihomo_config::parse_runtime_config_document;

    use super::native_support_gap_for_outbound_impl;

    #[test]
    fn masque_h2_supported_subset_has_no_native_gap() {
        let definition = parse_runtime_config_document(
            r#"
proxies:
  - type: masque
    name: edge-masque
    server: masque.example.com
    port: 443
    private-key: MHcCAQEEIHKf5w9Mpw/FQ96IUBf5l9H35bM9s0wYcn7wI3V6y2RSoAoGCCqGSM49AwEHoUQDQgAE9z2rP7A6J3q/0wx9r0Jkz5e9Awv+6Y4uR5N7xP6U1I0gFQj7B1eM4hJX8Y0r8xA0zq6H0w1w+T6JQ6jK5eJ+4g==
    public-key: MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE9z2rP7A6J3q/0wx9r0Jkz5e9Awv+6Y4uR5N7xP6U1I0gFQj7B1eM4hJX8Y0r8xA0zq6H0w1w+T6JQ6jK5eJ+4g==
    ip: 10.10.0.2/32
    network: h2
"#,
        )
        .unwrap()
        .proxies
        .into_iter()
        .next()
        .unwrap();

        assert_eq!(native_support_gap_for_outbound_impl(&definition), None);
    }

    #[test]
    fn masque_remote_dns_requires_explicit_dns_servers() {
        let definition = parse_runtime_config_document(
            r#"
proxies:
  - type: masque
    name: edge-masque
    server: masque.example.com
    port: 443
    private-key: key
    public-key: pub
    ip: 10.10.0.2/32
    network: h2
    remote-dns-resolve: true
"#,
        )
        .unwrap()
        .proxies
        .into_iter()
        .next()
        .unwrap();

        let gap = native_support_gap_for_outbound_impl(&definition).unwrap();
        assert!(gap.contains("explicit dns servers"));
    }

    #[test]
    fn masque_remote_dns_with_udp_nameserver_has_no_native_gap() {
        let definition = parse_runtime_config_document(
            r#"
proxies:
  - type: masque
    name: edge-masque
    server: masque.example.com
    port: 443
    private-key: key
    public-key: pub
    ip: 10.10.0.2/32
    network: h2
    remote-dns-resolve: true
    dns: [udp://1.1.1.1]
"#,
        )
        .unwrap()
        .proxies
        .into_iter()
        .next()
        .unwrap();

        assert_eq!(native_support_gap_for_outbound_impl(&definition), None);
    }

    #[test]
    fn wireguard_remote_dns_with_udp_nameserver_has_no_native_gap() {
        let definition = parse_runtime_config_document(
            r#"
proxies:
  - type: wireguard
    name: edge-wg
    server: 1.2.3.4
    port: 51820
    private-key: cHJpdmF0ZS1rZXktMzItYnl0ZXMtcHJpdmF0ZS1rZXk=
    public-key: cHVibGljLWtleS0zMi1ieXRlcy1wdWJsaWMta2V5LQ==
    ip: 10.0.0.2/32
    allowed-ips: [0.0.0.0/0]
    remote-dns-resolve: true
    dns: [udp://1.1.1.1]
"#,
        )
        .unwrap()
        .proxies
        .into_iter()
        .next()
        .unwrap();

        assert_eq!(native_support_gap_for_outbound_impl(&definition), None);
    }

    #[test]
    fn openvpn_remote_dns_with_udp_nameserver_has_no_native_gap() {
        let definition = parse_runtime_config_document(
            r#"
proxies:
  - type: openvpn
    name: edge-ovpn
    server: 1.2.3.4
    port: 1194
    proto: udp
    dev: tun
    cipher: AES-128-GCM
    auth: SHA256
    username: demo
    password: secret
    ca: demo
    tls-crypt: demo
    remote-dns-resolve: true
    dns: [udp://1.1.1.1]
"#,
        )
        .unwrap()
        .proxies
        .into_iter()
        .next()
        .unwrap();

        assert_eq!(native_support_gap_for_outbound_impl(&definition), None);
    }

    #[test]
    fn masque_h2_with_dialer_proxy_has_no_native_gap() {
        let definition = parse_runtime_config_document(
            r#"
proxies:
  - type: masque
    name: edge-masque
    server: masque.example.com
    port: 443
    private-key: key
    public-key: pub
    ip: 10.10.0.2/32
    network: h2
    dialer-proxy: outer
"#,
        )
        .unwrap()
        .proxies
        .into_iter()
        .next()
        .unwrap();

        assert_eq!(native_support_gap_for_outbound_impl(&definition), None);
    }
}
