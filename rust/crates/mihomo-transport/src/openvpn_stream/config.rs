use super::{
    OpenVpnConfig, OpenVpnOptions, AUTH_SHA256, CIPHER_AES_128_GCM, CIPHER_AES_256_GCM,
    PROTO_TCP, PROTO_UDP,
};
use crate::TransportError;

pub(crate) fn prepare_config(options: &OpenVpnOptions) -> Result<OpenVpnConfig, TransportError> {
    let remote_host = options.server.trim();
    if remote_host.is_empty() || options.port == 0 {
        return Err(TransportError::InvalidPlan(
            "openvpn config requires remote host and port".to_owned(),
        ));
    }

    let proto = normalize_proto(&options.proto);
    let dev = normalize_dev(&options.dev);
    let cipher = normalize_cipher(&options.cipher);
    let auth = normalize_auth(&options.auth);

    let ca = options.ca.trim().as_bytes().to_vec();
    let cert = options.cert.trim().as_bytes().to_vec();
    let key = options.key.trim().as_bytes().to_vec();
    let tls_crypt = options.tls_crypt.trim().as_bytes().to_vec();

    validate_install_script_subset(
        remote_host,
        options.port,
        &proto,
        &dev,
        &cipher,
        &auth,
        &ca,
        &cert,
        &key,
        &tls_crypt,
        options.username.trim(),
    )?;

    let tls_crypt_key = decode_static_key(&tls_crypt)?;

    Ok(OpenVpnConfig {
        remote_host: remote_host.to_owned(),
        remote_port: options.port,
        proto,
        dev,
        cipher,
        auth,
        ca,
        cert,
        key,
        tls_crypt,
        username: options.username.trim().to_owned(),
        password: options.password.to_owned(),
        tls_crypt_key,
        mtu: if options.mtu == 0 { 1500 } else { options.mtu },
    })
}

pub(crate) fn normalize_proto(proto: &str) -> String {
    match proto.trim().to_ascii_lowercase().as_str() {
        "" | "udp" | "udp4" => PROTO_UDP.to_owned(),
        "tcp" | "tcp-client" | "tcp4" | "tcp4-client" => PROTO_TCP.to_owned(),
        other => other.to_owned(),
    }
}

fn normalize_dev(dev: &str) -> String {
    let trimmed = dev.trim().to_ascii_lowercase();
    if trimmed.is_empty() {
        "tun".to_owned()
    } else {
        trimmed
    }
}

fn normalize_cipher(cipher: &str) -> String {
    let trimmed = cipher.trim().to_ascii_uppercase();
    if trimmed.is_empty() {
        CIPHER_AES_128_GCM.to_owned()
    } else {
        trimmed
    }
}

fn normalize_auth(auth: &str) -> String {
    let trimmed = auth.trim().to_ascii_uppercase();
    if trimmed.is_empty() {
        AUTH_SHA256.to_owned()
    } else {
        trimmed
    }
}

fn validate_install_script_subset(
    remote_host: &str,
    remote_port: u16,
    proto: &str,
    dev: &str,
    cipher: &str,
    auth: &str,
    ca: &[u8],
    cert: &[u8],
    key: &[u8],
    tls_crypt: &[u8],
    username: &str,
) -> Result<(), TransportError> {
    let _ = remote_port;
    if remote_host.is_empty() {
        return Err(TransportError::InvalidPlan(
            "openvpn config requires remote host and port".to_owned(),
        ));
    }
    if dev != "tun" {
        return Err(TransportError::InvalidPlan(format!(
            "unsupported openvpn dev {dev:?}: only dev tun is supported"
        )));
    }
    if proto != PROTO_UDP && proto != PROTO_TCP {
        return Err(TransportError::InvalidPlan(format!(
            "unsupported openvpn proto {proto:?}: only udp and tcp are supported"
        )));
    }
    if cipher != CIPHER_AES_128_GCM && cipher != CIPHER_AES_256_GCM {
        return Err(TransportError::InvalidPlan(format!(
            "unsupported openvpn cipher {cipher:?}: only {CIPHER_AES_128_GCM} and {CIPHER_AES_256_GCM} are supported"
        )));
    }
    if auth != AUTH_SHA256 {
        return Err(TransportError::InvalidPlan(format!(
            "unsupported openvpn auth {auth:?}: only {AUTH_SHA256} is supported"
        )));
    }
    if ca.is_empty() {
        return Err(TransportError::InvalidPlan(
            "openvpn config requires inline <ca> block".to_owned(),
        ));
    }
    if tls_crypt.is_empty() {
        return Err(TransportError::InvalidPlan(
            "openvpn config requires inline <tls-crypt> block".to_owned(),
        ));
    }

    let has_cert = !cert.is_empty() || !key.is_empty();
    if has_cert {
        if cert.is_empty() || key.is_empty() {
            return Err(TransportError::InvalidPlan(
                "openvpn cert and key must both be set when using client certificate auth"
                    .to_owned(),
            ));
        }
    } else if username.is_empty() {
        return Err(TransportError::InvalidPlan(
            "openvpn requires either cert+key or username (auth-user-pass)".to_owned(),
        ));
    }

    Ok(())
}

pub(crate) fn decode_static_key(block: &[u8]) -> Result<Vec<u8>, TransportError> {
    let mut hex_lines = Vec::new();
    let block_text = String::from_utf8_lossy(block);
    for raw in block_text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with("-----BEGIN OpenVPN Static key")
            || line.starts_with("-----END OpenVPN Static key")
        {
            continue;
        }
        hex_lines.push(line);
    }
    let encoded = hex_lines.join("");
    let key = hex::decode(encoded)
        .map_err(|err| TransportError::InvalidPlan(format!("parse tls-crypt key: {err}")))?;
    if key.len() != 256 {
        return Err(TransportError::InvalidPlan(format!(
            "invalid static key length {}, expected 256 bytes",
            key.len()
        )));
    }
    Ok(key)
}
