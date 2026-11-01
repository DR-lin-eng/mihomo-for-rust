use std::collections::BTreeMap;

use mihomo_config::TuicServerConfig;
use mihomo_inbound::{BaseInboundConfig, GenericInboundConfig};

use crate::listener_service_support::{extra_i32, extra_string, extra_string_list};

#[derive(Clone, Debug)]
pub(crate) struct TuicListenerConfig {
    pub base: BaseInboundConfig,
    pub token: Vec<String>,
    pub users: BTreeMap<String, String>,
    pub certificate: String,
    pub private_key: String,
    pub alpn: Vec<String>,
    pub max_udp_relay_packet_size: usize,
    pub client_auth_type: String,
    pub client_auth_cert: String,
}

impl TuicListenerConfig {
    pub(crate) fn try_from_generic(config: &GenericInboundConfig) -> Result<Self, String> {
        let token = extra_string_list(&config.extra, "token");
        let users = config
            .extra
            .get("users")
            .and_then(serde_yaml::Value::as_mapping)
            .map(|mapping| {
                mapping
                    .iter()
                    .filter_map(|(key, value)| {
                        Some((key.as_str()?.to_owned(), value.as_str()?.to_owned()))
                    })
                    .collect::<BTreeMap<_, _>>()
            })
            .unwrap_or_default();
        if token.is_empty() && users.is_empty() {
            return Err("tuic listener requires token and/or users".to_owned());
        }
        let certificate = extra_string(&config.extra, "certificate");
        let private_key = extra_string(&config.extra, "private-key");
        if certificate.trim().is_empty() || private_key.trim().is_empty() {
            return Err("tuic listener requires certificate and private-key".to_owned());
        }
        let client_auth_type = extra_string(&config.extra, "client-auth-type");
        let client_auth_cert = extra_string(&config.extra, "client-auth-cert");
        if !extra_string(&config.extra, "ech-key").trim().is_empty() {
            return Err("tuic listener ech is not implemented yet".to_owned());
        }
        let alpn = {
            let values = extra_string_list(&config.extra, "alpn");
            if values.is_empty() {
                vec!["h3".to_owned()]
            } else {
                values
            }
        };
        let max_udp_relay_packet_size = extra_i32(&config.extra, "max-udp-relay-packet-size");
        Ok(Self {
            base: config.base.clone(),
            token,
            users,
            certificate,
            private_key,
            alpn,
            max_udp_relay_packet_size: if max_udp_relay_packet_size <= 0 {
                1500
            } else {
                max_udp_relay_packet_size as usize
            },
            client_auth_type,
            client_auth_cert,
        })
    }

    pub(crate) fn from_top_level(config: &TuicServerConfig) -> Result<Self, String> {
        if config.token.is_empty() && config.users.is_empty() {
            return Err("top-level tuic-server requires token and/or users".to_owned());
        }
        if config.certificate.trim().is_empty() || config.private_key.trim().is_empty() {
            return Err("top-level tuic-server requires certificate and private-key".to_owned());
        }
        if !config.ech_key.trim().is_empty() {
            return Err("top-level tuic-server ech is not implemented yet".to_owned());
        }
        Ok(Self {
            base: BaseInboundConfig {
                name: "__top_level_tuic__".to_owned(),
                listen: String::new(),
                port: String::new(),
                special_rules: String::new(),
                special_proxy: String::new(),
            },
            token: config.token.clone(),
            users: config.users.clone(),
            certificate: config.certificate.clone(),
            private_key: config.private_key.clone(),
            alpn: if config.alpn.is_empty() {
                vec!["h3".to_owned()]
            } else {
                config.alpn.clone()
            },
            max_udp_relay_packet_size: if config.max_udp_relay_packet_size <= 0 {
                1500
            } else {
                config.max_udp_relay_packet_size as usize
            },
            client_auth_type: config.client_auth_type.clone(),
            client_auth_cert: config.client_auth_cert.clone(),
        })
    }
}
