use std::collections::BTreeMap;

use mihomo_inbound::{BaseInboundConfig, GenericInboundConfig};
use mihomo_transport::Hy2RealmOptions;

use crate::listener_service_support::{extra_i32, extra_string, extra_string_list};

#[derive(Clone, Debug)]
pub(crate) struct Hy2ListenerConfig {
    pub base: BaseInboundConfig,
    pub users: BTreeMap<String, String>,
    pub obfs: String,
    pub obfs_password: String,
    pub certificate: String,
    pub private_key: String,
    pub alpn: Vec<String>,
    pub udp_mtu: usize,
    pub realm: Hy2RealmOptions,
    pub client_auth_type: String,
    pub client_auth_cert: String,
}

impl Hy2ListenerConfig {
    pub(crate) fn try_from_generic(config: &GenericInboundConfig) -> Result<Self, String> {
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
        if users.is_empty() {
            return Err("hysteria2 listener requires users".to_owned());
        }
        let certificate = extra_string(&config.extra, "certificate");
        let private_key = extra_string(&config.extra, "private-key");
        if certificate.trim().is_empty() || private_key.trim().is_empty() {
            return Err("hysteria2 listener requires certificate and private-key".to_owned());
        }
        let obfs = extra_string(&config.extra, "obfs");
        let obfs_password = extra_string(&config.extra, "obfs-password");
        if !obfs.is_empty() && obfs != "salamander" {
            return Err(format!("hysteria2 listener obfs={} is not implemented", obfs));
        }
        if obfs == "salamander" && obfs_password.trim().is_empty() {
            return Err("hysteria2 listener salamander requires obfs-password".to_owned());
        }
        let client_auth_type = extra_string(&config.extra, "client-auth-type");
        let client_auth_cert = extra_string(&config.extra, "client-auth-cert");
        if !extra_string(&config.extra, "ech-key").trim().is_empty() {
            return Err("hysteria2 listener ech is not implemented yet".to_owned());
        }
        Ok(Self {
            base: config.base.clone(),
            users,
            obfs,
            obfs_password,
            certificate,
            private_key,
            alpn: {
                let values = extra_string_list(&config.extra, "alpn");
                if values.is_empty() {
                    vec!["h3".to_owned()]
                } else {
                    values
                }
            },
            udp_mtu: {
                let value = extra_i32(&config.extra, "udp-mtu");
                if value <= 0 { 1197 } else { value as usize }
            },
            realm: realm_options_from_generic(config),
            client_auth_type,
            client_auth_cert,
        })
    }
}

fn realm_options_from_generic(config: &GenericInboundConfig) -> Hy2RealmOptions {
    let mapping = config
        .extra
        .get("realm-opts")
        .and_then(serde_yaml::Value::as_mapping);
    let string_field = |key: &str| {
        mapping
            .and_then(|mapping| mapping.get(&serde_yaml::Value::String(key.to_owned())))
            .and_then(serde_yaml::Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };
    let bool_field = |key: &str| {
        mapping
            .and_then(|mapping| mapping.get(&serde_yaml::Value::String(key.to_owned())))
            .and_then(serde_yaml::Value::as_bool)
            .unwrap_or(false)
    };
    let list_field = |key: &str| {
        mapping
            .and_then(|mapping| mapping.get(&serde_yaml::Value::String(key.to_owned())))
            .and_then(serde_yaml::Value::as_sequence)
            .map(|items| {
                items
                    .iter()
                    .filter_map(serde_yaml::Value::as_str)
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    };
    Hy2RealmOptions {
        enabled: bool_field("enable"),
        server_url: string_field("server-url"),
        token: string_field("token"),
        realm_id: string_field("realm-id"),
        stun_servers: list_field("stun-servers"),
        sni: string_field("sni"),
        skip_cert_verify: bool_field("skip-cert-verify"),
        fingerprint: string_field("fingerprint"),
        certificate: string_field("certificate"),
        private_key: string_field("private-key"),
        alpn: list_field("alpn"),
        proxy: string_field("proxy"),
        proxy_plan: None,
    }
}
