#[path = "listener_service_configs_v2.rs"]
mod listener_service_configs_v2;

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::sync::Mutex;

use mihomo_inbound::{BaseInboundConfig, GenericInboundConfig};
use mihomo_transport::{SudokuHttpMaskServerAcceptor, XHttpOptions};
use rustls::ServerConfig;

use super::listener_service_models::ListenerAuthUser;
use crate::listener_service_support::{
    build_server_tls_config, extra_bool, extra_contains_key, extra_i32, extra_string,
    extra_string_list, nested_optional_bool, nested_string, non_empty_or,
};
use crate::listener_service::listener_service_xhttp::PendingXhttpSession;
use super::ListenerServiceError;
pub(super) use listener_service_configs_v2::{VlessInboundConfig, VmessInboundConfig};

#[derive(Clone, Debug)]
pub(super) struct ShadowSocksListenerConfig {
    pub(super) base: BaseInboundConfig,
    pub(super) password: String,
    pub(super) cipher: String,
    pub(super) obfs_mode: String,
}

#[derive(Clone, Debug)]
pub(super) struct TrojanListenerConfig {
    pub(super) base: BaseInboundConfig,
    pub(super) password_keys: Arc<BTreeMap<String, String>>,
    pub(super) shadowsocks: mihomo_transport::TrojanShadowsocksOptions,
    pub(super) network: String,
    pub(super) ws_path: String,
    pub(super) grpc_service_name: String,
    pub(super) http: mihomo_transport::HttpStreamOptions,
    pub(super) h2_hosts: Vec<String>,
    pub(super) h2_path: String,
    pub(super) xhttp: XHttpOptions,
    pub(super) xhttp_sessions: Arc<Mutex<HashMap<String, PendingXhttpSession>>>,
    pub(super) tls_config: Option<Arc<ServerConfig>>,
}

#[derive(Clone, Debug)]
pub(super) struct AnyTlsListenerConfig {
    pub(super) base: BaseInboundConfig,
    pub(super) users: Vec<ListenerAuthUser>,
    pub(super) tls_config: Arc<ServerConfig>,
}

#[derive(Clone, Debug)]
pub(super) struct TrustTunnelListenerConfig {
    pub(super) base: BaseInboundConfig,
    pub(super) users: Vec<ListenerAuthUser>,
    pub(super) tls_config: Arc<ServerConfig>,
}

impl AnyTlsListenerConfig {
    pub(super) fn try_from_generic(
        config: &GenericInboundConfig,
    ) -> Result<Self, ListenerServiceError> {
        let users = parse_listener_users_map(config, "anytls")?;
        if users.is_empty() {
            return Err(ListenerServiceError::Rule(
                "anytls listener requires password or users".to_owned(),
            ));
        }
        let certificate = extra_string(&config.extra, "certificate");
        let private_key = extra_string(&config.extra, "private-key");
        if certificate.trim().is_empty() || private_key.trim().is_empty() {
            return Err(ListenerServiceError::Rule(
                "anytls listener requires certificate and private-key".to_owned(),
            ));
        }
        let tls_config = Arc::new(build_server_tls_config(
            &certificate,
            &private_key,
            "",
            &extra_string(&config.extra, "client-auth-type"),
            &extra_string(&config.extra, "client-auth-cert"),
            &extra_string(&config.extra, "ech-key"),
            config.extra.get("reality-config").is_some(),
        )?);
        Ok(Self {
            base: config.base.clone(),
            users,
            tls_config,
        })
    }
}

impl TrustTunnelListenerConfig {
    pub(super) fn try_from_generic(
        config: &GenericInboundConfig,
    ) -> Result<Self, ListenerServiceError> {
        let users = parse_listener_users_entries(
            config,
            &extra_string(&config.extra, "username"),
            &extra_string(&config.extra, "password"),
        );
        if users.is_empty() {
            return Err(ListenerServiceError::Rule(
                "trusttunnel listener requires username and password or users".to_owned(),
            ));
        }
        let certificate = extra_string(&config.extra, "certificate");
        let private_key = extra_string(&config.extra, "private-key");
        if certificate.trim().is_empty() || private_key.trim().is_empty() {
            return Err(ListenerServiceError::Rule(
                "trusttunnel listener requires certificate and private-key".to_owned(),
            ));
        }
        let tls_config = Arc::new(build_server_tls_config(
            &certificate,
            &private_key,
            "grpc",
            &extra_string(&config.extra, "client-auth-type"),
            &extra_string(&config.extra, "client-auth-cert"),
            &extra_string(&config.extra, "ech-key"),
            config.extra.get("reality-config").is_some(),
        )?);
        Ok(Self {
            base: config.base.clone(),
            users,
            tls_config,
        })
    }
}

/// Parses Go-style `users` mappings (`{username: password}`) with a legacy
/// flat `password` fallback kept for configs written before `users` support.
fn parse_listener_users_map(
    config: &GenericInboundConfig,
    protocol: &str,
) -> Result<Vec<ListenerAuthUser>, ListenerServiceError> {
    let mut users = Vec::new();
    if let Some(mapping) = config
        .extra
        .get("users")
        .and_then(serde_yaml::Value::as_mapping)
    {
        for (key, value) in mapping {
            let Some(username) = key.as_str() else {
                return Err(ListenerServiceError::Rule(format!(
                    "{protocol} listener users entry must map username to password"
                )));
            };
            let Some(password) = value.as_str() else {
                return Err(ListenerServiceError::Rule(format!(
                    "{protocol} listener user {username} requires a password"
                )));
            };
            users.push(ListenerAuthUser {
                username: username.trim().to_owned(),
                password: password.to_owned(),
            });
        }
    }
    let legacy = extra_string(&config.extra, "password");
    if !legacy.trim().is_empty() && !users.iter().any(|user| user.password == legacy) {
        users.push(ListenerAuthUser {
            username: String::new(),
            password: legacy,
        });
    }
    Ok(users)
}

/// Parses Go-style `users` sequences (`[{username, password}]`) with legacy
/// flat `username`/`password` fallback.
fn parse_listener_users_entries(
    config: &GenericInboundConfig,
    legacy_username: &str,
    legacy_password: &str,
) -> Vec<ListenerAuthUser> {
    let mut users = Vec::new();
    if let Some(entries) = config
        .extra
        .get("users")
        .and_then(serde_yaml::Value::as_sequence)
    {
        for entry in entries {
            let Some(mapping) = entry.as_mapping() else {
                continue;
            };
            let password = mapping
                .get(serde_yaml::Value::String("password".to_owned()))
                .and_then(serde_yaml::Value::as_str)
                .unwrap_or_default()
                .trim()
                .to_owned();
            if password.is_empty() {
                continue;
            }
            let username = mapping
                .get(serde_yaml::Value::String("username".to_owned()))
                .and_then(serde_yaml::Value::as_str)
                .unwrap_or_default()
                .trim()
                .to_owned();
            users.push(ListenerAuthUser { username, password });
        }
    }
    if !legacy_password.trim().is_empty()
        && !users
            .iter()
            .any(|user| user.password == legacy_password && user.username == legacy_username)
    {
        users.push(ListenerAuthUser {
            username: legacy_username.to_owned(),
            password: legacy_password.to_owned(),
        });
    }
    users
}

#[derive(Clone, Debug)]
pub(super) struct SudokuInboundConfig {
    pub(super) base: BaseInboundConfig,
    pub(super) key: String,
    pub(super) aead_method: String,
    pub(super) table_type: String,
    pub(super) padding_min: i32,
    pub(super) padding_max: i32,
    pub(super) enable_pure_downlink: bool,
    pub(super) http_mask_enabled: bool,
    pub(super) http_mask_mode: String,
    pub(super) fallback: String,
    pub(super) http_mask_acceptor: Option<Arc<SudokuHttpMaskServerAcceptor>>,
    pub(super) tls_config: Option<Arc<ServerConfig>>,
    pub(super) custom_table: String,
    pub(super) custom_tables: Vec<String>,
}

pub(super) fn parse_trojan_shadowsocks_options(
    extra: &std::collections::BTreeMap<String, serde_yaml::Value>,
) -> Result<mihomo_transport::TrojanShadowsocksOptions, ListenerServiceError> {
    let Some(mapping) = extra
        .get("ss-option")
        .and_then(serde_yaml::Value::as_mapping)
    else {
        return Ok(mihomo_transport::TrojanShadowsocksOptions::default());
    };

    let enabled = mapping
        .get(serde_yaml::Value::String("enabled".to_owned()))
        .and_then(serde_yaml::Value::as_bool)
        .unwrap_or(false);
    if !enabled {
        return Ok(mihomo_transport::TrojanShadowsocksOptions::default());
    }

    let method = mapping
        .get(serde_yaml::Value::String("method".to_owned()))
        .and_then(serde_yaml::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("AES-128-GCM")
        .to_owned();
    let password = mapping
        .get(serde_yaml::Value::String("password".to_owned()))
        .and_then(serde_yaml::Value::as_str)
        .map(str::trim)
        .unwrap_or_default()
        .to_owned();
    if password.is_empty() {
        return Err(ListenerServiceError::Rule(
            "trojan listener ss-option requires password when enabled".to_owned(),
        ));
    }

    Ok(mihomo_transport::TrojanShadowsocksOptions {
        enabled,
        method,
        password,
    })
}


impl SudokuInboundConfig {
    pub(super) fn try_from_generic(
        config: &GenericInboundConfig,
    ) -> Result<Self, ListenerServiceError> {
        let extra = &config.extra;
        let key = extra_string(extra, "key");
        if key.trim().is_empty() {
            return Err(ListenerServiceError::Rule(
                "sudoku listener requires key".to_owned(),
            ));
        }

        let nested_httpmask_disable = nested_optional_bool(extra, "httpmask", "disable");
        let nested_httpmask_mode = nested_string(extra, "httpmask", "mode");
        let nested_httpmask_path_root = nested_string(extra, "httpmask", "path-root");
        let nested_httpmask_host = nested_string(extra, "httpmask", "host");
        let nested_httpmask_tls = nested_optional_bool(extra, "httpmask", "tls").unwrap_or(false);
        let has_nested_httpmask = extra
            .get("httpmask")
            .and_then(serde_yaml::Value::as_mapping)
            .is_some();

        let http_mask_enabled = if extra_contains_key(extra, "http-mask") {
            extra_bool(extra, "http-mask")
        } else if extra_contains_key(extra, "disable-http-mask") {
            !extra_bool(extra, "disable-http-mask")
        } else if let Some(disable) = nested_httpmask_disable {
            !disable
        } else if has_nested_httpmask {
            true
        } else {
            false
        };
        let http_mask_mode = extra_string(extra, "http-mask-mode");
        let http_mask_mode = if http_mask_mode.trim().is_empty() {
            nested_httpmask_mode
        } else {
            http_mask_mode
        };
        let path_root = {
            let flat = extra_string(extra, "path-root");
            if flat.trim().is_empty() {
                nested_httpmask_path_root
            } else {
                flat
            }
        };
        let http_mask_host = {
            let flat = extra_string(extra, "http-mask-host");
            if flat.trim().is_empty() {
                nested_httpmask_host
            } else {
                flat
            }
        };
        let http_mask_tls = if extra_contains_key(extra, "http-mask-tls") {
            extra_bool(extra, "http-mask-tls")
        } else {
            nested_httpmask_tls
        };
        let http_mask_acceptor = if http_mask_enabled && !http_mask_mode.trim().is_empty() {
            SudokuHttpMaskServerAcceptor::new(
                &key,
                &http_mask_mode,
                http_mask_tls,
                &http_mask_host,
                &path_root,
                !extra_string(extra, "fallback").trim().is_empty(),
            )
            .map_err(|err| ListenerServiceError::Rule(err.to_string()))?
            .map(Arc::new)
        } else {
            None
        };
        let certificate = extra_string(extra, "certificate");
        let private_key = extra_string(extra, "private-key");
        let tls_config = if certificate.trim().is_empty() && private_key.trim().is_empty() {
            None
        } else {
            Some(Arc::new(build_server_tls_config(
                &certificate,
                &private_key,
                "",
                &extra_string(extra, "client-auth-type"),
                &extra_string(extra, "client-auth-cert"),
                &extra_string(extra, "ech-key"),
                extra.get("reality-config").is_some(),
            )?))
        };

        Ok(Self {
            base: config.base.clone(),
            key,
            aead_method: non_empty_or(extra_string(extra, "aead-method"), "chacha20-poly1305"),
            table_type: non_empty_or(extra_string(extra, "table-type"), "prefer_entropy"),
            padding_min: extra_i32(extra, "padding-min"),
            padding_max: if extra_contains_key(extra, "padding-max") {
                extra_i32(extra, "padding-max")
            } else {
                0
            },
            enable_pure_downlink: if extra_contains_key(extra, "enable-pure-downlink") {
                extra_bool(extra, "enable-pure-downlink")
            } else {
                true
            },
            http_mask_enabled,
            http_mask_mode,
            fallback: extra_string(extra, "fallback").trim().to_owned(),
            http_mask_acceptor,
            tls_config,
            custom_table: extra_string(extra, "custom-table"),
            custom_tables: extra_string_list(extra, "custom-tables"),
        })
    }
}
