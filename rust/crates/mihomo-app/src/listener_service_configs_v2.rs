use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use mihomo_inbound::{BaseInboundConfig, GenericInboundConfig};
use mihomo_transport::XHttpOptions;
use rustls::ServerConfig;

use crate::listener_service_support::{
    build_server_tls_config, extra_string, nested_string, nested_string_map_list, non_empty_or,
};
use crate::listener_service::listener_service_xhttp::{xhttp_options, PendingXhttpSession};

use super::ListenerServiceError;

#[derive(Clone, Debug)]
pub(crate) struct VmessInboundConfig {
    pub(crate) base: BaseInboundConfig,
    pub(crate) uuids: Vec<String>,
    pub(crate) network: String,
    pub(crate) ws_path: String,
    pub(crate) grpc_service_name: String,
    pub(crate) http: mihomo_transport::HttpStreamOptions,
    pub(crate) h2_hosts: Vec<String>,
    pub(crate) h2_path: String,
    pub(crate) xhttp: XHttpOptions,
    pub(crate) xhttp_sessions: Arc<Mutex<HashMap<String, PendingXhttpSession>>>,
    pub(crate) tls_config: Option<Arc<ServerConfig>>,
}

#[derive(Clone, Debug)]
pub(crate) struct VlessInboundConfig {
    pub(crate) base: BaseInboundConfig,
    pub(crate) uuids: Vec<String>,
    pub(crate) reality: Option<mihomo_transport::RealityServerConfig>,
    pub(crate) network: String,
    pub(crate) ws_path: String,
    pub(crate) grpc_service_name: String,
    pub(crate) http: mihomo_transport::HttpStreamOptions,
    pub(crate) h2_hosts: Vec<String>,
    pub(crate) h2_path: String,
    pub(crate) xhttp: XHttpOptions,
    pub(crate) xhttp_sessions: Arc<Mutex<HashMap<String, PendingXhttpSession>>>,
    pub(crate) tls_config: Option<Arc<ServerConfig>>,
}

struct SharedV2Settings {
    network: String,
    reality: Option<mihomo_transport::RealityServerConfig>,
    ws_path: String,
    grpc_service_name: String,
    http: mihomo_transport::HttpStreamOptions,
    h2_hosts: Vec<String>,
    h2_path: String,
    xhttp: XHttpOptions,
    tls_config: Option<Arc<ServerConfig>>,
}

impl VmessInboundConfig {
    pub(crate) fn try_from_generic(
        config: &GenericInboundConfig,
    ) -> Result<Self, ListenerServiceError> {
        let uuids = parse_v2_listener_user_uuids(config, "vmess")?;
        let settings = parse_shared_v2_settings(config, "vmess")?;
        Ok(Self {
            base: config.base.clone(),
            uuids,
            network: settings.network,
            ws_path: settings.ws_path,
            grpc_service_name: settings.grpc_service_name,
            http: settings.http,
            h2_hosts: settings.h2_hosts,
            h2_path: settings.h2_path,
            xhttp: settings.xhttp,
            xhttp_sessions: Arc::new(Mutex::new(HashMap::new())),
            tls_config: settings.tls_config,
        })
    }
}

impl VlessInboundConfig {
    pub(crate) fn try_from_generic(
        config: &GenericInboundConfig,
    ) -> Result<Self, ListenerServiceError> {
        let uuids = parse_v2_listener_user_uuids(config, "vless")?;
        let settings = parse_shared_v2_settings(config, "vless")?;
        Ok(Self {
            base: config.base.clone(),
            uuids,
            reality: settings.reality,
            network: settings.network,
            ws_path: settings.ws_path,
            grpc_service_name: settings.grpc_service_name,
            http: settings.http,
            h2_hosts: settings.h2_hosts,
            h2_path: settings.h2_path,
            xhttp: settings.xhttp,
            xhttp_sessions: Arc::new(Mutex::new(HashMap::new())),
            tls_config: settings.tls_config,
        })
    }
}

/// Collects every configured user UUID so the listener can authenticate
/// multiple clients (Go's `users` list semantics).
fn parse_v2_listener_user_uuids(
    config: &GenericInboundConfig,
    protocol: &str,
) -> Result<Vec<String>, ListenerServiceError> {
    let users = config
        .extra
        .get("users")
        .and_then(serde_yaml::Value::as_sequence)
        .ok_or_else(|| {
            ListenerServiceError::Rule(format!("{protocol} listener requires users"))
        })?;
    let mut uuids = Vec::new();
    for entry in users {
        let Some(user) = entry.as_mapping() else {
            return Err(ListenerServiceError::Rule(format!(
                "{protocol} listener user entry must be a mapping"
            )));
        };
        let uuid = user
            .get(serde_yaml::Value::String("uuid".to_owned()))
            .and_then(serde_yaml::Value::as_str)
            .unwrap_or_default()
            .trim()
            .to_owned();
        if uuid.is_empty() {
            return Err(ListenerServiceError::Rule(format!(
                "{protocol} listener requires user uuid"
            )));
        }
        uuids.push(uuid);
    }
    if uuids.is_empty() {
        return Err(ListenerServiceError::Rule(format!(
            "{protocol} listener requires at least one user"
        )));
    }
    Ok(uuids)
}

fn parse_shared_v2_settings(
    config: &GenericInboundConfig,
    label: &str,
) -> Result<SharedV2Settings, ListenerServiceError> {
    let network = non_empty_or(extra_string(&config.extra, "network"), "tcp");
    if network != "tcp"
        && network != "ws"
        && network != "grpc"
        && network != "http"
        && network != "h2"
        && network != "xhttp"
        && !network.is_empty()
    {
        return Err(ListenerServiceError::Rule(format!(
            "{label} listener inbound network is not implemented yet: {network}"
        )));
    }
    let ws_path = if network == "ws" {
        non_empty_or(
            nested_string(&config.extra, "ws-opts", "path")
                .or_else_if_empty(extra_string(&config.extra, "ws-path")),
            "/",
        )
    } else {
        String::new()
    };
    let grpc_service_name = if network == "grpc" {
        non_empty_or(
            nested_string(&config.extra, "grpc-opts", "grpc-service-name")
                .or_else_if_empty(extra_string(&config.extra, "grpc-service-name")),
            "GunService",
        )
    } else {
        String::new()
    };
    let http = if network == "http" {
        build_http_options(&config.extra)
    } else {
        mihomo_transport::HttpStreamOptions::default()
    };
    let h2_hosts = if network == "h2" {
        config
            .extra
            .get("h2-opts")
            .and_then(serde_yaml::Value::as_mapping)
            .and_then(|mapping| mapping.get(&serde_yaml::Value::String("host".to_owned())))
            .and_then(serde_yaml::Value::as_sequence)
            .map(|items| {
                items
                    .iter()
                    .filter_map(serde_yaml::Value::as_str)
                    .map(str::to_owned)
                    .filter(|value| !value.trim().is_empty())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    let h2_path = if network == "h2" {
        config
            .extra
            .get("h2-opts")
            .and_then(serde_yaml::Value::as_mapping)
            .and_then(|mapping| mapping.get(&serde_yaml::Value::String("path".to_owned())))
            .and_then(serde_yaml::Value::as_str)
            .map(str::to_owned)
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "/".to_owned())
    } else {
        String::new()
    };
    let xhttp = if network == "xhttp" {
        xhttp_options(&config.extra)
    } else {
        XHttpOptions::default()
    };
    let certificate = extra_string(&config.extra, "certificate");
    let private_key = extra_string(&config.extra, "private-key");
    let has_reality = config.extra.get("reality-config").is_some();
    let reality = if has_reality {
        parse_reality_server_config(&config.extra)?
    } else {
        None
    };
    let tls_config = if certificate.trim().is_empty() && private_key.trim().is_empty() {
        None
    } else {
        if has_reality {
            return Err(ListenerServiceError::Rule(format!(
                "{label} listener cannot combine certificate with reality-config"
            )));
        }
        Some(Arc::new(build_server_tls_config(
            &certificate,
            &private_key,
            &network,
            &extra_string(&config.extra, "client-auth-type"),
            &extra_string(&config.extra, "client-auth-cert"),
            &extra_string(&config.extra, "ech-key"),
            false,
        )?))
    };
    Ok(SharedV2Settings {
        network,
        reality,
        ws_path,
        grpc_service_name,
        http,
        h2_hosts,
        h2_path,
        xhttp,
        tls_config,
    })
}

/// Parses the inbound `reality-config` block (dest, server-names,
/// private-key, short-id list).
fn parse_reality_server_config(
    extra: &std::collections::BTreeMap<String, serde_yaml::Value>,
) -> Result<Option<mihomo_transport::RealityServerConfig>, ListenerServiceError> {
    let Some(mapping) = extra
        .get("reality-config")
        .and_then(serde_yaml::Value::as_mapping)
    else {
        return Ok(None);
    };
    let get_str = |key: &str| -> String {
        mapping
            .get(serde_yaml::Value::String(key.to_owned()))
            .and_then(serde_yaml::Value::as_str)
            .unwrap_or_default()
            .trim()
            .to_owned()
    };
    let private_key_value = get_str("private-key");
    if private_key_value.is_empty() {
        return Err(ListenerServiceError::Rule(
            "reality-config requires private-key".to_owned(),
        ));
    }
    let private_key = mihomo_transport::parse_reality_private_key(&private_key_value)
        .map_err(|err| ListenerServiceError::Rule(err.to_string()))?;
    let server_names = mapping
        .get(serde_yaml::Value::String("server-names".to_owned()))
        .and_then(serde_yaml::Value::as_sequence)
        .map(|items| {
            items
                .iter()
                .filter_map(serde_yaml::Value::as_str)
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if server_names.is_empty() {
        return Err(ListenerServiceError::Rule(
            "reality-config requires server-names".to_owned(),
        ));
    }
    let dest = get_str("dest");
    if dest.is_empty() {
        return Err(ListenerServiceError::Rule(
            "reality-config requires dest".to_owned(),
        ));
    }
    let mut short_ids = Vec::new();
    if let Some(entries) = mapping
        .get(serde_yaml::Value::String("short-id".to_owned()))
        .and_then(serde_yaml::Value::as_sequence)
    {
        for entry in entries {
            let value = entry.as_str().unwrap_or_default().trim().to_owned();
            let parsed = mihomo_transport::parse_reality_short_id(&value)
                .map_err(|err| ListenerServiceError::Rule(err.to_string()))?;
            short_ids.push(parsed);
        }
    }
    Ok(Some(mihomo_transport::RealityServerConfig {
        private_key,
        server_names,
        short_ids,
        dest,
        max_time_diff: 0,
    }))
}

fn build_http_options(
    extra: &std::collections::BTreeMap<String, serde_yaml::Value>,
) -> mihomo_transport::HttpStreamOptions {
    let host = {
        let values = extra
            .get("http-opts")
            .and_then(serde_yaml::Value::as_mapping)
            .and_then(|mapping| mapping.get(&serde_yaml::Value::String("host".to_owned())))
            .and_then(serde_yaml::Value::as_sequence)
            .map(|items| {
                items
                    .iter()
                    .filter_map(serde_yaml::Value::as_str)
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if values.is_empty() {
            let single = nested_string(extra, "http-opts", "host");
            if single.trim().is_empty() {
                Vec::new()
            } else {
                vec![single]
            }
        } else {
            values
        }
    };
    let path = {
        let values = extra
            .get("http-opts")
            .and_then(serde_yaml::Value::as_mapping)
            .and_then(|mapping| mapping.get(&serde_yaml::Value::String("path".to_owned())))
            .and_then(serde_yaml::Value::as_sequence)
            .map(|items| {
                items
                    .iter()
                    .filter_map(serde_yaml::Value::as_str)
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if values.is_empty() {
            let single = nested_string(extra, "http-opts", "path");
            if single.trim().is_empty() {
                Vec::new()
            } else {
                vec![single]
            }
        } else {
            values
        }
    };
    mihomo_transport::HttpStreamOptions {
        method: nested_string(extra, "http-opts", "method"),
        host,
        path,
        headers: nested_string_map_list(extra, "http-opts", "headers"),
    }
}

trait OrElseIfEmpty {
    fn or_else_if_empty(self, fallback: String) -> String;
}

impl OrElseIfEmpty for String {
    fn or_else_if_empty(self, fallback: String) -> String {
        if self.trim().is_empty() {
            fallback
        } else {
            self
        }
    }
}
