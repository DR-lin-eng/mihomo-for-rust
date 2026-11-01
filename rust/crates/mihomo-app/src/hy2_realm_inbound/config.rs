use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::SocketAddr;
use std::sync::{
    Arc, Condvar, Mutex,
};
use std::time::{Duration, Instant};

use mihomo_inbound::{BaseInboundConfig, GenericInboundConfig};
use regex::Regex;
use rustls::ServerConfig;
use serde::Serialize;

use mihomo_core::TcpStream as MihomoTcpStream;

use crate::listener_service_support::{build_server_tls_config, extra_i32, extra_string};

const SESSION_TTL: Duration = Duration::from_secs(60);
const CONNECT_RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_REQUEST_BODY_BYTES: usize = 4 << 10;
const EVENTS_BUFFER_SIZE: usize = 16;
const MAX_PENDING_ATTEMPTS: usize = EVENTS_BUFFER_SIZE;
const MAX_ADDRESSES: usize = 8;
const NONCE_HEX_LEN: usize = 32;
const OBFS_HEX_LEN: usize = 64;
const DEFAULT_MAX_REALMS: i32 = 65_536;
const DEFAULT_MAX_REALMS_PER_IP: i32 = 4;
const DEFAULT_REALM_NAME_PATTERN: &str = "^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$";

#[derive(Clone, Debug)]
pub(super) struct Hy2RealmListenerConfig {
    pub base: BaseInboundConfig,
    pub token: String,
    pub max_realms: usize,
    pub max_realms_per_ip: usize,
    pub trusted_proxy_header: String,
    pub realm_name_pattern: String,
    pub tls_config: Option<Arc<ServerConfig>>,
}

impl Hy2RealmListenerConfig {
    pub(super) fn try_from_generic(config: &GenericInboundConfig) -> Result<Self, String> {
        let token = extra_string(&config.extra, "token");
        if token.trim().is_empty() {
            return Err("hysteria2-realm listener requires token".to_owned());
        }
        let realm_name_pattern = {
            let value = extra_string(&config.extra, "realm-name-pattern");
            if value.trim().is_empty() {
                DEFAULT_REALM_NAME_PATTERN.to_owned()
            } else {
                value
            }
        };
        Regex::new(&realm_name_pattern)
            .map_err(|err| format!("invalid hysteria2-realm realm-name-pattern: {err}"))?;

        let certificate = extra_string(&config.extra, "certificate");
        let private_key = extra_string(&config.extra, "private-key");
        let tls_config = if certificate.trim().is_empty() && private_key.trim().is_empty() {
            None
        } else {
            Some(Arc::new(
                build_server_tls_config(
                    &certificate,
                    &private_key,
                    "h2",
                    &extra_string(&config.extra, "client-auth-type"),
                    &extra_string(&config.extra, "client-auth-cert"),
                    &extra_string(&config.extra, "ech-key"),
                    false,
                )
                .map_err(|err| err.to_string())?,
            ))
        };

        Ok(Self {
            base: config.base.clone(),
            token,
            max_realms: normalize_limit(extra_i32(&config.extra, "max-realms"), DEFAULT_MAX_REALMS),
            max_realms_per_ip: normalize_limit(
                extra_i32(&config.extra, "max-realms-per-ip"),
                DEFAULT_MAX_REALMS_PER_IP,
            ),
            trusted_proxy_header: extra_string(&config.extra, "trusted-proxy-header"),
            realm_name_pattern,
            tls_config,
        })
    }
}

fn normalize_limit(value: i32, default_value: i32) -> usize {
    if value == 0 {
        0
    } else if value < 0 {
        default_value as usize
    } else {
        value as usize
    }
}
