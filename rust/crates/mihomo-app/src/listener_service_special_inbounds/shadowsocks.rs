use std::io;
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;

use mihomo_core::{BoxedTcpStream, ConnectionContext, Metadata, NetworkKind, SessionKind};
use mihomo_inbound::ShadowSocksInboundConfig;
use mihomo_runtime::{ListenerRuntimeError, RuntimeTunnel};
use mihomo_transport::accept_shadowsocks_test_stream;

use super::common::read_shadowsocks_target;
use crate::ListenerServiceError;
use crate::listener_service::listener_service_configs::ShadowSocksListenerConfig;
impl ShadowSocksListenerConfig {
    pub(in crate::listener_service) fn try_from_inbound(
        config: &ShadowSocksInboundConfig,
    ) -> Result<Self, ListenerServiceError> {
        if config.password.trim().is_empty() {
            return Err(ListenerServiceError::Rule(
                "shadowsocks listener requires password".to_owned(),
            ));
        }
        if config.cipher.trim().is_empty() {
            return Err(ListenerServiceError::Rule(
                "shadowsocks listener requires cipher".to_owned(),
            ));
        }
        if !config.shadow_tls.is_empty()
            || !config.kcp_tun.is_empty()
            || !config.mux_option.is_empty()
        {
            return Err(ListenerServiceError::Rule(
                "shadowsocks listener advanced shadow-tls/kcp-tun/mux inbound features are not implemented yet"
                    .to_owned(),
            ));
        }
        if config.simple_obfs.enable {
            let mode = config.simple_obfs.mode.trim();
            if mode != "http" && mode != "tls" {
                return Err(ListenerServiceError::Rule(format!(
                    "unsupported shadowsocks listener simple-obfs mode: {}",
                    config.simple_obfs.mode
                )));
            }
        }
        if mihomo_transport::is_shadowsocks_2022_cipher(&config.cipher) {
            if config.simple_obfs.enable {
                return Err(ListenerServiceError::Rule(
                    "shadowsocks 2022 listener does not support simple-obfs yet".to_owned(),
                ));
            }
            let psk_len =
                mihomo_transport::validate_shadowsocks_2022_psk(&config.cipher, &config.password)
                    .map_err(|err| ListenerServiceError::Rule(err.to_string()))?;
            let _ = psk_len;
        }
        Ok(Self {
            base: config.base.clone(),
            password: config.password.clone(),
            cipher: config.cipher.clone(),
            obfs_mode: if config.simple_obfs.enable {
                config.simple_obfs.mode.clone()
            } else {
                String::new()
            },
        })
    }
}

pub(in crate::listener_service) fn handle_shadowsocks_connection(
    config: ShadowSocksListenerConfig,
    tunnel: Arc<RuntimeTunnel>,
    stream: TcpStream,
    peer_addr: Option<SocketAddr>,
) -> Result<(), ListenerRuntimeError> {
    if mihomo_transport::is_shadowsocks_2022_cipher(&config.cipher) {
        let (target, stream) = mihomo_transport::accept_shadowsocks_2022_stream(
            Box::new(stream),
            &config.cipher,
            &config.password,
        )
        .map_err(|err| ListenerRuntimeError::Io(io::Error::other(err.to_string())))?;
        let mut metadata = Metadata {
            network: NetworkKind::Tcp,
            kind: SessionKind::ShadowSocks,
            inbound_name: config.base.name.clone(),
            special_proxy: config.base.special_proxy.clone(),
            special_rules: config.base.special_rules.clone(),
            ..Metadata::default()
        };
        if let Some(peer) = peer_addr {
            metadata.src_ip = Some(peer.ip());
            metadata.src_port = Some(peer.port());
        }
        metadata
            .set_remote_address(&target.authority())
            .map_err(ListenerRuntimeError::from)?;
        let mut context = ConnectionContext::new(stream, metadata);
        tunnel
            .forward_tcp_context_with_system_dialer(&mut context)
            .map_err(ListenerRuntimeError::from)?;
        return Ok(());
    }
    let stream: BoxedTcpStream = if config.obfs_mode.trim() == "http" {
        mihomo_transport::accept_simple_obfs_http_test_stream(Box::new(stream))
    } else if config.obfs_mode.trim() == "tls" {
        mihomo_transport::accept_simple_obfs_tls_test_stream(Box::new(stream))
    } else {
        Box::new(stream)
    };
    let mut stream = accept_shadowsocks_test_stream(stream, &config.cipher, &config.password)
        .map_err(|err| ListenerRuntimeError::Io(io::Error::other(err.to_string())))?;
    let target = read_shadowsocks_target(&mut *stream)?;
    let mut metadata = Metadata {
        network: NetworkKind::Tcp,
        kind: SessionKind::ShadowSocks,
        inbound_name: config.base.name.clone(),
        special_proxy: config.base.special_proxy.clone(),
        special_rules: config.base.special_rules.clone(),
        ..Metadata::default()
    };
    if let Some(peer) = peer_addr {
        metadata.src_ip = Some(peer.ip());
        metadata.src_port = Some(peer.port());
    }
    metadata
        .set_remote_address(&target)
        .map_err(ListenerRuntimeError::from)?;
    let mut context = ConnectionContext::new(stream, metadata);
    tunnel
        .forward_tcp_context_with_system_dialer(&mut context)
        .map_err(ListenerRuntimeError::from)?;
    Ok(())
}
