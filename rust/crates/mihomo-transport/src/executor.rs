use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::net::IpAddr;
use std::str::FromStr;

use base64::Engine;
use mihomo_core::BoxedTcpStream;
use uuid::Uuid;
use crate::transport_types::MasqueConnectOptions;

use crate::{
    anytls, grpc_stream, reality_tls, h2_stream, http_stream, hy2_realm::Hy2RealmOptions, hysteria_stream,
    hy2_stream, masque_stream, openvpn_stream,
    shadowsocks, shadowsocks_2022, simple_obfs, smux_stream, snell, ssr, sudoku, tls_client,
    trojan, trusttunnel, tuic_stream, v2ray_plugin_mux, vision, vless, vmess, websocket,
    wireguard_stream, xhttp_stream,
    BasicAuth, GrpcOptions, Http2Options, HttpStreamOptions, PrefixedTcpStream, SocketOptions,
    TcpDialPurpose, TcpDialer, TcpTransportExecutor, TlsOptions, TransportAction,
    TransportError, TransportPlan, TransportPlanRunner, TransportTarget, TransportTraceStep,
    TrojanShadowsocksOptions, WebsocketOptions, XHttpOptions,
};
#[cfg(feature = "ssh-transport")]
use crate::ssh;

impl<D> TcpTransportExecutor<D> {
    pub fn new(dialer: D) -> Self {
        Self {
            dialer,
            trace: Vec::new(),
        }
    }

    pub fn trace(&self) -> &[TransportTraceStep] {
        &self.trace
    }

    pub fn dialer(&self) -> &D {
        &self.dialer
    }

    pub fn dialer_mut(&mut self) -> &mut D {
        &mut self.dialer
    }

    pub fn into_dialer(self) -> D {
        self.dialer
    }
}

impl<D: TcpDialer> TransportPlanRunner for TcpTransportExecutor<D> {
    type Output = BoxedTcpStream;

    fn run_plan(&mut self, plan: &TransportPlan) -> Result<Self::Output, TransportError> {
        self.trace.clear();

        let mut stream: Option<BoxedTcpStream> = None;
        for hop in &plan.hops {
            self.trace.push(TransportTraceStep {
                name: hop.name.clone(),
                summary: hop.action.summary(),
            });
            stream = Some(match &hop.action {
                TransportAction::Direct { socket, target } => {
                    execute_direct(&mut self.dialer, stream.take(), socket, target)?
                }
                TransportAction::Reject { drop } => {
                    return Err(TransportError::Rejected { drop: *drop });
                }
                TransportAction::HttpConnect {
                    proxy,
                    auth,
                    tls,
                    headers,
                    socket,
                    target,
                } => execute_http_connect(
                    &mut self.dialer,
                    stream.take(),
                    proxy,
                    auth,
                    tls,
                    headers,
                    socket,
                    target,
                )?,
                TransportAction::Socks5Connect {
                    proxy,
                    auth,
                    tls,
                    udp,
                    socket,
                    target,
                } => execute_socks5_connect(
                    &mut self.dialer,
                    stream.take(),
                    proxy,
                    auth,
                    tls,
                    *udp,
                    socket,
                    target,
                )?,
                TransportAction::AnyTlsConnect {
                    proxy,
                    password,
                    tls,
                    alpn,
                    socket,
                    target,
                } => execute_anytls_connect(
                    &mut self.dialer,
                    stream.take(),
                    proxy,
                    password,
                    tls,
                    alpn,
                    socket,
                    target,
                )?,
                TransportAction::HysteriaConnect {
                    proxy,
                    ports,
                    protocol,
                    auth,
                    auth_str,
                    obfs,
                    sni,
                    alpn,
                    up,
                    down,
                    up_speed,
                    down_speed,
                    disable_mtu_discovery,
                    fast_open,
                    hop_interval,
                    skip_cert_verify,
                    socket,
                    target,
                } => execute_hysteria_connect(
                    &mut self.dialer,
                    stream.take(),
                    proxy,
                    ports,
                    protocol,
                    auth,
                    auth_str,
                    obfs,
                    sni,
                    alpn,
                    up,
                    down,
                    *up_speed,
                    *down_speed,
                    *disable_mtu_discovery,
                    *fast_open,
                    *hop_interval,
                    *skip_cert_verify,
                    socket,
                    target,
                )?,
                TransportAction::Hy2Connect {
                    proxy,
                    password,
                    sni,
                    certificate,
                    private_key,
                    obfs,
                    obfs_password,
                    realm_enabled,
                    realm_server_url,
                    realm_token,
                    realm_id,
                    realm_stun_servers,
                    realm_sni,
                    realm_skip_cert_verify,
                    realm_fingerprint,
                    realm_certificate,
                    realm_private_key,
                    realm_alpn,
                    realm_proxy,
                    realm_proxy_plan,
                    skip_cert_verify,
                    socket,
                    target,
                } => execute_hy2_connect(
                    &mut self.dialer,
                    stream.take(),
                    proxy,
                    password,
                    sni,
                    certificate,
                    private_key,
                    obfs,
                    obfs_password,
                    *realm_enabled,
                    realm_server_url,
                    realm_token,
                    realm_id,
                    realm_stun_servers,
                    realm_sni,
                    *realm_skip_cert_verify,
                    realm_fingerprint,
                    realm_certificate,
                    realm_private_key,
                    realm_alpn,
                    realm_proxy,
                    realm_proxy_plan.as_deref(),
                    *skip_cert_verify,
                    socket,
                    target,
                )?,
                TransportAction::TuicConnect {
                    proxy,
                    uuid,
                    password,
                    token,
                    udp,
                    sni,
                    certificate,
                    private_key,
                    alpn,
                    disable_sni,
                    request_timeout_ms,
                    heartbeat_interval_ms,
                    congestion_controller,
                    max_open_streams,
                    max_udp_relay_packet_size,
                    tls,
                    socket,
                    target,
                } => execute_tuic_connect(
                    &mut self.dialer,
                    stream.take(),
                    proxy,
                    uuid,
                    password,
                    token,
                    *udp,
                    sni,
                    certificate,
                    private_key,
                    alpn,
                    *disable_sni,
                    *request_timeout_ms,
                    *heartbeat_interval_ms,
                    congestion_controller,
                    *max_open_streams,
                    *max_udp_relay_packet_size,
                    tls,
                    socket,
                    target,
                )?,
                TransportAction::WireGuardConnect {
                    proxy,
                    private_key,
                    ip,
                    ipv6,
                    workers,
                    tunnel_dns,
                    peers,
                    outer_socks5,
                    mtu,
                    socket,
                    target,
                } => execute_wireguard_connect(
                    &mut self.dialer,
                    stream.take(),
                    proxy,
                    private_key,
                    ip,
                    ipv6,
                    *workers,
                    tunnel_dns,
                    peers,
                    outer_socks5.as_ref(),
                    *mtu,
                    socket,
                    target,
                )?,
                TransportAction::OpenVpnConnect {
                    proxy,
                    proto,
                    dev,
                    cipher,
                    auth,
                    ca,
                    cert,
                    key,
                    tls_crypt,
                    username,
                    password,
                    tunnel_dns,
                    outer_socks5,
                    mtu,
                    socket,
                    target,
                } => execute_openvpn_connect(
                    &mut self.dialer,
                    stream.take(),
                    proxy,
                    proto,
                    dev,
                    cipher,
                    auth,
                    ca,
                    cert,
                    key,
                    tls_crypt,
                    username,
                    password,
                    tunnel_dns,
                    outer_socks5.as_ref(),
                    *mtu,
                    socket,
                    target,
                )?,
                TransportAction::MasqueConnect {
                    proxy,
                    options,
                    tls,
                    outer_socks5,
                    socket,
                    target,
                } => execute_masque_connect(
                    &mut self.dialer,
                    stream.take(),
                    proxy,
                    options,
                    tls,
                    outer_socks5.as_ref(),
                    socket,
                    target,
                )?,
                TransportAction::ShadowsocksConnect {
                    proxy,
                    cipher,
                    password,
                    plugin,
                    plugin_mode,
                    plugin_host,
                    websocket,
                    tls,
                    mux,
                    socket,
                    target,
                } => execute_shadowsocks_connect(
                    &mut self.dialer,
                    stream.take(),
                    proxy,
                    cipher,
                    password,
                    plugin,
                    plugin_mode,
                    plugin_host,
                    websocket,
                    tls,
                    *mux,
                    socket,
                    target,
                )?,
                TransportAction::SsrConnect {
                    proxy,
                    password,
                    cipher,
                    obfs,
                    obfs_param,
                    protocol,
                    protocol_param,
                    udp,
                    socket,
                    target,
                } => execute_ssr_connect(
                    &mut self.dialer,
                    stream.take(),
                    proxy,
                    password,
                    cipher,
                    obfs,
                    obfs_param,
                    protocol,
                    protocol_param,
                    *udp,
                    socket,
                    target,
                )?,
                TransportAction::SnellConnect {
                    proxy,
                    psk,
                    version,
                    obfs_mode,
                    obfs_host,
                    socket,
                    target,
                } => execute_snell_connect(
                    &mut self.dialer,
                    stream.take(),
                    proxy,
                    psk,
                    *version,
                    obfs_mode,
                    obfs_host,
                    socket,
                    target,
                )?,
                TransportAction::TrojanConnect {
                    proxy,
                    password,
                    shadowsocks,
                    network,
                    websocket,
                    grpc,
                    h2,
                    http,
                    xhttp,
                    tls,
                    alpn,
                    socket,
                    target,
                } => execute_trojan_connect(
                    &mut self.dialer,
                    stream.take(),
                    proxy,
                    password,
                    shadowsocks,
                    network,
                    websocket,
                    grpc,
                    h2,
                    http,
                    xhttp,
                    tls,
                    alpn,
                    socket,
                    target,
                )?,
                TransportAction::TrustTunnelConnect {
                    proxy,
                    username,
                    password,
                    udp,
                    quic,
                    tls,
                    alpn,
                    socket,
                    target,
                } => execute_trusttunnel_connect(
                    &mut self.dialer,
                    stream.take(),
                    proxy,
                    username,
                    password,
                    *udp,
                    *quic,
                    tls,
                    alpn,
                    socket,
                    target,
                )?,
                TransportAction::VlessConnect {
                    proxy,
                    uuid,
                    flow,
                    reality_public_key,
                    reality_short_id,
                    reality_support_x25519mlkem768,
                    client_fingerprint,
                    udp,
                    network,
                    websocket,
                    grpc,
                    h2,
                    http,
                    xhttp,
                    encryption,
                    packet_addr,
                    xudp,
                    tls,
                    alpn,
                    socket,
                    target,
                } => execute_vless_connect(
                    &mut self.dialer,
                    stream.take(),
                        proxy,
                        uuid,
                        flow,
                        reality_public_key,
                        reality_short_id,
                        *reality_support_x25519mlkem768,
                        client_fingerprint,
                        *udp,
                        network,
                        websocket,
                        grpc,
                    h2,
                    http,
                    xhttp,
                    encryption,
                    *packet_addr,
                    *xudp,
                    tls,
                    alpn,
                    socket,
                    target,
                )?,
                TransportAction::VmessConnect {
                    proxy,
                    uuid,
                    alter_id,
                    cipher,
                    udp,
                    network,
                    websocket,
                    grpc,
                    h2,
                    http,
                    xhttp,
                    packet_addr,
                    xudp,
                    global_padding,
                    authenticated_length,
                    tls,
                    alpn,
                    socket,
                    target,
                } => execute_vmess_connect(
                    &mut self.dialer,
                    stream.take(),
                    proxy,
                    uuid,
                    *alter_id,
                    cipher,
                    *udp,
                    network,
                    websocket,
                    grpc,
                    h2,
                    http,
                    xhttp,
                    *packet_addr,
                    *xudp,
                    *global_padding,
                    *authenticated_length,
                    tls,
                    alpn,
                    socket,
                    target,
                )?,
                TransportAction::GostRelay {
                    proxy,
                    auth,
                    forward,
                    tls,
                    mux,
                    socket,
                    target,
                } => execute_gost_relay_connect(
                    &mut self.dialer,
                    stream.take(),
                    proxy,
                    auth,
                    *forward,
                    tls,
                    *mux,
                    socket,
                    target,
                )?,
                TransportAction::SudokuConnect {
                    proxy,
                    key,
                    aead_method,
                    table_type,
                    padding_min,
                    padding_max,
                    enable_pure_downlink,
                    http_mask_enabled,
                    http_mask_mode,
                    http_mask_tls,
                    http_mask_host,
                    path_root,
                    custom_table,
                    custom_tables,
                    socket,
                    target,
                } => execute_sudoku_connect(
                    &mut self.dialer,
                    stream.take(),
                    proxy,
                    key,
                    aead_method,
                    table_type,
                    *padding_min,
                    *padding_max,
                    *enable_pure_downlink,
                    *http_mask_enabled,
                    http_mask_mode,
                    *http_mask_tls,
                    http_mask_host,
                    path_root,
                    custom_table,
                    custom_tables,
                    socket,
                    target,
                )?,
                TransportAction::SshConnect {
                    proxy,
                    username,
                    password,
                    private_key,
                    private_key_passphrase,
                    host_keys,
                    host_key_algorithms,
                    socket,
                    target,
                } => execute_ssh_connect(
                    &mut self.dialer,
                    stream.take(),
                    proxy,
                    username,
                    password,
                    private_key,
                    private_key_passphrase,
                    host_keys,
                    host_key_algorithms,
                    socket,
                    target,
                )?,
                TransportAction::Unsupported { name, kind, .. } => {
                    return Err(TransportError::UnsupportedAction {
                        name: name.clone(),
                        kind: kind.clone(),
                    });
                }
            });
        }

        stream.ok_or_else(|| TransportError::InvalidPlan("no executable hops".to_owned()))
    }
}

fn execute_direct<D: TcpDialer>(
    dialer: &mut D,
    existing: Option<BoxedTcpStream>,
    socket: &SocketOptions,
    target: &TransportTarget,
) -> Result<BoxedTcpStream, TransportError> {
    if let Some(stream) = existing {
        Ok(stream)
    } else {
        dialer.connect(target, socket, TcpDialPurpose::FinalTarget)
    }
}

fn execute_http_connect<D: TcpDialer>(
    dialer: &mut D,
    existing: Option<BoxedTcpStream>,
    proxy: &TransportTarget,
    auth: &Option<BasicAuth>,
    tls: &TlsOptions,
    headers: &BTreeMap<String, String>,
    socket: &SocketOptions,
    target: &TransportTarget,
) -> Result<BoxedTcpStream, TransportError> {
    let trace_enabled = std::env::var_os("MIHOMO_TUN_TCP_TRACE").is_some();
    let mut stream =
        open_proxy_stream(dialer, existing, proxy, tls, &[], socket)?;

    let request = build_http_connect_request(target, auth, headers);
    if trace_enabled {
        eprintln!(
            "[http-connect-trace] proxy={} target={} request-bytes={}",
            proxy.authority(),
            target.authority(),
            request.len()
        );
    }
    stream.write_all(request.as_bytes())?;
    stream.flush()?;
    let buffered = read_http_connect_response(&mut *stream)?;
    if trace_enabled {
        eprintln!(
            "[http-connect-trace] proxy={} target={} buffered-after-connect={}",
            proxy.authority(),
            target.authority(),
            buffered.len()
        );
    }
    Ok(prepend_bytes(stream, buffered))
}

fn execute_socks5_connect<D: TcpDialer>(
    dialer: &mut D,
    existing: Option<BoxedTcpStream>,
    proxy: &TransportTarget,
    auth: &Option<BasicAuth>,
    tls: &TlsOptions,
    _udp: bool,
    socket: &SocketOptions,
    target: &TransportTarget,
) -> Result<BoxedTcpStream, TransportError> {
    let mut stream =
        open_proxy_stream(dialer, existing, proxy, tls, &[], socket)?;

    write_socks5_greeting(&mut *stream, auth.is_some())?;
    read_socks5_method_selection(&mut *stream, auth)?;
    if let Some(auth) = auth {
        write_socks5_auth(&mut *stream, auth)?;
        read_socks5_auth_result(&mut *stream)?;
    }
    write_socks5_connect_request(&mut *stream, target)?;
    read_socks5_connect_response(&mut *stream)?;
    Ok(stream)
}

fn execute_anytls_connect<D: TcpDialer>(
    dialer: &mut D,
    existing: Option<BoxedTcpStream>,
    proxy: &TransportTarget,
    password: &str,
    tls: &TlsOptions,
    alpn: &[String],
    socket: &SocketOptions,
    target: &TransportTarget,
) -> Result<BoxedTcpStream, TransportError> {
    let tls = tls
        .enabled
        .then_some(tls)
        .ok_or_else(|| TransportError::InvalidPlan("anytls transport requires tls".to_owned()))?;
    let resolved_alpn = if alpn.is_empty() {
        vec!["h2".to_owned(), "http/1.1".to_owned()]
    } else {
        alpn.to_vec()
    };
    let stream = open_proxy_stream(dialer, existing, proxy, tls, &resolved_alpn, socket)?;
    anytls::wrap_stream(stream, password, target)
}

#[allow(clippy::too_many_arguments)]
fn execute_hysteria_connect<D: TcpDialer>(
    dialer: &mut D,
    existing: Option<BoxedTcpStream>,
    proxy: &TransportTarget,
    ports: &str,
    protocol: &str,
    auth: &str,
    auth_str: &str,
    obfs: &str,
    sni: &str,
    alpn: &[String],
    up: &str,
    down: &str,
    up_speed: u32,
    down_speed: u32,
    disable_mtu_discovery: bool,
    fast_open: bool,
    hop_interval: u32,
    skip_cert_verify: bool,
    _socket: &SocketOptions,
    target: &TransportTarget,
) -> Result<BoxedTcpStream, TransportError> {
    if existing.is_some() {
        return Err(TransportError::UnsupportedFeature {
            proxy: proxy.authority(),
            feature: "hysteria over chained stream".to_owned(),
        });
    }
    hysteria_stream::connect_stream(
        dialer,
        proxy,
        &hysteria_stream::HysteriaOptions {
            ports: ports.to_owned(),
            protocol: protocol.to_owned(),
            auth: auth.to_owned(),
            auth_str: auth_str.to_owned(),
            obfs: obfs.to_owned(),
            sni: sni.to_owned(),
            alpn: alpn.to_vec(),
            up: up.to_owned(),
            down: down.to_owned(),
            up_speed,
            down_speed,
            disable_mtu_discovery,
            fast_open,
            hop_interval,
            skip_cert_verify,
        },
        target,
    )
}

fn execute_hy2_connect<D: TcpDialer>(
    dialer: &mut D,
    existing: Option<BoxedTcpStream>,
    proxy: &TransportTarget,
    password: &str,
    sni: &str,
    certificate: &str,
    private_key: &str,
    obfs: &str,
    obfs_password: &str,
    realm_enabled: bool,
    realm_server_url: &str,
    realm_token: &str,
    realm_id: &str,
    realm_stun_servers: &[String],
    realm_sni: &str,
    realm_skip_cert_verify: bool,
    realm_fingerprint: &str,
    realm_certificate: &str,
    realm_private_key: &str,
    realm_alpn: &[String],
    realm_proxy: &str,
    realm_proxy_plan: Option<&crate::TransportPlan>,
    skip_cert_verify: bool,
    _socket: &SocketOptions,
    target: &TransportTarget,
) -> Result<BoxedTcpStream, TransportError> {
    if existing.is_some() {
        return Err(TransportError::UnsupportedFeature {
            proxy: proxy.authority(),
            feature: "hysteria2 over chained stream".to_owned(),
        });
    }
    if !obfs.trim().is_empty() && obfs.trim() != "salamander" {
        return Err(TransportError::UnsupportedFeature {
            proxy: proxy.authority(),
            feature: format!("hysteria2 obfs={obfs}"),
        });
    }

    hy2_stream::connect_stream(
        dialer,
        proxy,
        &hy2_stream::Hy2Options {
            password: password.to_owned(),
            sni: sni.to_owned(),
            skip_cert_verify,
            certificate: certificate.to_owned(),
            private_key: private_key.to_owned(),
            obfs: obfs.to_owned(),
            obfs_password: obfs_password.to_owned(),
            udp_mtu: 1200,
            realm: Hy2RealmOptions {
                enabled: realm_enabled,
                server_url: realm_server_url.to_owned(),
                token: realm_token.to_owned(),
                realm_id: realm_id.to_owned(),
                stun_servers: realm_stun_servers.to_vec(),
                sni: realm_sni.to_owned(),
                skip_cert_verify: realm_skip_cert_verify,
                fingerprint: realm_fingerprint.to_owned(),
                certificate: realm_certificate.to_owned(),
                private_key: realm_private_key.to_owned(),
                alpn: realm_alpn.to_vec(),
                proxy: realm_proxy.to_owned(),
                proxy_plan: realm_proxy_plan.cloned().map(Box::new),
            },
        },
        target,
    )
}

#[allow(clippy::too_many_arguments)]
fn execute_tuic_connect<D: TcpDialer>(
    dialer: &mut D,
    existing: Option<BoxedTcpStream>,
    proxy: &TransportTarget,
    uuid: &str,
    password: &str,
    token: &str,
    _udp: bool,
    sni: &str,
    certificate: &str,
    private_key: &str,
    alpn: &[String],
    disable_sni: bool,
    request_timeout_ms: u64,
    heartbeat_interval_ms: u64,
    congestion_controller: &str,
    max_open_streams: u32,
    max_udp_relay_packet_size: u32,
    tls: &TlsOptions,
    _socket: &SocketOptions,
    target: &TransportTarget,
) -> Result<BoxedTcpStream, TransportError> {
    if existing.is_some() {
        return Err(TransportError::UnsupportedFeature {
            proxy: proxy.authority(),
            feature: "tuic over chained stream".to_owned(),
        });
    }
    tuic_stream::connect_stream(
        dialer,
        proxy,
        &tuic_stream::TuicOptions {
            uuid: uuid.to_owned(),
            password: password.to_owned(),
            token: token.to_owned(),
            udp: false,
            sni: sni.to_owned(),
            certificate: certificate.to_owned(),
            private_key: private_key.to_owned(),
            alpn: alpn.to_vec(),
            disable_sni,
            request_timeout_ms,
            heartbeat_interval_ms,
            congestion_controller: congestion_controller.to_owned(),
            max_open_streams,
            max_udp_relay_packet_size,
            skip_cert_verify: tls.skip_cert_verify,
        },
        target,
    )
}

#[allow(clippy::too_many_arguments)]
fn execute_wireguard_connect<D: TcpDialer>(
    dialer: &mut D,
    existing: Option<BoxedTcpStream>,
    proxy: &TransportTarget,
    private_key: &str,
    ip: &str,
    ipv6: &str,
    workers: usize,
    tunnel_dns: &crate::TunnelDnsOptions,
    peers: &[crate::transport_types::WireGuardPeerTransportOptions],
    outer_socks5: Option<&crate::OuterSocks5UdpPlan>,
    mtu: usize,
    _socket: &SocketOptions,
    target: &TransportTarget,
) -> Result<BoxedTcpStream, TransportError> {
    if existing.is_some() {
        return Err(TransportError::UnsupportedFeature {
            proxy: proxy.authority(),
            feature: "wireguard over chained stream".to_owned(),
        });
    }
    let options = wireguard_stream::WireGuardOptions {
        private_key: private_key.to_owned(),
        ip: ip.to_owned(),
        ipv6: ipv6.to_owned(),
        workers,
        mtu,
        remote_dns_resolve: tunnel_dns.remote_dns_resolve,
        dns: tunnel_dns.dns.clone(),
        peers: peers
            .iter()
            .map(|peer| wireguard_stream::WireGuardPeerOptions {
                server: peer.server.clone(),
                port: peer.port,
                public_key: peer.public_key.clone(),
                allowed_ips: peer.allowed_ips.clone(),
                persistent_keepalive: peer.persistent_keepalive,
            })
            .collect(),
    };
    if let Some(outer) = outer_socks5 {
        let control_stream = if let Some(prefix_plan) = outer.prefix_plan.as_deref() {
            run_transport_plan_with_dialer(dialer, prefix_plan)?
        } else {
            dialer.connect(
                &outer.proxy,
                &SocketOptions::default(),
                TcpDialPurpose::ProxyServer,
            )?
        };
        return wireguard_stream::connect_stream_with_socks5_stream(
            &options,
            target,
            control_stream,
            outer.proxy.clone(),
            outer.auth.clone(),
        );
    }
    wireguard_stream::connect_stream(&options, target)
}

fn run_transport_plan_with_dialer<D: TcpDialer>(
    dialer: &mut D,
    plan: &TransportPlan,
) -> Result<BoxedTcpStream, TransportError> {
    let mut stream: Option<BoxedTcpStream> = None;
    for hop in &plan.hops {
        stream = Some(match &hop.action {
            TransportAction::Direct { socket, target } => {
                execute_direct(dialer, stream.take(), socket, target)?
            }
            TransportAction::Reject { drop } => {
                return Err(TransportError::Rejected { drop: *drop });
            }
            TransportAction::HttpConnect {
                proxy,
                auth,
                tls,
                headers,
                socket,
                target,
            } => execute_http_connect(
                dialer,
                stream.take(),
                proxy,
                auth,
                tls,
                headers,
                socket,
                target,
            )?,
            TransportAction::Socks5Connect {
                proxy,
                auth,
                tls,
                udp,
                socket,
                target,
            } => execute_socks5_connect(
                dialer,
                stream.take(),
                proxy,
                auth,
                tls,
                *udp,
                socket,
                target,
            )?,
            other => {
                return Err(TransportError::UnsupportedFeature {
                    proxy: plan.leaf_name.clone(),
                    feature: format!(
                        "wireguard outer prefix transport does not support {}",
                        other.summary()
                    ),
                });
            }
        });
    }
    stream.ok_or_else(|| TransportError::InvalidPlan("no executable hops".to_owned()))
}

#[allow(clippy::too_many_arguments)]
fn execute_openvpn_connect<D: TcpDialer>(
    dialer: &mut D,
    existing: Option<BoxedTcpStream>,
    proxy: &TransportTarget,
    proto: &str,
    dev: &str,
    cipher: &str,
    auth: &str,
    ca: &str,
    cert: &str,
    key: &str,
    tls_crypt: &str,
    username: &str,
    password: &str,
    tunnel_dns: &crate::TunnelDnsOptions,
    outer_socks5: Option<&crate::OuterSocks5UdpPlan>,
    mtu: usize,
    _socket: &SocketOptions,
    target: &TransportTarget,
) -> Result<BoxedTcpStream, TransportError> {
    let options = openvpn_stream::OpenVpnOptions {
        server: proxy.host.clone(),
        port: proxy.port,
        proto: proto.to_owned(),
        dev: dev.to_owned(),
        cipher: cipher.to_owned(),
        auth: auth.to_owned(),
        ca: ca.to_owned(),
        cert: cert.to_owned(),
        key: key.to_owned(),
        tls_crypt: tls_crypt.to_owned(),
        username: username.to_owned(),
        password: password.to_owned(),
        remote_dns_resolve: tunnel_dns.remote_dns_resolve,
        dns: tunnel_dns.dns.clone(),
        mtu,
    };
    if existing.is_none() && openvpn_stream::normalize_proto(proto) == openvpn_stream::PROTO_UDP {
        if let Some(outer) = outer_socks5 {
            let control_stream = if let Some(prefix_plan) = outer.prefix_plan.as_deref() {
                run_transport_plan_with_dialer(dialer, prefix_plan)?
            } else {
                dialer.connect(
                    &outer.proxy,
                    &SocketOptions::default(),
                    TcpDialPurpose::ProxyServer,
                )?
            };
            return openvpn_stream::connect_stream_with_socks5_stream(
                &options,
                control_stream,
                outer.auth.clone(),
                target,
            );
        }
    }
    match existing {
        Some(stream) => {
            let normalized_proto = openvpn_stream::normalize_proto(proto);
            if normalized_proto != openvpn_stream::PROTO_TCP {
                return Err(TransportError::UnsupportedFeature {
                    proxy: proxy.authority(),
                    feature: "openvpn chained stream requires proto=tcp".to_owned(),
                });
            }
            openvpn_stream::connect_stream_with_boxed_tcp(&options, stream, target)
        }
        None => openvpn_stream::connect_stream(&options, target),
    }
}

fn execute_masque_connect<D: TcpDialer>(
    dialer: &mut D,
    existing: Option<BoxedTcpStream>,
    proxy: &TransportTarget,
    options: &MasqueConnectOptions,
    tls: &TlsOptions,
    outer_socks5: Option<&crate::OuterSocks5UdpPlan>,
    _socket: &SocketOptions,
    target: &TransportTarget,
) -> Result<BoxedTcpStream, TransportError> {
    let control_stream = if let Some(stream) = existing {
        stream
    } else if let Some(outer) = outer_socks5 {
        if let Some(prefix_plan) = outer.prefix_plan.as_deref() {
            run_transport_plan_with_dialer(dialer, prefix_plan)?
        } else {
            dialer.connect(
                &outer.proxy,
                &SocketOptions::default(),
                TcpDialPurpose::ProxyServer,
            )?
        }
    } else {
        dialer.connect(proxy, &SocketOptions::default(), TcpDialPurpose::ProxyServer)?
    };
    masque_stream::connect_stream(control_stream, proxy, options, tls, target)
}

fn execute_shadowsocks_connect<D: TcpDialer>(
    dialer: &mut D,
    existing: Option<BoxedTcpStream>,
    proxy: &TransportTarget,
    cipher: &str,
    password: &str,
    plugin: &str,
    plugin_mode: &str,
    plugin_host: &str,
    websocket: &WebsocketOptions,
    tls: &TlsOptions,
    mux: bool,
    socket: &SocketOptions,
    target: &TransportTarget,
) -> Result<BoxedTcpStream, TransportError> {
    let plugin = plugin.trim();
    let plugin_lower = plugin.to_ascii_lowercase();
    if shadowsocks_2022::Shadowsocks2022Cipher::parse(cipher).is_some() {
        if !plugin_lower.is_empty() {
            return Err(TransportError::UnsupportedFeature {
                proxy: proxy.authority(),
                feature: format!("shadowsocks 2022 cipher with plugin={plugin}"),
            });
        }
        let stream = if let Some(stream) = existing {
            stream
        } else {
            dialer.connect(proxy, socket, TcpDialPurpose::ProxyServer)?
        };
        return shadowsocks_2022::wrap_stream(stream, cipher, password, target);
    }
    match plugin_lower.as_str() {
        "" => {
            let stream = if let Some(stream) = existing {
                stream
            } else {
                dialer.connect(proxy, socket, TcpDialPurpose::ProxyServer)?
            };
            shadowsocks::wrap_stream(stream, cipher, password, target)
        }
        "obfs" => {
            let stream = if let Some(stream) = existing {
                stream
            } else {
                dialer.connect(proxy, socket, TcpDialPurpose::ProxyServer)?
            };
            let host = if plugin_host.trim().is_empty() {
                "bing.com"
            } else {
                plugin_host
            };
            let stream = match plugin_mode.trim() {
                "tls" => simple_obfs::wrap_tls_stream(stream, host),
                "http" => simple_obfs::wrap_http_stream(stream, host, &proxy.port.to_string()),
                other => {
                    return Err(TransportError::UnsupportedFeature {
                        proxy: proxy.authority(),
                        feature: format!("plugin={plugin} mode={other}"),
                    })
                }
            };
            shadowsocks::wrap_stream(stream, cipher, password, target)
        }
        "v2ray-plugin" | "gost-plugin" => {
            let mut stream = if let Some(stream) = existing {
                stream
            } else {
                dialer.connect(proxy, socket, TcpDialPurpose::ProxyServer)?
            };
            if tls.enabled {
                stream = tls_client::wrap_stream(
                    stream,
                    proxy,
                    tls,
                    &resolved_websocket_alpn(&[]),
                )?;
            }
            stream = websocket::wrap_stream(stream, proxy, websocket)?;
            if mux {
                stream = if plugin_lower == "v2ray-plugin" {
                    v2ray_plugin_mux::wrap_stream(stream).map_err(TransportError::from)?
                } else {
                    smux_stream::wrap_stream(stream).map_err(TransportError::from)?
                };
            }
            shadowsocks::wrap_stream(stream, cipher, password, target)
        }
        _ => Err(TransportError::UnsupportedFeature {
            proxy: proxy.authority(),
            feature: format!("plugin={plugin}"),
        }),
    }
}

fn execute_ssr_connect<D: TcpDialer>(
    dialer: &mut D,
    existing: Option<BoxedTcpStream>,
    proxy: &TransportTarget,
    password: &str,
    cipher: &str,
    obfs: &str,
    obfs_param: &str,
    protocol: &str,
    protocol_param: &str,
    _udp: bool,
    socket: &SocketOptions,
    target: &TransportTarget,
) -> Result<BoxedTcpStream, TransportError> {
    let stream = if let Some(stream) = existing {
        stream
    } else {
        dialer.connect(proxy, socket, TcpDialPurpose::ProxyServer)?
    };
    ssr::wrap_stream(
        stream,
        proxy,
        cipher,
        password,
        obfs,
        obfs_param,
        protocol,
        protocol_param,
        target,
    )
}

fn execute_snell_connect<D: TcpDialer>(
    dialer: &mut D,
    existing: Option<BoxedTcpStream>,
    proxy: &TransportTarget,
    psk: &str,
    version: u8,
    obfs_mode: &str,
    obfs_host: &str,
    socket: &SocketOptions,
    target: &TransportTarget,
) -> Result<BoxedTcpStream, TransportError> {
    match obfs_mode.trim() {
        "" | "http" | "tls" => {}
        other => {
            return Err(TransportError::UnsupportedFeature {
                proxy: proxy.authority(),
                feature: format!("obfs={other}"),
            })
        }
    }
    let mut stream = if let Some(stream) = existing {
        stream
    } else {
        dialer.connect(proxy, socket, TcpDialPurpose::ProxyServer)?
    };
    let host = if obfs_host.trim().is_empty() {
        "bing.com"
    } else {
        obfs_host
    };
    stream = match obfs_mode.trim() {
        "" => stream,
        "tls" => simple_obfs::wrap_tls_stream(stream, host),
        "http" => simple_obfs::wrap_http_stream(stream, host, &proxy.port.to_string()),
        _ => unreachable!("unsupported snell obfs prevalidated"),
    };
    snell::wrap_stream(stream, psk, version, "", target)
}

fn execute_trojan_connect<D: TcpDialer>(
    dialer: &mut D,
    existing: Option<BoxedTcpStream>,
    proxy: &TransportTarget,
    password: &str,
    shadowsocks: &TrojanShadowsocksOptions,
    network: &str,
    websocket: &WebsocketOptions,
    grpc: &GrpcOptions,
    h2: &Http2Options,
    http: &HttpStreamOptions,
    xhttp: &XHttpOptions,
    tls: &TlsOptions,
    alpn: &[String],
    socket: &SocketOptions,
    target: &TransportTarget,
) -> Result<BoxedTcpStream, TransportError> {
    if !network.trim().is_empty()
        && network != "tcp"
        && network != "ws"
        && network != "http"
        && network != "grpc"
        && network != "h2"
        && network != "xhttp"
    {
        return Err(TransportError::UnsupportedFeature {
            proxy: proxy.authority(),
            feature: format!("network={network}"),
        });
    }
    let tls = tls
        .enabled
        .then_some(tls)
        .ok_or_else(|| TransportError::InvalidPlan("trojan transport requires tls".to_owned()))?;
    let resolved_alpn = if alpn.is_empty() {
        trojan::DEFAULT_ALPN
            .iter()
            .map(|value| (*value).to_owned())
            .collect::<Vec<_>>()
    } else {
        alpn.to_vec()
    };
    let websocket_alpn = resolved_websocket_alpn(alpn);
    let h2_alpn = vec!["h2".to_owned()];
    let (websocket, tls) = if network == "ws" {
        prepare_websocket_options(websocket, tls, true)
    } else {
        (websocket.clone(), tls.clone())
    };
    if network == "grpc" {
        let stream = if let Some(stream) = existing {
            stream
        } else {
            dialer.connect(proxy, socket, TcpDialPurpose::ProxyServer)?
        };
        let stream = grpc_stream::wrap_tls_stream(stream, proxy, &tls, grpc)?;
        let stream = apply_trojan_shadowsocks(stream, shadowsocks)?;
        return trojan::wrap_stream(stream, password, target);
    }
    if network == "xhttp" {
        let stream = if let Some(stream) = existing {
            stream
        } else {
            dialer.connect(proxy, socket, TcpDialPurpose::ProxyServer)?
        };
        let stream = if tls.enabled {
            xhttp_stream::wrap_tls_stream(stream, proxy, &tls, alpn, xhttp)?
        } else {
            xhttp_stream::wrap_stream(stream, proxy, xhttp)?
        };
        let stream = apply_trojan_shadowsocks(stream, shadowsocks)?;
        return trojan::wrap_stream(stream, password, target);
    }
    if network == "h2" && tls.enabled {
        let stream = if let Some(stream) = existing {
            stream
        } else {
            dialer.connect(proxy, socket, TcpDialPurpose::ProxyServer)?
        };
        let authority = h2
            .host
            .iter()
            .find(|value| !value.trim().is_empty())
            .cloned()
            .unwrap_or_else(|| proxy.host.clone());
        let path = if h2.path.trim().is_empty() {
            "/".to_owned()
        } else if h2.path.starts_with('/') {
            h2.path.clone()
        } else {
            format!("/{}", h2.path)
        };
        let stream = h2_stream::wrap_tls_stream_with_request(
            stream,
            proxy,
            &tls,
            &h2_alpn,
            h2_stream::H2RequestOptions {
                authority,
                path,
                method: "PUT".to_owned(),
                headers: vec![("accept-encoding".to_owned(), "identity".to_owned())],
            },
        )?;
        let stream = apply_trojan_shadowsocks(stream, shadowsocks)?;
        return trojan::wrap_stream(stream, password, target);
    }
    let mut stream = open_proxy_stream(
        dialer,
        existing,
        proxy,
        &tls,
        if network == "ws" {
            &websocket_alpn
        } else {
            &resolved_alpn
        },
        socket,
    )?;
    if network == "ws" {
        stream = websocket::wrap_stream(stream, proxy, &websocket)?;
    } else if network == "h2" {
        stream = h2_stream::wrap_stream(stream, h2)?;
    } else if network == "http" {
        stream = http_stream::wrap_stream(stream, proxy, http);
    }
    stream = apply_trojan_shadowsocks(stream, shadowsocks)?;
    trojan::wrap_stream(stream, password, target)
}

pub(crate) fn apply_trojan_shadowsocks(
    stream: BoxedTcpStream,
    shadowsocks: &TrojanShadowsocksOptions,
) -> Result<BoxedTcpStream, TransportError> {
    if !shadowsocks.enabled {
        return Ok(stream);
    }
    shadowsocks::wrap_accepted_stream(stream, &shadowsocks.method, &shadowsocks.password)
}

fn execute_trusttunnel_connect<D: TcpDialer>(
    dialer: &mut D,
    existing: Option<BoxedTcpStream>,
    proxy: &TransportTarget,
    username: &str,
    password: &str,
    _udp: bool,
    quic: bool,
    tls: &TlsOptions,
    alpn: &[String],
    socket: &SocketOptions,
    target: &TransportTarget,
) -> Result<BoxedTcpStream, TransportError> {
    let tls = tls
        .enabled
        .then_some(tls)
        .ok_or_else(|| TransportError::InvalidPlan("trusttunnel transport requires tls".to_owned()))?;
    let resolved_alpn = if alpn.is_empty() {
        vec![if quic { "h3" } else { "h2" }.to_owned()]
    } else {
        alpn.to_vec()
    };
    if quic {
        if existing.is_some() {
            return Err(TransportError::UnsupportedFeature {
                proxy: proxy.authority(),
                feature: "quic over chained stream".to_owned(),
            });
        }
        return trusttunnel::wrap_quic_stream(
            proxy,
            tls,
            &resolved_alpn,
            username,
            password,
            target,
        );
    }
    let stream = if let Some(stream) = existing {
        stream
    } else {
        dialer.connect(proxy, socket, TcpDialPurpose::ProxyServer)?
    };
    trusttunnel::wrap_tls_stream(
        stream,
        proxy,
        tls,
        &resolved_alpn,
        username,
        password,
        target,
    )
}

fn execute_vless_connect<D: TcpDialer>(
    dialer: &mut D,
    existing: Option<BoxedTcpStream>,
    proxy: &TransportTarget,
    uuid: &str,
    flow: &str,
    reality_public_key: &str,
    reality_short_id: &str,
    reality_support_x25519mlkem768: bool,
    _client_fingerprint: &str,
    _udp: bool,
    network: &str,
    websocket: &WebsocketOptions,
    grpc: &GrpcOptions,
    h2: &Http2Options,
    http: &HttpStreamOptions,
    xhttp: &XHttpOptions,
    encryption: &str,
    _packet_addr: bool,
    _xudp: bool,
    tls: &TlsOptions,
    alpn: &[String],
    socket: &SocketOptions,
    target: &TransportTarget,
) -> Result<BoxedTcpStream, TransportError> {
    if !network.trim().is_empty()
        && network != "tcp"
        && network != "ws"
        && network != "grpc"
        && network != "http"
        && network != "h2"
        && network != "xhttp"
    {
        return Err(TransportError::UnsupportedFeature {
            proxy: proxy.authority(),
            feature: format!("network={network}"),
        });
    }
    let flow = flow.trim();
    let vision = flow == "xtls-rprx-vision";
    let has_reality = !reality_public_key.trim().is_empty()
        || !reality_short_id.trim().is_empty()
        || reality_support_x25519mlkem768;
    if !flow.is_empty() && !vision {
        return Err(TransportError::UnsupportedFeature {
            proxy: proxy.authority(),
            feature: format!("flow={flow}"),
        });
    }
    if !encryption.trim().is_empty() && encryption != "none" {
        return Err(TransportError::UnsupportedFeature {
            proxy: proxy.authority(),
            feature: format!("encryption={encryption}"),
        });
    }
    if vision && !tls.enabled {
        return Err(TransportError::UnsupportedFeature {
            proxy: proxy.authority(),
            feature: "flow=xtls-rprx-vision requires tls".to_owned(),
        });
    }
    if has_reality {
        if !network.trim().is_empty() && network != "tcp" {
            return Err(TransportError::UnsupportedFeature {
                proxy: proxy.authority(),
                feature: format!("reality network={network}"),
            });
        }
        let config = reality_tls::RealityClientConfig {
            public_key: reality_tls::parse_client_public_key(reality_public_key)?,
            short_id: reality_tls::parse_client_short_id_for_reality(reality_short_id)?,
            server_name: tls.sni.trim().to_owned(),
            support_x25519mlkem768: reality_support_x25519mlkem768,
            alpn: alpn.to_vec(),
        };
        let stream = if let Some(stream) = existing {
            stream
        } else {
            dialer.connect(proxy, socket, TcpDialPurpose::ProxyServer)?
        };
        let stream = reality_tls::wrap_stream(stream, &config, target)?;
        let stream = vless::wrap_stream_with_flow(stream, uuid, flow, target)?;
        return wrap_vision_stream_if_needed(stream, uuid, vision, true);
    }
    let websocket_alpn = resolved_websocket_alpn(alpn);
    let h2_alpn = vec!["h2".to_owned()];
    if vision {
        if !network.trim().is_empty()
            && network != "tcp"
            && network != "h2"
            && network != "grpc"
            && network != "ws"
            && network != "http"
        {
            return Err(TransportError::UnsupportedFeature {
                proxy: proxy.authority(),
                feature: format!("flow=xtls-rprx-vision network={network}"),
            });
        }
        if network == "ws" {
            let stream = if let Some(stream) = existing {
                stream
            } else {
                dialer.connect(proxy, socket, TcpDialPurpose::ProxyServer)?
            };
            let tls_stream = tls_client::wrap_stream_for_vision(stream, proxy, tls, &websocket_alpn)?;
            let tls13 = tls_stream.negotiated_tls13();
            let stream = websocket::wrap_stream(Box::new(tls_stream), proxy, &websocket)?;
            let stream = vless::wrap_stream_with_flow(stream, uuid, flow, target)?;
            return wrap_vision_stream_if_needed(stream, uuid, true, tls13);
        }
        if network == "grpc" {
            let stream = if let Some(stream) = existing {
                stream
            } else {
                dialer.connect(proxy, socket, TcpDialPurpose::ProxyServer)?
            };
            let stream = grpc_stream::wrap_tls_stream(stream, proxy, tls, grpc)?;
            let stream = vless::wrap_stream_with_flow(stream, uuid, flow, target)?;
            return wrap_vision_stream_if_needed(stream, uuid, true, true);
        }
        if network == "h2" {
            let stream = if let Some(stream) = existing {
                stream
            } else {
                dialer.connect(proxy, socket, TcpDialPurpose::ProxyServer)?
            };
            let stream = h2_stream::wrap_tls_stream_with_request(
                stream,
                proxy,
                tls,
                &h2_alpn,
                h2_stream::H2RequestOptions {
                    authority: h2
                        .host
                        .iter()
                        .find(|value| !value.trim().is_empty())
                        .cloned()
                        .unwrap_or_else(|| proxy.host.clone()),
                    path: if h2.path.trim().is_empty() {
                        "/".to_owned()
                    } else if h2.path.starts_with('/') {
                        h2.path.clone()
                    } else {
                        format!("/{}", h2.path)
                    },
                    method: "PUT".to_owned(),
                    headers: vec![("accept-encoding".to_owned(), "identity".to_owned())],
                },
            )?;
            let stream = vless::wrap_stream_with_flow(stream, uuid, flow, target)?;
            return wrap_vision_stream_if_needed(stream, uuid, true, true);
        }
        if network == "http" {
            let stream = if let Some(stream) = existing {
                stream
            } else {
                dialer.connect(proxy, socket, TcpDialPurpose::ProxyServer)?
            };
            let tls_stream = tls_client::wrap_stream_for_vision(stream, proxy, tls, alpn)?;
            let tls13 = tls_stream.negotiated_tls13();
            let stream = http_stream::wrap_stream(Box::new(tls_stream), proxy, http);
            let stream = vless::wrap_stream_with_flow(stream, uuid, flow, target)?;
            return wrap_vision_stream_if_needed(stream, uuid, true, tls13);
        }
        let stream = if let Some(stream) = existing {
            stream
        } else {
            dialer.connect(proxy, socket, TcpDialPurpose::ProxyServer)?
        };
        let tls_stream = tls_client::wrap_stream_for_vision(stream, proxy, tls, alpn)?;
        let tls13 = tls_stream.negotiated_tls13();
        let stream = vless::wrap_stream_with_flow(Box::new(tls_stream), uuid, flow, target)?;
        return wrap_vision_stream_if_needed(stream, uuid, true, tls13);
    }
    let (websocket, tls) = if network == "ws" {
        prepare_websocket_options(websocket, tls, false)
    } else {
        (websocket.clone(), tls.clone())
    };
    if network == "xhttp" {
        let stream = if let Some(stream) = existing {
            stream
        } else {
            dialer.connect(proxy, socket, TcpDialPurpose::ProxyServer)?
        };
        let stream = if tls.enabled {
            xhttp_stream::wrap_tls_stream(stream, proxy, &tls, alpn, xhttp)?
        } else {
            xhttp_stream::wrap_stream(stream, proxy, xhttp)?
        };
        let stream = vless::wrap_stream_with_flow(stream, uuid, flow, target)?;
        return wrap_vision_stream_if_needed(stream, uuid, vision, false);
    }
    let mut stream = if network == "grpc" && tls.enabled {
        let stream = if let Some(stream) = existing {
            stream
        } else {
            dialer.connect(proxy, socket, TcpDialPurpose::ProxyServer)?
        };
        grpc_stream::wrap_tls_stream(stream, proxy, &tls, grpc)?
    } else if network == "h2" && tls.enabled {
        let stream = if let Some(stream) = existing {
            stream
        } else {
            dialer.connect(proxy, socket, TcpDialPurpose::ProxyServer)?
        };
        h2_stream::wrap_tls_stream_with_request(
            stream,
            proxy,
            &tls,
            &h2_alpn,
            h2_stream::H2RequestOptions {
                authority: h2
                    .host
                    .iter()
                    .find(|value| !value.trim().is_empty())
                    .cloned()
                    .unwrap_or_else(|| proxy.host.clone()),
                path: if h2.path.trim().is_empty() {
                    "/".to_owned()
                } else if h2.path.starts_with('/') {
                    h2.path.clone()
                } else {
                    format!("/{}", h2.path)
                },
                method: "PUT".to_owned(),
                headers: vec![("accept-encoding".to_owned(), "identity".to_owned())],
            },
        )?
    } else {
        open_proxy_stream(
            dialer,
            existing,
            proxy,
            &tls,
            if network == "ws" {
                &websocket_alpn
            } else {
                alpn
            },
            socket,
        )?
    };
    if network == "ws" {
        stream = websocket::wrap_stream(stream, proxy, &websocket)?;
    } else if network == "grpc" && !tls.enabled {
        stream = grpc_stream::wrap_stream(stream, proxy, grpc)?;
    } else if network == "h2" && !tls.enabled {
        stream = h2_stream::wrap_stream(stream, h2)?;
    } else if network == "http" {
        stream = http_stream::wrap_stream(stream, proxy, http);
    }
    vless::wrap_stream_with_flow(stream, uuid, flow, target)
}

fn wrap_vision_stream_if_needed(
    stream: BoxedTcpStream,
    uuid: &str,
    enabled: bool,
    tls13: bool,
) -> Result<BoxedTcpStream, TransportError> {
    if !enabled {
        return Ok(stream);
    }
    if !tls13 {
        return Err(TransportError::UnsupportedFeature {
            proxy: "vless".to_owned(),
            feature: "flow=xtls-rprx-vision requires TLS 1.3".to_owned(),
        });
    }
    let mut vision_stream = vision::VisionStream::new(
        stream,
        tls13,
        *Uuid::parse_str(uuid)
            .map_err(|err| TransportError::InvalidPlan(format!("invalid vless uuid {uuid:?}: {err}")))?
            .as_bytes(),
    );
    vision_stream.start()?;
    Ok(Box::new(vision_stream))
}

fn execute_vmess_connect<D: TcpDialer>(
    dialer: &mut D,
    existing: Option<BoxedTcpStream>,
    proxy: &TransportTarget,
    uuid: &str,
    alter_id: u16,
    cipher: &str,
    _udp: bool,
    network: &str,
    websocket: &WebsocketOptions,
    grpc: &GrpcOptions,
    h2: &Http2Options,
    http: &HttpStreamOptions,
    xhttp: &XHttpOptions,
    _packet_addr: bool,
    _xudp: bool,
    global_padding: bool,
    authenticated_length: bool,
    tls: &TlsOptions,
    alpn: &[String],
    socket: &SocketOptions,
    target: &TransportTarget,
) -> Result<BoxedTcpStream, TransportError> {
    if !network.trim().is_empty()
        && network != "tcp"
        && network != "ws"
        && network != "grpc"
        && network != "http"
        && network != "h2"
        && network != "xhttp"
    {
        return Err(TransportError::UnsupportedFeature {
            proxy: proxy.authority(),
            feature: format!("network={network}"),
        });
    }
    let websocket_alpn = resolved_websocket_alpn(alpn);
    let h2_alpn = vec!["h2".to_owned()];
    let (websocket, tls) = if network == "ws" {
        prepare_websocket_options(websocket, tls, false)
    } else {
        (websocket.clone(), tls.clone())
    };
    if network == "xhttp" {
        let stream = if let Some(stream) = existing {
            stream
        } else {
            dialer.connect(proxy, socket, TcpDialPurpose::ProxyServer)?
        };
        let stream = if tls.enabled {
            xhttp_stream::wrap_tls_stream(stream, proxy, &tls, alpn, xhttp)?
        } else {
            xhttp_stream::wrap_stream(stream, proxy, xhttp)?
        };
        return vmess::wrap_stream(
            stream,
            uuid,
            alter_id,
            cipher,
            global_padding,
            authenticated_length,
            target,
        );
    }
    let mut stream = if network == "grpc" && tls.enabled {
        let stream = if let Some(stream) = existing {
            stream
        } else {
            dialer.connect(proxy, socket, TcpDialPurpose::ProxyServer)?
        };
        grpc_stream::wrap_tls_stream(stream, proxy, &tls, grpc)?
    } else if network == "h2" && tls.enabled {
        let stream = if let Some(stream) = existing {
            stream
        } else {
            dialer.connect(proxy, socket, TcpDialPurpose::ProxyServer)?
        };
        h2_stream::wrap_tls_stream_with_request(
            stream,
            proxy,
            &tls,
            &h2_alpn,
            h2_stream::H2RequestOptions {
                authority: h2
                    .host
                    .iter()
                    .find(|value| !value.trim().is_empty())
                    .cloned()
                    .unwrap_or_else(|| proxy.host.clone()),
                path: if h2.path.trim().is_empty() {
                    "/".to_owned()
                } else if h2.path.starts_with('/') {
                    h2.path.clone()
                } else {
                    format!("/{}", h2.path)
                },
                method: "PUT".to_owned(),
                headers: vec![("accept-encoding".to_owned(), "identity".to_owned())],
            },
        )?
    } else {
        open_proxy_stream(
            dialer,
            existing,
            proxy,
            &tls,
            if network == "ws" {
                &websocket_alpn
            } else {
                alpn
            },
            socket,
        )?
    };
    if network == "ws" {
        stream = websocket::wrap_stream(stream, proxy, &websocket)?;
    } else if network == "grpc" && !tls.enabled {
        stream = grpc_stream::wrap_stream(stream, proxy, grpc)?;
    } else if network == "h2" && !tls.enabled {
        stream = h2_stream::wrap_stream(stream, h2)?;
    } else if network == "http" {
        stream = http_stream::wrap_stream(stream, proxy, http);
    }
    vmess::wrap_stream(
        stream,
        uuid,
        alter_id,
        cipher,
        global_padding,
        authenticated_length,
        target,
    )
}

fn execute_gost_relay_connect<D: TcpDialer>(
    dialer: &mut D,
    existing: Option<BoxedTcpStream>,
    proxy: &TransportTarget,
    auth: &Option<BasicAuth>,
    forward: bool,
    tls: &TlsOptions,
    mux: bool,
    socket: &SocketOptions,
    target: &TransportTarget,
) -> Result<BoxedTcpStream, TransportError> {
    let mut stream = open_proxy_stream(dialer, existing, proxy, tls, &[], socket)?;
    if mux {
        stream = smux_stream::wrap_stream(stream)?;
    }

    write_gost_relay_connect_request(&mut *stream, auth, forward, target)?;
    read_gost_relay_connect_response(&mut *stream)?;
    Ok(stream)
}

fn execute_sudoku_connect<D: TcpDialer>(
    dialer: &mut D,
    existing: Option<BoxedTcpStream>,
    proxy: &TransportTarget,
    key: &str,
    aead_method: &str,
    table_type: &str,
    padding_min: i32,
    padding_max: i32,
    enable_pure_downlink: bool,
    http_mask_enabled: bool,
    http_mask_mode: &str,
    http_mask_tls: bool,
    http_mask_host: &str,
    path_root: &str,
    custom_table: &str,
    custom_tables: &[String],
    socket: &SocketOptions,
    target: &TransportTarget,
) -> Result<BoxedTcpStream, TransportError> {
    let stream = if let Some(stream) = existing {
        stream
    } else {
        dialer.connect(proxy, socket, TcpDialPurpose::ProxyServer)?
    };
    let stream = maybe_wrap_sudoku_ws_http_mask_tls(
        stream,
        proxy,
        http_mask_enabled,
        http_mask_mode,
        http_mask_tls,
        http_mask_host,
    )?;
    sudoku::wrap_stream(
        stream,
        proxy,
        key,
        aead_method,
        table_type,
        padding_min,
        padding_max,
        enable_pure_downlink,
        http_mask_enabled,
        http_mask_mode,
        http_mask_tls,
        http_mask_host,
        path_root,
        custom_table,
        custom_tables,
        target,
    )
}

fn execute_ssh_connect<D: TcpDialer>(
    dialer: &mut D,
    existing: Option<BoxedTcpStream>,
    proxy: &TransportTarget,
    username: &str,
    password: &str,
    private_key: &str,
    private_key_passphrase: &str,
    host_keys: &[String],
    host_key_algorithms: &[String],
    socket: &SocketOptions,
    target: &TransportTarget,
) -> Result<BoxedTcpStream, TransportError> {
    #[cfg(not(feature = "ssh-transport"))]
    {
        let _ = dialer;
        let _ = existing;
        let _ = proxy;
        let _ = username;
        let _ = password;
        let _ = private_key;
        let _ = private_key_passphrase;
        let _ = host_keys;
        let _ = host_key_algorithms;
        let _ = socket;
        let _ = target;
        return Err(TransportError::UnsupportedFeature {
            proxy: "<ssh>".to_owned(),
            feature: "ssh transport support is disabled in the default Rust build".to_owned(),
        });
    }
    #[cfg(feature = "ssh-transport")]
    {
    let stream = if let Some(stream) = existing {
        stream
    } else {
        dialer.connect(proxy, socket, TcpDialPurpose::ProxyServer)?
    };
    ssh::wrap_stream(
        stream,
        username,
        password,
        private_key,
        private_key_passphrase,
        host_keys,
        host_key_algorithms,
        target,
    )
    }
}

fn open_proxy_stream<D: TcpDialer>(
    dialer: &mut D,
    existing: Option<BoxedTcpStream>,
    proxy: &TransportTarget,
    tls: &TlsOptions,
    alpn: &[String],
    socket: &SocketOptions,
) -> Result<BoxedTcpStream, TransportError> {
    let stream = if let Some(stream) = existing {
        stream
    } else {
        dialer.connect(proxy, socket, TcpDialPurpose::ProxyServer)?
    };

    if tls.enabled {
        tls_client::wrap_stream(stream, proxy, tls, alpn)
    } else {
        Ok(stream)
    }
}

fn resolved_websocket_alpn(alpn: &[String]) -> Vec<String> {
    if alpn.is_empty() {
        vec!["http/1.1".to_owned()]
    } else {
        alpn.to_vec()
    }
}

pub(crate) fn maybe_wrap_sudoku_ws_http_mask_tls(
    stream: BoxedTcpStream,
    proxy: &TransportTarget,
    http_mask_enabled: bool,
    http_mask_mode: &str,
    http_mask_tls: bool,
    http_mask_host: &str,
) -> Result<BoxedTcpStream, TransportError> {
    if !http_mask_enabled || !http_mask_tls || http_mask_mode.trim() != "ws" {
        return Ok(stream);
    }
    let sni = if http_mask_host.trim().is_empty() {
        proxy.host.clone()
    } else {
        sudoku_http_mask_sni(http_mask_host)
    };
    tls_client::wrap_stream(
        stream,
        proxy,
        &TlsOptions {
            enabled: true,
            sni,
            skip_cert_verify: false,
            fingerprint: String::new(),
            certificate: String::new(),
            private_key: String::new(),
        },
        &resolved_websocket_alpn(&[]),
    )
}

fn sudoku_http_mask_sni(host: &str) -> String {
    let trimmed = host.trim();
    if let Ok((name, _)) = split_host_port(trimmed) {
        return name.to_owned();
    }
    trimmed.trim_start_matches('[').trim_end_matches(']').to_owned()
}

fn split_host_port(value: &str) -> Result<(&str, &str), ()> {
    if let Some(rest) = value.strip_prefix('[') {
        let Some(end) = rest.find(']') else {
            return Err(());
        };
        let host = &rest[..end];
        let remainder = &rest[end + 1..];
        let Some(port) = remainder.strip_prefix(':') else {
            return Err(());
        };
        return Ok((host, port));
    }
    let Some((host, port)) = value.rsplit_once(':') else {
        return Err(());
    };
    if host.contains(':') {
        return Err(());
    }
    Ok((host, port))
}

fn prepare_websocket_options(
    websocket: &WebsocketOptions,
    tls: &TlsOptions,
    use_sni_as_host: bool,
) -> (WebsocketOptions, TlsOptions) {
    let mut websocket = websocket.clone();
    let mut tls = tls.clone();
    let has_host = websocket
        .headers
        .keys()
        .any(|name| name.eq_ignore_ascii_case("host"));
    if use_sni_as_host && !tls.sni.trim().is_empty() && !has_host {
        websocket.headers.insert("Host".to_owned(), tls.sni.clone());
    }
    if tls.enabled && tls.sni.trim().is_empty() {
        if let Some((_, host)) = websocket
            .headers
            .iter()
            .find(|(name, value)| name.eq_ignore_ascii_case("host") && !value.trim().is_empty())
        {
            tls.sni = host.clone();
        }
    }
    (websocket, tls)
}

fn build_http_connect_request(
    target: &TransportTarget,
    auth: &Option<BasicAuth>,
    headers: &BTreeMap<String, String>,
) -> String {
    let authority = target.authority();
    let mut request = String::new();
    request.push_str(&format!("CONNECT {authority} HTTP/1.1\r\n"));
    request.push_str(&format!("Host: {authority}\r\n"));
    request.push_str("Proxy-Connection: Keep-Alive\r\n");
    if let Some(auth) = auth {
        let encoded =
            base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", auth.username, auth.password));
        request.push_str(&format!("Proxy-Authorization: Basic {encoded}\r\n"));
    }
    for (name, value) in headers {
        request.push_str(name);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    request
}

fn read_http_connect_response(stream: &mut dyn Read) -> Result<Vec<u8>, TransportError> {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            return Err(TransportError::invalid_proxy_response(
                "proxy closed before CONNECT response completed",
            ));
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(position) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            let header_end = position + 4;
            return validate_http_connect_response(&buffer, header_end);
        }
        if buffer.len() > 64 * 1024 {
            return Err(TransportError::invalid_proxy_response(
                "CONNECT response headers exceeded 64KiB",
            ));
        }
    }
}

fn validate_http_connect_response(
    buffer: &[u8],
    header_end: usize,
) -> Result<Vec<u8>, TransportError> {
    let text = String::from_utf8_lossy(&buffer[..header_end]);
    let status_line = text.lines().next().unwrap_or_default();
    let mut parts = status_line.split_whitespace();
    let version = parts.next().unwrap_or_default();
    let status = parts
        .next()
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| {
            TransportError::invalid_proxy_response(format!("missing HTTP status in {status_line:?}"))
        })?;
    if !version.starts_with("HTTP/") {
        return Err(TransportError::invalid_proxy_response(format!(
            "unexpected HTTP version in {status_line:?}"
        )));
    }
    if !(200..300).contains(&status) {
        return Err(TransportError::invalid_proxy_response(format!(
            "CONNECT failed with status {status}"
        )));
    }
    Ok(buffer[header_end..].to_vec())
}

pub(crate) fn prepend_bytes(stream: BoxedTcpStream, prefix: Vec<u8>) -> BoxedTcpStream {
    if prefix.is_empty() {
        stream
    } else {
        Box::new(PrefixedTcpStream {
            prefix: io::Cursor::new(prefix),
            inner: stream,
        })
    }
}

fn write_socks5_greeting(stream: &mut dyn Write, wants_auth: bool) -> Result<(), TransportError> {
    if wants_auth {
        stream.write_all(&[0x05, 0x02, 0x00, 0x02])?;
    } else {
        stream.write_all(&[0x05, 0x01, 0x00])?;
    }
    stream.flush()?;
    Ok(())
}

fn read_socks5_method_selection(
    stream: &mut dyn Read,
    auth: &Option<BasicAuth>,
) -> Result<(), TransportError> {
    let mut reply = [0_u8; 2];
    stream.read_exact(&mut reply)?;
    if reply[0] != 0x05 {
        return Err(TransportError::invalid_proxy_response(format!(
            "unexpected SOCKS version {}",
            reply[0]
        )));
    }
    match reply[1] {
        0x00 => Ok(()),
        0x02 if auth.is_some() => Ok(()),
        0x02 => Err(TransportError::invalid_proxy_response(
            "proxy requested username/password auth but none was configured",
        )),
        0xff => Err(TransportError::invalid_proxy_response(
            "proxy rejected all advertised SOCKS5 auth methods",
        )),
        method => Err(TransportError::invalid_proxy_response(format!(
            "unsupported SOCKS5 auth method {method}"
        ))),
    }
}

fn write_socks5_auth(stream: &mut dyn Write, auth: &BasicAuth) -> Result<(), TransportError> {
    let username = auth.username.as_bytes();
    let password = auth.password.as_bytes();
    if username.len() > u8::MAX as usize || password.len() > u8::MAX as usize {
        return Err(TransportError::InvalidPlan(
            "SOCKS5 username/password must fit within 255 bytes".to_owned(),
        ));
    }

    let mut request = Vec::with_capacity(3 + username.len() + password.len());
    request.push(0x01);
    request.push(username.len() as u8);
    request.extend_from_slice(username);
    request.push(password.len() as u8);
    request.extend_from_slice(password);
    stream.write_all(&request)?;
    stream.flush()?;
    Ok(())
}

fn read_socks5_auth_result(stream: &mut dyn Read) -> Result<(), TransportError> {
    let mut reply = [0_u8; 2];
    stream.read_exact(&mut reply)?;
    if reply[0] != 0x01 {
        return Err(TransportError::invalid_proxy_response(format!(
            "unexpected SOCKS5 auth version {}",
            reply[0]
        )));
    }
    if reply[1] != 0x00 {
        return Err(TransportError::invalid_proxy_response(format!(
            "SOCKS5 auth failed with status {}",
            reply[1]
        )));
    }
    Ok(())
}

fn write_socks5_connect_request(
    stream: &mut dyn Write,
    target: &TransportTarget,
) -> Result<(), TransportError> {
    let mut request = vec![0x05, 0x01, 0x00];
    request.extend_from_slice(&encode_socks5_target(target)?);
    request.extend_from_slice(&target.port.to_be_bytes());
    stream.write_all(&request)?;
    stream.flush()?;
    Ok(())
}

pub(crate) fn encode_socks5_target(
    target: &TransportTarget,
) -> Result<Vec<u8>, TransportError> {
    if let Ok(ip) = IpAddr::from_str(&target.host) {
        match ip {
            IpAddr::V4(ip) => Ok([vec![0x01], ip.octets().to_vec()].concat()),
            IpAddr::V6(ip) => Ok([vec![0x04], ip.octets().to_vec()].concat()),
        }
    } else {
        let host = target.host.as_bytes();
        if host.len() > u8::MAX as usize {
            return Err(TransportError::InvalidPlan(
                "SOCKS5 domain target must fit within 255 bytes".to_owned(),
            ));
        }
        let mut encoded = Vec::with_capacity(2 + host.len());
        encoded.push(0x03);
        encoded.push(host.len() as u8);
        encoded.extend_from_slice(host);
        Ok(encoded)
    }
}

fn write_gost_relay_connect_request(
    stream: &mut dyn Write,
    auth: &Option<BasicAuth>,
    forward: bool,
    target: &TransportTarget,
) -> Result<(), TransportError> {
    const RELAY_VERSION_1: u8 = 0x01;
    const RELAY_CMD_CONNECT: u8 = 0x01;
    const RELAY_FEATURE_USER_AUTH: u8 = 0x01;
    const RELAY_FEATURE_ADDR: u8 = 0x02;
    const RELAY_FEATURE_NETWORK: u8 = 0x04;
    const RELAY_NETWORK_TCP: u16 = 0x0000;

    let mut features = Vec::new();
    if let Some(auth) = auth {
        let auth_feature = encode_gost_relay_feature(
            RELAY_FEATURE_USER_AUTH,
            encode_gost_relay_user_auth(auth)?,
        )?;
        features.push(auth_feature);
    }
    if !forward {
        let addr_feature =
            encode_gost_relay_feature(RELAY_FEATURE_ADDR, encode_gost_relay_addr(target)?)?;
        features.push(addr_feature);
    }
    let network_feature = encode_gost_relay_feature(
        RELAY_FEATURE_NETWORK,
        RELAY_NETWORK_TCP.to_be_bytes().to_vec(),
    )?;
    features.push(network_feature);

    let feature_len = features.iter().map(Vec::len).sum::<usize>();
    if feature_len > u16::MAX as usize {
        return Err(TransportError::InvalidPlan(
            "gost relay feature list too large".to_owned(),
        ));
    }

    stream.write_all(&[
        RELAY_VERSION_1,
        RELAY_CMD_CONNECT,
        (feature_len >> 8) as u8,
        feature_len as u8,
    ])?;
    for feature in features {
        stream.write_all(&feature)?;
    }
    stream.flush()?;
    Ok(())
}

pub(crate) fn write_gost_relay_udp_associate_request(
    stream: &mut dyn Write,
    auth: &Option<BasicAuth>,
    forward: bool,
    target: std::net::SocketAddr,
) -> Result<(), TransportError> {
    const RELAY_VERSION_1: u8 = 0x01;
    const RELAY_CMD_CONNECT: u8 = 0x01;
    const RELAY_FLAG_UDP: u8 = 0x80;
    const RELAY_FEATURE_USER_AUTH: u8 = 0x01;
    const RELAY_FEATURE_ADDR: u8 = 0x02;
    const RELAY_FEATURE_NETWORK: u8 = 0x04;
    const RELAY_NETWORK_UDP: u16 = 0x0001;

    let mut features = Vec::new();
    if let Some(auth) = auth {
        let auth_feature = encode_gost_relay_feature(
            RELAY_FEATURE_USER_AUTH,
            encode_gost_relay_user_auth(auth)?,
        )?;
        features.push(auth_feature);
    }
    if !forward {
        let addr_feature = encode_gost_relay_feature(
            RELAY_FEATURE_ADDR,
            encode_gost_relay_addr(&TransportTarget::new(target.ip().to_string(), target.port()))?,
        )?;
        features.push(addr_feature);
    }
    let network_feature = encode_gost_relay_feature(
        RELAY_FEATURE_NETWORK,
        RELAY_NETWORK_UDP.to_be_bytes().to_vec(),
    )?;
    features.push(network_feature);

    let feature_len = features.iter().map(Vec::len).sum::<usize>();
    if feature_len > u16::MAX as usize {
        return Err(TransportError::InvalidPlan(
            "gost relay feature list too large".to_owned(),
        ));
    }

    stream.write_all(&[
        RELAY_VERSION_1,
        RELAY_CMD_CONNECT | RELAY_FLAG_UDP,
        (feature_len >> 8) as u8,
        feature_len as u8,
    ])?;
    for feature in features {
        stream.write_all(&feature)?;
    }
    stream.flush()?;
    Ok(())
}

fn encode_gost_relay_feature(feature_type: u8, payload: Vec<u8>) -> Result<Vec<u8>, TransportError> {
    if payload.len() > u16::MAX as usize {
        return Err(TransportError::InvalidPlan(
            "gost relay feature payload too large".to_owned(),
        ));
    }
    let mut encoded = Vec::with_capacity(3 + payload.len());
    encoded.push(feature_type);
    encoded.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    encoded.extend_from_slice(&payload);
    Ok(encoded)
}

fn encode_gost_relay_user_auth(auth: &BasicAuth) -> Result<Vec<u8>, TransportError> {
    if auth.username.len() > u8::MAX as usize || auth.password.len() > u8::MAX as usize {
        return Err(TransportError::InvalidPlan(
            "gost relay username or password too long".to_owned(),
        ));
    }
    let mut encoded = Vec::with_capacity(2 + auth.username.len() + auth.password.len());
    encoded.push(auth.username.len() as u8);
    encoded.extend_from_slice(auth.username.as_bytes());
    encoded.push(auth.password.len() as u8);
    encoded.extend_from_slice(auth.password.as_bytes());
    Ok(encoded)
}

fn encode_gost_relay_addr(target: &TransportTarget) -> Result<Vec<u8>, TransportError> {
    const RELAY_ADDR_IPV4: u8 = 0x01;
    const RELAY_ADDR_DOMAIN: u8 = 0x03;
    const RELAY_ADDR_IPV6: u8 = 0x04;

    let mut encoded = Vec::new();
    if let Ok(ip) = IpAddr::from_str(&target.host) {
        match ip {
            IpAddr::V4(ip) => {
                encoded.push(RELAY_ADDR_IPV4);
                encoded.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                encoded.push(RELAY_ADDR_IPV6);
                encoded.extend_from_slice(&ip.octets());
            }
        }
    } else {
        let host = target.host.as_bytes();
        if host.len() > u8::MAX as usize {
            return Err(TransportError::InvalidPlan(
                "gost relay target host too long".to_owned(),
            ));
        }
        encoded.push(RELAY_ADDR_DOMAIN);
        encoded.push(host.len() as u8);
        encoded.extend_from_slice(host);
    }
    encoded.extend_from_slice(&target.port.to_be_bytes());
    Ok(encoded)
}

pub(crate) fn read_gost_relay_connect_response(
    stream: &mut dyn Read,
) -> Result<(), TransportError> {
    const RELAY_VERSION_1: u8 = 0x01;
    const RELAY_STATUS_OK: u8 = 0x00;

    let mut header = [0_u8; 4];
    stream.read_exact(&mut header)?;
    if header[0] != RELAY_VERSION_1 {
        return Err(TransportError::invalid_proxy_response(format!(
            "unexpected gost relay version {}",
            header[0]
        )));
    }
    if header[1] != RELAY_STATUS_OK {
        return Err(TransportError::invalid_proxy_response(format!(
            "gost relay connect failed with status 0x{:02x}",
            header[1]
        )));
    }
    let feature_len = u16::from_be_bytes([header[2], header[3]]) as usize;
    if feature_len == 0 {
        return Ok(());
    }
    let mut discard = vec![0_u8; feature_len];
    stream.read_exact(&mut discard)?;
    Ok(())
}

fn read_socks5_connect_response(stream: &mut dyn Read) -> Result<(), TransportError> {
    let mut header = [0_u8; 4];
    stream.read_exact(&mut header)?;
    if header[0] != 0x05 {
        return Err(TransportError::invalid_proxy_response(format!(
            "unexpected SOCKS5 reply version {}",
            header[0]
        )));
    }
    if header[1] != 0x00 {
        return Err(TransportError::invalid_proxy_response(format!(
            "SOCKS5 connect failed with status {}",
            header[1]
        )));
    }
    consume_socks5_bound_address(stream, header[3])?;
    Ok(())
}

fn consume_socks5_bound_address(
    stream: &mut dyn Read,
    atyp: u8,
) -> Result<(), TransportError> {
    let length = match atyp {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut length = [0_u8; 1];
            stream.read_exact(&mut length)?;
            length[0] as usize
        }
        _ => {
            return Err(TransportError::invalid_proxy_response(format!(
                "unsupported SOCKS5 bound address type {atyp}"
            )));
        }
    };
    let mut address = vec![0_u8; length];
    stream.read_exact(&mut address)?;
    let mut port = [0_u8; 2];
    stream.read_exact(&mut port)?;
    Ok(())
}
