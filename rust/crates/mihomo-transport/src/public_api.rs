use std::io::{self, Read, Write};
use std::sync::Arc;

use mihomo_core::BoxedTcpStream;
use crate::transport_types::MasqueConnectOptions;

use crate::{
    anytls, apply_trojan_shadowsocks, grpc_stream, h2_stream, http_stream, hysteria_stream,
    hy2_stream, maybe_wrap_sudoku_ws_http_mask_tls, read_gost_relay_connect_response,
    masque_stream, shadowsocks, shadowsocks_2022, simple_obfs, smux_stream, snell, ssr, sudoku,
    sudoku_httpmask, tls_client,
    stream_prefix, trojan, trusttunnel, tuic_stream, v2ray_plugin_mux, vless, vmess, websocket,
    wireguard_stream, write_gost_relay_udp_associate_request, BasicAuth, GrpcOptions,
    Http2Options, HttpStreamOptions, HysteriaOptions, Hy2UdpOptions, TlsOptions,
    OpenVpnOptions, TransportError, TransportTarget, TrojanShadowsocksOptions, TuicUdpOptions,
    WebsocketOptions, WireGuardOptions, XHttpOptions, xhttp_stream,
};

pub fn encode_shadowsocks_udp_packet(
    cipher: &str,
    password: &str,
    target: std::net::SocketAddr,
    payload: &[u8],
) -> Result<Vec<u8>, TransportError> {
    shadowsocks::encode_udp_packet(cipher, password, target, payload)
}

pub fn encode_shadowsocks_udp_packet_for_target(
    cipher: &str,
    password: &str,
    target: &TransportTarget,
    payload: &[u8],
) -> Result<Vec<u8>, TransportError> {
    shadowsocks::encode_udp_packet_for_target(cipher, password, target, payload)
}

pub fn decode_shadowsocks_udp_packet(
    cipher: &str,
    password: &str,
    packet: &[u8],
) -> Result<(std::net::SocketAddr, Vec<u8>), TransportError> {
    shadowsocks::decode_udp_packet(cipher, password, packet)
}

#[doc(hidden)]
pub fn accept_simple_obfs_tls_test_stream(stream: BoxedTcpStream) -> BoxedTcpStream {
    simple_obfs::wrap_tls_server_stream(stream)
}

#[doc(hidden)]
pub fn accept_simple_obfs_http_test_stream(stream: BoxedTcpStream) -> BoxedTcpStream {
    simple_obfs::wrap_http_server_stream(stream)
}

#[doc(hidden)]
pub fn open_simple_obfs_http_stream_for_tests(
    stream: BoxedTcpStream,
    host: &str,
    port: &str,
) -> BoxedTcpStream {
    simple_obfs::wrap_http_stream(stream, host, port)
}

#[doc(hidden)]
pub fn open_simple_obfs_tls_stream_for_tests(
    stream: BoxedTcpStream,
    host: &str,
) -> BoxedTcpStream {
    simple_obfs::wrap_tls_stream(stream, host)
}

#[doc(hidden)]
pub fn accept_shadowsocks_test_stream(
    stream: BoxedTcpStream,
    cipher: &str,
    password: &str,
) -> Result<BoxedTcpStream, TransportError> {
    shadowsocks::wrap_accepted_stream(stream, cipher, password)
}

/// Validates a SIP022 PSK (base64) for the given 2022 cipher, returning the
/// decoded key length.
pub fn validate_shadowsocks_2022_psk(
    cipher: &str,
    password: &str,
) -> Result<usize, TransportError> {
    shadowsocks_2022::validate_psk(cipher, password)
}

/// Returns whether the cipher name refers to a SIP022 AEAD-2022 method.
pub fn is_shadowsocks_2022_cipher(cipher: &str) -> bool {
    shadowsocks_2022::Shadowsocks2022Cipher::parse(cipher).is_some()
}

pub fn parse_reality_private_key(value: &str) -> Result<[u8; 32], TransportError> {
    crate::reality_tls::RealityServerConfig::parse_private_key(value)
}

pub fn parse_reality_public_key(value: &str) -> Result<[u8; 32], TransportError> {
    crate::reality_tls::parse_client_public_key(value)
}

pub fn parse_reality_short_id(value: &str) -> Result<[u8; 8], TransportError> {
    crate::reality_tls::RealityServerConfig::parse_short_id(value)
}

#[doc(hidden)]
pub use shadowsocks_2022::{
    decode_udp_packet as decode_shadowsocks_2022_udp_packet,
    decode_udp_response as decode_shadowsocks_2022_udp_response,
    encode_udp_packet as encode_shadowsocks_2022_udp_packet,
    encode_udp_response as encode_shadowsocks_2022_udp_response,
    Shadowsocks2022UdpRegistry, Shadowsocks2022UdpResponseSession,
    Shadowsocks2022UdpState,
};

/// Process-wide SIP022 UDP session registry (replay window + responders).
pub fn shadowsocks_2022_udp_registry() -> &'static Shadowsocks2022UdpRegistry {
    static REGISTRY: std::sync::OnceLock<Shadowsocks2022UdpRegistry> =
        std::sync::OnceLock::new();
    REGISTRY.get_or_init(Shadowsocks2022UdpRegistry::new)
}

/// REALITY keypair generation (`generate reality-keypair` parity).
pub fn generate_reality_keys() -> crate::reality_tls::RealityKeys {
    crate::reality_tls::generate_keypair()
}

/// Inbound REALITY: validates the seal, mirrors the camouflage ServerHello
/// and completes the TLS 1.3 flight. `Err(Rejected)` means the connection
/// was transparently relayed to the camouflage site.
pub fn accept_reality_stream(
    stream: BoxedTcpStream,
    config: &crate::reality_tls::RealityServerConfig,
) -> Result<BoxedTcpStream, TransportError> {
    crate::reality_tls::accept_stream(stream, config)
}

/// Outbound REALITY: performs the client handshake and returns the
/// application-data stream.
pub fn wrap_reality_stream(
    stream: BoxedTcpStream,
    config: &crate::reality_tls::RealityClientConfig,
    target: &TransportTarget,
) -> Result<BoxedTcpStream, TransportError> {
    crate::reality_tls::wrap_stream(stream, config, target)
}

pub use crate::reality_tls::{RealityClientConfig, RealityServerConfig};

#[doc(hidden)]
pub fn test_support_reality_site_hello() -> Vec<u8> {
    crate::reality_tls::fake_site_server_hello()
}

#[doc(hidden)]
pub fn accept_shadowsocks_2022_stream(
    stream: BoxedTcpStream,
    cipher: &str,
    password: &str,
) -> Result<(TransportTarget, BoxedTcpStream), TransportError> {
    shadowsocks_2022::accept_stream(stream, cipher, password)
}

#[doc(hidden)]
pub fn open_shadowsocks_2022_tcp_stream_for_tests(
    stream: BoxedTcpStream,
    cipher: &str,
    password: &str,
    target: &TransportTarget,
) -> Result<BoxedTcpStream, TransportError> {
    shadowsocks_2022::wrap_stream(stream, cipher, password, target)
}

#[doc(hidden)]
pub fn open_shadowsocks_tcp_stream_for_tests(
    stream: BoxedTcpStream,
    cipher: &str,
    password: &str,
    target: &TransportTarget,
) -> Result<BoxedTcpStream, TransportError> {
    shadowsocks::wrap_stream(stream, cipher, password, target)
}

#[doc(hidden)]
pub fn accept_ssr_test_stream(
    stream: BoxedTcpStream,
    cipher: &str,
    password: &str,
) -> Result<BoxedTcpStream, TransportError> {
    ssr::wrap_accepted_stream(stream, cipher, password)
}

#[doc(hidden)]
pub fn accept_v2ray_plugin_mux_test_stream(stream: BoxedTcpStream) -> io::Result<BoxedTcpStream> {
    v2ray_plugin_mux::accept_test_stream(stream)
}

#[doc(hidden)]
pub fn accept_ssr_http_obfs_test_stream(
    stream: BoxedTcpStream,
) -> io::Result<(String, BoxedTcpStream)> {
    stream_prefix::accept_ssr_http_obfs_test_stream(stream)
}

#[doc(hidden)]
pub fn accept_smux_test_stream(stream: BoxedTcpStream) -> io::Result<BoxedTcpStream> {
    smux_stream::accept_test_stream(stream)
}

#[doc(hidden)]
pub fn wrap_smux_stream(stream: BoxedTcpStream) -> io::Result<BoxedTcpStream> {
    smux_stream::wrap_stream(stream)
}

pub fn encode_ssr_udp_packet(
    cipher: &str,
    password: &str,
    target: std::net::SocketAddr,
    payload: &[u8],
) -> Result<Vec<u8>, TransportError> {
    ssr::encode_udp_packet(cipher, password, target, payload)
}

pub fn decode_ssr_udp_packet(
    cipher: &str,
    password: &str,
    packet: &[u8],
) -> io::Result<(std::net::SocketAddr, Vec<u8>)> {
    ssr::decode_udp_packet(cipher, password, packet)
}

pub fn wrap_snell_udp_stream(
    stream: BoxedTcpStream,
    psk: &str,
    version: u8,
    obfs_mode: &str,
    obfs_host: &str,
    port: u16,
) -> Result<BoxedTcpStream, TransportError> {
    let host = if obfs_host.trim().is_empty() {
        "bing.com"
    } else {
        obfs_host
    };
    let stream = match obfs_mode.trim() {
        "" => stream,
        "tls" => simple_obfs::wrap_tls_stream(stream, host),
        "http" => simple_obfs::wrap_http_stream(stream, host, &port.to_string()),
        other => {
            return Err(TransportError::UnsupportedFeature {
                proxy: "<snell>".to_owned(),
                feature: format!("obfs={other}"),
            })
        }
    };
    snell::open_udp_stream(stream, psk, version, "")
}

pub fn accept_snell_udp_stream(
    stream: BoxedTcpStream,
    psk: &str,
    version: u8,
) -> Result<BoxedTcpStream, TransportError> {
    snell::wrap_accepted_stream(stream, psk, version)
}

pub fn write_snell_udp_packet(
    stream: &mut dyn Write,
    target: std::net::SocketAddr,
    payload: &[u8],
) -> io::Result<usize> {
    snell::write_udp_packet(stream, target, payload)
}

pub fn read_snell_udp_packet(
    stream: &mut dyn Read,
) -> io::Result<(std::net::SocketAddr, Vec<u8>)> {
    snell::read_udp_packet(stream)
}

pub fn open_vless_udp_stream(
    stream: BoxedTcpStream,
    uuid: &str,
    target: std::net::SocketAddr,
) -> Result<BoxedTcpStream, TransportError> {
    vless::open_udp_stream(stream, uuid, target)
}

/// Opens UDP for a Vision account over TLS 1.3/REALITY. The UDP command uses
/// an empty flow; Vision framing applies to TCP and the XUDP Mux command.
pub fn open_vless_vision_udp_stream(
    stream: BoxedTcpStream,
    uuid: &str,
    target: std::net::SocketAddr,
    packet_addr: bool,
    xudp: bool,
) -> Result<BoxedTcpStream, TransportError> {
    if !xudp {
        return if packet_addr {
            vless::open_packetaddr_udp_stream(stream, uuid)
        } else {
            vless::open_udp_stream(stream, uuid, target)
        };
    }
    let user = uuid::Uuid::parse_str(uuid)
        .map_err(|err| TransportError::InvalidPlan(format!("invalid vless uuid: {err}")))?;
    let stream = vless::open_udp_stream_with_flow(
        stream,
        uuid,
        "xtls-rprx-vision",
        target,
        packet_addr,
        xudp,
    )?;
    let mut stream = crate::vision::VisionStream::new(stream, true, *user.as_bytes());
    stream.start()?;
    Ok(Box::new(stream))
}

#[doc(hidden)]
pub fn open_vless_tcp_stream_for_tests(
    stream: BoxedTcpStream,
    uuid: &str,
    target: &TransportTarget,
) -> Result<BoxedTcpStream, TransportError> {
    vless::wrap_stream(stream, uuid, target)
}

pub fn open_vless_packetaddr_udp_stream(
    stream: BoxedTcpStream,
    uuid: &str,
) -> Result<BoxedTcpStream, TransportError> {
    vless::open_packetaddr_udp_stream(stream, uuid)
}

pub fn open_vless_xudp_stream(
    stream: BoxedTcpStream,
    uuid: &str,
) -> Result<BoxedTcpStream, TransportError> {
    vless::open_xudp_stream(stream, uuid)
}

pub fn open_vmess_udp_stream(
    stream: BoxedTcpStream,
    uuid: &str,
    alter_id: u16,
    cipher: &str,
    global_padding: bool,
    authenticated_length: bool,
    target: std::net::SocketAddr,
) -> Result<BoxedTcpStream, TransportError> {
    vmess::open_udp_stream(
        stream,
        uuid,
        alter_id,
        cipher,
        global_padding,
        authenticated_length,
        target,
    )
}

pub fn open_vmess_packetaddr_udp_stream(
    stream: BoxedTcpStream,
    uuid: &str,
    alter_id: u16,
    cipher: &str,
    global_padding: bool,
    authenticated_length: bool,
) -> Result<BoxedTcpStream, TransportError> {
    vmess::open_packetaddr_udp_stream(
        stream,
        uuid,
        alter_id,
        cipher,
        global_padding,
        authenticated_length,
    )
}

pub fn open_vmess_xudp_stream(
    stream: BoxedTcpStream,
    uuid: &str,
    alter_id: u16,
    cipher: &str,
    global_padding: bool,
    authenticated_length: bool,
) -> Result<BoxedTcpStream, TransportError> {
    vmess::open_xudp_stream(
        stream,
        uuid,
        alter_id,
        cipher,
        global_padding,
        authenticated_length,
    )
}

pub fn write_vmess_xudp_packet(
    stream: &mut dyn Write,
    target: std::net::SocketAddr,
    payload: &[u8],
) -> io::Result<usize> {
    vmess::write_xudp_packet(stream, target, payload)
}

pub fn read_vmess_xudp_packet(
    stream: &mut dyn Read,
) -> io::Result<(std::net::SocketAddr, Vec<u8>)> {
    vmess::read_xudp_packet(stream)
}

pub fn write_vless_udp_packet(stream: &mut dyn Write, payload: &[u8]) -> io::Result<usize> {
    vless::write_udp_packet(stream, payload)
}

pub fn read_vless_udp_packet(stream: &mut dyn Read) -> io::Result<Vec<u8>> {
    vless::read_udp_packet(stream)
}

pub fn write_vless_xudp_packet(
    stream: &mut dyn Write,
    target: std::net::SocketAddr,
    payload: &[u8],
) -> io::Result<usize> {
    vless::write_xudp_packet(stream, target, payload)
}

pub fn read_vless_xudp_packet(
    stream: &mut dyn Read,
) -> io::Result<(std::net::SocketAddr, Vec<u8>)> {
    vless::read_xudp_packet(stream)
}

pub fn write_vmess_udp_packet(stream: &mut dyn Write, payload: &[u8]) -> io::Result<usize> {
    vmess::write_udp_packet(stream, payload)
}

pub fn read_vmess_udp_packet(stream: &mut dyn Read) -> io::Result<Vec<u8>> {
    vmess::read_udp_packet(stream)
}

pub fn encode_packetaddr_udp_packet(
    destination: std::net::SocketAddr,
    payload: &[u8],
) -> Vec<u8> {
    let mut packet = Vec::with_capacity(1 + 16 + payload.len());
    match destination {
        std::net::SocketAddr::V4(addr) => {
            packet.push(0x01);
            packet.extend_from_slice(&addr.ip().octets());
            packet.extend_from_slice(&addr.port().to_be_bytes());
        }
        std::net::SocketAddr::V6(addr) => {
            packet.push(0x02);
            packet.extend_from_slice(&addr.ip().octets());
            packet.extend_from_slice(&addr.port().to_be_bytes());
        }
    }
    packet.extend_from_slice(payload);
    packet
}

pub fn decode_packetaddr_udp_packet(
    payload: &[u8],
) -> io::Result<(std::net::SocketAddr, Vec<u8>)> {
    if payload.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "packet-addr payload is empty",
        ));
    }
    let atyp = payload[0];
    let (ip, offset) = match atyp {
        0x01 => {
            if payload.len() < 1 + 4 + 2 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "packet-addr ipv4 payload is truncated",
                ));
            }
            let octets = [payload[1], payload[2], payload[3], payload[4]];
            (std::net::IpAddr::V4(std::net::Ipv4Addr::from(octets)), 5)
        }
        0x02 => {
            if payload.len() < 1 + 16 + 2 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "packet-addr ipv6 payload is truncated",
                ));
            }
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&payload[1..17]);
            (std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets)), 17)
        }
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsupported packet-addr family {other}"),
            ))
        }
    };
    let port = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
    Ok((
        std::net::SocketAddr::new(ip, port),
        payload[offset + 2..].to_vec(),
    ))
}

pub fn open_sudoku_udp_stream(
    stream: BoxedTcpStream,
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
) -> Result<BoxedTcpStream, TransportError> {
    let stream = maybe_wrap_sudoku_ws_http_mask_tls(
        stream,
        proxy,
        http_mask_enabled,
        http_mask_mode,
        http_mask_tls,
        http_mask_host,
    )?;
    sudoku::open_udp_stream(
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
    )
}

#[doc(hidden)]
pub fn open_sudoku_test_stream(
    stream: BoxedTcpStream,
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
    target: &TransportTarget,
) -> Result<BoxedTcpStream, TransportError> {
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

#[doc(hidden)]
pub fn open_sudoku_multiplex_test_stream(
    stream: BoxedTcpStream,
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
    target: &TransportTarget,
) -> Result<BoxedTcpStream, TransportError> {
    sudoku::open_multiplex_client_stream(
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

pub fn write_sudoku_udp_packet(
    stream: &mut dyn Write,
    target: std::net::SocketAddr,
    payload: &[u8],
) -> io::Result<usize> {
    sudoku::write_udp_packet(stream, target, payload)
}

pub fn read_sudoku_udp_packet(
    stream: &mut dyn Read,
) -> io::Result<(std::net::SocketAddr, Vec<u8>)> {
    sudoku::read_udp_packet(stream)
}

pub fn prewarm_sudoku_tables(
    key: &str,
    table_type: &str,
    custom_table: &str,
    custom_tables: &[String],
) -> Result<(), TransportError> {
    sudoku::prewarm_tables(key, table_type, custom_table, custom_tables)
}

pub enum SudokuAcceptedStream {
    Tcp {
        target: String,
        stream: BoxedTcpStream,
    },
    Multiplex {
        server: sudoku::SudokuMultiplexServer,
    },
    Udp {
        stream: BoxedTcpStream,
    },
}

pub enum SudokuInboundAccept {
    Session(SudokuAcceptedStream),
    PassThrough(BoxedTcpStream),
    Rejected(BoxedTcpStream),
}

pub fn accept_sudoku_stream(
    stream: BoxedTcpStream,
    key: &str,
    aead_method: &str,
    table_type: &str,
    padding_min: i32,
    padding_max: i32,
    enable_pure_downlink: bool,
    http_mask_enabled: bool,
) -> Result<SudokuAcceptedStream, TransportError> {
    match sudoku::accept_server_stream_for_tests(
        stream,
        key,
        aead_method,
        table_type,
        padding_min,
        padding_max,
        enable_pure_downlink,
        http_mask_enabled,
    )? {
        sudoku::SudokuServerSession::Tcp { target, stream } => {
            Ok(SudokuAcceptedStream::Tcp { target, stream })
        }
        sudoku::SudokuServerSession::Multiplex { stream } => {
            Ok(SudokuAcceptedStream::Multiplex {
                server: sudoku::SudokuMultiplexServer::new(stream)?,
            })
        }
        sudoku::SudokuServerSession::Udp { stream } => Ok(SudokuAcceptedStream::Udp { stream }),
    }
}

pub fn accept_sudoku_stream_allow_suspicious(
    stream: BoxedTcpStream,
    key: &str,
    aead_method: &str,
    table_type: &str,
    padding_min: i32,
    padding_max: i32,
    enable_pure_downlink: bool,
    http_mask_enabled: bool,
) -> Result<SudokuInboundAccept, TransportError> {
    match sudoku::accept_server_stream_for_tests_with_custom_tables_allow_suspicious(
        stream,
        key,
        aead_method,
        table_type,
        padding_min,
        padding_max,
        enable_pure_downlink,
        http_mask_enabled,
        "",
        &[],
    )? {
        sudoku::SudokuServerAcceptOutcome::Session(sudoku::SudokuServerSession::Tcp { target, stream }) => {
            Ok(SudokuInboundAccept::Session(SudokuAcceptedStream::Tcp { target, stream }))
        }
        sudoku::SudokuServerAcceptOutcome::Session(sudoku::SudokuServerSession::Multiplex { stream }) => {
            Ok(SudokuInboundAccept::Session(SudokuAcceptedStream::Multiplex {
                server: sudoku::SudokuMultiplexServer::new(stream)?,
            }))
        }
        sudoku::SudokuServerAcceptOutcome::Session(sudoku::SudokuServerSession::Udp { stream }) => {
            Ok(SudokuInboundAccept::Session(SudokuAcceptedStream::Udp { stream }))
        }
        sudoku::SudokuServerAcceptOutcome::Suspicious(stream) => {
            Ok(SudokuInboundAccept::PassThrough(stream))
        }
    }
}

pub fn accept_sudoku_stream_with_custom_tables_allow_suspicious(
    stream: BoxedTcpStream,
    key: &str,
    aead_method: &str,
    table_type: &str,
    padding_min: i32,
    padding_max: i32,
    enable_pure_downlink: bool,
    http_mask_enabled: bool,
    custom_table: &str,
    custom_tables: &[String],
) -> Result<SudokuInboundAccept, TransportError> {
    match sudoku::accept_server_stream_for_tests_with_custom_tables_allow_suspicious(
        stream,
        key,
        aead_method,
        table_type,
        padding_min,
        padding_max,
        enable_pure_downlink,
        http_mask_enabled,
        custom_table,
        custom_tables,
    )? {
        sudoku::SudokuServerAcceptOutcome::Session(sudoku::SudokuServerSession::Tcp { target, stream }) => {
            Ok(SudokuInboundAccept::Session(SudokuAcceptedStream::Tcp { target, stream }))
        }
        sudoku::SudokuServerAcceptOutcome::Session(sudoku::SudokuServerSession::Multiplex { stream }) => {
            Ok(SudokuInboundAccept::Session(SudokuAcceptedStream::Multiplex {
                server: sudoku::SudokuMultiplexServer::new(stream)?,
            }))
        }
        sudoku::SudokuServerAcceptOutcome::Session(sudoku::SudokuServerSession::Udp { stream }) => {
            Ok(SudokuInboundAccept::Session(SudokuAcceptedStream::Udp { stream }))
        }
        sudoku::SudokuServerAcceptOutcome::Suspicious(stream) => {
            Ok(SudokuInboundAccept::PassThrough(stream))
        }
    }
}

pub fn accept_sudoku_stream_with_http_mask(
    stream: BoxedTcpStream,
    acceptor: &sudoku_httpmask::HttpMaskServerAcceptor,
    key: &str,
    aead_method: &str,
    table_type: &str,
    padding_min: i32,
    padding_max: i32,
    enable_pure_downlink: bool,
    http_mask_enabled: bool,
) -> Result<Option<SudokuInboundAccept>, TransportError> {
    let Some(result) = acceptor.accept(stream)? else {
        return Ok(None);
    };
    match result {
        sudoku_httpmask::HttpMaskAcceptResult::Tunnel(stream) => {
            Ok(Some(SudokuInboundAccept::Session(accept_sudoku_stream(
                stream,
                key,
                aead_method,
                table_type,
                padding_min,
                padding_max,
                enable_pure_downlink,
                http_mask_enabled,
            )?)))
        }
        sudoku_httpmask::HttpMaskAcceptResult::PassThrough(stream) => {
            Ok(Some(accept_sudoku_stream_allow_suspicious(
                stream,
                key,
                aead_method,
                table_type,
                padding_min,
                padding_max,
                enable_pure_downlink,
                http_mask_enabled,
            )?))
        }
        sudoku_httpmask::HttpMaskAcceptResult::Rejected(stream) => {
            Ok(Some(SudokuInboundAccept::Rejected(stream)))
        }
    }
}

pub fn accept_sudoku_stream_with_custom_tables(
    stream: BoxedTcpStream,
    key: &str,
    aead_method: &str,
    table_type: &str,
    padding_min: i32,
    padding_max: i32,
    enable_pure_downlink: bool,
    http_mask_enabled: bool,
    custom_table: &str,
    custom_tables: &[String],
) -> Result<SudokuAcceptedStream, TransportError> {
    match sudoku::accept_server_stream_for_tests_with_custom_tables(
        stream,
        key,
        aead_method,
        table_type,
        padding_min,
        padding_max,
        enable_pure_downlink,
        http_mask_enabled,
        custom_table,
        custom_tables,
    )? {
        sudoku::SudokuServerSession::Tcp { target, stream } => {
            Ok(SudokuAcceptedStream::Tcp { target, stream })
        }
        sudoku::SudokuServerSession::Multiplex { stream } => {
            Ok(SudokuAcceptedStream::Multiplex {
                server: sudoku::SudokuMultiplexServer::new(stream)?,
            })
        }
        sudoku::SudokuServerSession::Udp { stream } => Ok(SudokuAcceptedStream::Udp { stream }),
    }
}

pub fn accept_sudoku_stream_with_custom_tables_and_http_mask(
    stream: BoxedTcpStream,
    acceptor: &sudoku_httpmask::HttpMaskServerAcceptor,
    key: &str,
    aead_method: &str,
    table_type: &str,
    padding_min: i32,
    padding_max: i32,
    enable_pure_downlink: bool,
    http_mask_enabled: bool,
    custom_table: &str,
    custom_tables: &[String],
) -> Result<Option<SudokuInboundAccept>, TransportError> {
    let Some(result) = acceptor.accept(stream)? else {
        return Ok(None);
    };
    match result {
        sudoku_httpmask::HttpMaskAcceptResult::Tunnel(stream) => Ok(Some(
            SudokuInboundAccept::Session(accept_sudoku_stream_with_custom_tables(
                stream,
                key,
                aead_method,
                table_type,
                padding_min,
                padding_max,
                enable_pure_downlink,
                http_mask_enabled,
                custom_table,
                custom_tables,
            )?),
        )),
        sudoku_httpmask::HttpMaskAcceptResult::PassThrough(stream) => Ok(Some(
            accept_sudoku_stream_with_custom_tables_allow_suspicious(
                stream,
                key,
                aead_method,
                table_type,
                padding_min,
                padding_max,
                enable_pure_downlink,
                http_mask_enabled,
                custom_table,
                custom_tables,
            )?,
        )),
        sudoku_httpmask::HttpMaskAcceptResult::Rejected(stream) => {
            Ok(Some(SudokuInboundAccept::Rejected(stream)))
        }
    }
}

#[doc(hidden)]
pub use accept_sudoku_stream as accept_sudoku_test_stream;

#[doc(hidden)]
pub use accept_sudoku_stream_with_custom_tables as accept_sudoku_test_stream_with_custom_tables;

#[doc(hidden)]
pub use SudokuAcceptedStream as SudokuAcceptedTestStream;

pub enum VmessAcceptedStream {
    Tcp {
        target: String,
        stream: BoxedTcpStream,
    },
    Udp {
        target: String,
        stream: BoxedTcpStream,
    },
    Xudp {
        target: String,
        stream: BoxedTcpStream,
    },
}

pub enum VlessAcceptedStream {
    Tcp {
        target: String,
        stream: BoxedTcpStream,
    },
    Udp {
        target: String,
        stream: BoxedTcpStream,
    },
    Xudp {
        target: String,
        stream: BoxedTcpStream,
    },
}

pub fn accept_vless_stream(
    mut stream: BoxedTcpStream,
    uuid: &str,
) -> Result<VlessAcceptedStream, TransportError> {
    let (version, request_uuid, _addons, _command, target, accepted) = vless::read_request(&mut *stream);
    if version != vless::VERSION {
        return Err(TransportError::invalid_proxy_response(format!(
            "unexpected vless version {version}"
        )));
    }
    if request_uuid != uuid {
        return Err(TransportError::invalid_proxy_response(format!(
            "unexpected vless user uuid {request_uuid}"
        )));
    }
    stream.write_all(&[vless::VERSION, 0])?;
    stream.flush()?;
    match accepted {
        vless::AcceptedStream::Tcp => Ok(VlessAcceptedStream::Tcp { target, stream }),
        vless::AcceptedStream::Udp => Ok(VlessAcceptedStream::Udp { target, stream }),
        vless::AcceptedStream::Xudp => Ok(VlessAcceptedStream::Xudp { target, stream }),
    }
}

/// Multi-user vless: matches the request UUID against the configured user
/// list (the UUID travels in plaintext in the vless request header).
pub fn accept_vless_stream_with_uuids(
    mut stream: BoxedTcpStream,
    uuids: &[String],
) -> Result<(VlessAcceptedStream, String), TransportError> {
    let (version, request_uuid, _addons, _command, target, accepted) = vless::read_request(&mut *stream);
    if version != vless::VERSION {
        return Err(TransportError::invalid_proxy_response(format!(
            "unexpected vless version {version}"
        )));
    }
    let Some(matched) = uuids
        .iter()
        .find(|uuid| uuid.trim() == request_uuid)
        .cloned()
    else {
        return Err(TransportError::invalid_proxy_response(format!(
            "unknown vless user uuid {request_uuid}"
        )));
    };
    stream.write_all(&[vless::VERSION, 0])?;
    stream.flush()?;
    let accepted = match accepted {
        vless::AcceptedStream::Tcp => VlessAcceptedStream::Tcp { target, stream },
        vless::AcceptedStream::Udp => VlessAcceptedStream::Udp { target, stream },
        vless::AcceptedStream::Xudp => VlessAcceptedStream::Xudp { target, stream },
    };
    Ok((accepted, matched))
}

pub fn accept_vmess_stream(
    stream: BoxedTcpStream,
    uuid: &str,
) -> Result<VmessAcceptedStream, TransportError> {
    match vmess::accept_server_stream(stream, uuid)? {
        vmess::VmessAcceptedStream::Tcp { target, stream } => {
            Ok(VmessAcceptedStream::Tcp { target, stream })
        }
        vmess::VmessAcceptedStream::Udp { target, stream } => {
            Ok(VmessAcceptedStream::Udp { target, stream })
        }
        vmess::VmessAcceptedStream::Xudp { target, stream } => {
            Ok(VmessAcceptedStream::Xudp { target, stream })
        }
    }
}

/// Multi-user vmess: replays the request header against each configured UUID
/// and returns the one whose AEAD key authenticated the request.
pub fn accept_vmess_stream_with_uuids(
    stream: BoxedTcpStream,
    uuids: &[String],
) -> Result<(VmessAcceptedStream, String), TransportError> {
    let (accepted, uuid) = vmess::accept_server_stream_with_uuids(stream, uuids)?;
    match accepted {
        vmess::VmessAcceptedStream::Tcp { target, stream } => {
            Ok((VmessAcceptedStream::Tcp { target, stream }, uuid))
        }
        vmess::VmessAcceptedStream::Udp { target, stream } => {
            Ok((VmessAcceptedStream::Udp { target, stream }, uuid))
        }
        vmess::VmessAcceptedStream::Xudp { target, stream } => {
            Ok((VmessAcceptedStream::Xudp { target, stream }, uuid))
        }
    }
}

#[doc(hidden)]
pub enum VmessAcceptedTestStream {
    Tcp {
        target: String,
        stream: BoxedTcpStream,
    },
    Udp {
        target: String,
        stream: BoxedTcpStream,
    },
    Xudp {
        target: String,
        stream: BoxedTcpStream,
    },
}

#[doc(hidden)]
pub fn accept_vmess_test_stream(
    stream: BoxedTcpStream,
    uuid: &str,
    cipher: &str,
) -> Result<VmessAcceptedTestStream, TransportError> {
    match vmess::accept_server_stream_for_tests(stream, uuid, cipher)? {
        vmess::VmessAcceptedStream::Tcp { target, stream } => {
            Ok(VmessAcceptedTestStream::Tcp { target, stream })
        }
        vmess::VmessAcceptedStream::Udp { target, stream } => {
            Ok(VmessAcceptedTestStream::Udp { target, stream })
        }
        vmess::VmessAcceptedStream::Xudp { target, stream } => {
            Ok(VmessAcceptedTestStream::Xudp { target, stream })
        }
    }
}

pub fn open_trojan_udp_stream(
    stream: BoxedTcpStream,
    password: &str,
    shadowsocks: &TrojanShadowsocksOptions,
    proxy: TransportTarget,
    target: TransportTarget,
    tls: &TlsOptions,
    alpn: &[String],
) -> Result<BoxedTcpStream, TransportError> {
    let stream = if tls.enabled {
        let resolved_alpn = if alpn.is_empty() {
            trojan::DEFAULT_ALPN
                .iter()
                .map(|value| (*value).to_owned())
                .collect::<Vec<_>>()
        } else {
            alpn.to_vec()
        };
        tls_client::wrap_stream(stream, &proxy, tls, &resolved_alpn)?
    } else {
        stream
    };
    let stream = apply_trojan_shadowsocks(stream, shadowsocks)?;
    trojan::open_udp_stream(stream, password, &target)
}

#[doc(hidden)]
pub fn open_trojan_tcp_stream_for_tests(
    stream: BoxedTcpStream,
    password: &str,
    target: &TransportTarget,
) -> Result<BoxedTcpStream, TransportError> {
    trojan::wrap_stream(stream, password, target)
}

pub fn wrap_trusttunnel_tls_proxy_stream(
    stream: BoxedTcpStream,
    proxy: TransportTarget,
    tls: &TlsOptions,
    alpn: &[String],
    username: &str,
    password: &str,
    target: TransportTarget,
) -> Result<BoxedTcpStream, TransportError> {
    trusttunnel::wrap_tls_stream(
        stream,
        &proxy,
        tls,
        alpn,
        username,
        password,
        &target,
    )
}

pub fn open_trusttunnel_udp_stream(
    stream: BoxedTcpStream,
    proxy: TransportTarget,
    tls: &TlsOptions,
    alpn: &[String],
    username: &str,
    password: &str,
) -> Result<BoxedTcpStream, TransportError> {
    trusttunnel::open_udp_stream(stream, &proxy, tls, alpn, username, password)
}

pub fn open_trusttunnel_quic_udp_stream(
    proxy: TransportTarget,
    tls: &TlsOptions,
    alpn: &[String],
    username: &str,
    password: &str,
) -> Result<BoxedTcpStream, TransportError> {
    trusttunnel::open_quic_udp_stream(&proxy, tls, alpn, username, password)
}

pub fn open_trusttunnel_quic_udp_stream_with_socks5_stream(
    proxy: TransportTarget,
    tls: &TlsOptions,
    alpn: &[String],
    username: &str,
    password: &str,
    control_stream: BoxedTcpStream,
    auth: Option<BasicAuth>,
) -> Result<BoxedTcpStream, TransportError> {
    trusttunnel::open_quic_udp_stream_with_socks5_stream(
        &proxy,
        tls,
        alpn,
        username,
        password,
        control_stream,
        auth,
    )
}

pub fn write_trusttunnel_udp_packet(
    stream: &mut dyn Write,
    target: std::net::SocketAddr,
    payload: &[u8],
) -> io::Result<usize> {
    trusttunnel::write_udp_packet(stream, target, payload)
}

pub fn read_trusttunnel_udp_packet(
    stream: &mut dyn Read,
) -> io::Result<(std::net::SocketAddr, Vec<u8>)> {
    trusttunnel::read_udp_packet(stream)
}

pub fn open_tuic_udp_stream(
    proxy: &TransportTarget,
    options: &TuicUdpOptions,
) -> Result<BoxedTcpStream, TransportError> {
    let mut dialer = crate::SystemTcpDialer;
    tuic_stream::open_udp_stream(&mut dialer, proxy, options)
}

pub fn open_tuic_udp_stream_with_dialer<D: crate::TcpDialer>(
    dialer: &mut D,
    proxy: &TransportTarget,
    options: &TuicUdpOptions,
) -> Result<BoxedTcpStream, TransportError> {
    tuic_stream::open_udp_stream(dialer, proxy, options)
}

pub fn open_tuic_udp_stream_with_socks5_stream<D: crate::TcpDialer>(
    dialer: &mut D,
    proxy: &TransportTarget,
    options: &TuicUdpOptions,
    control_stream: BoxedTcpStream,
    auth: Option<BasicAuth>,
) -> Result<BoxedTcpStream, TransportError> {
    tuic_stream::open_udp_stream_with_socks5_stream(
        dialer,
        proxy,
        options,
        Some(control_stream),
        auth,
    )
}

pub fn write_tuic_udp_packet(
    stream: &mut dyn Write,
    target: std::net::SocketAddr,
    payload: &[u8],
) -> io::Result<usize> {
    tuic_stream::write_udp_packet(stream, target, payload)
}

pub fn read_tuic_udp_packet(
    stream: &mut dyn Read,
) -> io::Result<(std::net::SocketAddr, Vec<u8>)> {
    tuic_stream::read_udp_packet(stream)
}

pub fn open_hy2_udp_stream(
    proxy: &TransportTarget,
    options: &Hy2UdpOptions,
) -> Result<BoxedTcpStream, TransportError> {
    let mut dialer = crate::SystemTcpDialer;
    hy2_stream::open_udp_stream(&mut dialer, proxy, options)
}

pub fn open_hy2_udp_stream_with_dialer<D: crate::TcpDialer>(
    dialer: &mut D,
    proxy: &TransportTarget,
    options: &Hy2UdpOptions,
) -> Result<BoxedTcpStream, TransportError> {
    hy2_stream::open_udp_stream(dialer, proxy, options)
}

pub fn open_hy2_udp_stream_with_socks5_stream<D: crate::TcpDialer>(
    dialer: &mut D,
    proxy: &TransportTarget,
    options: &Hy2UdpOptions,
    control_stream: BoxedTcpStream,
    auth: Option<BasicAuth>,
) -> Result<BoxedTcpStream, TransportError> {
    hy2_stream::open_udp_stream_with_socks5_stream(
        dialer,
        proxy,
        options,
        Some(control_stream),
        auth,
    )
}

pub fn write_hy2_udp_packet(
    stream: &mut dyn Write,
    target: std::net::SocketAddr,
    payload: &[u8],
) -> io::Result<usize> {
    hy2_stream::write_udp_packet(stream, target, payload)
}

pub fn read_hy2_udp_packet(
    stream: &mut dyn Read,
) -> io::Result<(std::net::SocketAddr, Vec<u8>)> {
    hy2_stream::read_udp_packet(stream)
}

pub fn open_hysteria_udp_stream(
    proxy: &TransportTarget,
    options: &HysteriaOptions,
) -> Result<BoxedTcpStream, TransportError> {
    let mut dialer = crate::SystemTcpDialer;
    hysteria_stream::open_udp_stream(&mut dialer, proxy, options)
}

pub fn open_hysteria_udp_stream_with_dialer<D: crate::TcpDialer>(
    dialer: &mut D,
    proxy: &TransportTarget,
    options: &HysteriaOptions,
) -> Result<BoxedTcpStream, TransportError> {
    hysteria_stream::open_udp_stream(dialer, proxy, options)
}

pub fn open_hysteria_udp_stream_with_socks5_stream<D: crate::TcpDialer>(
    dialer: &mut D,
    proxy: &TransportTarget,
    options: &HysteriaOptions,
    control_stream: BoxedTcpStream,
    auth: Option<BasicAuth>,
) -> Result<BoxedTcpStream, TransportError> {
    hysteria_stream::open_udp_stream_with_socks5_stream(
        dialer,
        proxy,
        options,
        Some(control_stream),
        auth,
    )
}

pub fn open_wireguard_udp_stream(
    options: &WireGuardOptions,
) -> Result<BoxedTcpStream, TransportError> {
    wireguard_stream::open_udp_stream(options)
}

pub fn open_openvpn_udp_stream(
    options: &OpenVpnOptions,
) -> Result<BoxedTcpStream, TransportError> {
    crate::openvpn_stream::open_udp_stream(options)
}

pub fn open_masque_udp_stream(
    stream: BoxedTcpStream,
    proxy: &TransportTarget,
    options: &MasqueConnectOptions,
    tls: &TlsOptions,
) -> Result<BoxedTcpStream, TransportError> {
    masque_stream::open_udp_stream(stream, proxy, options, tls)
}

pub fn resolve_masque_host_via_udp_stream(
    stream: &mut dyn mihomo_core::TcpStream,
    options: &MasqueConnectOptions,
    host: &str,
) -> Result<std::net::Ipv4Addr, TransportError> {
    masque_stream::resolve_remote_target_host(stream, options, host)
}

pub fn open_openvpn_udp_stream_with_boxed_tcp(
    options: &OpenVpnOptions,
    stream: BoxedTcpStream,
) -> Result<BoxedTcpStream, TransportError> {
    crate::openvpn_stream::open_udp_stream_with_boxed_tcp(options, stream)
}

pub fn open_openvpn_udp_stream_with_socks5_stream(
    options: &OpenVpnOptions,
    stream: BoxedTcpStream,
    auth: Option<BasicAuth>,
) -> Result<BoxedTcpStream, TransportError> {
    crate::openvpn_stream::open_udp_stream_with_socks5_stream(options, stream, auth)
}

pub fn write_hysteria_udp_packet(
    stream: &mut dyn Write,
    target: std::net::SocketAddr,
    payload: &[u8],
) -> io::Result<usize> {
    hysteria_stream::write_udp_packet(stream, target, payload)
}

pub fn read_hysteria_udp_packet(
    stream: &mut dyn Read,
) -> io::Result<(std::net::SocketAddr, Vec<u8>)> {
    hysteria_stream::read_udp_packet(stream)
}

pub fn write_wireguard_udp_packet(
    stream: &mut dyn Write,
    target: std::net::SocketAddr,
    payload: &[u8],
) -> io::Result<usize> {
    wireguard_stream::write_udp_packet(stream, target, payload)
}

pub fn resolve_wireguard_host_via_udp_stream(
    stream: &mut dyn mihomo_core::TcpStream,
    options: &WireGuardOptions,
    host: &str,
) -> Result<std::net::Ipv4Addr, TransportError> {
    wireguard_stream::resolve_remote_target_host(stream, options, host)
}

pub fn read_wireguard_udp_packet(
    stream: &mut dyn Read,
) -> io::Result<(std::net::SocketAddr, Vec<u8>)> {
    wireguard_stream::read_udp_packet(stream)
}

pub fn write_openvpn_udp_packet(
    stream: &mut dyn Write,
    target: std::net::SocketAddr,
    payload: &[u8],
) -> io::Result<usize> {
    crate::openvpn_stream::write_udp_packet(stream, target, payload)
}

pub fn resolve_openvpn_host_via_udp_stream(
    stream: &mut dyn mihomo_core::TcpStream,
    options: &OpenVpnOptions,
    host: &str,
) -> Result<std::net::Ipv4Addr, TransportError> {
    crate::openvpn_stream::resolve_remote_target_host_via_udp_stream(stream, options, host)
}

pub fn read_openvpn_udp_packet(
    stream: &mut dyn Read,
) -> io::Result<(std::net::SocketAddr, Vec<u8>)> {
    crate::openvpn_stream::read_udp_packet(stream)
}

pub fn write_masque_udp_packet(
    stream: &mut dyn Write,
    target: std::net::SocketAddr,
    payload: &[u8],
) -> io::Result<usize> {
    masque_stream::write_udp_packet(stream, target, payload)
}

pub fn read_masque_udp_packet(
    stream: &mut dyn Read,
) -> io::Result<(std::net::SocketAddr, Vec<u8>)> {
    masque_stream::read_udp_packet(stream)
}

pub fn wrap_tls_proxy_stream(
    stream: BoxedTcpStream,
    proxy: TransportTarget,
    tls: &TlsOptions,
    alpn: &[String],
) -> Result<BoxedTcpStream, TransportError> {
    tls_client::wrap_stream(stream, &proxy, tls, alpn)
}

pub fn wrap_vless_vision_tls_stream(
    stream: BoxedTcpStream,
    proxy: TransportTarget,
    tls: &TlsOptions,
    alpn: &[String],
) -> Result<BoxedTcpStream, TransportError> {
    let stream = tls_client::wrap_stream_for_vision(stream, &proxy, tls, alpn)?;
    if !stream.negotiated_tls13() {
        return Err(TransportError::UnsupportedFeature {
            proxy: proxy.authority(),
            feature: "flow=xtls-rprx-vision requires TLS 1.3".to_owned(),
        });
    }
    Ok(Box::new(stream))
}

#[doc(hidden)]
pub fn tls_root_store_for_tests_and_runtime() -> Result<rustls::RootCertStore, TransportError> {
    tls_client::system_root_store()
}

#[doc(hidden)]
pub fn register_test_root_certificate(pem: &str) -> Result<(), TransportError> {
    tls_client::register_test_root_certificate(pem)?;
    mihomo_dns::register_test_root_certificate_for_tests_and_runtime(pem)
        .map_err(|err| TransportError::InvalidPlan(err.to_string()))
}

pub fn wrap_websocket_proxy_stream(
    stream: BoxedTcpStream,
    proxy: TransportTarget,
    websocket: &WebsocketOptions,
) -> Result<BoxedTcpStream, TransportError> {
    websocket::wrap_stream(stream, &proxy, websocket)
}

pub fn wrap_http_proxy_stream(
    stream: BoxedTcpStream,
    proxy: TransportTarget,
    http: &HttpStreamOptions,
) -> BoxedTcpStream {
    http_stream::wrap_stream(stream, &proxy, http)
}

pub fn wrap_xhttp_tls_proxy_stream(
    stream: BoxedTcpStream,
    proxy: TransportTarget,
    tls: &TlsOptions,
    alpn: &[String],
    xhttp: &XHttpOptions,
) -> Result<BoxedTcpStream, TransportError> {
    xhttp_stream::wrap_tls_stream(stream, &proxy, tls, alpn, xhttp)
}

pub fn wrap_xhttp_proxy_stream(
    stream: BoxedTcpStream,
    proxy: TransportTarget,
    xhttp: &XHttpOptions,
) -> Result<BoxedTcpStream, TransportError> {
    xhttp_stream::wrap_stream(stream, &proxy, xhttp)
}

pub fn wrap_grpc_proxy_stream(
    stream: BoxedTcpStream,
    proxy: TransportTarget,
    grpc: &GrpcOptions,
) -> Result<BoxedTcpStream, TransportError> {
    grpc_stream::wrap_stream(stream, &proxy, grpc)
}

pub fn wrap_grpc_tls_proxy_stream(
    stream: BoxedTcpStream,
    proxy: TransportTarget,
    tls: &TlsOptions,
    grpc: &GrpcOptions,
) -> Result<BoxedTcpStream, TransportError> {
    grpc_stream::wrap_tls_stream(stream, &proxy, tls, grpc)
}

pub fn wrap_h2_proxy_stream(
    stream: BoxedTcpStream,
    h2: &Http2Options,
) -> Result<BoxedTcpStream, TransportError> {
    h2_stream::wrap_stream(stream, h2)
}

pub fn wrap_h2_tls_proxy_stream(
    stream: BoxedTcpStream,
    proxy: TransportTarget,
    tls: &TlsOptions,
    h2: &Http2Options,
) -> Result<BoxedTcpStream, TransportError> {
    h2_stream::wrap_tls_stream_with_request(
        stream,
        &proxy,
        tls,
        &["h2".to_owned()],
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
    )
}

#[doc(hidden)]
pub fn accept_grpc_test_stream(stream: BoxedTcpStream) -> BoxedTcpStream {
    grpc_stream::accept_test_stream(stream)
}

#[doc(hidden)]
pub fn accept_h2_test_stream(
    stream: BoxedTcpStream,
) -> io::Result<(h2_stream::H2AcceptedTestRequest, BoxedTcpStream)> {
    h2_stream::accept_server_stream(stream)
}

#[doc(hidden)]
pub fn accept_h2_tls_test_stream(
    stream: BoxedTcpStream,
    tls_config: Arc<rustls::ServerConfig>,
) -> io::Result<(h2_stream::H2AcceptedTestRequest, BoxedTcpStream)> {
    h2_stream::accept_tls_server_stream(stream, tls_config)
}

pub fn open_anytls_udp_stream(
    stream: BoxedTcpStream,
    password: &str,
    destination: std::net::SocketAddr,
) -> Result<BoxedTcpStream, TransportError> {
    anytls::open_udp_stream(stream, password, destination)
}

#[doc(hidden)]
pub fn open_anytls_tcp_stream_for_tests(
    stream: BoxedTcpStream,
    password: &str,
    target: &TransportTarget,
) -> Result<BoxedTcpStream, TransportError> {
    anytls::wrap_stream(stream, password, target)
}

pub fn accept_anytls_server_stream(
    stream: BoxedTcpStream,
    password: &str,
) -> Result<(TransportTarget, BoxedTcpStream), TransportError> {
    anytls::accept_server_stream(stream, password)
}

pub fn accept_anytls_server_stream_with_passwords(
    stream: BoxedTcpStream,
    passwords: &[String],
) -> Result<(TransportTarget, usize, BoxedTcpStream), TransportError> {
    use sha2::{Digest as _, Sha256};
    let hashes = passwords
        .iter()
        .map(|password| Sha256::digest(password.as_bytes()).into())
        .collect::<Vec<[u8; 32]>>();
    anytls::accept_server_stream_with_password_hashes(stream, &hashes)
}

pub const ANYTLS_UOT_MAGIC_HOST: &str = anytls::UOT_MAGIC_ADDRESS;

pub fn write_anytls_udp_packet(
    stream: &mut dyn Write,
    destination: std::net::SocketAddr,
    payload: &[u8],
) -> io::Result<usize> {
    anytls::write_udp_packet(stream, destination, payload)
}

pub fn read_anytls_udp_packet(
    stream: &mut dyn Read,
) -> io::Result<(std::net::SocketAddr, Vec<u8>)> {
    anytls::read_udp_packet(stream)
}

pub fn read_anytls_uot_request(
    stream: &mut dyn Read,
) -> io::Result<(bool, std::net::SocketAddr)> {
    anytls::read_uot_request(stream)
}

pub fn write_trojan_udp_packet(
    stream: &mut dyn Write,
    target: std::net::SocketAddr,
    payload: &[u8],
) -> io::Result<usize> {
    trojan::write_udp_packet(stream, target, payload)
}

pub fn read_trojan_udp_packet(
    stream: &mut dyn Read,
) -> io::Result<(std::net::SocketAddr, Vec<u8>)> {
    trojan::read_udp_packet(stream)
}

pub fn open_gost_relay_udp_stream(
    mut stream: BoxedTcpStream,
    auth: Option<BasicAuth>,
    forward: bool,
    target: std::net::SocketAddr,
) -> Result<BoxedTcpStream, TransportError> {
    write_gost_relay_udp_associate_request(&mut *stream, &auth, forward, target)?;
    read_gost_relay_connect_response(&mut *stream)?;
    Ok(stream)
}

pub fn write_gost_relay_udp_packet(
    stream: &mut dyn Write,
    payload: &[u8],
) -> io::Result<usize> {
    if payload.len() > u16::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("gost relay udp packet too large: {}", payload.len()),
        ));
    }
    stream.write_all(&(payload.len() as u16).to_be_bytes())?;
    stream.write_all(payload)?;
    stream.flush()?;
    Ok(payload.len())
}

pub fn read_gost_relay_udp_packet(stream: &mut dyn Read) -> io::Result<Vec<u8>> {
    let mut header = [0_u8; 2];
    stream.read_exact(&mut header)?;
    let length = u16::from_be_bytes(header) as usize;
    let mut payload = vec![0_u8; length];
    stream.read_exact(&mut payload)?;
    Ok(payload)
}
