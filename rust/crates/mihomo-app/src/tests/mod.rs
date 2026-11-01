#![cfg(test)]

#[path = "../tests_network_helpers.rs"]
mod tests_network_helpers;
#[path = "inbound_shadowsocks.rs"]
mod inbound_shadowsocks;
#[path = "inbound_trojan_anytls.rs"]
mod inbound_trojan_anytls;
#[path = "inbound_tuic.rs"]
mod inbound_tuic;
#[path = "inbound_hy2.rs"]
mod inbound_hy2;
#[path = "inbound_hy2_realm.rs"]
mod inbound_hy2_realm;
#[path = "inbound_wireguard.rs"]
mod inbound_wireguard;
#[path = "inbound_openvpn.rs"]
mod inbound_openvpn;
#[path = "inbound_openvpn_variants.rs"]
mod inbound_openvpn_variants;
#[path = "inbound_openvpn_udp.rs"]
mod inbound_openvpn_udp;
#[path = "inbound_vless.rs"]
mod inbound_vless;
#[path = "inbound_vmess_basic.rs"]
mod inbound_vmess_basic;
#[path = "inbound_vmess_networks.rs"]
mod inbound_vmess_networks;
#[path = "inbound_vmess_h2_tls.rs"]
mod inbound_vmess_h2_tls;
#[path = "inbound_vmess_ws_extensions.rs"]
mod inbound_vmess_ws_extensions;
#[path = "outbound_masque.rs"]
mod outbound_masque;
#[path = "outer_socks_udp.rs"]
mod outer_socks_udp;
#[path = "sudoku_tunnel.rs"]
mod sudoku_tunnel;

use base64::Engine as _;
use bytes::{Buf, Bytes};
use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, Scalar};
use hmac::{Hmac, Mac};
use rand_core::RngCore;
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::io::IoSliceMut;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{mpsc, Arc, Mutex, OnceLock};
use std::task::{Context, Poll};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use mihomo_config::{BootEnvironment, BootOptions, Command};
use mihomo_core::{BoxedTcpStream, TcpStream as _};
use mihomo_runtime::{build_runtime_registry, RuntimeTunnel, UdpSudokuRoute};
use mihomo_transport::{
    accept_grpc_test_stream, accept_h2_test_stream, accept_h2_tls_test_stream,
    accept_shadowsocks_test_stream, accept_simple_obfs_http_test_stream,
    accept_simple_obfs_tls_test_stream, accept_smux_test_stream, accept_snell_udp_stream,
    accept_ssr_http_obfs_test_stream, accept_ssr_test_stream, accept_sudoku_test_stream,
    accept_sudoku_test_stream_with_custom_tables, accept_v2ray_plugin_mux_test_stream,
    accept_vmess_test_stream, decode_packetaddr_udp_packet, decode_shadowsocks_udp_packet,
    decode_ssr_udp_packet, encode_shadowsocks_udp_packet, encode_shadowsocks_udp_packet_for_target,
    encode_ssr_udp_packet, open_anytls_udp_stream, open_hy2_udp_stream,
    open_sudoku_multiplex_test_stream, open_sudoku_test_stream, open_sudoku_udp_stream,
    open_trojan_udp_stream, open_tuic_udp_stream,
    read_anytls_udp_packet, read_gost_relay_udp_packet, read_hy2_udp_packet,
    read_snell_udp_packet, read_sudoku_udp_packet, read_trojan_udp_packet,
    read_tuic_udp_packet, read_vless_udp_packet,
    read_vless_xudp_packet, read_vmess_udp_packet, read_vmess_xudp_packet,
    write_anytls_udp_packet, write_gost_relay_udp_packet, write_hy2_udp_packet,
    write_snell_udp_packet, write_sudoku_udp_packet, write_trojan_udp_packet,
    write_tuic_udp_packet, write_vless_udp_packet,
    write_vless_xudp_packet, write_vmess_udp_packet, write_vmess_xudp_packet, OpenVpnTestServer,
    SocketOptions, SudokuAcceptedTestStream, SystemTcpDialer, TcpTransportExecutor,
    TransportAction, TransportHop, TransportPlan, TransportPlanRunner, TransportTarget,
    TlsOptions, VmessAcceptedTestStream, wrap_tls_proxy_stream,
};
#[cfg(feature = "ssh-transport-tests")]
use rand_010::rng;
use rcgen::generate_simple_self_signed;
#[cfg(feature = "ssh-transport-tests")]
use russh::keys::{self as russh_keys, PrivateKey as RusshPrivateKey, PublicKeyBase64};
#[cfg(feature = "ssh-transport-tests")]
use russh::server::{
    self as russh_server, Msg as RusshServerMsg, Server as _, Session as RusshSession,
};
use rustls::server::AllowAnyAuthenticatedClient;
use rustls::{Certificate, PrivateKey, RootCertStore, ServerConfig, ServerConnection, StreamOwned};
use serde_json::Value;
use sha1::{Digest as Sha1Digest, Sha1};
use sha2::{Sha224, Sha256};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
#[cfg(feature = "ssh-transport-tests")]
use tokio::net::TcpListener as TokioTcpListener;
#[cfg(feature = "ssh-transport-tests")]
use tokio::net::TcpStream as TokioTcpStream;
use tokio_wireguard::{
    config::{Config as WgConfig, Interface as WgInterface, Peer as WgPeer},
    x25519, TcpListener as WgTcpListener, UdpSocket as WgUdpSocket,
};
use uuid::Uuid;
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, Runtime as QuinnRuntime, UdpPoller};

use crate::listener_service;
use super::RunningApp;
use tests_network_helpers::{
    spawn_socks5_udp_associate_proxy, TestWireGuardMultiPeerServer, TestWireGuardServer,
};

include!("prefix_support.rs");
include!("body.rs");
include!("support.rs");
