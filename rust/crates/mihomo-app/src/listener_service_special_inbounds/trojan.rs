use std::collections::{BTreeMap, HashMap};
use std::io;
use std::net::{SocketAddr, TcpStream};
use std::sync::{Arc, Mutex};

use mihomo_core::{BoxedTcpStream, ConnectionContext, Metadata, NetworkKind, SessionKind};
use mihomo_inbound::GenericInboundConfig;
use mihomo_runtime::{ListenerRuntimeError, RuntimeTunnel};
use mihomo_transport::{
    read_trojan_udp_packet, write_trojan_udp_packet, HttpStreamOptions, XHttpOptions,
};
use sha2::Digest as _;

use super::common::read_trojan_request;
use crate::listener_service::listener_service_configs::{
    parse_trojan_shadowsocks_options, TrojanListenerConfig,
};
use crate::listener_service::listener_service_models::ListenerAuthUser;
use crate::listener_service::listener_service_xhttp::{
    accept_inbound_xhttp_stream, xhttp_options, AcceptedXhttpRequest,
};
use crate::listener_service_support::{
    accept_http_server_stream, accept_tls_server_stream, accept_websocket_server_stream,
    build_server_tls_config, extra_string, nested_string, nested_string_map_list, non_empty_or,
};
use crate::{stream_udp, ListenerServiceError};

include!("trojan_config.rs");
include!("trojan_handler.rs");
include!("trojan_accept.rs");
