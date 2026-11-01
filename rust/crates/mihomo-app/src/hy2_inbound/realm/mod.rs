use std::collections::BTreeMap;
use std::io::{self, IoSliceMut};
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket as StdUdpSocket};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use mihomo_core::{BoxedTcpStream, Metadata, NetworkKind, SessionKind};
use mihomo_runtime::RuntimeTunnel;
use mihomo_transport::{
    connect_http_target_via_realm_proxy, decode_hy2_realm_punch_packet,
    decode_hy2_realm_stun_message, discover_hy2_realm_stun_addresses,
    encode_hy2_realm_punch_packet, is_hy2_realm_stun_message,
    new_hy2_realm_stun_binding_request, resolve_hy2_realm_stun_mapped_address,
    Hy2RealmControlClient, Hy2RealmOptions, Hy2RealmPunchMetadata, Hy2RealmPunchPacketType,
    Hy2RealmStunTransactionId,
};
use quinn::{
    udp::{RecvMeta, Transmit},
    AsyncUdpSocket, Endpoint as QuinnEndpoint, Runtime as QuinnRuntime,
    ServerConfig as QuinnServerConfig, UdpPoller,
};
use rand_core::RngCore;

include!("endpoint.rs");
include!("state.rs");
include!("socket.rs");
include!("control.rs");
