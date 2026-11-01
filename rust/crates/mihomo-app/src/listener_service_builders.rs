use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use mihomo_config::RuntimeConfigDocument;
use mihomo_inbound::{
    AuthUser, BaseInboundConfig, HttpInboundConfig, InboundDefinition, TlsInboundConfig,
};
use mihomo_inbound::TProxyInboundConfig;
use mihomo_transport::XHttpOptions;

use super::listener_service_configs::{
    AnyTlsListenerConfig, ShadowSocksListenerConfig, SudokuInboundConfig,
    TrojanListenerConfig, TrustTunnelListenerConfig, VlessInboundConfig,
    VmessInboundConfig,
};
use super::listener_service_models::{
    ManagedQuicListenerConfig, ManagedQuicListenerHandler, ManagedTcpListenerConfig,
    ManagedTcpListenerHandler, ManagedUdpListenerConfig, ManagedUdpListenerHandler,
};
use super::{hy2_inbound, hy2_realm_inbound, tuic_inbound, ListenerServiceError};

include!("listener_service_builders_tcp.rs");
include!("listener_service_builders_udp.rs");
include!("listener_service_builders_quic.rs");
include!("listener_service_builders_helpers.rs");
