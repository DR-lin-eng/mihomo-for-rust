mod blocking_executor;
mod dns_transport;
mod app;
mod listener_service;
mod listener_service_support;
mod listener_udp_support;
mod quic_tls;
mod selected_proxy;
pub mod startup_trace;
mod stream_udp;
mod tun_icmp_packet;
mod tun_auto_redirect;
mod tun_packet;
mod tun_tcp_packet;
mod tun_tcp_stack;
mod tun_worker;

pub use app::{AppStartError, RunningApp};
pub use listener_service::{BoundTcpListener, ListenerServiceError, RunningListenerService};

pub use selected_proxy::{
    restore_selected_proxy_mapping, selected_proxy_mapping_from_env,
    selected_proxy_mapping_from_state, SELECTED_PROXY_ENV,
};

#[cfg(test)]
mod tests;
