#[path = "listener_service_special_inbounds/common.rs"]
mod common;
#[path = "listener_service_special_inbounds/shadowsocks.rs"]
mod shadowsocks;
#[path = "listener_service_special_inbounds/trojan.rs"]
mod trojan;

pub(super) use shadowsocks::handle_shadowsocks_connection;
pub(super) use trojan::handle_trojan_connection;
