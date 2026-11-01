mod anytls;
mod executor;
mod exports;
mod grpc_stream;
mod h2_stream;
mod h3_stream;
mod hysteria_stream;
mod hy2_realm;
mod hy2_stream;
mod http_stream;
mod ip_packet_tunnel;
mod masque_dns;
mod masque_stream;
mod openvpn_stream;
mod public_api;
mod simple_obfs;
mod smux_stream;
mod ssr;
mod ssr_http_obfs;
mod stream_prefix;
#[cfg(feature = "ssh-transport")]
mod ssh;
mod shadowsocks;
mod shadowsocks_2022;
mod reality_tls;
mod snell;
mod socks5_udp_underlay;
mod sudoku;
mod sudoku_httpmask;
mod tls_client;
mod transport_types;
mod tunnel_dns;
mod tuic_stream;
mod trojan;
mod trusttunnel;
mod udp_channel;
mod v2ray_plugin_mux;
mod vision;
mod vless;
mod vmess;
mod wireguard_stream;
mod websocket;
mod xhttp_stream;

mod manifest;

pub(crate) use executor::{
    apply_trojan_shadowsocks, encode_socks5_target, maybe_wrap_sudoku_ws_http_mask_tls,
    prepend_bytes, read_gost_relay_connect_response, write_gost_relay_udp_associate_request,
};
pub(crate) use stream_prefix::PrefixedTcpStream;

pub use exports::*;
pub use manifest::{manifest, MODULE};

#[cfg(test)]
mod tests;
