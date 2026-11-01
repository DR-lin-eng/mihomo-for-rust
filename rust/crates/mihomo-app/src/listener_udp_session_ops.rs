use std::io;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

use mihomo_buf::ByteWindow;
use mihomo_core::{Metadata, UdpSession};
use mihomo_runtime::UdpOutboundRoute;
use mihomo_transport::{
    encode_shadowsocks_udp_packet, encode_ssr_udp_packet,
};

use super::listener_udp_prepare::prepare_udp_send;
use super::listener_udp_session::{PreparedUdpRoute, SystemUdpSession};
use super::listener_udp_socks5::build_socks5_udp_frame;
use super::listener_udp_stream_io::{send_stream_backed_packet, stream_route_missing_label};

impl UdpSession for SystemUdpSession {
    fn prepare_send(&mut self, metadata: &mut Metadata) -> io::Result<()> {
        let previous=self.prepared_plan.clone();
        let started=std::time::Instant::now();
        let result=prepare_udp_send(self, metadata);
        if result.is_ok() && (self.smart_tracker.is_none() || previous!=self.prepared_plan) {
            self.smart_tracker=self.prepared_plan.as_ref().and_then(|plan|self.tunnel.smart_tracker(metadata,plan,started.elapsed().as_millis() as u64));
        }
        if result.is_err(){if let Some(tracker)=&self.smart_tracker{tracker.record_failure();}}
        result
    }

    fn resolve_udp(&mut self, metadata: &mut Metadata) -> io::Result<()> {
        self.tunnel
            .preprocess_metadata_for_routing(metadata)
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
        if let Ok(route) = self.tunnel.resolve_udp_outbound(metadata) {
            let unresolved_domain = metadata
                .host
                .as_deref()
                .is_some_and(|host| host.parse::<IpAddr>().is_err());
            let skip_local_resolution = match route {
                UdpOutboundRoute::Masque(route) => {
                    route.remote_dns_resolve && !route.dns.is_empty() && unresolved_domain
                }
                UdpOutboundRoute::WireGuard(route) => {
                    route.remote_dns_resolve && !route.dns.is_empty() && unresolved_domain
                }
                UdpOutboundRoute::OpenVpn(route) => {
                    route.remote_dns_resolve && !route.dns.is_empty() && unresolved_domain
                }
                _ => false,
            };
            if skip_local_resolution {
                return Ok(());
            }
        }
        if let Some(dns_runtime) = &mut self.dns_runtime {
            self.tunnel.seed_dns_fake_ip_state(dns_runtime);
            dns_runtime
                .resolve_metadata(metadata)
                .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
            self.tunnel.capture_dns_fake_ip_state(dns_runtime);
            if metadata.dst_ip.is_some() {
                return Ok(());
            }
        } else if let Some(shared) = self.tunnel.dns_runtime() {
            let mut dns_runtime = shared.lock().unwrap();
            dns_runtime
                .resolve_metadata(metadata)
                .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
            if metadata.dst_ip.is_some() {
                return Ok(());
            }
        }
        let Some(host) = metadata.host.clone() else {
            return Ok(());
        };
        let port = metadata.dst_port.unwrap_or(0);
        let mut addrs = (host.as_str(), port).to_socket_addrs()?;
        if let Some(addr) = addrs.next() {
            metadata.dst_ip = Some(addr.ip());
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("failed to resolve host: {host}"),
            ))
        }
    }

    fn send_to(&mut self, payload: ByteWindow, target: SocketAddr) -> io::Result<usize> {
        if let Some(tracker)=&self.smart_tracker {tracker.record_upload(payload.len());}
        match &self.prepared_route {
            Some(PreparedUdpRoute::Direct) | None => self.socket.send_to(payload.as_slice(), target),
            Some(PreparedUdpRoute::Dns) => {
                let response = crate::dns_transport::relay_shared_query_packet(self.tunnel.clone(), payload.as_slice())
                    .map_err(io::Error::other)?;
                self.pending_response = response.map(|packet| (packet, target));
                Ok(payload.len())
            }
            Some(PreparedUdpRoute::Socks5 { relay_addr }) => {
                let framed = build_socks5_udp_frame(target, payload.as_slice());
                self.socket.send_to(&framed, relay_addr)
            }
            Some(PreparedUdpRoute::ShadowSocks {
                proxy_addr,
                cipher,
                password,
            }) => {
                let packet = if mihomo_transport::is_shadowsocks_2022_cipher(cipher) {
                    let state = self
                        .ss2022_udp_state
                        .get_or_insert_with(mihomo_transport::Shadowsocks2022UdpState::client);
                    let ss_target =
                        mihomo_transport::TransportTarget::new(target.ip().to_string(), target.port());
                    mihomo_transport::encode_shadowsocks_2022_udp_packet(
                        cipher,
                        password,
                        state,
                        &ss_target,
                        payload.as_slice(),
                    )
                } else {
                    encode_shadowsocks_udp_packet(cipher, password, target, payload.as_slice())
                }
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;
                self.socket.send_to(&packet, proxy_addr)
            }
            Some(PreparedUdpRoute::Ssr {
                proxy_addr,
                cipher,
                password,
            }) => {
                let packet = encode_ssr_udp_packet(cipher, password, target, payload.as_slice())
                    .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;
                self.socket.send_to(&packet, proxy_addr)
            }
            Some(route) => {
                if let Some(label) = stream_route_missing_label(route) {
                    let stream = self.proxy_stream.as_mut().ok_or_else(|| {
                        io::Error::new(io::ErrorKind::NotConnected, format!("missing {label}"))
                    })?;
                    if let Some(written) =
                        send_stream_backed_packet(route, &mut **stream, target, payload.as_slice())?
                    {
                        return Ok(written);
                    }
                }
                Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "unsupported udp route send path",
                ))
            }
        }
    }
}
