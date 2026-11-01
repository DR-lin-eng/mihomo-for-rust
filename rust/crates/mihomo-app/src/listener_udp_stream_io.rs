use std::io::{self, Read, Write};
use std::net::SocketAddr;

use mihomo_transport::{
    decode_packetaddr_udp_packet, encode_packetaddr_udp_packet, read_anytls_udp_packet,
    read_gost_relay_udp_packet, read_hy2_udp_packet, read_hysteria_udp_packet,
    read_masque_udp_packet, read_openvpn_udp_packet, read_snell_udp_packet,
    read_sudoku_udp_packet, read_trojan_udp_packet, read_trusttunnel_udp_packet,
    read_tuic_udp_packet, read_vless_udp_packet, read_vless_xudp_packet,
    read_vmess_udp_packet, read_vmess_xudp_packet, read_wireguard_udp_packet,
    write_anytls_udp_packet, write_gost_relay_udp_packet, write_hy2_udp_packet,
    write_hysteria_udp_packet, write_masque_udp_packet, write_openvpn_udp_packet,
    write_snell_udp_packet, write_sudoku_udp_packet, write_trojan_udp_packet,
    write_trusttunnel_udp_packet, write_tuic_udp_packet, write_vless_udp_packet,
    write_vless_xudp_packet, write_vmess_udp_packet, write_vmess_xudp_packet,
    write_wireguard_udp_packet,
};

use super::listener_udp_session::PreparedUdpRoute;

fn map_stream_read<T>(result: io::Result<T>) -> io::Result<Option<T>> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(err) if matches!(err.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {
            Ok(None)
        }
        Err(err) => Err(err),
    }
}

pub(super) fn stream_route_missing_label(route: &PreparedUdpRoute) -> Option<&'static str> {
    match route {
        PreparedUdpRoute::AnyTls => Some("anytls udp stream"),
        PreparedUdpRoute::Hysteria => Some("hysteria udp stream"),
        PreparedUdpRoute::Hy2 => Some("hysteria2 udp stream"),
        PreparedUdpRoute::Snell => Some("snell udp stream"),
        PreparedUdpRoute::Trojan => Some("trojan udp stream"),
        PreparedUdpRoute::TrustTunnel => Some("trusttunnel udp stream"),
        PreparedUdpRoute::Tuic => Some("tuic udp stream"),
        PreparedUdpRoute::WireGuard => Some("wireguard udp stream"),
        PreparedUdpRoute::OpenVpn => Some("openvpn udp stream"),
        PreparedUdpRoute::Masque => Some("masque udp stream"),
        PreparedUdpRoute::Sudoku => Some("sudoku udp stream"),
        PreparedUdpRoute::Vless { .. } => Some("vless udp stream"),
        PreparedUdpRoute::VlessXudp => Some("vless xudp stream"),
        PreparedUdpRoute::VlessPacketAddr => Some("vless packet-addr udp stream"),
        PreparedUdpRoute::Vmess { .. } => Some("vmess udp stream"),
        PreparedUdpRoute::VmessXudp => Some("vmess xudp stream"),
        PreparedUdpRoute::VmessPacketAddr => Some("vmess packet-addr udp stream"),
        PreparedUdpRoute::GostRelay { .. } => Some("gost relay udp stream"),
        _ => None,
    }
}

pub(super) fn recv_stream_backed_packet(
    route: &PreparedUdpRoute,
    stream: &mut dyn Read,
) -> io::Result<Option<(Vec<u8>, SocketAddr)>> {
    match route {
        PreparedUdpRoute::Snell => {
            Ok(map_stream_read(read_snell_udp_packet(stream))?.map(|(source, payload)| {
                (payload, source)
            }))
        }
        PreparedUdpRoute::AnyTls => {
            Ok(map_stream_read(read_anytls_udp_packet(stream))?.map(|(source, payload)| {
                (payload, source)
            }))
        }
        PreparedUdpRoute::Hysteria => Ok(
            map_stream_read(read_hysteria_udp_packet(stream))?.map(|(source, payload)| {
                (payload, source)
            }),
        ),
        PreparedUdpRoute::Hy2 => {
            Ok(map_stream_read(read_hy2_udp_packet(stream))?.map(|(source, payload)| {
                (payload, source)
            }))
        }
        PreparedUdpRoute::Trojan => {
            Ok(map_stream_read(read_trojan_udp_packet(stream))?.map(|(source, payload)| {
                (payload, source)
            }))
        }
        PreparedUdpRoute::TrustTunnel => Ok(
            map_stream_read(read_trusttunnel_udp_packet(stream))?.map(|(source, payload)| {
                (payload, source)
            }),
        ),
        PreparedUdpRoute::Tuic => {
            Ok(map_stream_read(read_tuic_udp_packet(stream))?.map(|(source, payload)| {
                (payload, source)
            }))
        }
        PreparedUdpRoute::WireGuard => Ok(
            map_stream_read(read_wireguard_udp_packet(stream))?.map(|(source, payload)| {
                (payload, source)
            }),
        ),
        PreparedUdpRoute::OpenVpn => {
            Ok(map_stream_read(read_openvpn_udp_packet(stream))?.map(|(source, payload)| {
                (payload, source)
            }))
        }
        PreparedUdpRoute::Masque => {
            Ok(map_stream_read(read_masque_udp_packet(stream))?.map(|(source, payload)| {
                (payload, source)
            }))
        }
        PreparedUdpRoute::Sudoku => {
            Ok(map_stream_read(read_sudoku_udp_packet(stream))?.map(|(source, payload)| {
                (payload, source)
            }))
        }
        PreparedUdpRoute::Vless { source } => Ok(
            map_stream_read(read_vless_udp_packet(stream))?.map(|payload| (payload, *source)),
        ),
        PreparedUdpRoute::VlessXudp => {
            Ok(map_stream_read(read_vless_xudp_packet(stream))?.map(|(source, payload)| {
                (payload, source)
            }))
        }
        PreparedUdpRoute::VlessPacketAddr => {
            let Some(payload) = map_stream_read(read_vless_udp_packet(stream))? else {
                return Ok(None);
            };
            let (source, packet) = decode_packetaddr_udp_packet(&payload)?;
            Ok(Some((packet, source)))
        }
        PreparedUdpRoute::Vmess { source } => Ok(
            map_stream_read(read_vmess_udp_packet(stream))?.map(|payload| (payload, *source)),
        ),
        PreparedUdpRoute::VmessXudp => {
            Ok(map_stream_read(read_vmess_xudp_packet(stream))?.map(|(source, payload)| {
                (payload, source)
            }))
        }
        PreparedUdpRoute::VmessPacketAddr => {
            let Some(payload) = map_stream_read(read_vmess_udp_packet(stream))? else {
                return Ok(None);
            };
            let (source, packet) = decode_packetaddr_udp_packet(&payload)?;
            Ok(Some((packet, source)))
        }
        PreparedUdpRoute::GostRelay { source } => Ok(
            map_stream_read(read_gost_relay_udp_packet(stream))?.map(|payload| (payload, *source)),
        ),
        _ => Ok(None),
    }
}

pub(super) fn send_stream_backed_packet(
    route: &PreparedUdpRoute,
    stream: &mut dyn Write,
    target: SocketAddr,
    payload: &[u8],
) -> io::Result<Option<usize>> {
    match route {
        PreparedUdpRoute::AnyTls => write_anytls_udp_packet(stream, target, payload).map(Some),
        PreparedUdpRoute::Hysteria => write_hysteria_udp_packet(stream, target, payload).map(Some),
        PreparedUdpRoute::Hy2 => write_hy2_udp_packet(stream, target, payload).map(Some),
        PreparedUdpRoute::Snell => write_snell_udp_packet(stream, target, payload).map(Some),
        PreparedUdpRoute::Trojan => write_trojan_udp_packet(stream, target, payload).map(Some),
        PreparedUdpRoute::TrustTunnel => {
            write_trusttunnel_udp_packet(stream, target, payload).map(Some)
        }
        PreparedUdpRoute::Tuic => write_tuic_udp_packet(stream, target, payload).map(Some),
        PreparedUdpRoute::WireGuard => write_wireguard_udp_packet(stream, target, payload).map(Some),
        PreparedUdpRoute::OpenVpn => write_openvpn_udp_packet(stream, target, payload).map(Some),
        PreparedUdpRoute::Masque => write_masque_udp_packet(stream, target, payload).map(Some),
        PreparedUdpRoute::Sudoku => write_sudoku_udp_packet(stream, target, payload).map(Some),
        PreparedUdpRoute::Vless { .. } => write_vless_udp_packet(stream, payload).map(Some),
        PreparedUdpRoute::VlessXudp => write_vless_xudp_packet(stream, target, payload).map(Some),
        PreparedUdpRoute::VlessPacketAddr => {
            let framed = encode_packetaddr_udp_packet(target, payload);
            write_vless_udp_packet(stream, &framed).map(Some)
        }
        PreparedUdpRoute::Vmess { .. } => write_vmess_udp_packet(stream, payload).map(Some),
        PreparedUdpRoute::VmessXudp => write_vmess_xudp_packet(stream, target, payload).map(Some),
        PreparedUdpRoute::VmessPacketAddr => {
            let framed = encode_packetaddr_udp_packet(target, payload);
            write_vmess_udp_packet(stream, &framed).map(Some)
        }
        PreparedUdpRoute::GostRelay { .. } => write_gost_relay_udp_packet(stream, payload).map(Some),
        _ => Ok(None),
    }
}
