use mihomo_runtime::{prepare_tun_udp_metadata, RuntimeTunnel};
use mihomo_tun::TunRuntimeSpec;
use std::fs::File;
use std::io::{self, Write};
use std::sync::{Arc, Mutex};

/// This runs before either TCP termination or UDP socket creation. Only the
/// original packet is reinjected; the kernel keeps the end-to-end TCP sequence.
pub(crate) fn try_kernel_direct(
    spec: &TunRuntimeSpec,
    tunnel: &Arc<RuntimeTunnel>,
    frame: &[u8],
    writer: &Arc<Mutex<File>>,
) -> io::Result<bool> {
    let Some(runtime) = tunnel.kernel_direct_runtime() else {
        return Ok(false);
    };
    let Some(packet) = mihomo_ebpf::DirectPacket::parse(frame) else {
        return Ok(false);
    };
    let Some(key) = packet.key else {
        if packet
            .fragment
            .as_ref()
            .and_then(|f| runtime.direct_fragment(f))
            .is_some_and(|k| runtime.direct_contains(&k))
        {
            writer.lock().unwrap().write_all(frame)?;
            return Ok(true);
        }
        return Ok(false);
    };
    let sequence = (key.protocol == 6).then_some(packet.tcp_sequence);
    if tunnel.kernel_direct_existing(&key, if packet.tcp_syn { sequence } else { None }) {
        if let Some(fragment) = packet.fragment {
            runtime.direct_remember_fragment(fragment, key);
        }
        writer.lock().unwrap().write_all(frame)?;
        return Ok(true);
    }
    if key.protocol == 6 && !packet.tcp_syn {
        return Ok(false);
    }
    if !runtime.direct_pending(&key) {
        return Ok(false);
    }
    // A fresh SYN or a fresh UDP association can reuse a closed tuple.
    tunnel.retire_kernel_direct(&key);
    let source = key.source_socket();
    let destination = key.destination_socket();
    let mut metadata = if key.protocol == 6 {
        spec.prepare_tcp_metadata(Some(source), destination)
    } else {
        prepare_tun_udp_metadata(spec, Some(source), destination)
    };
    metadata.dscp = Some(if key.family == 4 {
        frame[1] >> 2
    } else {
        ((frame[0] & 15) << 4 | frame[1] >> 4) >> 2
    });
    let mut candidate = tunnel.kernel_direct_plan(&mut metadata);
    if candidate.is_none() && !tunnel.kernel_direct_needs_resolution(&metadata) {
        return Ok(false);
    }
    if metadata.dst_ip.is_none() {
        let mut dns = tunnel
            .dns_runtime()
            .map(|v| v.lock().unwrap().clone().without_fake_ip_persistence())
            .ok_or_else(|| io::Error::other("kernel DIRECT requires a DNS runtime for fake-IP"))?;
        let host = metadata
            .host
            .as_deref()
            .ok_or_else(|| io::Error::other("missing fake-IP domain"))?;
        let special = if dns.config.respect_rules {
            "RULES"
        } else {
            "DIRECT"
        };
        let transport = crate::dns_transport::TunnelDnsPacketTransport::new(
            tunnel.clone(),
            Some(dns.clone()),
            special,
        );
        let mut upstream = mihomo_dns::NetworkDnsUpstream::new(transport);
        let addresses = dns
            .resolve_host_addrs_with_upstream(host, &mut upstream)
            .map_err(io::Error::other)?;
        tunnel.capture_dns_resolution_cache(&dns);
        let Some(ip) = addresses
            .into_iter()
            .find(|ip| ip.is_ipv6() == (key.family == 6))
        else {
            return Ok(false);
        };
        metadata.dst_ip = Some(ip);
        let Some(rechecked) = tunnel.kernel_direct_plan(&mut metadata) else {
            return Ok(false);
        };
        candidate = Some(rechecked);
    }
    let Some((plan, generation)) = candidate else {
        return Ok(false);
    };
    let timeout = if spec.config.udp_timeout > 0 {
        spec.config.udp_timeout as u64
    } else {
        300
    };
    if tunnel.install_kernel_direct(
        key,
        metadata,
        plan,
        generation,
        packet.tcp_sequence,
        timeout,
    )? {
        if let Some(fragment) = packet.fragment {
            runtime.direct_remember_fragment(fragment, key);
        }
        writer.lock().unwrap().write_all(frame)?;
        return Ok(true);
    }
    Ok(false)
}
