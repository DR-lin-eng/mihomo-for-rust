//! Non-blocking multi-datagram Initial inspection. A worker is never held while
//! waiting for another CRYPTO fragment; queued packets retain their exact bytes.
use crate::sniffer::{tls_hello, Parsed, Sniffer};
use mihomo_core::PacketEnvelope;
use std::collections::HashMap;
use std::time::{Duration, Instant};
#[derive(Default)]
pub(crate) struct QuicFlows {
    entries: HashMap<String, Flow>,
}
struct Flow {
    created: Instant,
    updated: Instant,
    dcid: Vec<u8>,
    data: Vec<u8>,
    received: Vec<bool>,
    packets: Vec<PacketEnvelope>,
    bytes: usize,
    done: bool,
    host: Option<String>,
}
impl Sniffer {
    pub fn sniff_udp(&self, packet: PacketEnvelope) -> Vec<PacketEnvelope> {
        if !self.eligible(packet.metadata()) {
            return vec![packet];
        }
        let Some(replace) = self.protocol("QUIC", packet.metadata().dst_port.unwrap_or(0)) else {
            return vec![packet];
        };
        let m = packet.metadata();
        let key = format!(
            "{}|{:?}|{:?}|{:?}|{:?}",
            m.inbound_name, m.src_ip, m.src_port, m.dst_ip, m.dst_port
        );
        let payload = packet.payload();
        let decoded = mihomo_transport::sniff_quic_initial(payload.as_slice());
        let now = Instant::now();
        let mut state = self.quic.lock().unwrap();
        state
            .entries
            .retain(|_, v| now.duration_since(v.updated) < Duration::from_secs(60));
        if let Some(flow) = state.entries.get_mut(&key) {
            if decoded.as_ref().is_some_and(|d| d.dcid != flow.dcid) {
                state.entries.remove(&key);
            }
        }
        if !state.entries.contains_key(&key) {
            let Some(decoded) = decoded.as_ref() else {
                return vec![packet];
            };
            if state.entries.len() >= 64 {
                return vec![packet];
            }
            state.entries.insert(
                key.clone(),
                Flow {
                    created: now,
                    updated: now,
                    dcid: decoded.dcid.clone(),
                    data: Vec::new(),
                    received: Vec::new(),
                    packets: Vec::new(),
                    bytes: 0,
                    done: false,
                    host: None,
                },
            );
        }
        let flow = state.entries.get_mut(&key).unwrap();
        flow.updated = now;
        if flow.done {
            let mut packet = packet;
            if let Some(host) = flow.host.as_ref() {
                self.apply_host(packet.metadata_mut(), host.clone(), replace);
            }
            return vec![packet];
        }
        flow.bytes += payload.len();
        flow.packets.push(packet);
        if now.duration_since(flow.created) >= Duration::from_secs(3)
            || flow.bytes > 24576
            || flow.packets.len() > 8
        {
            flow.done = true;
            flow.data.clear();
            flow.received.clear();
            return std::mem::take(&mut flow.packets);
        }
        let Some(decoded) = decoded else {
            return Vec::new();
        };
        for (offset, bytes) in decoded.fragments {
            let end = offset + bytes.len();
            if end > 16384 {
                flow.done = true;
                return std::mem::take(&mut flow.packets);
            }
            flow.data.resize(flow.data.len().max(end), 0);
            flow.received.resize(flow.received.len().max(end), false);
            for (i, byte) in bytes.into_iter().enumerate() {
                let p = offset + i;
                if flow.received[p] && flow.data[p] != byte {
                    flow.done = true;
                    return std::mem::take(&mut flow.packets);
                }
                flow.data[p] = byte;
                flow.received[p] = true;
            }
        }
        let contiguous = flow
            .received
            .iter()
            .position(|bit| !*bit)
            .unwrap_or(flow.received.len());
        match tls_hello(&flow.data[..contiguous]) {
            Parsed::NeedMore => Vec::new(),
            parsed => {
                flow.done = true;
                flow.host = if let Parsed::Domain(host) = parsed {
                    Some(host)
                } else {
                    None
                };
                flow.data = Vec::new();
                flow.received = Vec::new();
                let mut packets = std::mem::take(&mut flow.packets);
                if let Some(host) = flow.host.as_ref() {
                    for packet in &mut packets {
                        self.apply_host(packet.metadata_mut(), host.clone(), replace);
                    }
                }
                packets
            }
        }
    }
    pub fn clear_udp(&self) {
        self.quic.lock().unwrap().entries.clear();
    }
}
