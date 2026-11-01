//! A bounded, TTL-aware DNS answer -> original question mapping. Shared by
//! resolver snapshots so listener I/O can stay outside the resolver mutex.
use crate::{DnsError, DnsRuntime, EnhancedMode};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone, Debug, Default)]
pub(crate) struct DomainMappings(Arc<Mutex<State>>);
#[derive(Debug, Default)]
struct State {
    entries: HashMap<IpAddr, Entry>,
    sequence: u64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Entry {
    host: String,
    expires: Instant,
    sequence: u64,
}
impl PartialEq for DomainMappings {
    fn eq(&self, other: &Self) -> bool {
        if Arc::ptr_eq(&self.0, &other.0) {
            return true;
        }
        let left = self.0.lock().unwrap().entries.clone();
        let right = other.0.lock().unwrap().entries.clone();
        left == right
    }
}
impl Eq for DomainMappings {}
impl DomainMappings {
    fn insert(&self, host: &str, records: Vec<(IpAddr, u32)>, capacity: usize) {
        let now = Instant::now();
        let mut state = self.0.lock().unwrap();
        state.entries.retain(|_, entry| entry.expires > now);
        for (ip, ttl) in records {
            if ttl == 0 {
                if state
                    .entries
                    .get(&ip)
                    .is_some_and(|entry| entry.host == host)
                {
                    state.entries.remove(&ip);
                }
                continue;
            }
            while state.entries.len() >= capacity && !state.entries.contains_key(&ip) {
                let Some(oldest) = state
                    .entries
                    .iter()
                    .min_by_key(|(_, entry)| entry.sequence)
                    .map(|(ip, _)| *ip)
                else {
                    break;
                };
                state.entries.remove(&oldest);
            }
            state.sequence = state.sequence.wrapping_add(1);
            let sequence = state.sequence;
            state.entries.insert(
                ip,
                Entry {
                    host: host.into(),
                    expires: now + Duration::from_secs(u64::from(ttl)),
                    sequence,
                },
            );
        }
    }
    pub fn lookup(&self, ip: IpAddr) -> Option<String> {
        let mut state = self.0.lock().unwrap();
        if state
            .entries
            .get(&ip)
            .is_some_and(|entry| entry.expires <= Instant::now())
        {
            state.entries.remove(&ip);
        }
        let host = state.entries.get(&ip)?.host.clone();
        state.sequence = state.sequence.wrapping_add(1);
        let sequence = state.sequence;
        state.entries.get_mut(&ip).unwrap().sequence = sequence;
        Some(host)
    }
    pub fn clear(&self) {
        self.0.lock().unwrap().entries.clear();
    }
}

impl DnsRuntime {
    pub fn domain_for_ip(&self, ip: IpAddr) -> Option<String> {
        if self.config.enhanced_mode == EnhancedMode::Disabled {
            return None;
        }
        (self.config.enhanced_mode == EnhancedMode::FakeIp)
            .then(|| self.reverse_lookup(ip))
            .flatten()
            .map(str::to_owned)
            .or_else(|| self.domain_mappings.lookup(ip))
    }
    pub(crate) fn observe_dns_response(
        &self,
        query: &[u8],
        response: &[u8],
    ) -> Result<(), DnsError> {
        if self.config.enhanced_mode == EnhancedMode::Disabled {
            return Ok(());
        }
        crate::packet::validate_dns_reply(query, response)?;
        let parsed = crate::packet::parse_dns_query_packet(query)?;
        if response[2] & 0x02 != 0 || response[3] & 0x0f != 0 {
            return Ok(());
        }
        let host = parsed.host.trim_end_matches('.').to_ascii_lowercase();
        if host.is_empty() || host.len() > 253 || host.parse::<IpAddr>().is_ok() {
            return Ok(());
        }
        let records = answer_addresses(response, &host)?
            .into_iter()
            .filter(|(ip, _)| !self.is_fake_ip_addr(*ip))
            .collect();
        self.domain_mappings
            .insert(&host, records, self.config.cache_size.clamp(1, 4096));
        Ok(())
    }
}

fn bad() -> DnsError {
    DnsError::DnsProtocol("malformed DNS mapping response".into())
}
fn word(data: &[u8], offset: usize) -> Result<u16, DnsError> {
    Ok(u16::from_be_bytes(
        data.get(offset..offset + 2)
            .ok_or_else(bad)?
            .try_into()
            .unwrap(),
    ))
}
fn name(data: &[u8], offset: &mut usize) -> Result<String, DnsError> {
    let mut cursor = *offset;
    let mut consumed = None;
    let mut labels = Vec::new();
    let mut length = 0;
    for _ in 0..128 {
        let byte = *data.get(cursor).ok_or_else(bad)?;
        if byte & 0xc0 == 0xc0 {
            let pointer = word(data, cursor)? as usize & 0x3fff;
            consumed.get_or_insert(cursor + 2);
            cursor = pointer;
            continue;
        }
        if byte & 0xc0 != 0 {
            return Err(bad());
        }
        cursor += 1;
        if byte == 0 {
            *offset = consumed.unwrap_or(cursor);
            return Ok(labels.join(".").to_ascii_lowercase());
        }
        let part = data.get(cursor..cursor + byte as usize).ok_or_else(bad)?;
        length += part.len() + 1;
        if length > 254 {
            return Err(bad());
        }
        labels.push(std::str::from_utf8(part).map_err(|_| bad())?.to_owned());
        cursor += part.len();
    }
    Err(bad())
}
fn answer_addresses(data: &[u8], host: &str) -> Result<Vec<(IpAddr, u32)>, DnsError> {
    let mut offset = 12;
    for _ in 0..word(data, 4)? {
        name(data, &mut offset)?;
        offset = offset.checked_add(4).ok_or_else(bad)?;
        if offset > data.len() {
            return Err(bad());
        }
    }
    let mut aliases = HashMap::new();
    let mut addresses = Vec::new();
    let count = word(data, 6)? as usize;
    if count > 4096 {
        return Err(bad());
    }
    for _ in 0..count {
        let owner = name(data, &mut offset)?;
        let kind = word(data, offset)?;
        let class = word(data, offset + 2)?;
        let ttl = u32::from_be_bytes(
            data.get(offset + 4..offset + 8)
                .ok_or_else(bad)?
                .try_into()
                .unwrap(),
        );
        let size = word(data, offset + 8)? as usize;
        offset += 10;
        let end = offset
            .checked_add(size)
            .filter(|end| *end <= data.len())
            .ok_or_else(bad)?;
        if class == 1 {
            match kind {
                1 if size == 4 => addresses.push((
                    owner,
                    IpAddr::from(<[u8; 4]>::try_from(&data[offset..end]).unwrap()),
                    ttl,
                )),
                28 if size == 16 => addresses.push((
                    owner,
                    IpAddr::from(<[u8; 16]>::try_from(&data[offset..end]).unwrap()),
                    ttl,
                )),
                5 => {
                    let mut position = offset;
                    let target = name(data, &mut position)?;
                    if position != end {
                        return Err(bad());
                    }
                    aliases.insert(owner, (target, ttl));
                }
                64 | 65 if size >= 3 => {
                    let mut position = offset + 2;
                    let target = name(data, &mut position)?;
                    if position > end {
                        return Err(bad());
                    }
                    if word(data, offset)? == 0 && !target.is_empty() {
                        aliases.insert(owner.clone(), (target, ttl));
                    }
                    while position < end {
                        if position + 4 > end {
                            return Err(bad());
                        }
                        let key = word(data, position)?;
                        let n = word(data, position + 2)? as usize;
                        position += 4;
                        let stop = position
                            .checked_add(n)
                            .filter(|stop| *stop <= end)
                            .ok_or_else(bad)?;
                        if key == 4 && n % 4 == 0 {
                            for ip in data[position..stop].chunks_exact(4) {
                                addresses.push((
                                    owner.clone(),
                                    IpAddr::from(<[u8; 4]>::try_from(ip).unwrap()),
                                    ttl,
                                ));
                            }
                        }
                        if key == 6 && n % 16 == 0 {
                            for ip in data[position..stop].chunks_exact(16) {
                                addresses.push((
                                    owner.clone(),
                                    IpAddr::from(<[u8; 16]>::try_from(ip).unwrap()),
                                    ttl,
                                ));
                            }
                        }
                        position = stop;
                    }
                }
                _ => {}
            }
        }
        offset = end;
    }
    let mut reachable = HashMap::new();
    let mut current = host.to_owned();
    let mut ttl = u32::MAX;
    let mut visited = HashSet::new();
    for _ in 0..128 {
        if !visited.insert(current.clone()) {
            break;
        }
        reachable.insert(current.clone(), ttl);
        let Some((next, alias_ttl)) = aliases.get(&current) else {
            break;
        };
        ttl = ttl.min(*alias_ttl);
        current = next.clone();
    }
    Ok(addresses
        .into_iter()
        .filter_map(|(owner, ip, ttl)| {
            reachable
                .get(&owner)
                .map(|chain_ttl| (ip, ttl.min(*chain_ttl)))
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{packet, DnsRecordType};
    fn runtime() -> DnsRuntime {
        DnsRuntime::from_document(&mihomo_config::parse_runtime_config_document("dns:\n  enable: true\n  enhanced-mode: redir-host\n  nameserver: [rcode://success]\n").unwrap()).unwrap()
    }
    fn query(host: &str, kind: DnsRecordType) -> Vec<u8> {
        packet::build_dns_query(host, kind, 42).unwrap()
    }
    fn encoded(name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for label in name.split('.') {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out
    }
    fn rr(out: &mut Vec<u8>, owner: &[u8], kind: u16, ttl: u32, data: &[u8]) {
        out.extend_from_slice(owner);
        out.extend_from_slice(&kind.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&ttl.to_be_bytes());
        out.extend_from_slice(&(data.len() as u16).to_be_bytes());
        out.extend_from_slice(data);
    }
    fn reply(query: &[u8], n: u16) -> Vec<u8> {
        let mut data = query.to_vec();
        data[2] = 0x81;
        data[3] = 0x80;
        data[6..8].copy_from_slice(&n.to_be_bytes());
        data
    }
    #[test]
    fn real_ipv4_ipv6_mappings_are_shared_across_listener_snapshots() {
        let runtime = runtime();
        let snapshot = runtime.clone();
        for ip in ["203.0.113.7", "2001:db8::7"] {
            let ip: IpAddr = ip.parse().unwrap();
            let q = query(
                "Video.Example.com",
                if ip.is_ipv4() {
                    DnsRecordType::A
                } else {
                    DnsRecordType::Aaaa
                },
            );
            let parsed = packet::parse_dns_query_packet(&q).unwrap();
            let r = packet::build_dns_response(&parsed, 120, &[ip]);
            snapshot.observe_dns_response(&q, &r).unwrap();
            assert_eq!(
                runtime.domain_for_ip(ip).as_deref(),
                Some("video.example.com")
            );
            assert!(!runtime.is_fake_ip_addr(ip));
        }
        let mut restored = self::runtime();
        restored.clone_fake_ip_state_from(&snapshot);
        assert_eq!(
            restored
                .domain_for_ip("203.0.113.7".parse().unwrap())
                .as_deref(),
            Some("video.example.com")
        );
        restored.clear_cache();
        assert!(snapshot
            .domain_for_ip("203.0.113.7".parse().unwrap())
            .is_none());
    }
    #[test]
    fn cname_chain_maps_question_and_uses_shortest_ttl_without_unrelated_answers() {
        let runtime = runtime();
        let q = query("alias.example", DnsRecordType::A);
        let mut r = reply(&q, 3);
        rr(&mut r, &[0xc0, 0x0c], 5, 5, &encoded("edge.example"));
        rr(&mut r, &encoded("edge.example"), 1, 90, &[203, 0, 113, 8]);
        rr(
            &mut r,
            &encoded("unrelated.example"),
            1,
            90,
            &[203, 0, 113, 9],
        );
        runtime.observe_dns_response(&q, &r).unwrap();
        let ip = "203.0.113.8".parse().unwrap();
        assert_eq!(runtime.domain_for_ip(ip).as_deref(), Some("alias.example"));
        assert!(runtime
            .domain_for_ip("203.0.113.9".parse().unwrap())
            .is_none());
        let state = runtime.domain_mappings.0.lock().unwrap();
        assert!(
            state.entries[&ip]
                .expires
                .saturating_duration_since(Instant::now())
                <= Duration::from_secs(5)
        );
    }
    #[test]
    fn https_records_keep_wire_bytes_and_learn_ipv4_ipv6_hints() {
        let runtime = runtime();
        let q = query("h3.example", DnsRecordType::Other(65));
        let mut r = reply(&q, 1);
        let mut params = vec![0, 1, 0, 0, 4, 0, 4, 203, 0, 113, 11, 0, 6, 0, 16];
        params.extend_from_slice(
            &"2001:db8::11"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets(),
        );
        rr(&mut r, &[0xc0, 0x0c], 65, 60, &params);
        let original = r.clone();
        runtime.observe_dns_response(&q, &r).unwrap();
        assert_eq!(r, original);
        for ip in ["203.0.113.11", "2001:db8::11"] {
            assert_eq!(
                runtime.domain_for_ip(ip.parse().unwrap()).as_deref(),
                Some("h3.example")
            );
        }
    }
    #[test]
    fn zero_ttl_expiry_and_capacity_do_not_route_stale_names() {
        let map = DomainMappings::default();
        let ip = "203.0.113.1".parse().unwrap();
        map.insert("old.test", vec![(ip, 10)], 2);
        assert!(map.lookup(ip).is_some());
        map.0.lock().unwrap().entries.get_mut(&ip).unwrap().expires =
            Instant::now() - Duration::from_millis(1);
        assert!(map.lookup(ip).is_none());
        map.insert("old.test", vec![(ip, 10)], 2);
        map.insert("old.test", vec![(ip, 0)], 2);
        assert!(map.lookup(ip).is_none());
        for n in 1..=3 {
            map.insert(
                "bounded.test",
                vec![(IpAddr::from([203, 0, 113, n]), 60)],
                2,
            );
        }
        assert_eq!(map.0.lock().unwrap().entries.len(), 2);
        assert!(map.lookup(ip).is_none());
    }
    #[test]
    fn mismatched_truncated_and_compression_cycles_cannot_poison_mapping() {
        let runtime = runtime();
        let q = query("good.example", DnsRecordType::A);
        let mut r = reply(&q, 1);
        rr(&mut r, &[0xc0, 0x0c], 1, 60, &[203, 0, 113, 1]);
        r[0] = 1;
        assert!(runtime.observe_dns_response(&q, &r).is_err());
        r[0] = 0;
        r[2] |= 2;
        runtime.observe_dns_response(&q, &r).unwrap();
        assert!(runtime.domain_mappings.0.lock().unwrap().entries.is_empty());
        let mut r = reply(&q, 1);
        let p = r.len();
        let owner = [0xc0 | ((p >> 8) as u8), p as u8];
        rr(&mut r, &owner, 1, 60, &[203, 0, 113, 1]);
        assert!(runtime.observe_dns_response(&q, &r).is_err());
        assert!(runtime.domain_mappings.0.lock().unwrap().entries.is_empty());
    }
    #[test]
    fn fake_ip_is_not_inserted_into_real_mapping_and_mode_change_is_safe() {
        let doc = mihomo_config::parse_runtime_config_document(
            "dns:\n  enable: true\n  enhanced-mode: fake-ip\n  nameserver: [rcode://success]\n",
        )
        .unwrap();
        let mut runtime = DnsRuntime::from_document(&doc).unwrap();
        let q = query("fake.example", DnsRecordType::A);
        runtime.local_query_packet(&q).unwrap().unwrap();
        assert_eq!(
            runtime
                .domain_for_ip("198.18.0.4".parse().unwrap())
                .as_deref(),
            Some("fake.example")
        );
        assert!(runtime.domain_mappings.0.lock().unwrap().entries.is_empty());
        runtime.config.enhanced_mode = EnhancedMode::RedirHost;
        assert!(runtime
            .domain_for_ip("198.18.0.4".parse().unwrap())
            .is_none());
    }
}
