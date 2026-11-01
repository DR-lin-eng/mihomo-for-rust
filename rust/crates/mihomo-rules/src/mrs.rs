use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::net::IpAddr;

use mihomo_config::RuleProviderBehavior;

use crate::matcher_support::{normalize, prefix_mask_u128, prefix_mask_u32, Cidr};
use crate::types::RuleError;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DomainMrsSet {
    nodes: Vec<DomainMrsCompactNode>,
    edges: Vec<DomainMrsCompactEdge>,
    entries: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct IpMrsSet {
    ranges: Vec<IpMrsRange>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DomainMrsCompactNode {
    first_child: u32,
    child_len: u32,
    leaf: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DomainMrsCompactEdge {
    label: u8,
    child: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct IpMrsRange {
    start: u128,
    end: u128,
}

impl DomainMrsSet {
    pub(crate) fn entry_count(&self)->usize {self.entries}
    pub(crate) fn matches(&self, host: &str) -> bool {
        let normalized = normalize(host);
        if normalized.is_empty() {
            return false;
        }

        let reversed = normalized
            .as_bytes()
            .iter()
            .rev()
            .copied()
            .collect::<Vec<_>>();
        let mut node_index = 0_usize;
        for (index, label) in reversed.iter().copied().enumerate() {
            let Some(child_index) = self.find_child(node_index, label) else {
                return false;
            };
            node_index = child_index;

            if index + 1 == reversed.len() {
                return self.nodes[node_index].leaf;
            }

            if reversed[index + 1] == b'.' && self.has_suffix_marker(node_index) {
                return true;
            }
        }

        false
    }

    pub(crate) fn contains_wildcards(&self) -> bool {
        self.edges
            .iter()
            .any(|edge| matches!(edge.label, b'*' | b'?'))
    }

    pub(crate) fn to_rules(&self) -> Result<Vec<String>, RuleError> {
        let mut keys = Vec::new();
        let mut current = Vec::new();
        self.collect_keys(0, &mut current, &mut keys)?;
        keys.sort();
        let key_set = keys.iter().cloned().collect::<BTreeSet<_>>();
        Ok(keys
            .into_iter()
            .filter(|key| !key_set.contains(&format!("+.{key}")))
            .collect())
    }

    fn from_encoded_parts(
        leaves: &[u64],
        label_bitmap: &[u64],
        labels: &[u8],
    ) -> Result<Self, RuleError> {
        let max_node_count = labels
            .len()
            .checked_add(1)
            .ok_or_else(|| RuleError::InvalidRuleProviderContent("length is invalid".into()))?;
        let mut nodes = Vec::with_capacity(max_node_count);
        nodes.push(DomainMrsCompactNode {
            first_child: 0,
            child_len: 0,
            leaf: false,
        });
        let mut edges = Vec::with_capacity(labels.len());

        let mut bit_index = 0_usize;
        let mut label_index = 0_usize;
        let mut current_node = 0_usize;
        while current_node < nodes.len() {
            let first_child = edges.len();
            let mut child_len = 0_usize;
            loop {
                let bit = get_bit(label_bitmap, bit_index).ok_or_else(|| {
                    RuleError::InvalidRuleProviderContent("length is invalid".into())
                })?;
                bit_index += 1;
                if bit != 0 {
                    break;
                }

                let label = *labels.get(label_index).ok_or_else(|| {
                    RuleError::InvalidRuleProviderContent("length is invalid".into())
                })?;
                label_index += 1;

                let child_index = nodes.len();
                nodes.push(DomainMrsCompactNode {
                    first_child: 0,
                    child_len: 0,
                    leaf: false,
                });
                edges.push(DomainMrsCompactEdge {
                    label,
                    child: child_index as u32,
                });
                child_len += 1;
            }

            nodes[current_node].first_child = first_child as u32;
            nodes[current_node].child_len = child_len as u32;
            nodes[current_node].leaf = has_bit(leaves, current_node);
            current_node += 1;
        }

        if label_index != labels.len() {
            return Err(RuleError::InvalidRuleProviderContent(
                "length is invalid".into(),
            ));
        }

        let entries=nodes.iter().filter(|node|node.leaf).count();
        Ok(Self { nodes, edges, entries })
    }

    fn find_child(&self, node_index: usize, label: u8) -> Option<usize> {
        let node = self.nodes.get(node_index)?;
        let start = node.first_child as usize;
        let end = start + node.child_len as usize;
        let edges = self.edges.get(start..end)?;
        let child = edges
            .binary_search_by_key(&label, |edge| edge.label)
            .ok()
            .and_then(|index| edges.get(index))?;
        Some(child.child as usize)
    }

    fn has_suffix_marker(&self, node_index: usize) -> bool {
        let Some(dot_child) = self.find_child(node_index, b'.') else {
            return false;
        };
        let Some(plus_child) = self.find_child(dot_child, b'+') else {
            return false;
        };
        self.nodes.get(plus_child).is_some_and(|node| node.leaf)
    }

    fn collect_keys(
        &self,
        node_index: usize,
        current: &mut Vec<u8>,
        out: &mut Vec<String>,
    ) -> Result<(), RuleError> {
        if self
            .nodes
            .get(node_index)
            .ok_or_else(|| RuleError::InvalidRuleProviderContent("length is invalid".into()))?
            .leaf
        {
            let reversed = current.iter().rev().copied().collect::<Vec<_>>();
            out.push(
                String::from_utf8(reversed)
                    .map_err(|err| RuleError::InvalidRuleProviderContent(err.to_string()))?,
            );
        }

        let node = self
            .nodes
            .get(node_index)
            .ok_or_else(|| RuleError::InvalidRuleProviderContent("length is invalid".into()))?;
        let start = node.first_child as usize;
        let end = start + node.child_len as usize;
        for edge in self
            .edges
            .get(start..end)
            .ok_or_else(|| RuleError::InvalidRuleProviderContent("length is invalid".into()))?
        {
            current.push(edge.label);
            self.collect_keys(edge.child as usize, current, out)?;
            current.pop();
        }

        Ok(())
    }
}

impl IpMrsSet {
    pub(crate) fn entry_count(&self)->usize {self.ranges.len()}
    pub(crate) fn matches(&self, ip: IpAddr) -> bool {
        let value = ip_addr_sort_key(ip);
        let end = self.ranges.partition_point(|range| range.start <= value);
        if end == 0 {
            return false;
        }
        let range = self.ranges[end - 1];
        value <= range.end
    }

    pub(crate) fn to_cidrs(&self) -> Vec<String> {
        let mut cidrs = Vec::new();
        for range in &self.ranges {
            cidrs.extend(ip_range_to_cidrs(
                sort_key_to_ip_addr(range.start),
                sort_key_to_ip_addr(range.end),
            ));
        }
        cidrs
    }
}

pub(crate) fn write_domain_mrs_body(
    w: &mut impl Write,
    payload: &[String],
) -> Result<(), RuleError> {
    let mut stored_rules = Vec::new();
    for raw in payload {
        stored_rules.extend(expand_domain_rule_for_mrs(raw));
    }
    if stored_rules.is_empty() {
        return Err(RuleError::InvalidRuleProviderContent("empty rule".into()));
    }

    let mut reversed = stored_rules
        .into_iter()
        .map(|rule| reverse_ascii(&rule).into_bytes())
        .collect::<Vec<_>>();
    reversed.sort();
    reversed.dedup();

    let (leaves, label_bitmap, labels) = build_domain_set_binary(&reversed);
    w.write_all(&[1])
        .map_err(|err| RuleError::InvalidRuleProviderContent(err.to_string()))?;
    write_u64_vec(w, &leaves)?;
    write_u64_vec(w, &label_bitmap)?;
    w.write_all(&(labels.len() as i64).to_be_bytes())
        .map_err(|err| RuleError::InvalidRuleProviderContent(err.to_string()))?;
    w.write_all(&labels)
        .map_err(|err| RuleError::InvalidRuleProviderContent(err.to_string()))?;
    Ok(())
}

pub(crate) fn read_domain_mrs_body(r: &mut impl Read) -> Result<Vec<String>, RuleError> {
    read_domain_mrs_set(r)?.to_rules()
}

pub(crate) fn read_domain_mrs_set(r: &mut impl Read) -> Result<DomainMrsSet, RuleError> {
    let version = read_u8(r)?;
    if version != 1 {
        return Err(RuleError::InvalidRuleProviderContent(
            "version is invalid".into(),
        ));
    }
    let leaves = read_u64_vec(r)?;
    let label_bitmap = read_u64_vec(r)?;
    let labels_len = read_i64_be(r)?;
    if labels_len < 1 {
        return Err(RuleError::InvalidRuleProviderContent(
            "length is invalid".into(),
        ));
    }
    let mut labels = vec![0_u8; labels_len as usize];
    r.read_exact(&mut labels)
        .map_err(|err| RuleError::InvalidRuleProviderContent(err.to_string()))?;
    DomainMrsSet::from_encoded_parts(&leaves, &label_bitmap, &labels)
}

pub(crate) fn write_ipcidr_mrs_body(
    w: &mut impl Write,
    payload: &[String],
) -> Result<(), RuleError> {
    let ranges = payload
        .iter()
        .map(|raw| Cidr::parse(raw))
        .collect::<Result<Vec<_>, _>>()?;
    if ranges.is_empty() {
        return Err(RuleError::InvalidRuleProviderContent("empty rule".into()));
    }
    w.write_all(&[1])
        .map_err(|err| RuleError::InvalidRuleProviderContent(err.to_string()))?;
    w.write_all(&(ranges.len() as i64).to_be_bytes())
        .map_err(|err| RuleError::InvalidRuleProviderContent(err.to_string()))?;
    for cidr in ranges {
        let (start, end) = cidr_bounds(&cidr);
        write_ip16(w, start)?;
        write_ip16(w, end)?;
    }
    Ok(())
}

pub(crate) fn read_ipcidr_mrs_body(r: &mut impl Read) -> Result<Vec<String>, RuleError> {
    Ok(read_ipcidr_mrs_set(r)?.to_cidrs())
}

pub(crate) fn read_ipcidr_mrs_set(r: &mut impl Read) -> Result<IpMrsSet, RuleError> {
    let version = read_u8(r)?;
    if version != 1 {
        return Err(RuleError::InvalidRuleProviderContent(
            "version is invalid".into(),
        ));
    }
    let len = read_i64_be(r)?;
    if len < 1 {
        return Err(RuleError::InvalidRuleProviderContent(
            "length is invalid".into(),
        ));
    }
    let mut ranges = Vec::with_capacity(len as usize);
    for _ in 0..len {
        let start = read_ip16(r)?;
        let end = read_ip16(r)?;
        ranges.push(IpMrsRange {
            start: ip_addr_sort_key(start),
            end: ip_addr_sort_key(end),
        });
    }
    ranges.sort_unstable_by_key(|range| range.start);

    let mut merged: Vec<IpMrsRange> = Vec::with_capacity(ranges.len());
    for range in ranges {
        if let Some(last) = merged.last_mut() {
            if range.start <= last.end.saturating_add(1) {
                last.end = last.end.max(range.end);
                continue;
            }
        }
        merged.push(range);
    }

    Ok(IpMrsSet { ranges: merged })
}

pub(crate) fn mrs_behavior_byte(behavior: RuleProviderBehavior) -> u8 {
    match behavior {
        RuleProviderBehavior::Domain => 0,
        RuleProviderBehavior::IpCidr => 1,
        RuleProviderBehavior::Classical => 2,
    }
}

pub(crate) fn read_u8(r: &mut impl Read) -> Result<u8, RuleError> {
    let mut buf = [0_u8; 1];
    r.read_exact(&mut buf)
        .map_err(|err| RuleError::InvalidRuleProviderContent(err.to_string()))?;
    Ok(buf[0])
}

pub(crate) fn read_i64_be(r: &mut impl Read) -> Result<i64, RuleError> {
    let mut buf = [0_u8; 8];
    r.read_exact(&mut buf)
        .map_err(|err| RuleError::InvalidRuleProviderContent(err.to_string()))?;
    Ok(i64::from_be_bytes(buf))
}

fn expand_domain_rule_for_mrs(raw: &str) -> Vec<String> {
    let normalized = normalize(raw);
    if normalized.is_empty() || normalized.ends_with('.') {
        return Vec::new();
    }
    if normalized.starts_with("+.") {
        let suffix = normalized.trim_start_matches("+.").to_owned();
        if suffix.is_empty() {
            return Vec::new();
        }
        return vec![suffix.clone(), format!("+.{suffix}")];
    }
    if normalized.starts_with('.') && normalized.len() > 1 {
        return vec![format!("+{}", normalized)];
    }
    vec![normalized]
}

fn reverse_ascii(value: &str) -> String {
    value.bytes().rev().map(char::from).collect()
}

fn build_domain_set_binary(keys: &[Vec<u8>]) -> (Vec<u64>, Vec<u64>, Vec<u8>) {
    #[derive(Clone, Copy)]
    struct QueueElt {
        start: usize,
        end: usize,
        col: usize,
    }

    let mut leaves = Vec::new();
    let mut label_bitmap = Vec::new();
    let mut labels = Vec::new();
    let mut queue = vec![QueueElt {
        start: 0,
        end: keys.len(),
        col: 0,
    }];
    let mut bit_index = 0_usize;

    let mut node_index = 0_usize;
    while node_index < queue.len() {
        let mut elt = queue[node_index];
        if elt.col == keys[elt.start].len() {
            elt.start += 1;
            set_bit(&mut leaves, node_index, true);
        }

        let mut cursor = elt.start;
        while cursor < elt.end {
            let first = cursor;
            while cursor < elt.end && keys[cursor][elt.col] == keys[first][elt.col] {
                cursor += 1;
            }
            queue.push(QueueElt {
                start: first,
                end: cursor,
                col: elt.col + 1,
            });
            labels.push(keys[first][elt.col]);
            set_bit(&mut label_bitmap, bit_index, false);
            bit_index += 1;
        }
        set_bit(&mut label_bitmap, bit_index, true);
        bit_index += 1;
        node_index += 1;
    }

    (leaves, label_bitmap, labels)
}

fn cidr_bounds(cidr: &Cidr) -> (IpAddr, IpAddr) {
    match cidr.network {
        IpAddr::V4(ip) => {
            let start = u32::from(ip) & prefix_mask_u32(cidr.prefix_len);
            let host_mask = if cidr.prefix_len == 32 {
                0
            } else {
                (1_u32 << (32 - cidr.prefix_len)) - 1
            };
            (
                IpAddr::V4(std::net::Ipv4Addr::from(start)),
                IpAddr::V4(std::net::Ipv4Addr::from(start | host_mask)),
            )
        }
        IpAddr::V6(ip) => {
            let start = u128::from(ip) & prefix_mask_u128(cidr.prefix_len);
            let host_mask = if cidr.prefix_len == 128 {
                0
            } else {
                (1_u128 << (128 - cidr.prefix_len)) - 1
            };
            (
                IpAddr::V6(std::net::Ipv6Addr::from(start)),
                IpAddr::V6(std::net::Ipv6Addr::from(start | host_mask)),
            )
        }
    }
}

fn write_u64_vec(w: &mut impl Write, values: &[u64]) -> Result<(), RuleError> {
    if values.is_empty() {
        return Err(RuleError::InvalidRuleProviderContent(
            "length is invalid".into(),
        ));
    }
    w.write_all(&(values.len() as i64).to_be_bytes())
        .map_err(|err| RuleError::InvalidRuleProviderContent(err.to_string()))?;
    for value in values {
        w.write_all(&value.to_be_bytes())
            .map_err(|err| RuleError::InvalidRuleProviderContent(err.to_string()))?;
    }
    Ok(())
}

fn read_u64_vec(r: &mut impl Read) -> Result<Vec<u64>, RuleError> {
    let len = read_i64_be(r)?;
    if len < 1 {
        return Err(RuleError::InvalidRuleProviderContent(
            "length is invalid".into(),
        ));
    }
    let mut values = Vec::with_capacity(len as usize);
    for _ in 0..len {
        let mut buf = [0_u8; 8];
        r.read_exact(&mut buf)
            .map_err(|err| RuleError::InvalidRuleProviderContent(err.to_string()))?;
        values.push(u64::from_be_bytes(buf));
    }
    Ok(values)
}

fn set_bit(bits: &mut Vec<u64>, index: usize, value: bool) {
    while index / 64 >= bits.len() {
        bits.push(0);
    }
    if value {
        bits[index / 64] |= 1_u64 << (index % 64);
    }
}

fn has_bit(bits: &[u64], index: usize) -> bool {
    get_bit(bits, index).unwrap_or(0) != 0
}

fn get_bit(bits: &[u64], index: usize) -> Option<u64> {
    let word = *bits.get(index / 64)?;
    Some((word >> (index % 64)) & 1)
}

fn write_ip16(w: &mut impl Write, ip: IpAddr) -> Result<(), RuleError> {
    let octets = match ip {
        IpAddr::V4(ip) => ip.to_ipv6_mapped().octets(),
        IpAddr::V6(ip) => ip.octets(),
    };
    w.write_all(&octets)
        .map_err(|err| RuleError::InvalidRuleProviderContent(err.to_string()))
}

fn read_ip16(r: &mut impl Read) -> Result<IpAddr, RuleError> {
    let mut octets = [0_u8; 16];
    r.read_exact(&mut octets)
        .map_err(|err| RuleError::InvalidRuleProviderContent(err.to_string()))?;
    if octets[..10].iter().all(|byte| *byte == 0) && octets[10] == 0xff && octets[11] == 0xff {
        return Ok(IpAddr::V4(std::net::Ipv4Addr::new(
            octets[12], octets[13], octets[14], octets[15],
        )));
    }
    Ok(IpAddr::V6(std::net::Ipv6Addr::from(octets)))
}

fn ip_addr_sort_key(ip: IpAddr) -> u128 {
    match ip {
        IpAddr::V4(ip) => u128::from(ip.to_ipv6_mapped()),
        IpAddr::V6(ip) => u128::from(ip),
    }
}

fn sort_key_to_ip_addr(value: u128) -> IpAddr {
    let octets = value.to_be_bytes();
    if octets[..10].iter().all(|byte| *byte == 0) && octets[10] == 0xff && octets[11] == 0xff {
        return IpAddr::V4(std::net::Ipv4Addr::new(
            octets[12], octets[13], octets[14], octets[15],
        ));
    }
    IpAddr::V6(std::net::Ipv6Addr::from(octets))
}

fn ip_range_to_cidrs(start: IpAddr, end: IpAddr) -> Vec<String> {
    match (start, end) {
        (IpAddr::V4(start), IpAddr::V4(end)) => range_to_cidrs_v4(u32::from(start), u32::from(end))
            .into_iter()
            .map(|(network, prefix)| format!("{}/{}", std::net::Ipv4Addr::from(network), prefix))
            .collect(),
        (IpAddr::V6(start), IpAddr::V6(end)) => {
            range_to_cidrs_v6(u128::from(start), u128::from(end))
                .into_iter()
                .map(|(network, prefix)| {
                    format!("{}/{}", std::net::Ipv6Addr::from(network), prefix)
                })
                .collect()
        }
        _ => Vec::new(),
    }
}

fn range_to_cidrs_v4(mut start: u32, end: u32) -> Vec<(u32, u8)> {
    let mut result = Vec::new();
    while start <= end {
        let align = if start == 0 {
            32
        } else {
            start.trailing_zeros()
        };
        let max_len = 32 - align;
        let remaining = end - start + 1;
        let max_block = 31 - remaining.leading_zeros();
        let prefix = (32 - max_block.min(max_len)) as u8;
        result.push((start, prefix));
        let block = 1_u32 << (32 - prefix);
        start = start.saturating_add(block);
    }
    result
}

fn range_to_cidrs_v6(mut start: u128, end: u128) -> Vec<(u128, u8)> {
    let mut result = Vec::new();
    while start <= end {
        let align = if start == 0 {
            128
        } else {
            start.trailing_zeros()
        };
        let max_len = 128 - align;
        let remaining = end - start + 1;
        let max_block = 127 - remaining.leading_zeros();
        let prefix = (128 - max_block.min(max_len)) as u8;
        result.push((start, prefix));
        let block = 1_u128 << (128 - prefix);
        start = start.saturating_add(block);
    }
    result
}
