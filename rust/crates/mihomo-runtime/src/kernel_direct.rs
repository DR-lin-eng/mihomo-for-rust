use mihomo_ebpf::{monotonic_ns, DirectFlowKey};

struct KernelTracked {
    tracked: Arc<TrackedConnection>,
    upload: u64,
    download: u64,
    sequence: u32,
    retired_at: Option<u64>,
}

#[cfg(test)]
mod kernel_policy_tests {
    use super::*;
    use mihomo_config::parse_runtime_config_document;
    use mihomo_core::{NetworkKind, SessionKind};
    #[test]
    fn offload_decision_respects_ordered_rules_and_sniffing() {
        let document=parse_runtime_config_document("mode: rule\nsniffer:\n  enable: true\n  parse-pure-ip: true\n  sniff:\n    TLS: {ports: [443]}\nrules: ['DOMAIN,blocked.test,REJECT', 'MATCH,DIRECT']\n").unwrap();
        let tunnel = RuntimeTunnel::new(
            document.mode.clone(),
            crate::build_runtime_registry(&document).unwrap(),
        )
        .with_rule_set(mihomo_rules::compile_rule_set(&document.rules).unwrap())
        .with_sniffer(document.sniffer.clone());
        let mut m = Metadata {
            network: NetworkKind::Tcp,
            kind: SessionKind::Tun,
            src_ip: Some("192.0.2.2".parse().unwrap()),
            src_port: Some(32000),
            dst_ip: Some("203.0.113.30".parse().unwrap()),
            dst_port: Some(443),
            ..Metadata::default()
        };
        assert!(tunnel.kernel_direct_plan(&mut m).is_none());
        m.dst_port = Some(12345);
        assert!(tunnel.kernel_direct_plan(&mut m).is_some());
        m.host = Some("blocked.test".into());
        assert!(tunnel.kernel_direct_plan(&mut m).is_none());
        tunnel.set_rule_disabled(0, true);
        assert!(tunnel.kernel_direct_plan(&mut m).is_some());
        m.dns_hijacked = true;
        assert!(tunnel.kernel_direct_plan(&mut m).is_none());
    }
}

impl RuntimeTunnel {
    pub fn kernel_direct_needs_resolution(&self, metadata: &Metadata) -> bool {
        if metadata.host.is_none() || metadata.dst_ip.is_some() || self.current_mode() != "rule" {
            return false;
        }
        let sniffer = self.sniffer.read().unwrap();
        let port = metadata.dst_port.unwrap_or_default();
        if sniffer.eligible(metadata)
            && (sniffer.protocol("TLS", port).is_some()
                || sniffer.protocol("HTTP", port).is_some()
                || sniffer.protocol("QUIC", port).is_some())
        {
            return false;
        }
        self.rules.read().unwrap().needs_destination_ip(metadata)
    }
    pub fn kernel_direct_runtime(&self) -> Option<Arc<mihomo_ebpf::EbpfRuntime>> {
        self.ebpf
            .read()
            .unwrap()
            .as_ref()
            .filter(|v| v.direct_ready())
            .cloned()
    }
    /// Apply exactly the runtime policy, but decline any flow whose destination
    /// still requires payload sniffing. No socket has been accepted/created yet.
    pub fn kernel_direct_plan(&self, metadata: &mut Metadata) -> Option<(ExecutionPlan, u64)> {
        let _gate = self.kernel_policy_gate.lock().unwrap();
        self.preprocess_metadata_for_routing(metadata).ok()?;
        if metadata.dns_hijacked || metadata.dst_port == Some(53) {
            return None;
        }
        let sniffer = self.sniffer.read().unwrap();
        let port = metadata.dst_port?;
        if sniffer.eligible(metadata)
            && match metadata.network {
                mihomo_core::NetworkKind::Tcp => {
                    sniffer.protocol("TLS", port).is_some()
                        || sniffer.protocol("HTTP", port).is_some()
                }
                _ => sniffer.protocol("QUIC", port).is_some(),
            }
        {
            return None;
        }
        drop(sniffer);
        let mode = self.current_mode();
        let states = self.candidate_states.lock().unwrap().clone();
        let rules = self.rules.read().unwrap().clone();
        let mut registry = self.registry.lock().unwrap();
        let target = if mode == "rule" && metadata.special_proxy.is_empty() {
            rules
                .target_for(metadata)
                .filter(|name| {
                    registry.proxies.contains_key(*name) || registry.groups.contains_key(*name)
                })
                .unwrap_or(RULE_FALLBACK_TARGET)
                .to_owned()
        } else {
            select_target_name(&mode, metadata, &registry, &rules)
        };
        let plan = build_execution_plan(&mut registry, &target, Some(metadata), &states).ok()?;
        // Automatic and unfixed selections can change without an API mutation.
        // Explicit selectors are stable until the existing mutation gate runs.
        for name in &plan.selected_path {
            if let Some(group) = registry.groups.get(name) {
                if group.runtime.group.group_type != "select" || group.runtime.selected().is_none()
                {
                    return None;
                }
            }
        }
        if plan.hops.len() != 1 {
            return None;
        }
        match &plan.hops[0].spec {
            ExecutionHopSpec::Direct(spec)
                if spec.socket == crate::execution::SocketOptions::default() => {}
            _ => return None,
        }
        Some((plan, self.kernel_policy_generation.load(Ordering::Acquire)))
    }

    pub fn kernel_direct_existing(&self, key: &DirectFlowKey, sequence: Option<u32>) -> bool {
        let Some(runtime) = self.kernel_direct_runtime() else {
            return false;
        };
        let records = self.kernel_direct.lock().unwrap();
        records.get(key).is_some_and(|record| {
            record.retired_at.is_none()
                && sequence.is_none_or(|n| n == record.sequence)
                && runtime.direct_contains(key)
        })
    }

    pub fn retire_kernel_direct(&self, key: &DirectFlowKey) {
        self.sync_kernel_direct();
        let Some(runtime) = self.kernel_direct_runtime() else {
            return;
        };
        let mut records = self.kernel_direct.lock().unwrap();
        if let Some(record) = records.remove(key) {
            runtime.direct_close(key);
            self.unregister_connection(record.tracked.id);
        }
        runtime.direct_forget(key);
    }

    pub fn install_kernel_direct(
        &self,
        key: DirectFlowKey,
        metadata: Metadata,
        plan: ExecutionPlan,
        generation: u64,
        sequence: u32,
        udp_timeout: u64,
    ) -> io::Result<bool> {
        let _gate = self.kernel_policy_gate.lock().unwrap();
        if generation != self.kernel_policy_generation.load(Ordering::Acquire) {
            return Ok(false);
        }
        let Some(runtime) = self.kernel_direct_runtime() else {
            return Ok(false);
        };
        let Some(target) = metadata.destination_socket_addr() else {
            return Ok(false);
        };
        let id = (1_u64 << 62) | self.next_udp_connection_id.fetch_add(1, Ordering::Relaxed);
        let timeout = if key.protocol == 17 {
            udp_timeout.max(1)
        } else {
            7200
        };
        if !runtime.direct_install(key, target, id, timeout)? {
            return Ok(false);
        }
        let tracked = self.register_connection(id, metadata, Some(&plan), Vec::new());
        // Count the selected rule once per new connection; the BPF data path
        // does not repeatedly rematch policy for every packet.
        if self.current_mode() == "rule" && tracked.metadata.special_proxy.is_empty() {
            self.rules
                .read()
                .unwrap()
                .matched_rule_definition_and_record(&tracked.metadata);
        }
        self.kernel_direct.lock().unwrap().insert(
            key,
            KernelTracked {
                tracked,
                upload: 0,
                download: 0,
                sequence,
                retired_at: None,
            },
        );
        Ok(true)
    }

    pub fn sync_kernel_direct(&self) {
        let Some(runtime) = self.kernel_direct_runtime() else {
            return;
        };
        let mut records = self.kernel_direct.lock().unwrap();
        let now = monotonic_ns();
        for sample in runtime.direct_samples() {
            let Some(record) = records.get_mut(&sample.key) else {
                continue;
            };
            if record.tracked.id != sample.id {
                continue;
            }
            let upload = sample.upload.saturating_sub(record.upload);
            let download = sample.download.saturating_sub(record.download);
            self.traffic
                .record(true, upload, Some(&record.tracked.upload));
            self.traffic
                .record(false, download, Some(&record.tracked.download));
            record.upload = sample.upload;
            record.download = sample.download;
            if sample.active && !sample.closed {
                record
                    .tracked
                    .last_activity_elapsed_ms
                    .store(self.traffic.elapsed_ms(), Ordering::Relaxed);
            } else if record.retired_at.is_none() {
                record.retired_at = Some(now);
                self.unregister_connection(record.tracked.id);
            }
        }
        let expired = records
            .iter()
            .filter(|(_, record)| {
                record
                    .retired_at
                    .is_some_and(|retired| now.saturating_sub(retired) > 120_000_000_000)
            })
            .map(|(key, _)| *key)
            .collect::<Vec<_>>();
        for key in expired {
            runtime.direct_forget(&key);
            records.remove(&key);
        }
    }

    fn invalidate_kernel_udp(&self) {
        self.kernel_policy_generation.fetch_add(1, Ordering::AcqRel);
        if let Some(runtime) = self.kernel_direct_runtime() {
            runtime.direct_invalidate_udp();
        }
        self.sync_kernel_direct();
    }
    fn close_kernel_connection(&self, id: u64) -> bool {
        let Some(runtime) = self.kernel_direct_runtime() else {
            return false;
        };
        self.sync_kernel_direct();
        let mut records = self.kernel_direct.lock().unwrap();
        if let Some((key, record)) = records
            .iter_mut()
            .find(|(_, record)| record.tracked.id == id && record.retired_at.is_none())
        {
            runtime.direct_close(key);
            record.retired_at = Some(monotonic_ns());
            self.unregister_connection(id);
            true
        } else {
            false
        }
    }
    pub fn close_all_kernel_connections(&self) -> usize {
        let Some(runtime) = self.kernel_direct_runtime() else {
            return 0;
        };
        self.sync_kernel_direct();
        let mut count = 0;
        for (key, record) in self.kernel_direct.lock().unwrap().iter_mut() {
            if record.retired_at.is_none() {
                count += 1;
            }
            runtime.direct_close(key);
            record.retired_at = Some(monotonic_ns());
            self.unregister_connection(record.tracked.id);
        }
        count
    }
}
