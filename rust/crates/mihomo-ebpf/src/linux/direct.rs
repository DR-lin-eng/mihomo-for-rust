use super::*;
use crate::{
    monotonic_ns, DirectFlowKey, DirectFlowSample, DirectFlowValue, DirectFragmentKey,
    DirectOffloadStatus,
};
use std::collections::HashMap;
use std::process::Command;

#[cfg(target_endian = "little")]
static DIRECT_OBJECT: &[u8] =
    aya::include_bytes_aligned!(concat!(env!("CARGO_MANIFEST_DIR"), "/bpf/direct.bpfel.o"));
#[cfg(target_endian = "big")]
static DIRECT_OBJECT: &[u8] =
    aya::include_bytes_aligned!(concat!(env!("CARGO_MANIFEST_DIR"), "/bpf/direct.bpfeb.o"));
const CAPACITY: u32 = 4096;
const LOCK_FLAG: u64 = 4;
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Action {
    id: u64,
    enabled: u32,
    pad: u32,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Pending {
    seen: u64,
    interface: u32,
    pad: u32,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Fragment {
    key: DirectFlowKey,
    seen: u64,
    reply: u32,
    pad: u32,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Config {
    mark: u32,
    tun_index: u32,
    enabled: u32,
    pad: u32,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct LocalAddress {
    address: [u8; 16],
    family: u32,
}
unsafe impl Pod for LocalAddress {}
unsafe impl Pod for DirectFlowKey {}
unsafe impl Pod for DirectFlowValue {}
unsafe impl Pod for DirectFragmentKey {}
unsafe impl Pod for Action {}
unsafe impl Pod for Pending {}
unsafe impl Pod for Fragment {}
unsafe impl Pod for Config {}
type Table<K, V> = BpfHashMap<MapData, K, V>;

struct Attachment {
    index: u32,
    owned: bool,
    lock: std::fs::File,
}
impl Drop for Attachment {
    fn drop(&mut self) {
        if self.owned {
            let _ = netlink::remove_empty_clsact(self.index);
        }
        use std::io::{Seek, SeekFrom, Write};
        let _ = self.lock.set_len(0);
        let _ = self.lock.seek(SeekFrom::Start(0));
        let _ = self.lock.write_all(b"0");
    }
}
pub(super) struct DirectRuntime {
    bpf: Option<Ebpf>,
    attachments: Vec<Attachment>,
    rules: Vec<Vec<String>>,
    route_lock: std::fs::File,
    flows: Table<DirectFlowKey, DirectFlowValue>,
    actions: Table<DirectFlowKey, Action>,
    replies: Table<DirectFlowKey, DirectFlowKey>,
    pending: Table<DirectFlowKey, Pending>,
    fragments: Table<DirectFragmentKey, Fragment>,
    keys: HashMap<DirectFlowKey, DirectFlowKey>,
    interfaces: Vec<String>,
    program_ids: Vec<u32>,
    ipv6: bool,
}
fn ip(args: &[String]) -> io::Result<String> {
    for binary in ["ip", "/system/bin/ip", "/sbin/ip"] {
        match Command::new(binary).args(args).output() {
            Ok(output) => {
                return if output.status.success() {
                    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
                } else {
                    Err(other(String::from_utf8_lossy(&output.stderr)))
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        }
    }
    Err(invalid("ip utility unavailable"))
}
impl DirectRuntime {
    pub(super) fn install(
        document: &RuntimeConfigDocument,
        addresses: &[InterfaceAddress],
    ) -> io::Result<Option<Self>> {
        if document.ebpf.direct_offload.is_empty() {
            return Ok(None);
        }
        if std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward")?.trim() != "1" {
            return Err(invalid("eBPF direct-offload requires net.ipv4.ip_forward=1 and working LAN-to-WAN routing/firewall"));
        }
        let ipv6 = document.ipv6
            && std::fs::read_to_string("/proc/sys/net/ipv6/conf/all/forwarding")
                .is_ok_and(|v| v.trim() == "1");
        let tun_name = &document.tun.config.device;
        let tun_index = interface_index(tun_name)?;
        let route_lock = Self::route_lock(document.ebpf.effective_bypass_mark())?;
        for name in &document.ebpf.direct_offload {
            let a = addresses
                .iter()
                .find(|a| a.name == *name)
                .ok_or_else(|| invalid(format!("missing direct-offload interface {name}")))?;
            if a.flags & libc::IFF_UP as u32 == 0 || a.link_type != Some(1) {
                return Err(invalid(format!(
                    "direct-offload source {name} must be an active Ethernet LAN interface"
                )));
            }
        }
        let mut bpf = aya::EbpfLoader::new_without_btf()
            .btf(None)
            .load(DIRECT_OBJECT)
            .map_err(other)?;
        {
            let mut local =
                BpfHashMap::<_, LocalAddress, u32>::try_from(bpf.map_mut("direct_local").unwrap())
                    .map_err(other)?;
            for address in addresses.iter().flat_map(|v| &v.addresses) {
                let mut key = LocalAddress::default();
                match address {
                    IpAddr::V4(ip) => {
                        key.family = 4;
                        key.address[..4].copy_from_slice(&ip.octets());
                    }
                    IpAddr::V6(ip) => {
                        key.family = 6;
                        key.address = ip.octets();
                    }
                }
                local.insert(key, 1, 0).map_err(other)?;
            }
        }
        let mut cfg =
            Array::<_, Config>::try_from(bpf.take_map("direct_config").unwrap()).map_err(other)?;
        cfg.set(
            0,
            Config {
                mark: document.ebpf.effective_bypass_mark(),
                tun_index,
                enabled: 0,
                pad: 0,
            },
            0,
        )
        .map_err(other)?;
        let mut result = Self {
            flows: Table::try_from(bpf.take_map("direct_flows").unwrap()).map_err(other)?,
            actions: Table::try_from(bpf.take_map("direct_actions").unwrap()).map_err(other)?,
            replies: Table::try_from(bpf.take_map("direct_replies").unwrap()).map_err(other)?,
            pending: Table::try_from(bpf.take_map("direct_pending").unwrap()).map_err(other)?,
            fragments: Table::try_from(bpf.take_map("direct_fragments").unwrap()).map_err(other)?,
            bpf: Some(bpf),
            attachments: Vec::new(),
            rules: Vec::new(),
            route_lock,
            keys: HashMap::new(),
            interfaces: document.ebpf.direct_offload.clone(),
            program_ids: Vec::new(),
            ipv6,
        };
        for program in ["mihomo_kd_in", "mihomo_kd_out", "mihomo_kd_tun"] {
            let p: &mut SchedClassifier = result
                .bpf
                .as_mut()
                .unwrap()
                .program_mut(program)
                .unwrap()
                .try_into()
                .map_err(other)?;
            p.load().map_err(other)?;
            result.program_ids.push(p.info().map_err(other)?.id());
        }
        let mut names = document.ebpf.direct_offload.clone();
        names.push(tun_name.clone());
        for name in names {
            let index = interface_index(&name)?;
            let (lock, was_owned) = interface_lock(index)?;
            for (p, d) in [
                ("mihomo_kd_in", TcAttachType::Ingress),
                ("mihomo_kd_out", TcAttachType::Egress),
                ("mihomo_kd_tun", TcAttachType::Ingress),
            ] {
                if let Err(e) = tc::qdisc_detach_program(&name, d, p) {
                    if !matches!(e.raw_os_error(), Some(libc::ENOENT) | Some(libc::EINVAL))
                        && e.kind() != io::ErrorKind::NotFound
                    {
                        return Err(e);
                    }
                }
            }
            let owned = match tc::qdisc_add_clsact(&name) {
                Ok(()) => true,
                Err(e) if e.raw_os_error() == Some(libc::EEXIST) => was_owned,
                Err(e) => return Err(e),
            };
            use std::io::Write;
            lock.set_len(0)?;
            (&lock).write_all(if owned { b"1" } else { b"0" })?;
            result.attachments.push(Attachment { index, owned, lock });
            let programs = if name == *tun_name {
                vec![("mihomo_kd_tun", TcAttachType::Ingress)]
            } else {
                vec![
                    ("mihomo_kd_in", TcAttachType::Ingress),
                    ("mihomo_kd_out", TcAttachType::Egress),
                ]
            };
            for (p, direction) in programs {
                let p: &mut SchedClassifier = result
                    .bpf
                    .as_mut()
                    .unwrap()
                    .program_mut(p)
                    .unwrap()
                    .try_into()
                    .map_err(other)?;
                p.attach_with_options(
                    &name,
                    direction,
                    TcAttachOptions::Netlink(NlOptions {
                        priority: 49151,
                        ..Default::default()
                    }),
                )
                .map_err(other)?;
            }
        }
        // The mark is set only after a full runtime DIRECT decision (or on core
        // sockets). Keep the normal main-table route ahead of TUN policy rules.
        let priority = if document.tun.config.iproute2_rule_index > 1 {
            document.tun.config.iproute2_rule_index - 1
        } else {
            8999
        };
        for family in if ipv6 { vec!["-4", "-6"] } else { vec!["-4"] } {
            let args: Vec<String> = [
                family,
                "rule",
                "add",
                "fwmark",
                &format!("0x{:x}", document.ebpf.effective_bypass_mark()),
                "lookup",
                "main",
                "priority",
                &priority.to_string(),
            ]
            .iter()
            .map(|s| s.to_string())
            .collect();
            let query: Vec<String> = [family, "rule", "show"]
                .iter()
                .map(|s| s.to_string())
                .collect();
            let marker = format!(
                "fwmark 0x{:x} lookup main",
                document.ebpf.effective_bypass_mark()
            );
            if !ip(&query)?.lines().any(|line| line.contains(&marker)) {
                let occupied = ip(&query)?.lines().any(|line| {
                    line.split_once(':')
                        .is_some_and(|(p, _)| p.trim() == priority.to_string())
                });
                if occupied {
                    return Err(invalid(format!(
                        "direct-offload routing priority {priority} is already in use"
                    )));
                }
                ip(&args)?;
                result.rules.push(args);
                use std::io::{Seek, SeekFrom, Write};
                result.route_lock.set_len(0)?;
                result.route_lock.seek(SeekFrom::Start(0))?;
                for rule in &result.rules {
                    writeln!(&result.route_lock, "{}", rule.join(" "))?;
                }
                result.route_lock.sync_data()?;
            }
        }
        cfg.set(
            0,
            Config {
                mark: document.ebpf.effective_bypass_mark(),
                tun_index,
                enabled: 1,
                pad: 0,
            },
            0,
        )
        .map_err(other)?;
        Ok(Some(result))
    }
    fn route_lock(mark: u32) -> io::Result<std::fs::File> {
        use std::io::{Read, Seek, SeekFrom};
        use std::os::{
            fd::AsRawFd,
            unix::fs::{MetadataExt, OpenOptionsExt},
        };
        let ns = std::fs::metadata("/proc/self/ns/net")?.ino();
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(format!("/tmp/mihomo-direct-routes-{ns}-{mark}.lock"))?;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(invalid(
                "kernel DIRECT routing mark is already owned by another active core",
            ));
        }
        let mut previous = String::new();
        (&mut file).take(4096).read_to_string(&mut previous)?;
        for line in previous.lines() {
            let mut args: Vec<String> = line.split_ascii_whitespace().map(str::to_owned).collect();
            if args.len() == 9
                && matches!(args[0].as_str(), "-4" | "-6")
                && args[1..4] == ["rule", "add", "fwmark"]
                && args[4] == format!("0x{mark:x}")
                && args[5..8] == ["lookup", "main", "priority"]
            {
                args[2] = "del".into();
                let _ = ip(&args);
            }
        }
        file.set_len(0)?;
        file.seek(SeekFrom::Start(0))?;
        Ok(file)
    }
    pub(super) fn pending(&self, key: &DirectFlowKey) -> bool {
        self.pending.get(key, 0).is_ok_and(|p| {
            monotonic_ns().saturating_sub(p.seen) < 5_000_000_000
                && self.attachments.iter().any(|a| a.index == p.interface)
        })
    }
    pub(super) fn fragment(&self, key: &DirectFragmentKey) -> Option<DirectFlowKey> {
        self.fragments
            .get(key, 0)
            .ok()
            .filter(|f| f.reply == 0 && monotonic_ns().saturating_sub(f.seen) < 30_000_000_000)
            .map(|f| f.key)
    }
    pub(super) fn remember_fragment(&mut self, fragment: DirectFragmentKey, key: DirectFlowKey) {
        let _ = self.fragments.insert(
            fragment,
            Fragment {
                key,
                seen: monotonic_ns(),
                reply: 0,
                pad: 0,
            },
            0,
        );
    }
    pub(super) fn contains(&self, key: &DirectFlowKey) -> bool {
        self.flows.get(key, LOCK_FLAG).ok().is_some_and(|v| {
            self.actions
                .get(key, 0)
                .is_ok_and(|a| a.enabled != 0 && a.id == v.id)
                && monotonic_ns().saturating_sub(v.last_seen_ns) < v.timeout_ns
        })
    }
    pub(super) fn install_flow(
        &mut self,
        key: DirectFlowKey,
        target: SocketAddr,
        id: u64,
        timeout: u64,
    ) -> io::Result<bool> {
        if !self.pending(&key) || (key.family == 6 && !self.ipv6) {
            return Ok(false);
        }
        if self.keys.len() >= CAPACITY as usize && !self.keys.contains_key(&key) {
            return Ok(false);
        }
        let Some(real) = key.with_destination(target) else {
            return Ok(false);
        };
        if self
            .replies
            .get(&real, 0)
            .ok()
            .is_some_and(|old| old != key)
        {
            return Ok(false);
        }
        self.forget(&key);
        let value = DirectFlowValue {
            id,
            target: real.destination,
            target_port: real.destination_port,
            timeout_ns: timeout.saturating_mul(1_000_000_000),
            last_seen_ns: monotonic_ns(),
            ..Default::default()
        };
        self.flows.insert(key, value, 0).map_err(other)?;
        if let Err(e) = self.replies.insert(real, key, 0) {
            let _ = self.flows.remove(&key);
            return Err(other(e));
        }
        if let Err(e) = self.actions.insert(
            key,
            Action {
                id,
                enabled: 1,
                pad: 0,
            },
            0,
        ) {
            let _ = self.replies.remove(&real);
            let _ = self.flows.remove(&key);
            return Err(other(e));
        }
        let _ = self.pending.remove(&key);
        self.keys.insert(key, real);
        Ok(true)
    }
    pub(super) fn samples(&self) -> Vec<DirectFlowSample> {
        self.keys
            .keys()
            .filter_map(|key| {
                self.flows
                    .get(key, LOCK_FLAG)
                    .ok()
                    .map(|v| DirectFlowSample {
                        key: *key,
                        id: v.id,
                        active: self.contains(key),
                        closed: v.flags & 16 != 0 || v.flags & 12 == 12,
                        last_seen_ns: v.last_seen_ns,
                        upload: v.upload,
                        download: v.download,
                    })
            })
            .collect()
    }
    pub(super) fn close(&mut self, key: &DirectFlowKey) {
        if let Ok(v) = self.flows.get(key, LOCK_FLAG) {
            let _ = self.actions.insert(
                *key,
                Action {
                    id: v.id,
                    enabled: 0,
                    pad: 0,
                },
                0,
            );
        }
    }
    pub(super) fn forget(&mut self, key: &DirectFlowKey) {
        self.close(key);
        let _ = self.actions.remove(key);
        if let Some(real) = self.keys.remove(key) {
            let _ = self.replies.remove(&real);
        }
        let _ = self.flows.remove(key);
    }
    pub(super) fn invalidate_udp(&mut self) {
        for key in self
            .keys
            .keys()
            .copied()
            .filter(|key| key.protocol == 17)
            .collect::<Vec<_>>()
        {
            self.close(&key);
        }
    }
    pub(super) fn status(&self) -> DirectOffloadStatus {
        let samples = self.samples();
        DirectOffloadStatus {
            enabled: true,
            running: true,
            interfaces: self.interfaces.clone(),
            program_ids: self.program_ids.clone(),
            capacity: CAPACITY,
            flows: samples.iter().filter(|s| s.active).count(),
            upload: samples.iter().map(|s| s.upload).sum(),
            download: samples.iter().map(|s| s.download).sum(),
        }
    }
}
impl Drop for DirectRuntime {
    fn drop(&mut self) {
        // Drop program links before considering shared clsact ownership.
        self.bpf.take();
        self.attachments.clear();
        for mut rule in self.rules.drain(..).rev() {
            rule[2] = "del".into();
            let _ = ip(&rule);
        }
        let _ = self.route_lock.set_len(0);
    }
}
