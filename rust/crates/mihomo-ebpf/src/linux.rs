use super::*;
use aya::{
    maps::{Array, HashMap as BpfHashMap, MapData},
    programs::{
        tc,
        tc::{NlOptions, TcAttachOptions},
        SchedClassifier, TcAttachType,
    },
    Ebpf, Pod,
};
use std::ffi::CString;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Mutex,
};

mod netlink;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Params {
    mark: u32,
    tun_index: u32,
    redir4: [u8; 4],
    redir6: [u8; 16],
    port: u16,
    pad: u16,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct FlowKey {
    source: [u8; 16],
    proxy: [u8; 16],
    source_port: u16,
    proxy_port: u16,
    family: u32,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Origin {
    address: [u8; 16],
    port: u16,
    pad: u16,
}
unsafe impl Pod for Params {}
unsafe impl Pod for FlowKey {}
unsafe impl Pod for Origin {}
unsafe impl Pod for Counters {}

#[cfg(target_endian = "little")]
static OBJECT: &[u8] =
    aya::include_bytes_aligned!(concat!(env!("CARGO_MANIFEST_DIR"), "/bpf/mihomo.bpfel.o"));
#[cfg(target_endian = "big")]
static OBJECT: &[u8] =
    aya::include_bytes_aligned!(concat!(env!("CARGO_MANIFEST_DIR"), "/bpf/mihomo.bpfeb.o"));

type Origins = BpfHashMap<MapData, FlowKey, Origin>;
struct Interface {
    name: String,
    index: u32,
    mode: &'static str,
    program_ids: Vec<u32>,
    ingress: bool,
    egress: bool,
    origins: Option<Origins>,
    stats: Array<MapData, Counters>,
    bpf: Option<Ebpf>,
    qdisc_owned: bool,
    _lock: std::fs::File,
}
impl Drop for Interface {
    fn drop(&mut self) {
        // Programs own their exact netlink links; closing them removes only those filters.
        self.bpf.take();
        if self.qdisc_owned {
            let _ = netlink::remove_empty_clsact(self.index);
        }
        // A clean exit relinquishes qdisc ownership too. If a foreign program
        // kept it alive, a later instance must treat that qdisc as shared.
        use std::io::{Seek, SeekFrom, Write};
        let _ = self._lock.set_len(0);
        let _ = self._lock.seek(SeekFrom::Start(0));
        let _ = self._lock.write_all(b"0");
    }
}

pub struct EbpfRuntime {
    interfaces: Mutex<Vec<Interface>>,
    running: AtomicBool,
}
impl std::fmt::Debug for EbpfRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EbpfRuntime")
            .field("status", &self.status())
            .finish()
    }
}
impl EbpfRuntime {
    pub fn install(document: &RuntimeConfigDocument) -> io::Result<Option<Self>> {
        if !document.ebpf.enabled() {
            return Ok(None);
        }
        document.validate().map_err(invalid)?;
        let addresses = interface_addresses()?;
        // Preflight every source and destination before loading or attaching anything.
        let tun_index = if document.ebpf.redirect_to_tun.is_empty() {
            0
        } else {
            interface_index(&document.tun.config.device)?
        };
        let mut planned = Vec::new();
        for (mode, names) in [
            ("redirect-to-tun", &document.ebpf.redirect_to_tun),
            ("auto-redir", &document.ebpf.auto_redir),
        ] {
            for name in names {
                let index = interface_index(name)?;
                let info = addresses
                    .iter()
                    .find(|entry| entry.name == *name)
                    .ok_or_else(|| {
                        invalid(format!(
                            "eBPF interface {name} has no addresses or link metadata"
                        ))
                    })?;
                if info.flags & libc::IFF_UP as u32 == 0 {
                    return Err(invalid(format!("eBPF interface {name} is down")));
                }
                if info.link_type != Some(1) {
                    return Err(invalid(format!("eBPF source {name} must be an Ethernet interface (including veth or bridge)")));
                }
                let mut params = Params {
                    mark: document.ebpf.effective_bypass_mark(),
                    tun_index,
                    port: document.redir_port.to_be(),
                    ..Default::default()
                };
                if mode == "auto-redir" {
                    if let Some(IpAddr::V4(ip)) = info.addresses.iter().find(|ip| ip.is_ipv4()) {
                        params.redir4 = ip.octets();
                    }
                    if document.ipv6
                        && (document.bind_address.is_empty()
                            || document.bind_address == "*"
                            || document.bind_address.contains(':'))
                    {
                        if let Some(IpAddr::V6(ip))=info.addresses.iter().find(|ip|matches!(ip,IpAddr::V6(ip) if !ip.is_unicast_link_local()&&!ip.is_multicast()&&!ip.is_loopback())){params.redir6=ip.octets();}
                    }
                    if params.redir4 == [0; 4] && params.redir6 == [0; 16] {
                        return Err(invalid(format!("eBPF auto-redir {name} needs an IPv4 or unicast IPv6 interface address")));
                    }
                    if document.redir_port == 0 {
                        return Err(invalid("eBPF auto-redir requires a redir-port"));
                    }
                    if !document.allow_lan {
                        return Err(invalid("eBPF auto-redir requires allow-lan: true so the redir listener can accept LAN traffic"));
                    }
                }
                planned.push((name.clone(), index, mode, params));
            }
        }
        // Older kernels charge BPF maps against RLIMIT_MEMLOCK. Failure is diagnosed
        // by the actual map/program operation so memcg-accounted kernels still work.
        let limit = libc::rlimit {
            rlim_cur: libc::RLIM_INFINITY,
            rlim_max: libc::RLIM_INFINITY,
        };
        unsafe {
            libc::setrlimit(libc::RLIMIT_MEMLOCK, &limit);
        }
        let mut interfaces = Vec::new();
        for (name, index, mode, params) in planned {
            let interface=load_interface(&name,index,mode,params,&addresses).map_err(|error|io::Error::new(error.kind(),format!("eBPF {mode} on {name}: {error}; Linux with CONFIG_BPF_SYSCALL/NET_CLS_BPF and CAP_BPF (or CAP_SYS_ADMIN) plus CAP_NET_ADMIN is required")))?;
            interfaces.push(interface);
        }
        Ok(Some(Self {
            interfaces: Mutex::new(interfaces),
            running: AtomicBool::new(true),
        }))
    }
    pub fn shutdown(&self) {
        self.running.store(false, Ordering::Release);
        self.interfaces.lock().unwrap().clear();
    }
    pub fn original_destination(
        &self,
        peer: SocketAddr,
        local: SocketAddr,
    ) -> io::Result<Option<SocketAddr>> {
        let peer = unmap(peer);
        let local = unmap(local);
        let (family, source, proxy) = match (peer.ip(), local.ip()) {
            (IpAddr::V4(a), IpAddr::V4(b)) => {
                let mut source = [0; 16];
                let mut proxy = [0; 16];
                source[..4].copy_from_slice(&a.octets());
                proxy[..4].copy_from_slice(&b.octets());
                (4, source, proxy)
            }
            (IpAddr::V6(a), IpAddr::V6(b)) => (6, a.octets(), b.octets()),
            _ => return Ok(None),
        };
        let key = FlowKey {
            source,
            proxy,
            source_port: peer.port().to_be(),
            proxy_port: local.port().to_be(),
            family,
        };
        for interface in self.interfaces.lock().unwrap().iter() {
            let Some(origins) = &interface.origins else {
                continue;
            };
            match origins.get(&key, 0) {
                Ok(origin) => {
                    let ip = if family == 4 {
                        IpAddr::V4(Ipv4Addr::new(
                            origin.address[0],
                            origin.address[1],
                            origin.address[2],
                            origin.address[3],
                        ))
                    } else {
                        IpAddr::V6(Ipv6Addr::from(origin.address))
                    };
                    return Ok(Some(SocketAddr::new(ip, u16::from_be(origin.port))));
                }
                Err(aya::maps::MapError::KeyNotFound) => {}
                Err(error) => return Err(other(error)),
            }
        }
        Ok(None)
    }
    pub fn status(&self) -> EbpfStatus {
        let interfaces = self
            .interfaces
            .lock()
            .unwrap()
            .iter()
            .map(|interface| InterfaceStatus {
                name: interface.name.clone(),
                mode: interface.mode.into(),
                ingress: interface.ingress,
                egress: interface.egress,
                program_ids: interface.program_ids.clone(),
                counters: interface.stats.get(&0, 0).unwrap_or_default(),
            })
            .collect();
        EbpfStatus {
            supported: true,
            running: self.running.load(Ordering::Acquire),
            interfaces,
        }
    }
}
impl Drop for EbpfRuntime {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn load_interface(
    name: &str,
    index: u32,
    mode: &'static str,
    params: Params,
    addresses: &[InterfaceAddress],
) -> io::Result<Interface> {
    match load_interface_with_log(
        name,
        index,
        mode,
        params,
        addresses,
        aya::VerifierLogLevel::STATS,
    ) {
        Ok(interface) => Ok(interface),
        Err(error)
            if matches!(
                error
                    .get_ref()
                    .and_then(|source| source.downcast_ref::<aya::programs::ProgramError>()),
                Some(aya::programs::ProgramError::LoadError { .. })
            ) =>
        {
            // Keep detailed verifier diagnostics on failure. Successful loads
            // need only the short stats log, avoiding a multi-MiB debug buffer.
            load_interface_with_log(
                name,
                index,
                mode,
                params,
                addresses,
                aya::VerifierLogLevel::default(),
            )
        }
        Err(error) => Err(error),
    }
}

fn load_interface_with_log(
    name: &str,
    index: u32,
    mode: &'static str,
    params: Params,
    addresses: &[InterfaceAddress],
    log: aya::VerifierLogLevel,
) -> io::Result<Interface> {
    let (interface_lock, previously_owned) = interface_lock(index)?;
    // A process killed with SIGKILL cannot run Drop on older netlink TC links.
    // The per-interface lock proves no live instance owns our reserved names.
    for (program, direction) in [
        ("mihomo_rs_tun", TcAttachType::Egress),
        ("mihomo_rs_in", TcAttachType::Ingress),
        ("mihomo_rs_out", TcAttachType::Egress),
    ] {
        match tc::qdisc_detach_program(name, direction, program) {
            Ok(()) => {}
            Err(error)
                if matches!(
                    error.raw_os_error(),
                    Some(libc::ENOENT) | Some(libc::EINVAL)
                ) || error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    let mut bpf = aya::EbpfLoader::new_without_btf()
        .btf(None)
        .verifier_log_level(log)
        .set_max_entries("origins", if mode == "auto-redir" { 65536 } else { 1 })
        .set_max_entries(
            "local4",
            addresses
                .iter()
                .flat_map(|entry| entry.addresses.iter())
                .filter(|ip| ip.is_ipv4())
                .count()
                .max(1) as u32,
        )
        .set_max_entries(
            "local6",
            addresses
                .iter()
                .flat_map(|entry| entry.addresses.iter())
                .filter(|ip| ip.is_ipv6())
                .count()
                .max(1) as u32,
        )
        .load(OBJECT)
        .map_err(other)?;
    Array::<_, Params>::try_from(
        bpf.map_mut("config")
            .ok_or_else(|| invalid("missing eBPF config map"))?,
    )
    .map_err(other)?
    .set(0, params, 0)
    .map_err(other)?;
    {
        let mut v4 =
            BpfHashMap::<_, u32, u32>::try_from(bpf.map_mut("local4").unwrap()).map_err(other)?;
        for ip in addresses
            .iter()
            .flat_map(|interface| interface.addresses.iter())
        {
            if let IpAddr::V4(ip) = ip {
                v4.insert(u32::from_ne_bytes(ip.octets()), 1, 0)
                    .map_err(other)?;
            }
        }
    }
    {
        let mut v6 = BpfHashMap::<_, Origin, u32>::try_from(bpf.map_mut("local6").unwrap())
            .map_err(other)?;
        for ip in addresses
            .iter()
            .flat_map(|interface| interface.addresses.iter())
        {
            if let IpAddr::V6(ip) = ip {
                v6.insert(
                    Origin {
                        address: ip.octets(),
                        ..Default::default()
                    },
                    1,
                    0,
                )
                .map_err(other)?;
            }
        }
    }
    let origins = if mode == "auto-redir" {
        Some(BpfHashMap::try_from(bpf.take_map("origins").unwrap()).map_err(other)?)
    } else {
        None
    };
    let stats = Array::try_from(bpf.take_map("stats").unwrap()).map_err(other)?;
    // Keep a guard before creating a qdisc, so a partial failure rolls back too.
    let mut interface = Interface {
        name: name.into(),
        index,
        mode,
        program_ids: Vec::new(),
        ingress: mode == "auto-redir",
        egress: true,
        origins,
        stats,
        bpf: Some(bpf),
        qdisc_owned: previously_owned,
        _lock: interface_lock,
    };
    match tc::qdisc_add_clsact(name) {
        Ok(()) => interface.qdisc_owned = true,
        Err(error) if error.raw_os_error() == Some(libc::EEXIST) => {}
        Err(error) => return Err(error),
    }
    use std::io::Write;
    interface._lock.set_len(0)?;
    (&interface._lock).write_all(if interface.qdisc_owned { b"1" } else { b"0" })?;
    let names = if mode == "redirect-to-tun" {
        vec![("mihomo_rs_tun", TcAttachType::Egress)]
    } else {
        vec![
            ("mihomo_rs_in", TcAttachType::Ingress),
            ("mihomo_rs_out", TcAttachType::Egress),
        ]
    };
    for (program_name, direction) in names {
        let program: &mut SchedClassifier = interface
            .bpf
            .as_mut()
            .unwrap()
            .program_mut(program_name)
            .ok_or_else(|| invalid(format!("missing {program_name}")))?
            .try_into()
            .map_err(other)?;
        program.load().map_err(io::Error::other)?;
        // Netlink attaches are supported on OpenWrt LTS kernels. The kernel allocates
        // an unused handle; CREATE|EXCL never replaces an existing filter.
        program
            .attach_with_options(
                name,
                direction,
                TcAttachOptions::Netlink(NlOptions {
                    priority: 49152,
                    handle: 0,
                }),
            )
            .map_err(other)?;
        interface
            .program_ids
            .push(program.info().map_err(other)?.id());
    }
    Ok(interface)
}

fn interface_index(name: &str) -> io::Result<u32> {
    let name = CString::new(name).map_err(invalid)?;
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if index == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(index)
    }
}
#[derive(Default)]
struct InterfaceAddress {
    name: String,
    flags: u32,
    link_type: Option<u16>,
    addresses: Vec<IpAddr>,
}
fn interface_addresses() -> io::Result<Vec<InterfaceAddress>> {
    let mut head = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return Err(io::Error::last_os_error());
    }
    struct Free(*mut libc::ifaddrs);
    impl Drop for Free {
        fn drop(&mut self) {
            unsafe { libc::freeifaddrs(self.0) }
        }
    }
    let _free = Free(head);
    let mut current = head;
    let mut result = std::collections::BTreeMap::<String, InterfaceAddress>::new();
    while !current.is_null() {
        unsafe {
            let address = &*current;
            if !address.ifa_name.is_null() {
                let name = std::ffi::CStr::from_ptr(address.ifa_name)
                    .to_string_lossy()
                    .into_owned();
                let entry = result
                    .entry(name.clone())
                    .or_insert_with(|| InterfaceAddress {
                        name,
                        flags: address.ifa_flags,
                        ..Default::default()
                    });
                if !address.ifa_addr.is_null() {
                    match (*address.ifa_addr).sa_family as i32 {
                        libc::AF_PACKET => {
                            entry.link_type =
                                Some((*(address.ifa_addr as *const libc::sockaddr_ll)).sll_hatype);
                        }
                        libc::AF_INET => {
                            let raw = &*(address.ifa_addr as *const libc::sockaddr_in);
                            entry.addresses.push(IpAddr::V4(Ipv4Addr::from(
                                raw.sin_addr.s_addr.to_ne_bytes(),
                            )));
                        }
                        libc::AF_INET6 => {
                            let raw = &*(address.ifa_addr as *const libc::sockaddr_in6);
                            entry
                                .addresses
                                .push(IpAddr::V6(Ipv6Addr::from(raw.sin6_addr.s6_addr)));
                        }
                        _ => {}
                    }
                }
            }
            current = address.ifa_next;
        }
    }
    Ok(result.into_values().collect())
}
fn unmap(address: SocketAddr) -> SocketAddr {
    match address {
        SocketAddr::V6(addr) => addr
            .ip()
            .to_ipv4_mapped()
            .map(|ip| SocketAddr::new(IpAddr::V4(ip), addr.port()))
            .unwrap_or(address),
        _ => address,
    }
}
fn invalid(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, error.to_string())
}
fn other(error: impl std::fmt::Display) -> io::Error {
    io::Error::other(error.to_string())
}

fn interface_lock(index: u32) -> io::Result<(std::fs::File, bool)> {
    use std::io::Read;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let namespace = std::fs::metadata("/proc/self/ns/net")?.ino();
    let path = format!("/tmp/mihomo-ebpf-{namespace}-{index}.lock");
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            format!("interface {index} is already owned by another running Mihomo eBPF instance"),
        ));
    }
    let mut state = String::new();
    (&mut file).take(8).read_to_string(&mut state)?;
    use std::io::{Seek, SeekFrom};
    file.seek(SeekFrom::Start(0))?;
    Ok((file, state == "1"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bpf_map_layouts_match_the_kernel_program_abi() {
        assert_eq!(std::mem::size_of::<Params>(), 32);
        assert_eq!(std::mem::size_of::<FlowKey>(), 40);
        assert_eq!(std::mem::size_of::<Origin>(), 20);
        assert_eq!(std::mem::size_of::<Counters>(), 32);
    }
}
