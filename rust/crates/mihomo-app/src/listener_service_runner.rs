use std::net::{TcpListener, UdpSocket};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use mihomo_runtime::{BootstrapState, RuntimeTunnel};
use mihomo_tun::TunRuntimeSpec;

use super::listener_service_models::ManagedQuicListenerHandler;
#[cfg(not(any(target_os = "linux", target_os = "android")))]
use super::listener_service_models::ManagedUdpListenerHandler;
#[cfg(any(target_os = "linux", target_os = "android"))]
use super::listener_service_models::ManagedUdpListenerHandler;
use super::listener_service_runtime::{accept_loop, dns_loop, dns_tcp_loop, udp_loop};
use super::listener_udp_dispatch::{spawn_udp_workers, UdpDispatchQueue};
use super::{
    hy2_inbound, listener_service_builders, tuic_inbound, BoundTcpListener, ListenerServiceError,
    LISTENER_POLL_TIMEOUT,
};
use crate::startup_trace;

pub struct RunningListenerService {
    bound_listeners: Vec<BoundTcpListener>,
    shutdown: Arc<AtomicBool>,
    udp_queue: Arc<UdpDispatchQueue>,
    join_handles: Vec<JoinHandle<()>>,
    background_shutdown: Arc<AtomicBool>,
    background_handles: Vec<JoinHandle<()>>,
    route_sources_hash: Option<[u8; 32]>,
    detected_default_interface: Option<String>,
    tun_auto_redirect: Option<crate::tun_auto_redirect::TunAutoRedirectGuard>,
    ebpf: Option<Arc<mihomo_ebpf::EbpfRuntime>>,
    ebpf_mark: bool,
    smart_tunnel: Arc<RuntimeTunnel>,
}

impl std::fmt::Debug for RunningListenerService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RunningListenerService")
            .field("bound_listeners", &self.bound_listeners)
            .field("shutdown", &self.shutdown.load(Ordering::Relaxed))
            .field("join_handle_count", &self.join_handles.len())
            .finish()
    }
}

impl RunningListenerService {
    pub fn start(state: &BootstrapState) -> Result<Self, ListenerServiceError> {
        let tunnel = Arc::new(
            state
                .build_runtime_tunnel()
                .map_err(|err| ListenerServiceError::Rule(err.to_string()))?,
        );
        Self::start_with_tunnel(state, tunnel)
    }

    pub fn start_with_tunnel(
        state: &BootstrapState,
        tunnel: Arc<RuntimeTunnel>,
    ) -> Result<Self, ListenerServiceError> {
        startup_trace::mark("listener-service:start");
        let ebpf_mark = if state.document.ebpf.enabled() {
            state.document.ebpf.effective_bypass_mark()
        } else {
            0
        };
        let shutdown = Arc::new(AtomicBool::new(false));
        let udp_queue = Arc::new(UdpDispatchQueue::new());
        // Own every worker immediately so a later bind failure releases it.
        let mut service = Self {
            bound_listeners: Vec::new(),
            shutdown: Arc::clone(&shutdown),
            udp_queue: Arc::clone(&udp_queue),
            join_handles: Vec::new(),
            background_shutdown: Arc::new(AtomicBool::new(false)),
            background_handles: Vec::new(),
            route_sources_hash: None,
            detected_default_interface: None,
            tun_auto_redirect: None,
            ebpf: None,
            ebpf_mark: false,
            smart_tunnel: tunnel.clone(),
        };
        let bound_listeners = &mut service.bound_listeners;
        let join_handles = &mut service.join_handles;
        let dns_runtime = state
            .build_dns_runtime()
            .ok()
            .map(|runtime| runtime.without_fake_ip_persistence());
        let tun_rule_provider_sources = state.provider_sources_for_snapshot().ok();
        startup_trace::mark("listener-service:dns-runtime-ready");
        let mut udp_workers = spawn_udp_workers(Arc::clone(&udp_queue));
        join_handles.append(&mut udp_workers);
        startup_trace::mark("listener-service:udp-workers-ready");
        let tun_specs = mihomo_runtime::build_tun_runtime_specs(&state.document);
        service.route_sources_hash = route_sources_hash(&tun_specs, tun_rule_provider_sources.as_ref());
        let detected_default_interface = configure_tun_default_interface(&tun_specs);
        let mut tun_workers = crate::tun_worker::spawn_tun_workers(
            &tun_specs,
            tunnel.clone(),
            dns_runtime.clone(),
            shutdown.clone(),
        )
        .map_err(|err| {
            if tun_specs.is_empty() {
                ListenerServiceError::Io(err)
            } else {
                ListenerServiceError::Rule(format!("failed to start tun workers: {err}"))
            }
        })?;
        join_handles.append(&mut tun_workers);
        startup_trace::mark("listener-service:tun-workers-ready");

        if let Some(runtime) = dns_runtime
            .clone()
            .filter(|runtime| runtime.config.enabled && !runtime.config.listen.trim().is_empty())
        {
            let dns_socket = UdpSocket::bind(&runtime.config.listen)?;
            mihomo_core::mark_udp_socket(&dns_socket, ebpf_mark)?;
            let local_addr = dns_socket.local_addr()?;
            dns_socket.set_read_timeout(Some(LISTENER_POLL_TIMEOUT))?;
            bound_listeners.push(BoundTcpListener {
                name: "__dns__".into(),
                kind: "dns".into(),
                configured_addr: runtime.config.listen.clone(),
                local_addr,
            });
            let tcp_listener = TcpListener::bind(local_addr)?;
            mihomo_core::mark_tcp_listener(&tcp_listener, ebpf_mark)?;
            tcp_listener.set_nonblocking(true)?;
            let tcp_shutdown = shutdown.clone();
            let tcp_tunnel = tunnel.clone();
            join_handles.push(thread::spawn(move || {
                dns_tcp_loop(tcp_listener, tcp_shutdown, tcp_tunnel)
            }));
            let shutdown_flag = shutdown.clone();
            let tunnel = tunnel.clone();
            let join_handle = thread::spawn(move || dns_loop(dns_socket, shutdown_flag, tunnel));
            join_handles.push(join_handle);
        }
        startup_trace::mark("listener-service:dns-listener-ready");

        for listener in listener_service_builders::build_tcp_listener_configs(&state.document)? {
            let tcp_listener = TcpListener::bind(&listener.address)?;
            mihomo_core::mark_tcp_listener(&tcp_listener, ebpf_mark)?;
            #[cfg(any(target_os = "linux", target_os = "android"))]
            if matches!(
                listener.handler,
                super::listener_service_models::ManagedTcpListenerHandler::TProxy(_)
            ) {
                crate::listener_service::transparent::configure_tproxy_tcp_listener_socket(
                    &tcp_listener,
                )?;
            }
            let local_addr = tcp_listener.local_addr()?;
            tcp_listener.set_nonblocking(false)?;

            bound_listeners.push(BoundTcpListener {
                name: listener.name.clone(),
                kind: listener.handler.kind_name().to_owned(),
                configured_addr: listener.address.clone(),
                local_addr,
            });

            let shutdown_flag = shutdown.clone();
            let tunnel = tunnel.clone();
            let handler = listener.handler.clone();
            let dns_runtime = dns_runtime.clone();
            let udp_queue = Arc::clone(&udp_queue);
            let join_handle = thread::spawn(move || {
                accept_loop(
                    tcp_listener,
                    shutdown_flag,
                    tunnel,
                    handler,
                    dns_runtime,
                    udp_queue,
                );
            });
            join_handles.push(join_handle);
        }
        startup_trace::mark("listener-service:tcp-listeners-ready");

        for listener in listener_service_builders::build_udp_listener_configs(&state.document)? {
            #[cfg(not(any(target_os = "linux", target_os = "android")))]
            if matches!(
                listener.handler,
                ManagedUdpListenerHandler::TProxy(_) | ManagedUdpListenerHandler::Redir(_)
            ) {
                return Err(ListenerServiceError::Rule(
                    "tproxy udp listener is only implemented on Linux/Android".to_owned(),
                ));
            }
            let udp_socket = UdpSocket::bind(&listener.address)?;
            mihomo_core::mark_udp_socket(&udp_socket, ebpf_mark)?;
            let local_addr = udp_socket.local_addr()?;
            udp_socket.set_read_timeout(Some(LISTENER_POLL_TIMEOUT))?;
            #[cfg(any(target_os = "linux", target_os = "android"))]
            if matches!(
                listener.handler,
                ManagedUdpListenerHandler::TProxy(_) | ManagedUdpListenerHandler::Redir(_)
            ) {
                crate::listener_service::configure_tproxy_udp_listener_socket(&udp_socket)?;
            }

            bound_listeners.push(BoundTcpListener {
                name: listener.name.clone(),
                kind: listener.kind_name().to_owned(),
                configured_addr: listener.address.clone(),
                local_addr,
            });

            let shutdown_flag = shutdown.clone();
            let tunnel = tunnel.clone();
            let dns_runtime = dns_runtime.clone();
            let udp_queue = Arc::clone(&udp_queue);
            let join_handle = thread::spawn(move || {
                udp_loop(
                    udp_socket,
                    shutdown_flag,
                    tunnel,
                    listener,
                    dns_runtime,
                    udp_queue,
                );
            });
            join_handles.push(join_handle);
        }
        startup_trace::mark("listener-service:udp-listeners-ready");

        let tun_auto_redirect = crate::tun_auto_redirect::TunAutoRedirectGuard::install(
            &state.document,
            tun_rule_provider_sources.as_ref(),
        )
        .map_err(ListenerServiceError::Io)?;
        startup_trace::mark("listener-service:auto-redirect-ready");

        for listener in listener_service_builders::build_quic_listener_configs(&state.document)? {
            match listener.handler.clone() {
                ManagedQuicListenerHandler::Tuic(config) => {
                    let (local_addr, join_handle) = tuic_inbound::spawn_tuic_listener(
                        listener.address.clone(),
                        config,
                        tunnel.clone(),
                        shutdown.clone(),
                    )?;
                    bound_listeners.push(BoundTcpListener {
                        name: listener.name.clone(),
                        kind: listener.kind_name().to_owned(),
                        configured_addr: listener.address.clone(),
                        local_addr,
                    });
                    join_handles.push(join_handle);
                }
                ManagedQuicListenerHandler::Hy2(config) => {
                    let (local_addr, join_handle) = hy2_inbound::spawn_hy2_listener(
                        listener.address.clone(),
                        config,
                        tunnel.clone(),
                        shutdown.clone(),
                    )?;
                    bound_listeners.push(BoundTcpListener {
                        name: listener.name.clone(),
                        kind: listener.kind_name().to_owned(),
                        configured_addr: listener.address.clone(),
                        local_addr,
                    });
                    join_handles.push(join_handle);
                }
            }
        }
        startup_trace::mark("listener-service:quic-listeners-ready");
        if state.document.ebpf.enabled() {
            mihomo_transport::set_default_routing_mark(
                state.document.ebpf.effective_bypass_mark() as i32
            );
            service.ebpf_mark = true;
            if let Some(runtime) = mihomo_ebpf::EbpfRuntime::install(&state.document)
                .map_err(ListenerServiceError::Io)?
            {
                let runtime = Arc::new(runtime);
                tunnel.set_ebpf_runtime(Some(Arc::clone(&runtime)));
                service.ebpf = Some(runtime);
                if !state.document.ebpf.direct_offload.is_empty() {
                    let weak=Arc::downgrade(&tunnel);let stop=shutdown.clone();
                    join_handles.push(thread::spawn(move||{
                        while !stop.load(Ordering::Relaxed) {
                            if let Some(tunnel)=weak.upgrade(){tunnel.sync_kernel_direct();}else{break;}
                            thread::sleep(Duration::from_millis(100));
                        }
                    }));
                }
            }
        }

        let mut healthcheck_workers =
            spawn_provider_healthcheck_workers(state, Arc::clone(&tunnel), Arc::clone(&service.background_shutdown));
        startup_trace::mark("listener-service:healthcheck-workers-ready");

        service.background_handles.append(&mut healthcheck_workers);
        service.background_handles.extend(spawn_smart_workers(
            state,
            Arc::clone(&tunnel),
            Arc::clone(&service.background_shutdown),
        ));
        startup_trace::mark("listener-service:done");

        service.detected_default_interface = detected_default_interface;
        service.tun_auto_redirect = tun_auto_redirect;
        Ok(service)
    }

    pub fn bound_listeners(&self) -> &[BoundTcpListener] {
        &self.bound_listeners
    }

    pub fn has_background_tasks(&self) -> bool {
        !self.join_handles.is_empty() || !self.background_handles.is_empty()
    }

    pub(crate) fn stop_background_workers(&mut self) {
        self.background_shutdown.store(true, Ordering::Release);
        self.smart_tunnel.stop_smart_probes();
        for handle in self.background_handles.drain(..) { let _ = handle.join(); }
    }

    pub(crate) fn can_reload_policy(&self, state: &BootstrapState) -> bool {
        if self.shutdown.load(Ordering::Acquire) { return false; }
        let specs = mihomo_runtime::build_tun_runtime_specs(&state.document);
        let sources = if specs.iter().any(|spec| !spec.config.route_address_set.is_empty()
            || !spec.config.route_exclude_address_set.is_empty()) {
            state.provider_sources_for_snapshot().ok()
        } else { None };
        self.route_sources_hash.is_some() && self.route_sources_hash == route_sources_hash(&specs, sources.as_ref())
    }

    pub(crate) fn start_background_workers(&mut self, state: &BootstrapState) {
        self.background_shutdown = Arc::new(AtomicBool::new(false));
        self.background_handles = spawn_provider_healthcheck_workers(
            state, self.smart_tunnel.clone(), self.background_shutdown.clone());
        self.background_handles.extend(spawn_smart_workers(
            state, self.smart_tunnel.clone(), self.background_shutdown.clone()));
    }

    pub fn shutdown(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        self.stop_background_workers();
        if let Some(ebpf) = self.ebpf.take() {
            ebpf.shutdown();
        }
        if std::mem::take(&mut self.ebpf_mark) {
            mihomo_transport::clear_default_routing_mark();
        }
        self.shutdown.store(true, Ordering::Relaxed);
        self.smart_tunnel.stop_smart_probes();
        self.udp_queue.close();
        for handle in self.join_handles.drain(..) {
            let _ = handle.join();
        }
        self.smart_tunnel.clear_sniffer_state();
        self.tun_auto_redirect.take();
        if self.detected_default_interface.take().is_some() {
            mihomo_transport::clear_default_interface_name();
        }
    }
}

fn route_sources_hash(
    specs: &[TunRuntimeSpec], sources: Option<&mihomo_runtime::ProviderContentSources>,
) -> Option<[u8; 32]> {
    if !specs.iter().any(|spec| !spec.config.route_address_set.is_empty()
        || !spec.config.route_exclude_address_set.is_empty()) {
        return Some([0; 32]);
    }
    let sources = sources?;
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    for (kind, entries) in [(b'f', &sources.file_contents), (b'h', &sources.http_contents)] {
        hash.update([kind]);
        for (key, value) in entries {
            hash.update((key.len() as u64).to_le_bytes());
            hash.update(key.as_bytes());
            hash.update((value.len() as u64).to_le_bytes());
            hash.update(value.as_bytes());
        }
    }
    for (kind, entries) in [(b'F', &sources.file_blobs), (b'H', &sources.http_blobs)] {
        hash.update([kind]);
        for (key, value) in entries {
            hash.update((key.len() as u64).to_le_bytes());
            hash.update(key.as_bytes());
            hash.update((value.len() as u64).to_le_bytes());
            hash.update(value);
        }
    }
    Some(hash.finalize().into())
}

impl Drop for RunningListenerService {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn spawn_provider_healthcheck_workers(
    state: &BootstrapState,
    tunnel: Arc<RuntimeTunnel>,
    shutdown: Arc<AtomicBool>,
) -> Vec<JoinHandle<()>> {
    state
        .registry
        .providers
        .values()
        .filter(|provider| provider.health_check.enabled)
        .filter(|provider| !provider.health_check.url.trim().is_empty())
        .filter(|provider| !provider.members.is_empty())
        .map(|provider| {
            let proxy_names = provider
                .members
                .iter()
                .map(|member| member.name.clone())
                .collect::<Vec<_>>();
            let url = provider.health_check.url.clone();
            let expected_status = provider.health_check.expected_status.clone();
            let interval = provider.health_check.interval_secs.max(1) as u64;
            let timeout_ms = provider.health_check.timeout_ms.max(1) as u64;
            let tunnel = Arc::clone(&tunnel);
            let shutdown = Arc::clone(&shutdown);
            thread::spawn(move || {
                run_provider_healthcheck_once(
                    &proxy_names,
                    &url,
                    &expected_status,
                    timeout_ms,
                    &tunnel,
                );
                while !shutdown.load(Ordering::Relaxed) {
                    thread::sleep(Duration::from_secs(interval));
                    if shutdown.load(Ordering::Relaxed) {
                        break;
                    }
                    run_provider_healthcheck_once(
                        &proxy_names,
                        &url,
                        &expected_status,
                        timeout_ms,
                        &tunnel,
                    );
                }
            })
        })
        .collect()
}

#[cfg(not(target_os = "linux"))]
fn configure_tun_default_interface(_specs: &[TunRuntimeSpec]) -> Option<String> {
    None
}

#[cfg(target_os = "linux")]
fn configure_tun_default_interface(specs: &[TunRuntimeSpec]) -> Option<String> {
    if !specs.iter().any(|spec| spec.config.auto_detect_interface) {
        return None;
    }

    let excluded = specs.iter().filter_map(|spec| {
        mihomo_tun::requested_linux_tun_name(spec).ok()
    }).collect::<Vec<_>>();
    let interface = detect_linux_default_interface_name_for_family("", &excluded)
        .or_else(|| detect_linux_default_interface_name_for_family("-6", &excluded))
        .unwrap_or_default();
    if interface.trim().is_empty() {
        return None;
    }
    mihomo_transport::set_default_interface_name(interface.clone());
    Some(interface)
}

fn detect_linux_default_interface_name_for_family(family_flag: &str, excluded: &[String]) -> Option<String> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (family_flag, excluded);
        None
    }
    #[cfg(target_os = "linux")]
    {
        // Android commonly keeps the usable default route in a netd table,
        // and its ip binary lives outside the usual OpenWrt paths.
        for all_tables in [false, true] {
        for candidate in ["/system/bin/ip", "/sbin/ip", "/usr/sbin/ip", "ip"] {
            let mut command = std::process::Command::new(candidate);
            if !family_flag.is_empty() {
                command.arg(family_flag);
            }
            command.args(["route", "show"]);
            if all_tables { command.args(["table", "all"]); }
            let Ok(output) = command.output() else { continue; };
            if !output.status.success() {
                continue;
            }
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let tokens = line.split_whitespace().collect::<Vec<_>>();
                for pair in tokens.windows(2) {
                    if pair[0] == "dev" && !pair[1].trim().is_empty()
                        && pair[1] != "lo" && !excluded.iter().any(|name| name == pair[1]) {
                        return Some(pair[1].trim().to_owned());
                    }
                }
            }
        }
        }
        None
    }
}

fn run_provider_healthcheck_once(
    proxy_names: &[String],
    url: &str,
    expected_status: &str,
    timeout_ms: u64,
    tunnel: &Arc<RuntimeTunnel>,
) {
    mihomo_runtime::run_provider_healthcheck_with_timeout(
        Arc::clone(tunnel),
        proxy_names,
        url,
        expected_status,
        Some(timeout_ms),
    );
}

#[cfg(test)]
mod tests {
    use super::RunningListenerService;
    use std::fs;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    #[test]
    fn listener_service_runs_provider_healthcheck_on_start() {
        let temp = unique_temp_dir("mihomo-app-provider-healthcheck");
        fs::create_dir_all(&temp).unwrap();
        fs::write(
            temp.join("provider.yaml"),
            "proxies:\n  - name: provider-a\n    type: direct\n",
        )
        .unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut buf = [0_u8; 1024];
            loop {
                let read = stream.read(&mut buf).unwrap();
                assert!(read > 0);
                request.extend_from_slice(&buf[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let request = String::from_utf8(request).unwrap();
            assert!(request.starts_with("GET /delay HTTP/1.1\r\n"), "{request}");
            stream
                .write_all(
                    b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .unwrap();
        });

        let (document, provider_sources, registry) = mihomo_runtime::bootstrap_from_yaml(
            &format!(
                r#"
proxy-providers:
  provider1:
    type: file
    path: provider.yaml
    health-check:
      enable: true
      url: http://127.0.0.1:{port}/delay
      interval: 1
proxy-groups:
  - name: selector
    type: select
    use: [provider1]
"#,
                port = addr.port(),
            ),
            &temp,
        )
        .unwrap();
        let state = mihomo_runtime::BootstrapState {
            resolved_boot: mihomo_config::BootOptions {
                home_dir: Some(temp.to_string_lossy().into_owned()),
                ..mihomo_config::BootOptions::default()
            }
            .resolve(&temp, &mihomo_config::BootEnvironment::default()),
            document,
            provider_sources,
            registry,
        };
        let tunnel = Arc::new(state.build_runtime_tunnel().unwrap());
        let mut service =
            RunningListenerService::start_with_tunnel(&state, Arc::clone(&tunnel)).unwrap();

        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        while std::time::Instant::now() < deadline {
            if let Some(snapshot) = tunnel.proxy_health_snapshot("provider-a") {
                assert!(snapshot.alive);
                assert!(!snapshot.history.is_empty());
                service.shutdown();
                worker.join().unwrap();
                let _ = fs::remove_dir_all(temp);
                return;
            }
            thread::sleep(Duration::from_millis(50));
        }

        service.shutdown();
        worker.join().unwrap();
        panic!("provider health-check state was not populated");
    }

    #[test]
    fn listener_service_background_healthcheck_updates_original_runtime_tunnel() {
        let temp = unique_temp_dir("mihomo-app-provider-healthcheck-original");
        fs::create_dir_all(&temp).unwrap();
        fs::write(
            temp.join("provider.yaml"),
            "proxies:\n  - name: provider-a\n    type: direct\n  - name: provider-b\n    type: direct\n",
        )
        .unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = Vec::new();
                let mut buf = [0_u8; 1024];
                loop {
                    let read = stream.read(&mut buf).unwrap();
                    assert!(read > 0);
                    request.extend_from_slice(&buf[..read]);
                    if request.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                let request = String::from_utf8(request).unwrap();
                assert!(request.starts_with("GET /delay HTTP/1.1\r\n"), "{request}");
                stream
                    .write_all(
                        b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .unwrap();
            }
        });

        let (document, provider_sources, registry) = mihomo_runtime::bootstrap_from_yaml(
            &format!(
                r#"
proxy-providers:
  provider1:
    type: file
    path: provider.yaml
    health-check:
      enable: true
      url: http://127.0.0.1:{port}/delay
      interval: 1
proxy-groups:
  - name: selector
    type: select
    use: [provider1]
"#,
                port = addr.port(),
            ),
            &temp,
        )
        .unwrap();
        let state = mihomo_runtime::BootstrapState {
            resolved_boot: mihomo_config::BootOptions {
                home_dir: Some(temp.to_string_lossy().into_owned()),
                ..mihomo_config::BootOptions::default()
            }
            .resolve(&temp, &mihomo_config::BootEnvironment::default()),
            document,
            provider_sources,
            registry,
        };
        let tunnel = Arc::new(state.build_runtime_tunnel().unwrap());
        let mut service =
            RunningListenerService::start_with_tunnel(&state, Arc::clone(&tunnel)).unwrap();

        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        while std::time::Instant::now() < deadline {
            let a_ready = tunnel
                .proxy_health_snapshot("provider-a")
                .is_some_and(|snapshot| snapshot.alive && !snapshot.history.is_empty());
            let b_ready = tunnel
                .proxy_health_snapshot("provider-b")
                .is_some_and(|snapshot| snapshot.alive && !snapshot.history.is_empty());
            if a_ready && b_ready {
                service.shutdown();
                worker.join().unwrap();
                let _ = fs::remove_dir_all(temp);
                return;
            }
            thread::sleep(Duration::from_millis(50));
        }

        service.shutdown();
        worker.join().unwrap();
        panic!("background provider health-check did not update original runtime tunnel");
    }

    fn unique_temp_dir(prefix: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{nanos}"))
    }
}

fn spawn_smart_workers(
    state: &BootstrapState,
    tunnel: Arc<RuntimeTunnel>,
    shutdown: Arc<AtomicBool>,
) -> Vec<JoinHandle<()>> {
    if !state
        .registry
        .groups
        .values()
        .any(|view| view.runtime.smart.is_some())
    {
        return vec![];
    }
    let groups = state
        .document
        .proxy_groups
        .iter()
        .filter(|definition| definition.group_type == "smart")
        .filter_map(|definition| {
            let view = state.registry.groups.get(&definition.name)?;
            Some((
                definition.name.clone(),
                view.candidate_names.clone(),
                view.runtime.test_url.clone(),
                view.runtime.expected_status.clone(),
                if definition.interval > 0 {
                    definition.interval as u64
                } else {
                    300
                },
                if definition.timeout > 0 {
                    definition.timeout as u64
                } else {
                    5000
                },
                definition.lazy,
            ))
        })
        .collect::<Vec<_>>();
    let update = state
        .document
        .extra
        .get("lgbm-auto-update")
        .and_then(serde_yaml::Value::as_bool)
        .unwrap_or(false);
    let hours = state
        .document
        .extra
        .get("lgbm-update-interval")
        .and_then(serde_yaml::Value::as_u64)
        .unwrap_or(72)
        .max(1);
    let url = state
        .document
        .extra
        .get("lgbm-url")
        .and_then(serde_yaml::Value::as_str)
        .unwrap_or(mihomo_runtime::smart::DEFAULT_MODEL_URL)
        .to_owned();
    let mut workers=Vec::new();
    tunnel.start_smart_probes();
    for _ in 0..2 {
        let tunnel=tunnel.clone();let shutdown=shutdown.clone();
        workers.push(thread::spawn(move||tunnel.run_smart_probe_worker(&shutdown)));
    }
    workers.push(thread::spawn(move || {
        if !tunnel.smart_model_loaded()
            && tunnel.smart_model_required()
            && !shutdown.load(Ordering::Relaxed)
        {
            if let Err(error) = tunnel.update_smart_model(&url) {
                mihomo_core::push_log(
                    mihomo_core::LogLevel::Warn,
                    format!(
                        "[Smart] model download failed, adaptive scoring remains active: {error}"
                    ),
                );
            }
        }
        let mut checks = std::collections::BTreeMap::<String, u64>::new();
        let started = std::time::Instant::now();
        let mut last_save = 0;
        let mut last_model = 0;
        while !shutdown.load(Ordering::Relaxed) {
            let elapsed = started.elapsed().as_secs();
            for (name, nodes, url, expected, interval, timeout, lazy) in &groups {
                if shutdown.load(Ordering::Relaxed) {
                    break;
                }
                let due = checks
                    .get(name)
                    .is_none_or(|previous| elapsed.saturating_sub(*previous) >= *interval);
                let used = tunnel.smart_group_last_used(name) > 0;
                if due && (!*lazy || used) {
                    for node in nodes {
                        if shutdown.load(Ordering::Relaxed) {
                            break;
                        }
                        let _ = mihomo_runtime::run_proxy_health_check_with_timeout(
                            tunnel.as_ref(),
                            node,
                            url,
                            expected,
                            Some(*timeout),
                        );
                    }
                    checks.insert(name.clone(), elapsed);
                }
            }
            if elapsed.saturating_sub(last_save) >= 30 {
                let _ = tunnel.persist_smart_state();
                last_save = elapsed;
            }
            if update && elapsed.saturating_sub(last_model) >= hours.saturating_mul(3600) {
                let _ = tunnel.update_smart_model(&url);
                last_model = elapsed;
            }
            for _ in 0..10 {
                if shutdown.load(Ordering::Relaxed) {
                    break;
                }
                thread::sleep(Duration::from_millis(100));
            }
        }
    }));
    workers
}
