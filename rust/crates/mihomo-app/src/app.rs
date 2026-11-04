use std::net::SocketAddr;
use std::path::Path;
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;

use mihomo_api::{ApiControlCommand, ApiController, ControllerError, RunningApiController};
use mihomo_config::{BootEnvironment, BootOptions};
use mihomo_outbound::OutboundDefinition;
use mihomo_runtime::{bootstrap_from_boot_options, BootstrapError, BootstrapState, RuntimeTunnel};

use crate::{
    restore_selected_proxy_mapping, startup_trace, BoundTcpListener, ListenerServiceError,
    RunningListenerService,
};

#[derive(Debug)]
pub enum AppStartError {
    Bootstrap(BootstrapError),
    Controller(ControllerError),
    ListenerService(ListenerServiceError),
}

impl std::fmt::Display for AppStartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bootstrap(err) => write!(f, "{err}"),
            Self::Controller(err) => write!(f, "{err}"),
            Self::ListenerService(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for AppStartError {}

impl From<BootstrapError> for AppStartError {
    fn from(value: BootstrapError) -> Self {
        Self::Bootstrap(value)
    }
}

impl From<ControllerError> for AppStartError {
    fn from(value: ControllerError) -> Self {
        Self::Controller(value)
    }
}

impl From<ListenerServiceError> for AppStartError {
    fn from(value: ListenerServiceError) -> Self {
        Self::ListenerService(value)
    }
}

#[derive(Debug)]
pub struct RunningApp {
    pub state: BootstrapState,
    pub controllers: Vec<RunningApiController>,
    pub listener_service: Option<RunningListenerService>,
    pub runtime_tunnel: Arc<RuntimeTunnel>,
    control_rx: mpsc::Receiver<ApiControlCommand>,
    shared_bootstrap_state: Arc<Mutex<BootstrapState>>,
    stopped: bool,
    summary: String,
}

impl RunningApp {
    pub fn start(
        options: &BootOptions,
        cwd: &Path,
        environment: &BootEnvironment,
    ) -> Result<Self, AppStartError> {
        startup_trace::mark("app:start");
        let mut state = bootstrap_from_boot_options(options, cwd, environment)?;
        startup_trace::mark("app:start:bootstrapped");
        restore_selected_proxy_mapping(&mut state);
        startup_trace::mark("app:start:selected-restored");
        Self::from_state(options, state)
    }

    pub fn from_state(options: &BootOptions, state: BootstrapState) -> Result<Self, AppStartError> {
        startup_trace::mark("app:from_state:enter");
        mihomo_core::set_log_level(&state.document.log_level);
        let plan = mihomo_runtime::build_runtime_plan(options);
        let listeners = mihomo_runtime::build_effective_listeners(&state.document);
        startup_trace::mark("app:from_state:listeners-built");
        prewarm_cold_outbounds(&state)
            .map_err(|err| ListenerServiceError::Rule(err.to_string()))?;
        startup_trace::mark("app:from_state:prewarm-finished");
        let runtime_tunnel = Arc::new(
            state
                .build_runtime_tunnel()
                .map_err(|err| ListenerServiceError::Rule(err.to_string()))?,
        );
        startup_trace::mark("app:from_state:runtime-tunnel-built");
        let (control_tx, control_rx) = mpsc::channel();
        let mut controllers = Vec::new();
        let shared_bootstrap_state = Arc::new(Mutex::new(state.clone()));
        if !state.document.external_controller.is_empty()
            || !state.document.external_controller_tls.is_empty()
            || !state.document.external_controller_unix.is_empty()
        {
            let controller = ApiController::from_running_state(Arc::clone(&shared_bootstrap_state),Arc::clone(&runtime_tunnel))
                .map_err(ControllerError::from)?
                .with_control_tx(control_tx.clone())
                .with_dns_exchange({
                    let tunnel = Arc::clone(&runtime_tunnel);
                    move |packet| {
                        crate::dns_transport::relay_shared_query_packet(Arc::clone(&tunnel), packet)
                    }
                });
            if !state.document.external_controller.is_empty() {
                controllers.push(controller.serve_configured_http()?);
            }
            if !state.document.external_controller_tls.is_empty() {
                controllers.push(controller.serve_configured_tls()?);
            }
            #[cfg(unix)]
            if !state.document.external_controller_unix.is_empty() {
                controllers.push(controller.serve_configured_unix()?);
            }
        }
        startup_trace::mark("app:from_state:controllers-ready");
        let listener_service =
            RunningListenerService::start_with_tunnel(&state, Arc::clone(&runtime_tunnel))?;
        startup_trace::mark("app:from_state:listener-service-ready");
        let controller_suffix = if controllers.is_empty() {
            String::new()
        } else {
            format!(
                " controllers={}",
                controllers
                    .iter()
                    .map(|running| running.local_addr().to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            )
        };
        let listener_suffix = if listener_service.bound_listeners().is_empty() {
            String::new()
        } else {
            format!(
                " bound_listeners={}",
                listener_service.bound_listeners().len()
            )
        };
        let summary = format!(
            "{} config_source={} listeners={} proxies={} groups={} providers={}{}{}",
            plan.render_human_summary(),
            state.resolved_boot.config_source.kind(),
            listeners.len(),
            state.registry.proxies.len(),
            state.registry.groups.len(),
            state.registry.providers.len(),
            controller_suffix,
            listener_suffix
        );

        Ok(Self {
            state,
            controllers,
            listener_service: Some(listener_service),
            runtime_tunnel,
            control_rx,
            shared_bootstrap_state,
            stopped: false,
            summary,
        })
    }

    pub fn summary(&self) -> &str {
        &self.summary
    }

    pub fn has_background_services(&self) -> bool {
        !self.controllers.is_empty()
            || self
                .listener_service
                .as_ref()
                .is_some_and(RunningListenerService::has_background_tasks)
    }

    pub fn controller_addr(&self) -> Option<SocketAddr> {
        self.controllers
            .first()
            .map(RunningApiController::local_addr)
    }

    pub fn controller_addrs(&self) -> Vec<SocketAddr> {
        self.controllers
            .iter()
            .map(RunningApiController::local_addr)
            .collect()
    }

    pub fn listener_addrs(&self) -> &[BoundTcpListener] {
        self.listener_service
            .as_ref()
            .map(RunningListenerService::bound_listeners)
            .unwrap_or(&[])
    }

    pub fn poll_control_command(&self) -> Option<ApiControlCommand> {
        self.control_rx.try_recv().ok()
    }

    pub fn shutdown(&mut self) {
        if self.stopped {
            return;
        }
        self.stopped = true;
        let _ = self.runtime_tunnel.close_all_connections();
        if let Some(listener_service) = &mut self.listener_service {
            listener_service.shutdown();
        }
        for controller in &mut self.controllers {
            controller.shutdown();
        }
        if let Err(error) = self.runtime_tunnel.persist_smart_state() {
            mihomo_core::push_log(
                mihomo_core::LogLevel::Warn,
                format!("[Smart] persist statistics: {error}"),
            );
        }
    }

    pub fn reload(
        &mut self,
        options: &BootOptions,
        cwd: &Path,
        environment: &BootEnvironment,
    ) -> Result<(), AppStartError> {
        let mut state = bootstrap_from_boot_options(options, cwd, environment)?;
        restore_selected_proxy_mapping(&mut state);
        self.apply_config(options, state)
    }

    pub fn apply_config(
        &mut self,
        options: &BootOptions,
        mut state: BootstrapState,
    ) -> Result<(), AppStartError> {
        let selected = self
            .state
            .document
            .proxy_groups
            .iter()
            .filter_map(|group| {
                self.runtime_tunnel
                    .group_selected(&group.name)
                    .map(|name| (group.name.clone(), name))
            })
            .collect();
        state.apply_selected_proxy_mapping(&selected);
        // Validate before releasing listeners; rebind only after they close.
        let prepared = state
            .build_runtime_tunnel()
            .map_err(|err| ListenerServiceError::Rule(err.to_string()))?;
        state
            .build_dns_runtime()
            .map_err(|err| ListenerServiceError::Rule(err.to_string()))?;
        prewarm_cold_outbounds(&state)
            .map_err(|error| ListenerServiceError::Rule(error.to_string()))?;
        if !self.stopped && self.state.resolved_boot.home_dir == state.resolved_boot.home_dir
            && supports_policy_reload(&self.state.document, &state.document)
            && self.listener_service.as_ref().is_some_and(|service| service.can_reload_policy(&state))
            && self.runtime_tunnel.dns_runtime().zip(prepared.dns_runtime())
                .is_some_and(|(current, next)| current.lock().unwrap().has_same_policy(&next.lock().unwrap()))
        {
            if let Some(service) = &mut self.listener_service { service.stop_background_workers(); }
            self.runtime_tunnel.apply_prepared_policy(&prepared);
            mihomo_core::set_log_level(&state.document.log_level);
            *self.shared_bootstrap_state.lock().unwrap() = state.clone();
            if let Some(service) = &mut self.listener_service { service.start_background_workers(&state); }
            self.state = state;
            mihomo_core::push_log(mihomo_core::LogLevel::Info,
                "[Config] policy reloaded with existing listeners and TCP connections");
            return Ok(());
        }
        let mut previous = self.shared_bootstrap_state.lock().unwrap().clone();
        previous.document.mode = self.runtime_tunnel.current_mode();
        let previous_dns = self
            .runtime_tunnel
            .dns_runtime()
            .map(|shared| shared.lock().unwrap().clone());
        self.shutdown();
        match Self::from_state(options, state) {
            Ok(new_app) => {
                if let Some(dns) = &previous_dns {
                    new_app.runtime_tunnel.capture_dns_fake_ip_state(dns);
                }
                *self = new_app;
                Ok(())
            }
            Err(error) => {
                match Self::from_state(options, previous) {
                    Ok(restored) => {
                        if let Some(dns) = &previous_dns {
                            restored.runtime_tunnel.capture_dns_fake_ip_state(dns);
                        }
                        *self = restored;
                    }
                    Err(rollback) => {
                        return Err(ListenerServiceError::Rule(format!(
                            "reload failed: {error}; restore failed: {rollback}"
                        ))
                        .into())
                    }
                }
                Err(error)
            }
        }
    }

    pub fn run_forever(self) -> ! {
        let _app = self;
        loop {
            thread::park_timeout(Duration::from_secs(3600));
        }
    }
}

/// A staged policy swap is valid only while every socket, DNS setting, TUN
/// option, routing mark and controller setting keeps its existing semantics.
fn supports_policy_reload(
    previous: &mihomo_config::RuntimeConfigDocument,
    next: &mihomo_config::RuntimeConfigDocument,
) -> bool {
    let mut fixed = previous.clone();
    fixed.mode = next.mode.clone();
    fixed.log_level = next.log_level.clone();
    fixed.proxies = next.proxies.clone();
    fixed.proxy_groups = next.proxy_groups.clone();
    fixed.proxy_providers = next.proxy_providers.clone();
    fixed.rules = next.rules.clone();
    fixed.sub_rules = next.sub_rules.clone();
    fixed.rule_providers = next.rule_providers.clone();
    fixed.sniffer = next.sniffer.clone();
    fixed == *next
}

fn prewarm_cold_outbounds(state: &BootstrapState) -> Result<(), mihomo_transport::TransportError> {
    for definition in state.registry.proxy_definitions.values() {
        let OutboundDefinition::Sudoku(config) = definition else {
            continue;
        };
        let key = config
            .extra
            .get("key")
            .and_then(serde_yaml::Value::as_str)
            .unwrap_or_default();
        let table_type = config
            .extra
            .get("table-type")
            .and_then(serde_yaml::Value::as_str)
            .unwrap_or("prefer_entropy");
        let custom_table = config
            .extra
            .get("custom-table")
            .and_then(serde_yaml::Value::as_str)
            .unwrap_or_default();
        let custom_tables = config
            .extra
            .get("custom-tables")
            .and_then(serde_yaml::Value::as_sequence)
            .map(|items| {
                items
                    .iter()
                    .filter_map(serde_yaml::Value::as_str)
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        mihomo_transport::prewarm_sudoku_tables(key, table_type, custom_table, &custom_tables)?;
    }
    Ok(())
}

impl Drop for RunningApp {
    fn drop(&mut self) {
        self.shutdown();
    }
}
