use std::collections::BTreeMap;
use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::IpAddr;
use std::net::{SocketAddr, TcpListener, TcpStream};
#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::sync::mpsc;
use std::thread;
use std::time::UNIX_EPOCH;
use std::time::Duration;

use base64::Engine as _;
use chrono::{DateTime, Utc};
use mihomo_config::RuntimeConfigDocument;
use mihomo_core::{recent_logs, subscribe_logs, LogEntry, LogLevel};
use mihomo_dns::DnsRecordType;
use mihomo_rules::compile_rule_table_with_providers;
use mihomo_runtime::build_runtime_registry_with_sources;
use rustls::{Certificate, PrivateKey, ServerConfig, ServerConnection, StreamOwned};
use sha1::{Digest, Sha1};
use mihomo_runtime::{
    ActiveConnectionSnapshot, BootstrapError, BootstrapState, RuntimeControlError, RuntimeTunnel,
};
use serde::Serialize;
use serde_json::{Map, Value as JsonValue};

use crate::{
    build_api_snapshot, build_api_snapshot_from_bootstrap, ApiError, ApiGroupSnapshot,
    ApiListenerSnapshot, ApiProxyProviderSnapshot,
    ApiRuleExtraSnapshot, ApiRuleProviderSnapshot, ApiRuleSnapshot, ApiSnapshot,
    storage::{default_storage_root, StorageError, StorageStore},
};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ApiHttpRequest {
    pub method: String,
    pub target: String,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

impl ApiHttpRequest {
    pub fn get(target: impl Into<String>) -> Self {
        Self {
            method: "GET".into(),
            target: target.into(),
            headers: BTreeMap::new(),
            body: Vec::new(),
        }
    }

    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers
            .insert(name.into().to_ascii_lowercase(), value.into());
        self
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(String::as_str)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApiHttpResponse {
    pub status_code: u16,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

impl ApiHttpResponse {
    pub fn content_type(&self) -> Option<&str> {
        self.headers.get("Content-Type").map(String::as_str)
    }

    fn head_only(mut self) -> Self {
        self.body.clear();
        self
    }
}

#[derive(Clone, Debug)]
pub struct ApiController {
    snapshot: ApiSnapshot,
    secret: String,
    ui_path: Option<PathBuf>,
    doh_path: Option<String>,
    storage: Option<StorageStore>,
    control_tx: Option<mpsc::Sender<ApiControlCommand>>,
    tls_addr: Option<String>,
    unix_addr: Option<PathBuf>,
    certificate: String,
    private_key: String,
    client_auth_type: String,
    client_auth_cert: String,
    bootstrap_state: Option<Arc<Mutex<BootstrapState>>>,
    runtime_tunnel: Option<Arc<RuntimeTunnel>>,
}

#[derive(Debug)]
pub enum ControllerError {
    Api(ApiError),
    Io(std::io::Error),
    Json(serde_json::Error),
    MissingExternalController,
    InvalidHttpRequest(String),
}

impl std::fmt::Display for ControllerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Api(err) => write!(f, "{err}"),
            Self::Io(err) => write!(f, "{err}"),
            Self::Json(err) => write!(f, "{err}"),
            Self::MissingExternalController => {
                write!(f, "external-controller is not configured")
            }
            Self::InvalidHttpRequest(message) => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for ControllerError {}

impl From<ApiError> for ControllerError {
    fn from(value: ApiError) -> Self {
        Self::Api(value)
    }
}

impl From<std::io::Error> for ControllerError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<serde_json::Error> for ControllerError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApiControlCommand {
    Restart,
}

#[derive(Debug)]
pub struct RunningApiController {
    local_addr: SocketAddr,
    shutdown_tx: Option<mpsc::Sender<()>>,
    join_handle: Option<thread::JoinHandle<()>>,
}

impl RunningApiController {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn shutdown(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.join_handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for RunningApiController {
    fn drop(&mut self) {
        self.shutdown();
    }
}

impl ApiController {
    pub fn from_document(document: &RuntimeConfigDocument) -> Result<Self, ApiError> {
        Ok(Self {
            snapshot: build_api_snapshot(document)?,
            secret: document.secret.clone(),
            ui_path: (!document.external_ui.is_empty())
                .then(|| PathBuf::from(document.external_ui.clone())),
            doh_path: normalize_doh_path(&document.external_doh_server),
            storage: None,
            control_tx: None,
            tls_addr: normalize_optional_string(&document.external_controller_tls),
            unix_addr: normalize_optional_path(&document.external_controller_unix, None),
            certificate: tls_string(&document.extra, "certificate"),
            private_key: tls_string(&document.extra, "private-key"),
            client_auth_type: tls_string(&document.extra, "client-auth-type"),
            client_auth_cert: tls_string(&document.extra, "client-auth-cert"),
            bootstrap_state: None,
            runtime_tunnel: None,
        })
    }

    pub fn from_bootstrap(state: &BootstrapState) -> Result<Self, ApiError> {
        let ui_path = (!state.document.external_ui.is_empty()).then(|| {
            let candidate = PathBuf::from(&state.document.external_ui);
            if candidate.is_absolute() {
                candidate
            } else {
                state.resolved_boot.home_dir.join(candidate)
            }
        });
        Ok(Self {
            snapshot: build_api_snapshot_from_bootstrap(state)?,
            secret: state.document.secret.clone(),
            ui_path,
            doh_path: normalize_doh_path(&state.document.external_doh_server),
            storage: Some(StorageStore::new(default_storage_root(
                &state.resolved_boot.home_dir,
            ))),
            control_tx: None,
            tls_addr: normalize_optional_string(&state.document.external_controller_tls),
            unix_addr: normalize_optional_path(
                &state.document.external_controller_unix,
                Some(&state.resolved_boot.home_dir),
            ),
            certificate: tls_string(&state.document.extra, "certificate"),
            private_key: tls_string(&state.document.extra, "private-key"),
            client_auth_type: tls_string(&state.document.extra, "client-auth-type"),
            client_auth_cert: tls_string(&state.document.extra, "client-auth-cert"),
            bootstrap_state: Some(Arc::new(Mutex::new(state.clone()))),
            runtime_tunnel: None,
        })
    }

    pub fn with_bootstrap_state(mut self, bootstrap_state: Arc<Mutex<BootstrapState>>) -> Self {
        self.bootstrap_state = Some(bootstrap_state);
        self
    }

    pub fn with_runtime_tunnel(mut self, runtime_tunnel: Arc<RuntimeTunnel>) -> Self {
        self.runtime_tunnel = Some(runtime_tunnel);
        self
    }

    pub fn with_control_tx(mut self, control_tx: mpsc::Sender<ApiControlCommand>) -> Self {
        self.control_tx = Some(control_tx);
        self
    }

    pub fn snapshot(&self) -> &ApiSnapshot {
        &self.snapshot
    }

    pub fn handle_request(&self, request: &ApiHttpRequest) -> ApiHttpResponse {
        let method = request.method.to_ascii_uppercase();
        let (path, query) = split_target(&request.target);
        let head_only = method == "HEAD";
        if let Some(response) = self.handle_ui_request(path) {
            return if head_only { response.head_only() } else { response };
        }

        if self.matches_doh_path(path) {
            return self.handle_doh_request(&method, request, query);
        }

        if !self.is_authorized(request, query) {
            return self.unauthorized();
        }
        if method == "POST" {
            return self.handle_post_request(path);
        }

        if method == "PUT" || method == "PATCH" || method == "DELETE" {
            return self.handle_write_request(path, &method, request);
        }
        if method != "GET" && !head_only {
            return self.method_not_allowed();
        }

        let snapshot = self.current_snapshot();
        let response = match path {
            "/" => self.json_ok(&HelloPayload { hello: "mihomo" }),
            "/version" => self.json_ok(&snapshot.version),
            "/configs" => self.json_ok(&snapshot.general),
            "/proxies" => self.json_ok(&ListPayload {
                proxies: snapshot
                    .proxies
                    .iter()
                    .map(|entry| {
                        let value = snapshot
                            .groups
                            .iter()
                            .find(|group| group.name == entry.name)
                            .map(serde_json::to_value)
                            .unwrap_or_else(|| serde_json::to_value(entry))
                            .unwrap_or(JsonValue::Null);
                        (entry.name.clone(), value)
                    })
                    .collect(),
            }),
            "/group" => self.json_ok(&GroupListPayload {
                proxies: snapshot.groups.clone(),
            }),
            "/providers/proxies" => self.json_ok(&ProviderListPayload {
                providers: to_named_map(&snapshot.proxy_providers, |entry| entry.name.clone()),
            }),
            "/providers/rules" => self.json_ok(&RuleProviderListPayload {
                providers: to_named_map(&snapshot.rule_providers, |entry| entry.name.clone()),
            }),
            "/rules" => self.json_ok(&self.current_rules_payload(&snapshot)),
            "/dns" => self.json_ok(&snapshot.dns),
            "/dns/query" => self.handle_dns_query(query),
            "/tun" => self.json_ok(&snapshot.tun),
            "/listeners" => self.json_ok(&ListenersPayload {
                listeners: snapshot.listeners.clone(),
            }),
            "/traffic" => self.json_ok(&self.current_traffic_payload()),
            "/connections" => self.json_ok(&self.current_connections_payload()),
            "/memory" => self.json_ok(&self.current_memory_payload()),
            "/logs" => self.handle_logs_request(query),
            other if other.starts_with("/storage/") => {
                let key = percent_decode(other.trim_start_matches("/storage/"));
                self.handle_storage_get(&key)
            }
            other if other.starts_with("/proxies/") => {
                let name = percent_decode(other.trim_start_matches("/proxies/"));
                match snapshot.groups.iter().find(|entry| entry.name == name) {
                    Some(group) => self.json_ok(group),
                    None => match snapshot.proxies.iter().find(|entry| entry.name == name) {
                        Some(proxy) => self.json_ok(proxy),
                        None => self.not_found(),
                    },
                }
            }
            other if other.starts_with("/group/") => {
                let name = percent_decode(other.trim_start_matches("/group/"));
                match snapshot.groups.iter().find(|entry| entry.name == name) {
                    Some(group) => self.json_ok(group),
                    None => self.not_found(),
                }
            }
            other if other.starts_with("/providers/proxies/") => {
                let suffix = other.trim_start_matches("/providers/proxies/");
                if let Some((provider_name, proxy_name)) = suffix.split_once('/') {
                    let provider_name = percent_decode(provider_name);
                    let proxy_name = percent_decode(proxy_name);
                    match snapshot
                        .proxy_providers
                        .iter()
                        .find(|entry| entry.name == provider_name)
                        .and_then(|provider| {
                            provider
                                .proxies
                                .iter()
                                .find(|proxy| proxy.name == proxy_name)
                        }) {
                        Some(proxy) => self.json_ok(proxy),
                        None => self.not_found(),
                    }
                } else {
                    let name = percent_decode(suffix);
                    match snapshot.proxy_providers.iter().find(|entry| entry.name == name) {
                        Some(provider) => self.json_ok(provider),
                        None => self.not_found(),
                    }
                }
            }
            other if other.starts_with("/providers/rules/") => {
                let name = percent_decode(other.trim_start_matches("/providers/rules/"));
                match snapshot.rule_providers.iter().find(|entry| entry.name == name) {
                    Some(provider) => self.json_ok(provider),
                    None => self.not_found(),
                }
            }
            _ => self.not_found(),
        };

        if head_only {
            response.head_only()
        } else {
            response
        }
    }

    pub fn serve_document(
        document: &RuntimeConfigDocument,
    ) -> Result<RunningApiController, ControllerError> {
        if document.external_controller.is_empty() {
            return Err(ControllerError::MissingExternalController);
        }
        Self::from_document(document)?.serve(&document.external_controller)
    }

    pub fn serve_bootstrap(
        state: &BootstrapState,
    ) -> Result<RunningApiController, ControllerError> {
        if state.document.external_controller.is_empty() {
            return Err(ControllerError::MissingExternalController);
        }
        Self::from_bootstrap(state)?.serve(&state.document.external_controller)
    }

    pub fn serve_bootstrap_with_runtime(
        state: &BootstrapState,
        runtime_tunnel: Arc<RuntimeTunnel>,
    ) -> Result<RunningApiController, ControllerError> {
        Self::serve_bootstrap_with_runtime_and_control(state, runtime_tunnel, None)
    }

    pub fn serve_bootstrap_with_runtime_and_control(
        state: &BootstrapState,
        runtime_tunnel: Arc<RuntimeTunnel>,
        control_tx: Option<mpsc::Sender<ApiControlCommand>>,
    ) -> Result<RunningApiController, ControllerError> {
        if state.document.external_controller.is_empty() {
            return Err(ControllerError::MissingExternalController);
        }
        let mut controller = Self::from_bootstrap(state)?.with_runtime_tunnel(runtime_tunnel);
        if let Some(control_tx) = control_tx {
            controller = controller.with_control_tx(control_tx);
        }
        controller.serve(&state.document.external_controller)
    }

    pub fn serve_configured_http(&self) -> Result<RunningApiController, ControllerError> {
        if self.snapshot.general.external_controller.is_empty() {
            return Err(ControllerError::MissingExternalController);
        }
        self.serve(&self.snapshot.general.external_controller)
    }

    pub fn serve_configured_tls(&self) -> Result<RunningApiController, ControllerError> {
        let Some(bind_addr) = self.tls_addr.as_deref() else {
            return Err(ControllerError::MissingExternalController);
        };
        self.serve_tls(bind_addr)
    }

    pub fn serve_tls_document(
        document: &RuntimeConfigDocument,
    ) -> Result<RunningApiController, ControllerError> {
        let controller = Self::from_document(document)?;
        let Some(bind_addr) = controller.tls_addr.as_deref() else {
            return Err(ControllerError::MissingExternalController);
        };
        controller.serve_tls(bind_addr)
    }

    pub fn serve_tls_bootstrap(
        state: &BootstrapState,
    ) -> Result<RunningApiController, ControllerError> {
        let controller = Self::from_bootstrap(state)?;
        let Some(bind_addr) = controller.tls_addr.as_deref() else {
            return Err(ControllerError::MissingExternalController);
        };
        controller.serve_tls(bind_addr)
    }

    pub fn serve_tls_bootstrap_with_runtime(
        state: &BootstrapState,
        runtime_tunnel: Arc<RuntimeTunnel>,
    ) -> Result<RunningApiController, ControllerError> {
        Self::serve_tls_bootstrap_with_runtime_and_control(state, runtime_tunnel, None)
    }

    pub fn serve_tls_bootstrap_with_runtime_and_control(
        state: &BootstrapState,
        runtime_tunnel: Arc<RuntimeTunnel>,
        control_tx: Option<mpsc::Sender<ApiControlCommand>>,
    ) -> Result<RunningApiController, ControllerError> {
        let mut controller = Self::from_bootstrap(state)?.with_runtime_tunnel(runtime_tunnel);
        if let Some(control_tx) = control_tx {
            controller = controller.with_control_tx(control_tx);
        }
        let Some(bind_addr) = controller.tls_addr.as_deref() else {
            return Err(ControllerError::MissingExternalController);
        };
        controller.serve_tls(bind_addr)
    }

    #[cfg(unix)]
    pub fn serve_unix_document(
        document: &RuntimeConfigDocument,
    ) -> Result<RunningApiController, ControllerError> {
        let controller = Self::from_document(document)?;
        let Some(bind_path) = controller.unix_addr.clone() else {
            return Err(ControllerError::MissingExternalController);
        };
        controller.serve_unix(&bind_path)
    }

    #[cfg(unix)]
    pub fn serve_unix_bootstrap(
        state: &BootstrapState,
    ) -> Result<RunningApiController, ControllerError> {
        let controller = Self::from_bootstrap(state)?;
        let Some(bind_path) = controller.unix_addr.clone() else {
            return Err(ControllerError::MissingExternalController);
        };
        controller.serve_unix(&bind_path)
    }

    #[cfg(unix)]
    pub fn serve_unix_bootstrap_with_runtime(
        state: &BootstrapState,
        runtime_tunnel: Arc<RuntimeTunnel>,
    ) -> Result<RunningApiController, ControllerError> {
        Self::serve_unix_bootstrap_with_runtime_and_control(state, runtime_tunnel, None)
    }

    #[cfg(unix)]
    pub fn serve_unix_bootstrap_with_runtime_and_control(
        state: &BootstrapState,
        runtime_tunnel: Arc<RuntimeTunnel>,
        control_tx: Option<mpsc::Sender<ApiControlCommand>>,
    ) -> Result<RunningApiController, ControllerError> {
        let mut controller = Self::from_bootstrap(state)?.with_runtime_tunnel(runtime_tunnel);
        if let Some(control_tx) = control_tx {
            controller = controller.with_control_tx(control_tx);
        }
        let Some(bind_path) = controller.unix_addr.clone() else {
            return Err(ControllerError::MissingExternalController);
        };
        controller.serve_unix(&bind_path)
    }

    #[cfg(unix)]
    pub fn serve_configured_unix(&self) -> Result<RunningApiController, ControllerError> {
        let Some(bind_path) = self.unix_addr.clone() else {
            return Err(ControllerError::MissingExternalController);
        };
        self.serve_unix(&bind_path)
    }

    pub fn serve(&self, bind_addr: &str) -> Result<RunningApiController, ControllerError> {
        let listener = TcpListener::bind(bind_addr)?;
        let local_addr = listener.local_addr()?;
        listener.set_nonblocking(true)?;

        let controller = self.clone();
        let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>();
        let join_handle = thread::spawn(move || {
            loop {
                if shutdown_rx.try_recv().is_ok() {
                    break;
                }

                match listener.accept() {
                    Ok((stream, _)) => {
                        let _ = stream.set_nonblocking(false);
                        let controller = controller.clone();
                        thread::spawn(move || {
                            let _ = controller.handle_stream(stream);
                        });
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });

        Ok(RunningApiController {
            local_addr,
            shutdown_tx: Some(shutdown_tx),
            join_handle: Some(join_handle),
        })
    }

    pub fn serve_tls(&self, bind_addr: &str) -> Result<RunningApiController, ControllerError> {
        let tls_config = Arc::new(build_controller_tls_config(
            &self.certificate,
            &self.private_key,
            &self.client_auth_type,
            &self.client_auth_cert,
        )?);
        let listener = TcpListener::bind(bind_addr)?;
        let local_addr = listener.local_addr()?;
        listener.set_nonblocking(true)?;

        let controller = self.clone();
        let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>();
        let join_handle = thread::spawn(move || {
            loop {
                if shutdown_rx.try_recv().is_ok() {
                    break;
                }

                match listener.accept() {
                    Ok((stream, _)) => {
                        let _ = stream.set_nonblocking(false);
                        let controller = controller.clone();
                        let tls_config = Arc::clone(&tls_config);
                        thread::spawn(move || {
                            let _ = controller.handle_tls_stream(stream, tls_config);
                        });
                    }
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });

        Ok(RunningApiController {
            local_addr,
            shutdown_tx: Some(shutdown_tx),
            join_handle: Some(join_handle),
        })
    }

    #[cfg(unix)]
    pub fn serve_unix(&self, bind_path: &Path) -> Result<RunningApiController, ControllerError> {
        if let Some(parent) = bind_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let _ = fs::remove_file(bind_path);
        let listener = UnixListener::bind(bind_path)?;
        listener.set_nonblocking(true)?;

        let controller = self.clone();
        let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>();
        let join_handle = thread::spawn(move || {
            loop {
                if shutdown_rx.try_recv().is_ok() {
                    break;
                }

                match listener.accept() {
                    Ok((stream, _)) => {
                        let controller = controller.clone();
                        thread::spawn(move || {
                            let _ = controller.handle_unix_stream(stream);
                        });
                    }
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });

        Ok(RunningApiController {
            local_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            shutdown_tx: Some(shutdown_tx),
            join_handle: Some(join_handle),
        })
    }

    fn handle_stream(&self, mut stream: TcpStream) -> Result<(), ControllerError> {
        let request = parse_http_request(&mut stream)?;
        let (path, query) = split_target(&request.target);
        if let Some(route) = self.websocket_route(&request, path) {
            if !self.is_authorized(&request, query) {
                write_http_response(&mut stream, &self.unauthorized())?;
                return Ok(());
            }
            return match route {
                LiveWebsocketRoute::Connections => self.handle_connections_websocket(Box::new(stream), &request),
                LiveWebsocketRoute::Traffic => self.handle_traffic_websocket(Box::new(stream), &request),
                LiveWebsocketRoute::Memory => self.handle_memory_websocket(Box::new(stream), &request),
                LiveWebsocketRoute::Logs => self.handle_logs_websocket(Box::new(stream), &request),
            };
        }
        if let Some(route) = self.http_stream_route(&request, path) {
            if !self.is_authorized(&request, query) {
                write_http_response(&mut stream, &self.unauthorized())?;
                return Ok(());
            }
            return match route {
                LiveHttpStreamRoute::Traffic => self.handle_traffic_http_stream(Box::new(stream), &request),
                LiveHttpStreamRoute::Memory => self.handle_memory_http_stream(Box::new(stream), &request),
                LiveHttpStreamRoute::Logs => self.handle_logs_http_stream(Box::new(stream), &request),
            };
        }
        if self.matches_doh_path(path) {
            let response = self.handle_doh_request(&request.method, &request, query);
            write_http_response(&mut stream, &response)?;
            return Ok(());
        }
        let response = self.handle_request(&request);
        write_http_response(&mut stream, &response)?;
        Ok(())
    }

    fn handle_tls_stream(
        &self,
        stream: TcpStream,
        tls_config: Arc<ServerConfig>,
    ) -> Result<(), ControllerError> {
        let mut tls_stream = accept_tls_server_stream(stream, tls_config)?;
        let request = parse_http_request(&mut tls_stream)?;
        let (path, query) = split_target(&request.target);
        if let Some(route) = self.websocket_route(&request, path) {
            if !self.is_authorized(&request, query) {
                write_http_response(&mut tls_stream, &self.unauthorized())?;
                return Ok(());
            }
            return match route {
                LiveWebsocketRoute::Connections => self.handle_connections_websocket(Box::new(tls_stream), &request),
                LiveWebsocketRoute::Traffic => self.handle_traffic_websocket(Box::new(tls_stream), &request),
                LiveWebsocketRoute::Memory => self.handle_memory_websocket(Box::new(tls_stream), &request),
                LiveWebsocketRoute::Logs => self.handle_logs_websocket(Box::new(tls_stream), &request),
            };
        }
        if let Some(route) = self.http_stream_route(&request, path) {
            if !self.is_authorized(&request, query) {
                write_http_response(&mut tls_stream, &self.unauthorized())?;
                return Ok(());
            }
            return match route {
                LiveHttpStreamRoute::Traffic => self.handle_traffic_http_stream(Box::new(tls_stream), &request),
                LiveHttpStreamRoute::Memory => self.handle_memory_http_stream(Box::new(tls_stream), &request),
                LiveHttpStreamRoute::Logs => self.handle_logs_http_stream(Box::new(tls_stream), &request),
            };
        }
        if self.matches_doh_path(path) {
            let response = self.handle_doh_request(&request.method, &request, query);
            write_http_response(&mut tls_stream, &response)?;
            return Ok(());
        }
        let response = self.handle_request(&request);
        write_http_response(&mut tls_stream, &response)?;
        Ok(())
    }

    #[cfg(unix)]
    fn handle_unix_stream(&self, mut stream: UnixStream) -> Result<(), ControllerError> {
        let request = parse_http_request(&mut stream)?;
        let (path, query) = split_target(&request.target);
        if let Some(route) = self.websocket_route(&request, path) {
            return match route {
                LiveWebsocketRoute::Connections => {
                    self.handle_connections_websocket(Box::new(stream), &request)
                }
                LiveWebsocketRoute::Traffic => {
                    self.handle_traffic_websocket(Box::new(stream), &request)
                }
                LiveWebsocketRoute::Memory => {
                    self.handle_memory_websocket(Box::new(stream), &request)
                }
                LiveWebsocketRoute::Logs => {
                    self.handle_logs_websocket(Box::new(stream), &request)
                }
            };
        }
        if let Some(route) = self.http_stream_route(&request, path) {
            return match route {
                LiveHttpStreamRoute::Traffic => {
                    self.handle_traffic_http_stream(Box::new(stream), &request)
                }
                LiveHttpStreamRoute::Memory => {
                    self.handle_memory_http_stream(Box::new(stream), &request)
                }
                LiveHttpStreamRoute::Logs => {
                    self.handle_logs_http_stream(Box::new(stream), &request)
                }
            };
        }
        if self.matches_doh_path(path) {
            let response = self.handle_doh_request(&request.method, &request, query);
            write_http_response(&mut stream, &response)?;
            return Ok(());
        }
        let response = self.handle_request_unix(&request);
        write_http_response(&mut stream, &response)?;
        Ok(())
    }

    fn is_authorized(&self, request: &ApiHttpRequest, query: &str) -> bool {
        if self.secret.is_empty() {
            return true;
        }

        let is_websocket = request
            .header("upgrade")
            .is_some_and(|value| value.eq_ignore_ascii_case("websocket"));
        if is_websocket {
            let params = parse_query(query);
            if params
                .get("token")
                .is_some_and(|token| token.as_str() == self.secret)
            {
                return true;
            }
        }

        request
            .header("authorization")
            .and_then(parse_bearer_token)
            .is_some_and(|token| token == self.secret)
    }

    fn handle_request_unix(&self, request: &ApiHttpRequest) -> ApiHttpResponse {
        let method = request.method.to_ascii_uppercase();
        let (path, query) = split_target(&request.target);
        let head_only = method == "HEAD";
        if let Some(response) = self.handle_ui_request(path) {
            return if head_only { response.head_only() } else { response };
        }

        if self.matches_doh_path(path) {
            return self.handle_doh_request(&method, request, query);
        }
        if method == "POST" {
            return self.handle_post_request(path);
        }
        if method == "PUT" || method == "PATCH" || method == "DELETE" {
            return self.handle_write_request(path, &method, request);
        }
        if method != "GET" && !head_only {
            return self.method_not_allowed();
        }
        let snapshot = self.current_snapshot();
        let response = match path {
            "/" => self.json_ok(&HelloPayload { hello: "mihomo" }),
            "/version" => self.json_ok(&snapshot.version),
            "/configs" => self.json_ok(&snapshot.general),
            "/proxies" => self.json_ok(&ListPayload {
                proxies: snapshot
                    .proxies
                    .iter()
                    .map(|entry| {
                        let value = snapshot
                            .groups
                            .iter()
                            .find(|group| group.name == entry.name)
                            .map(serde_json::to_value)
                            .unwrap_or_else(|| serde_json::to_value(entry))
                            .unwrap_or(JsonValue::Null);
                        (entry.name.clone(), value)
                    })
                    .collect(),
            }),
            "/group" => self.json_ok(&GroupListPayload {
                proxies: snapshot.groups.clone(),
            }),
            "/providers/proxies" => self.json_ok(&ProviderListPayload {
                providers: to_named_map(&snapshot.proxy_providers, |entry| entry.name.clone()),
            }),
            "/providers/rules" => self.json_ok(&RuleProviderListPayload {
                providers: to_named_map(&snapshot.rule_providers, |entry| entry.name.clone()),
            }),
            "/rules" => self.json_ok(&self.current_rules_payload(&snapshot)),
            "/dns" => self.json_ok(&snapshot.dns),
            "/dns/query" => self.handle_dns_query(query),
            "/tun" => self.json_ok(&snapshot.tun),
            "/listeners" => self.json_ok(&ListenersPayload {
                listeners: snapshot.listeners.clone(),
            }),
            "/traffic" => self.json_ok(&self.current_traffic_payload()),
            "/connections" => self.json_ok(&self.current_connections_payload()),
            "/memory" => self.json_ok(&self.current_memory_payload()),
            "/logs" => self.handle_logs_request(query),
            other if other.starts_with("/storage/") => {
                let key = percent_decode(other.trim_start_matches("/storage/"));
                self.handle_storage_get(&key)
            }
            other if other.starts_with("/proxies/") => {
                let name = percent_decode(other.trim_start_matches("/proxies/"));
                match snapshot.proxies.iter().find(|entry| entry.name == name) {
                    Some(proxy) => self.json_ok(proxy),
                    None => self.not_found(),
                }
            }
            other if other.starts_with("/group/") => {
                let name = percent_decode(other.trim_start_matches("/group/"));
                match snapshot.groups.iter().find(|entry| entry.name == name) {
                    Some(group) => self.json_ok(group),
                    None => self.not_found(),
                }
            }
            other if other.starts_with("/providers/proxies/") => {
                let suffix = other.trim_start_matches("/providers/proxies/");
                if let Some((provider_name, proxy_name)) = suffix.split_once('/') {
                    let provider_name = percent_decode(provider_name);
                    let proxy_name = percent_decode(proxy_name);
                    match snapshot
                        .proxy_providers
                        .iter()
                        .find(|entry| entry.name == provider_name)
                        .and_then(|provider| {
                            provider
                                .proxies
                                .iter()
                                .find(|proxy| proxy.name == proxy_name)
                        }) {
                        Some(proxy) => self.json_ok(proxy),
                        None => self.not_found(),
                    }
                } else {
                    let name = percent_decode(suffix);
                    match snapshot.proxy_providers.iter().find(|entry| entry.name == name) {
                        Some(provider) => self.json_ok(provider),
                        None => self.not_found(),
                    }
                }
            }
            other if other.starts_with("/providers/rules/") => {
                let name = percent_decode(other.trim_start_matches("/providers/rules/"));
                match snapshot.rule_providers.iter().find(|entry| entry.name == name) {
                    Some(provider) => self.json_ok(provider),
                    None => self.not_found(),
                }
            }
            _ => self.not_found(),
        };
        if head_only {
            response.head_only()
        } else {
            response
        }
    }

    fn handle_ui_request(&self, path: &str) -> Option<ApiHttpResponse> {
        let ui_root = self.ui_path.as_ref()?;
        if path == "/ui" {
            return Some(ApiHttpResponse {
                status_code: 307,
                headers: BTreeMap::from([("Location".into(), "/ui/".into())]),
                body: Vec::new(),
            });
        }

        let relative = path.strip_prefix("/ui/")?;
        let file_path = match sanitize_ui_path(ui_root, relative) {
            Some(file_path) => file_path,
            None => return Some(self.not_found()),
        };
        let body = match fs::read(&file_path) {
            Ok(body) => body,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Some(self.not_found()),
            Err(err) => {
                return Some(self.internal_server_error(&err.to_string()));
            }
        };

        Some(ApiHttpResponse {
            status_code: 200,
            headers: BTreeMap::from([(
                "Content-Type".into(),
                content_type_for(&file_path).into(),
            )]),
            body,
        })
    }

    fn json_ok<T: Serialize>(&self, value: &T) -> ApiHttpResponse {
        json_response(200, value).unwrap_or_else(|err| self.internal_server_error(&err.to_string()))
    }

    fn current_snapshot(&self) -> ApiSnapshot {
        let mut snapshot = self
            .bootstrap_state
            .as_ref()
            .and_then(|state| {
                let state = state.lock().unwrap();
                build_api_snapshot_from_bootstrap(&state).ok()
            })
            .unwrap_or_else(|| self.snapshot.clone());
        let Some(runtime_tunnel) = &self.runtime_tunnel else {
            return snapshot;
        };
        snapshot.general.mode = runtime_tunnel.current_mode();
        for group in &mut snapshot.groups {
            group.selected = runtime_tunnel.effective_group_selected(&group.name, None);
            group.fixed = runtime_tunnel.group_selected(&group.name);
        }
        snapshot
    }

    fn current_traffic_payload(&self) -> TrafficPayload {
        self.runtime_tunnel
            .as_ref()
            .map(|runtime_tunnel| {
                let snapshot = runtime_tunnel.traffic_snapshot();
                TrafficPayload {
                    up: snapshot.up,
                    down: snapshot.down,
                    up_total: snapshot.up_total,
                    down_total: snapshot.down_total,
                }
            })
            .unwrap_or_default()
    }

    fn current_connections_payload(&self) -> ConnectionsPayload {
        let traffic = self.current_traffic_payload();
        let connections = self
            .runtime_tunnel
            .as_ref()
            .map(|runtime_tunnel| runtime_tunnel.connections_snapshot())
            .unwrap_or_default()
            .into_iter()
            .map(connection_payload_from_snapshot)
            .collect();
        ConnectionsPayload {
            download_total: traffic.down_total,
            upload_total: traffic.up_total,
            connections,
            memory: process_resident_memory_bytes().unwrap_or(0),
        }
    }

    fn current_memory_payload(&self) -> MemoryPayload {
        MemoryPayload {
            inuse: process_resident_memory_bytes().unwrap_or(0),
            oslimit: 0,
        }
    }

    fn current_rules_payload(&self, snapshot: &ApiSnapshot) -> RulesPayload {
        let rules = self
            .runtime_tunnel
            .as_ref()
            .map(|runtime_tunnel| runtime_rule_snapshots_payload(runtime_tunnel))
            .unwrap_or_else(|| snapshot.rules.clone());
        RulesPayload { rules }
    }

    fn current_logs_payload(&self, level: LogLevel, format: LogFormat) -> LogsPayload {
        LogsPayload {
            logs: recent_logs(level)
                .into_iter()
                .map(|entry| encode_log_entry(entry, format))
                .collect(),
        }
    }

    fn handle_logs_request(&self, query: &str) -> ApiHttpResponse {
        match parse_logs_query(query) {
            Ok((level, format)) => self.json_ok(&self.current_logs_payload(level, format)),
            Err(response) => response,
        }
    }

    fn handle_dns_query(&self, query: &str) -> ApiHttpResponse {
        let Some(runtime_tunnel) = &self.runtime_tunnel else {
            return error_response(500, "DNS section is disabled");
        };
        let Some(runtime) = runtime_tunnel.dns_runtime() else {
            return error_response(500, "DNS section is disabled");
        };

        let params = parse_query(query);
        let name = params
            .get("name")
            .map(String::as_str)
            .unwrap_or_default()
            .trim();
        if name.is_empty() {
            return error_response(400, "name is required");
        }

        let query_type = match params
            .get("type")
            .map(String::as_str)
            .unwrap_or("A")
            .trim()
            .to_ascii_uppercase()
            .as_str()
        {
            "A" => DnsRecordType::A,
            "AAAA" => DnsRecordType::Aaaa,
            _ => return error_response(400, "invalid query type"),
        };

        let mut guard = runtime.lock().unwrap();
        let ips = match guard.resolve_host_via_system(name) {
            Ok(Some(ip)) if dns_matches_query_type(ip, query_type) => vec![ip],
            Ok(Some(_)) => Vec::new(),
            Ok(None) => guard
                .cached_answer(name)
                .map(|answer| {
                    answer
                        .ips
                        .iter()
                        .copied()
                        .filter(|ip| dns_matches_query_type(*ip, query_type))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default(),
            Err(err) => return error_response(500, &err.to_string()),
        };

        let mut payload = Map::new();
        payload.insert("Status".into(), JsonValue::from(0));
        payload.insert(
            "Question".into(),
            JsonValue::Array(vec![dns_question_json(name, query_type)]),
        );
        payload.insert("TC".into(), JsonValue::Bool(false));
        payload.insert("RD".into(), JsonValue::Bool(true));
        payload.insert("RA".into(), JsonValue::Bool(true));
        payload.insert("AD".into(), JsonValue::Bool(false));
        payload.insert("CD".into(), JsonValue::Bool(false));
        if !ips.is_empty() {
            payload.insert(
                "Answer".into(),
                JsonValue::Array(
                    ips.into_iter()
                        .map(|ip| dns_answer_json(name, query_type, ip))
                        .collect(),
                ),
            );
        }
        self.json_ok(&JsonValue::Object(payload))
    }

    fn handle_doh_request(
        &self,
        method: &str,
        request: &ApiHttpRequest,
        query: &str,
    ) -> ApiHttpResponse {
        let Some(runtime_tunnel) = &self.runtime_tunnel else {
            return ApiHttpResponse {
                status_code: 500,
                headers: BTreeMap::from([("Content-Type".into(), "text/plain".into())]),
                body: b"DNS section is disabled".to_vec(),
            };
        };
        let Some(runtime) = runtime_tunnel.dns_runtime() else {
            return ApiHttpResponse {
                status_code: 500,
                headers: BTreeMap::from([("Content-Type".into(), "text/plain".into())]),
                body: b"DNS section is disabled".to_vec(),
            };
        };

        let dns_data = match method {
            "GET" => {
                let params = parse_query(query);
                let Some(raw_dns) = params.get("dns") else {
                    return ApiHttpResponse {
                        status_code: 500,
                        headers: BTreeMap::from([("Content-Type".into(), "text/plain".into())]),
                        body: b"missing dns query".to_vec(),
                    };
                };
                match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(raw_dns) {
                    Ok(data) => data,
                    Err(err) => {
                        return ApiHttpResponse {
                            status_code: 500,
                            headers: BTreeMap::from([("Content-Type".into(), "text/plain".into())]),
                            body: err.to_string().into_bytes(),
                        };
                    }
                }
            }
            "POST" => {
                if request.header("content-type") != Some("application/dns-message") {
                    return ApiHttpResponse {
                        status_code: 500,
                        headers: BTreeMap::from([("Content-Type".into(), "text/plain".into())]),
                        body: b"invalid content-type".to_vec(),
                    };
                }
                request.body.clone()
            }
            _ => {
                return ApiHttpResponse {
                    status_code: 405,
                    headers: BTreeMap::from([
                        ("Content-Type".into(), "text/plain".into()),
                        ("Allow".into(), "GET, POST".into()),
                    ]),
                    body: b"method not allowed".to_vec(),
                };
            }
        };

        let mut guard = runtime.lock().unwrap();
        match guard.relay_query_packet_via_system(&dns_data) {
            Ok(Some(response)) => ApiHttpResponse {
                status_code: 200,
                headers: BTreeMap::from([(
                    "Content-Type".into(),
                    "application/dns-message".into(),
                )]),
                body: response,
            },
            Ok(None) => ApiHttpResponse {
                status_code: 500,
                headers: BTreeMap::from([("Content-Type".into(), "text/plain".into())]),
                body: b"DNS section is disabled".to_vec(),
            },
            Err(err) => ApiHttpResponse {
                status_code: 500,
                headers: BTreeMap::from([("Content-Type".into(), "text/plain".into())]),
                body: err.to_string().into_bytes(),
            },
        }
    }

    fn matches_doh_path(&self, path: &str) -> bool {
        let Some(doh_path) = &self.doh_path else {
            return false;
        };
        path == doh_path || path == format!("{doh_path}/")
    }

    fn handle_connections_websocket(
        &self,
        stream: Box<dyn ReadWriteStream>,
        request: &ApiHttpRequest,
    ) -> Result<(), ControllerError> {
        self.stream_live_websocket_json(stream, request, |controller| {
            controller.current_connections_payload()
        })
    }

    fn handle_traffic_websocket(
        &self,
        stream: Box<dyn ReadWriteStream>,
        request: &ApiHttpRequest,
    ) -> Result<(), ControllerError> {
        self.stream_live_websocket_json(stream, request, |controller| {
            controller.current_traffic_payload()
        })
    }

    fn handle_memory_websocket(
        &self,
        stream: Box<dyn ReadWriteStream>,
        request: &ApiHttpRequest,
    ) -> Result<(), ControllerError> {
        self.stream_live_websocket_json(stream, request, |controller| {
            controller.current_memory_payload()
        })
    }

    fn handle_logs_websocket(
        &self,
        stream: Box<dyn ReadWriteStream>,
        request: &ApiHttpRequest,
    ) -> Result<(), ControllerError> {
        let (level, format) = parse_logs_query(split_target(&request.target).1)
            .map_err(|response| ControllerError::InvalidHttpRequest(String::from_utf8_lossy(&response.body).into_owned()))?;
        self.stream_live_log_websocket(stream, request, level, format)
    }

    fn handle_traffic_http_stream(
        &self,
        stream: Box<dyn ReadWriteStream>,
        request: &ApiHttpRequest,
    ) -> Result<(), ControllerError> {
        self.stream_live_http_json(stream, request, |controller| {
            controller.current_traffic_payload()
        })
    }

    fn handle_memory_http_stream(
        &self,
        stream: Box<dyn ReadWriteStream>,
        request: &ApiHttpRequest,
    ) -> Result<(), ControllerError> {
        self.stream_live_http_json(stream, request, |controller| {
            controller.current_memory_payload()
        })
    }

    fn handle_logs_http_stream(
        &self,
        stream: Box<dyn ReadWriteStream>,
        request: &ApiHttpRequest,
    ) -> Result<(), ControllerError> {
        let (level, format) = parse_logs_query(split_target(&request.target).1)
            .map_err(|response| ControllerError::InvalidHttpRequest(String::from_utf8_lossy(&response.body).into_owned()))?;
        self.stream_live_log_http(stream, request, level, format)
    }

    fn stream_live_log_websocket(
        &self,
        stream: Box<dyn ReadWriteStream>,
        _request: &ApiHttpRequest,
        level: LogLevel,
        format: LogFormat,
    ) -> Result<(), ControllerError> {
        let mut ws = self.upgrade_websocket(stream, _request)?;
        let rx = subscribe_logs();
        for entry in rx {
            if !level.includes(entry.level) {
                continue;
            }
            let payload = serde_json::to_vec(&encode_log_entry(entry, format))?;
            ws.write_text_frame(&payload)?;
        }
        Ok(())
    }

    fn stream_live_log_http(
        &self,
        stream: Box<dyn ReadWriteStream>,
        _request: &ApiHttpRequest,
        level: LogLevel,
        format: LogFormat,
    ) -> Result<(), ControllerError> {
        let mut http = self.open_chunked_json_stream(stream)?;
        let rx = subscribe_logs();
        for entry in rx {
            if !level.includes(entry.level) {
                continue;
            }
            let payload = serde_json::to_vec(&encode_log_entry(entry, format))?;
            http.write_json_chunk(&payload)?;
        }
        Ok(())
    }

    fn handle_write_request(
        &self,
        path: &str,
        method: &str,
        request: &ApiHttpRequest,
    ) -> ApiHttpResponse {
        if let Some(raw_key) = path.strip_prefix("/storage/") {
            let key = percent_decode(raw_key);
            return match method {
                "PUT" => self.handle_storage_put(&key, request),
                "DELETE" => self.handle_storage_delete(&key),
                _ => self.method_not_allowed(),
            };
        }
        if method == "PUT" {
            return self.handle_put_request(path, request);
        }
        if method == "PATCH" {
            return self.handle_patch_request(path, request);
        }
        if method == "DELETE" {
            return self.handle_delete_request(path);
        }
        self.method_not_allowed()
    }

    fn handle_post_request(&self, path: &str) -> ApiHttpResponse {
        if path == "/restart" {
            let Some(control_tx) = &self.control_tx else {
                return error_response(503, "restart control is unavailable");
            };
            match control_tx.send(ApiControlCommand::Restart) {
                Ok(()) => return self.json_ok(&StatusPayload { status: "ok" }),
                Err(_) => return error_response(503, "restart control is unavailable"),
            }
        }
        let Some(runtime_tunnel) = &self.runtime_tunnel else {
            return error_response(503, "runtime tunnel is unavailable");
        };
        let Some(runtime) = runtime_tunnel.dns_runtime() else {
            return error_response(503, "dns runtime is unavailable");
        };
        let mut guard = runtime.lock().unwrap();
        match path {
            "/cache/dns/flush" => {
                guard.clear_cache();
                ApiHttpResponse {
                    status_code: 204,
                    headers: BTreeMap::new(),
                    body: Vec::new(),
                }
            }
            "/cache/fakeip/flush" => {
                guard.flush_fake_ip();
                ApiHttpResponse {
                    status_code: 204,
                    headers: BTreeMap::new(),
                    body: Vec::new(),
                }
            }
            _ => self.method_not_allowed(),
        }
    }

    fn handle_put_request(&self, path: &str, request: &ApiHttpRequest) -> ApiHttpResponse {
        if let Some(raw_name) = path.strip_prefix("/providers/proxies/") {
            let provider_name = percent_decode(raw_name);
            let Some(runtime_tunnel) = &self.runtime_tunnel else {
                return error_response(503, "runtime tunnel is unavailable");
            };
            let Some(bootstrap_state) = &self.bootstrap_state else {
                return error_response(503, "bootstrap state is unavailable");
            };
            let mut state = bootstrap_state.lock().unwrap();
            if !state.document.proxy_providers.contains_key(&provider_name) {
                return self.not_found();
            }
            let original_sources = state.provider_sources.clone();
            if let Err(err) = state.refresh_proxy_provider_sources(&provider_name, runtime_tunnel) {
                return match err {
                    BootstrapError::MissingProxyProvider(_) => self.not_found(),
                    _ => error_response(503, &err.to_string()),
                };
            }
            let registry = match build_runtime_registry_with_sources(
                &state.document,
                &state.provider_sources,
            ) {
                Ok(registry) => registry,
                Err(err) => {
                    state.provider_sources = original_sources;
                    return error_response(503, &err.to_string());
                }
            };
            runtime_tunnel.replace_registry(registry.clone());
            state.registry = registry;
            return ApiHttpResponse {
                status_code: 204,
                headers: BTreeMap::new(),
                body: Vec::new(),
            };
        }
        if let Some(raw_name) = path.strip_prefix("/providers/rules/") {
            let provider_name = percent_decode(raw_name);
            let Some(runtime_tunnel) = &self.runtime_tunnel else {
                return error_response(503, "runtime tunnel is unavailable");
            };
            let Some(bootstrap_state) = &self.bootstrap_state else {
                return error_response(503, "bootstrap state is unavailable");
            };
            let mut state = bootstrap_state.lock().unwrap();
            if !state.document.rule_providers.contains_key(&provider_name) {
                return self.not_found();
            }
            let original_sources = state.provider_sources.clone();
            if let Err(err) = state.refresh_rule_provider_sources(&provider_name, runtime_tunnel) {
                return match err {
                    BootstrapError::MissingRuleProvider(_) => self.not_found(),
                    _ => error_response(503, &err.to_string()),
                };
            }
            let rules = match compile_rule_table_with_providers(
                &state.document.rules,
                &state.document.sub_rules,
                &state.document.rule_providers,
                &state.provider_sources.file_blobs,
                &state.provider_sources.http_blobs,
            ) {
                Ok(rules) => rules,
                Err(err) => {
                    state.provider_sources = original_sources;
                    return error_response(503, &err.to_string());
                }
            };
            let dns_runtime = match state.build_dns_runtime() {
                Ok(runtime) => runtime,
                Err(err) => {
                    state.provider_sources = original_sources;
                    return error_response(503, &err.to_string());
                }
            };
            runtime_tunnel.replace_rule_set(rules);
            runtime_tunnel.replace_dns_runtime(Some(dns_runtime));
            return ApiHttpResponse {
                status_code: 204,
                headers: BTreeMap::new(),
                body: Vec::new(),
            };
        }
        match path.strip_prefix("/proxies/") {
            Some(raw_name) => {
                let group_name = percent_decode(raw_name);
                let payload = match serde_json::from_slice::<UpdateProxyRequest>(&request.body) {
                    Ok(payload) => payload,
                    Err(_) => return error_response(400, "Body invalid"),
                };
                if !self.snapshot.proxies.iter().any(|entry| entry.name == group_name)
                    && !self.snapshot.groups.iter().any(|entry| entry.name == group_name)
                {
                    return self.not_found();
                }
                let Some(runtime_tunnel) = &self.runtime_tunnel else {
                    return error_response(503, "runtime tunnel is unavailable");
                };
                match runtime_tunnel.set_group_selected(&group_name, &payload.name) {
                    Ok(()) => ApiHttpResponse {
                        status_code: 204,
                        headers: BTreeMap::new(),
                        body: Vec::new(),
                    },
                    Err(RuntimeControlError::InvalidMode(_)) => error_response(400, "Body invalid"),
                    Err(RuntimeControlError::ProxyNotFound(_)) => self.not_found(),
                    Err(RuntimeControlError::GroupNotFound(_)) => {
                        error_response(400, "Must be a Selector")
                    }
                    Err(RuntimeControlError::GroupCandidateNotFound { .. }) => error_response(
                        400,
                        &format!("Selector update error: group {group_name} does not contain candidate {}", payload.name),
                    ),
                }
            }
            None => self.method_not_allowed(),
        }
    }

    fn handle_patch_request(&self, path: &str, request: &ApiHttpRequest) -> ApiHttpResponse {
        if path == "/rules/disable" {
            let payload = match serde_json::from_slice::<BTreeMap<usize, bool>>(&request.body) {
                Ok(payload) => payload,
                Err(_) => return error_response(400, "Body invalid"),
            };
            let Some(runtime_tunnel) = &self.runtime_tunnel else {
                return error_response(503, "runtime tunnel is unavailable");
            };
            for (index, disabled) in payload {
                let _ = runtime_tunnel.set_rule_disabled(index, disabled);
            }
            return ApiHttpResponse {
                status_code: 204,
                headers: BTreeMap::new(),
                body: Vec::new(),
            };
        }
        if path != "/configs" {
            return self.method_not_allowed();
        }
        let payload = match serde_json::from_slice::<PatchConfigRequest>(&request.body) {
            Ok(payload) => payload,
            Err(_) => return error_response(400, "Body invalid"),
        };
        let Some(mode) = payload.mode else {
            return error_response(400, "Body invalid");
        };
        let Some(runtime_tunnel) = &self.runtime_tunnel else {
            return error_response(503, "runtime tunnel is unavailable");
        };
        match runtime_tunnel.set_mode(&mode) {
            Ok(()) => ApiHttpResponse {
                status_code: 204,
                headers: BTreeMap::new(),
                body: Vec::new(),
            },
            Err(RuntimeControlError::InvalidMode(_)) => error_response(400, "Body invalid"),
            Err(err) => self.internal_server_error(&err.to_string()),
        }
    }

    fn handle_delete_request(&self, path: &str) -> ApiHttpResponse {
        if let Some(raw_name) = path.strip_prefix("/proxies/") {
            let group_name = percent_decode(raw_name);
            if !self.snapshot.proxies.iter().any(|entry| entry.name == group_name)
                && !self.snapshot.groups.iter().any(|entry| entry.name == group_name)
            {
                return self.not_found();
            }
            let is_group = self.snapshot.groups.iter().any(|entry| entry.name == group_name);
            if !is_group {
                return error_response(400, "Must be a Selector");
            }
            if self
                .snapshot
                .groups
                .iter()
                .find(|entry| entry.name == group_name)
                .is_some_and(|entry| entry.group_type == "select")
            {
                return error_response(400, "Must be a Selector");
            }
            let Some(runtime_tunnel) = &self.runtime_tunnel else {
                return error_response(503, "runtime tunnel is unavailable");
            };
            return match runtime_tunnel.clear_group_selected(&group_name) {
                Ok(()) => ApiHttpResponse {
                    status_code: 204,
                    headers: BTreeMap::new(),
                    body: Vec::new(),
                },
                Err(RuntimeControlError::ProxyNotFound(_)) => self.not_found(),
                Err(RuntimeControlError::GroupNotFound(_)) => {
                    error_response(400, "Must be a Selector")
                }
                Err(err) => self.internal_server_error(&err.to_string()),
            };
        }
        if path == "/connections" {
            let Some(runtime_tunnel) = &self.runtime_tunnel else {
                return error_response(503, "runtime tunnel is unavailable");
            };
            runtime_tunnel.close_all_connections();
            return ApiHttpResponse {
                status_code: 204,
                headers: BTreeMap::new(),
                body: Vec::new(),
            };
        }
        if let Some(raw_id) = path.strip_prefix("/connections/") {
            let Some(runtime_tunnel) = &self.runtime_tunnel else {
                return error_response(503, "runtime tunnel is unavailable");
            };
            let Ok(id) = raw_id.parse::<u64>() else {
                return error_response(400, "invalid connection id");
            };
            let _ = runtime_tunnel.close_connection(id);
            return ApiHttpResponse {
                status_code: 204,
                headers: BTreeMap::new(),
                body: Vec::new(),
            };
        }
        self.method_not_allowed()
    }

    fn unauthorized(&self) -> ApiHttpResponse {
        error_response(401, "Unauthorized")
    }

    fn not_found(&self) -> ApiHttpResponse {
        error_response(404, "Resource not found")
    }

    fn method_not_allowed(&self) -> ApiHttpResponse {
        let mut response = error_response(405, "Method not allowed");
        response
            .headers
            .insert("Allow".into(), "GET, HEAD".into());
        response
    }

    fn internal_server_error(&self, message: &str) -> ApiHttpResponse {
        error_response(500, message)
    }

    fn handle_storage_get(&self, key: &str) -> ApiHttpResponse {
        let Some(storage) = &self.storage else {
            return self.not_found();
        };
        match storage.get(key) {
            Ok(Some(data)) => ApiHttpResponse {
                status_code: 200,
                headers: BTreeMap::from([("Content-Type".into(), "application/json".into())]),
                body: data,
            },
            Ok(None) => ApiHttpResponse {
                status_code: 200,
                headers: BTreeMap::from([("Content-Type".into(), "application/json".into())]),
                body: b"null".to_vec(),
            },
            Err(err) => storage_error_response(err),
        }
    }

    fn handle_storage_put(&self, key: &str, request: &ApiHttpRequest) -> ApiHttpResponse {
        let Some(storage) = &self.storage else {
            return self.not_found();
        };
        match storage.set(key, &request.body) {
            Ok(()) => ApiHttpResponse {
                status_code: 204,
                headers: BTreeMap::new(),
                body: Vec::new(),
            },
            Err(err) => storage_error_response(err),
        }
    }

    fn handle_storage_delete(&self, key: &str) -> ApiHttpResponse {
        let Some(storage) = &self.storage else {
            return self.not_found();
        };
        match storage.delete(key) {
            Ok(()) => ApiHttpResponse {
                status_code: 204,
                headers: BTreeMap::new(),
                body: Vec::new(),
            },
            Err(err) => storage_error_response(err),
        }
    }

    fn websocket_route(&self, request: &ApiHttpRequest, path: &str) -> Option<LiveWebsocketRoute> {
        if !request.method.eq_ignore_ascii_case("GET")
            || !request
                .header("upgrade")
                .is_some_and(|value| value.eq_ignore_ascii_case("websocket"))
        {
            return None;
        }

        match path {
            "/connections" => Some(LiveWebsocketRoute::Connections),
            "/traffic" => Some(LiveWebsocketRoute::Traffic),
            "/memory" => Some(LiveWebsocketRoute::Memory),
            "/logs" => Some(LiveWebsocketRoute::Logs),
            _ => None,
        }
    }

    fn http_stream_route(
        &self,
        request: &ApiHttpRequest,
        path: &str,
    ) -> Option<LiveHttpStreamRoute> {
        if !request.method.eq_ignore_ascii_case("GET")
            || request
                .header("connection")
                .is_some_and(|value| value.eq_ignore_ascii_case("close"))
        {
            return None;
        }

        match path {
            "/traffic" => Some(LiveHttpStreamRoute::Traffic),
            "/memory" => Some(LiveHttpStreamRoute::Memory),
            "/logs" => Some(LiveHttpStreamRoute::Logs),
            _ => None,
        }
    }

    fn stream_live_websocket_json<T, F>(
        &self,
        stream: Box<dyn ReadWriteStream>,
        request: &ApiHttpRequest,
        payload_fn: F,
    ) -> Result<(), ControllerError>
    where
        T: Serialize,
        F: Fn(&Self) -> T,
    {
        let interval_ms = websocket_interval_ms(request)?;
        let mut ws = self.upgrade_websocket(stream, request)?;
        let first = serde_json::to_vec(&payload_fn(self))?;
        ws.write_text_frame(&first)?;
        loop {
            thread::sleep(Duration::from_millis(interval_ms));
            let payload = serde_json::to_vec(&payload_fn(self))?;
            ws.write_text_frame(&payload)?;
        }
    }

    fn stream_live_http_json<T, F>(
        &self,
        stream: Box<dyn ReadWriteStream>,
        request: &ApiHttpRequest,
        payload_fn: F,
    ) -> Result<(), ControllerError>
    where
        T: Serialize,
        F: Fn(&Self) -> T,
    {
        let interval_ms = websocket_interval_ms(request)?;
        let mut http = self.open_chunked_json_stream(stream)?;
        let first = serde_json::to_vec(&payload_fn(self))?;
        http.write_json_chunk(&first)?;
        loop {
            thread::sleep(Duration::from_millis(interval_ms));
            let payload = serde_json::to_vec(&payload_fn(self))?;
            http.write_json_chunk(&payload)?;
        }
    }

    fn upgrade_websocket(
        &self,
        mut stream: Box<dyn ReadWriteStream>,
        request: &ApiHttpRequest,
    ) -> Result<ServerWebsocketStream, ControllerError> {
        let key = request
            .header("sec-websocket-key")
            .ok_or_else(|| ControllerError::InvalidHttpRequest("missing Sec-WebSocket-Key".into()))?;
        let accept = websocket_accept_key(key);
        write!(
            stream,
            "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
        )?;
        stream.flush()?;
        Ok(ServerWebsocketStream::new(stream))
    }

    fn open_chunked_json_stream(
        &self,
        mut stream: Box<dyn ReadWriteStream>,
    ) -> Result<ServerHttpChunkedStream, ControllerError> {
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nCache-Control: no-cache\r\nTransfer-Encoding: chunked\r\n\r\n"
        )?;
        stream.flush()?;
        Ok(ServerHttpChunkedStream::new(stream))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LiveWebsocketRoute {
    Connections,
    Traffic,
    Memory,
    Logs,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LiveHttpStreamRoute {
    Traffic,
    Memory,
    Logs,
}

#[derive(Serialize)]
struct HelloPayload<'a> {
    hello: &'a str,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct StatusPayload<'a> {
    status: &'a str,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
struct LogsPayload {
    logs: Vec<JsonValue>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
struct TrafficPayload {
    up: u64,
    down: u64,
    #[serde(rename = "upTotal")]
    up_total: u64,
    #[serde(rename = "downTotal")]
    down_total: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
struct MemoryPayload {
    inuse: u64,
    oslimit: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LogFormat {
    Plain,
    Structured,
}

#[cfg(target_os = "linux")]
fn process_resident_memory_bytes() -> Option<u64> {
    let page_size = page_size_bytes()?;
    let statm = fs::read_to_string("/proc/self/statm").ok()?;
    let resident_pages = statm.split_whitespace().nth(1)?.parse::<u64>().ok()?;
    resident_pages.checked_mul(page_size)
}

#[cfg(target_os = "macos")]
fn process_resident_memory_bytes() -> Option<u64> {
    use libc::{c_int, c_void, getpid};

    const PROC_PIDTASKINFO: c_int = 4;

    #[repr(C)]
    struct ProcTaskInfo {
        pti_virtual_size: u64,
        pti_resident_size: u64,
        pti_total_user: u64,
        pti_total_system: u64,
        pti_threads_user: u64,
        pti_threads_system: u64,
        pti_policy: i32,
        pti_faults: i32,
        pti_pageins: i32,
        pti_cow_faults: i32,
        pti_messages_sent: i32,
        pti_messages_received: i32,
        pti_syscalls_mach: i32,
        pti_syscalls_unix: i32,
        pti_csw: i32,
        pti_threadnum: i32,
        pti_numrunning: i32,
        pti_priority: i32,
    }

    unsafe extern "C" {
        fn proc_pidinfo(
            pid: i32,
            flavor: c_int,
            arg: u64,
            buffer: *mut c_void,
            buffersize: c_int,
        ) -> c_int;
    }

    let mut info = std::mem::MaybeUninit::<ProcTaskInfo>::uninit();
    let size = std::mem::size_of::<ProcTaskInfo>();
    let written = unsafe {
        proc_pidinfo(
            getpid(),
            PROC_PIDTASKINFO,
            0,
            info.as_mut_ptr().cast(),
            i32::try_from(size).ok()?,
        )
    };
    if usize::try_from(written).ok()? != size {
        return None;
    }
    Some(unsafe { info.assume_init() }.pti_resident_size)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn process_resident_memory_bytes() -> Option<u64> {
    None
}

#[cfg(target_os = "linux")]
fn page_size_bytes() -> Option<u64> {
    use libc::{_SC_PAGESIZE, sysconf};

    let size = unsafe { sysconf(_SC_PAGESIZE) };
    if size <= 0 {
        return None;
    }
    u64::try_from(size).ok()
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct ListPayload {
    proxies: BTreeMap<String, JsonValue>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct GroupListPayload {
    proxies: Vec<ApiGroupSnapshot>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct ProviderListPayload {
    providers: BTreeMap<String, ApiProxyProviderSnapshot>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct RuleProviderListPayload {
    providers: BTreeMap<String, ApiRuleProviderSnapshot>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct RulesPayload {
    rules: Vec<ApiRuleSnapshot>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct ListenersPayload {
    listeners: Vec<ApiListenerSnapshot>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct ConnectionsPayload {
    #[serde(rename = "downloadTotal")]
    download_total: u64,
    #[serde(rename = "uploadTotal")]
    upload_total: u64,
    connections: Vec<ConnectionPayload>,
    memory: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct ConnectionPayload {
    id: String,
    upload: u64,
    download: u64,
    start: u64,
    chains: Vec<String>,
    #[serde(rename = "providerChains")]
    provider_chains: Vec<String>,
    rule: String,
    #[serde(rename = "rulePayload")]
    rule_payload: String,
    metadata: ConnectionMetadataPayload,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct ConnectionMetadataPayload {
    network: String,
    #[serde(rename = "type")]
    session_type: String,
    #[serde(rename = "sourceIP")]
    source_ip: String,
    #[serde(rename = "sourcePort")]
    source_port: String,
    #[serde(rename = "destinationIP")]
    destination_ip: String,
    #[serde(rename = "destinationPort")]
    destination_port: String,
    #[serde(rename = "sourceGeoIP")]
    source_geo_ip: Vec<String>,
    #[serde(rename = "destinationGeoIP")]
    destination_geo_ip: Vec<String>,
    #[serde(rename = "sourceIPASN")]
    source_ip_asn: String,
    #[serde(rename = "destinationIPASN")]
    destination_ip_asn: String,
    #[serde(rename = "inboundIP")]
    inbound_ip: String,
    #[serde(rename = "inboundPort")]
    inbound_port: String,
    host: String,
    #[serde(rename = "dnsMode")]
    dns_mode: String,
    uid: u32,
    process: String,
    #[serde(rename = "processPath")]
    process_path: String,
    #[serde(rename = "specialProxy")]
    special_proxy: String,
    #[serde(rename = "specialRules")]
    special_rules: String,
    #[serde(rename = "remoteDestination")]
    remote_destination: String,
    dscp: u8,
    #[serde(rename = "sniffHost")]
    sniff_host: String,
    #[serde(rename = "inboundName")]
    inbound_name: String,
    #[serde(rename = "inboundUser")]
    inbound_user: String,
}

trait ReadWriteStream: Read + Write + Send {}
impl<T: Read + Write + Send> ReadWriteStream for T {}

struct ServerWebsocketStream {
    inner: Box<dyn ReadWriteStream>,
}

impl ServerWebsocketStream {
    fn new(inner: Box<dyn ReadWriteStream>) -> Self {
        Self { inner }
    }

    fn write_text_frame(&mut self, payload: &[u8]) -> std::io::Result<()> {
        self.write_frame(0x1, payload)
    }

    fn write_frame(&mut self, opcode: u8, payload: &[u8]) -> std::io::Result<()> {
        let mut header = Vec::with_capacity(10);
        header.push(0x80 | (opcode & 0x0f));
        if payload.len() < 126 {
            header.push(payload.len() as u8);
        } else if payload.len() < 65_536 {
            header.push(126);
            header.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        } else {
            header.push(127);
            header.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        }
        self.inner.write_all(&header)?;
        self.inner.write_all(payload)?;
        self.inner.flush()
    }
}

struct ServerHttpChunkedStream {
    inner: Box<dyn ReadWriteStream>,
}

impl ServerHttpChunkedStream {
    fn new(inner: Box<dyn ReadWriteStream>) -> Self {
        Self { inner }
    }

    fn write_json_chunk(&mut self, payload: &[u8]) -> std::io::Result<()> {
        let len = payload
            .len()
            .checked_add(1)
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "chunk too large"))?;
        write!(self.inner, "{len:X}\r\n")?;
        self.inner.write_all(payload)?;
        self.inner.write_all(b"\n\r\n")?;
        self.inner.flush()
    }
}

struct ServerTlsStream(StreamOwned<ServerConnection, TcpStream>);

impl Read for ServerTlsStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl Write for ServerTlsStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct ErrorPayload<'a> {
    message: &'a str,
}

#[derive(serde::Deserialize)]
struct UpdateProxyRequest {
    name: String,
}

#[derive(serde::Deserialize)]
struct PatchConfigRequest {
    mode: Option<String>,
}

fn json_response<T: Serialize>(status_code: u16, value: &T) -> Result<ApiHttpResponse, ControllerError> {
    let body = serde_json::to_vec(value)?;
    Ok(ApiHttpResponse {
        status_code,
        headers: BTreeMap::from([("Content-Type".into(), "application/json".into())]),
        body,
    })
}

fn error_response(status_code: u16, message: &str) -> ApiHttpResponse {
    json_response(status_code, &ErrorPayload { message })
        .unwrap_or_else(|_| ApiHttpResponse {
            status_code,
            headers: BTreeMap::from([("Content-Type".into(), "application/json".into())]),
            body: br#"{"message":"internal serialization error"}"#.to_vec(),
        })
}

fn storage_error_response(err: StorageError) -> ApiHttpResponse {
    match err {
        StorageError::InvalidKey | StorageError::PayloadInvalidJson => {
            error_response(400, &err.to_string())
        }
        StorageError::PayloadTooLarge => error_response(413, &err.to_string()),
        StorageError::Io(message) => error_response(500, &message),
    }
}

fn connection_payload_from_snapshot(snapshot: ActiveConnectionSnapshot) -> ConnectionPayload {
    ConnectionPayload {
        id: snapshot.id.to_string(),
        upload: snapshot.upload,
        download: snapshot.download,
        start: snapshot.start_unix_ms,
        chains: snapshot.chains,
        provider_chains: snapshot.provider_chains,
        rule: snapshot.rule,
        rule_payload: snapshot.rule_payload,
        metadata: ConnectionMetadataPayload {
            network: format!("{:?}", snapshot.metadata.network).to_ascii_lowercase(),
            session_type: format!("{:?}", snapshot.metadata.kind).to_ascii_lowercase(),
            source_ip: snapshot
                .metadata
                .src_ip
                .map(|ip| ip.to_string())
                .unwrap_or_default(),
            source_port: snapshot
                .metadata
                .src_port
                .map(|port| port.to_string())
                .unwrap_or_default(),
            destination_ip: snapshot
                .metadata
                .dst_ip
                .map(|ip| ip.to_string())
                .unwrap_or_default(),
            destination_port: snapshot
                .metadata
                .dst_port
                .map(|port| port.to_string())
                .unwrap_or_default(),
            source_geo_ip: snapshot.metadata.src_geoip.unwrap_or_default(),
            destination_geo_ip: snapshot.metadata.dst_geoip.unwrap_or_default(),
            source_ip_asn: snapshot.metadata.src_ip_asn,
            destination_ip_asn: snapshot.metadata.dst_ip_asn,
            inbound_ip: snapshot
                .metadata
                .inbound_ip
                .map(|ip| ip.to_string())
                .unwrap_or_default(),
            inbound_port: snapshot
                .metadata
                .inbound_port
                .map(|port| port.to_string())
                .unwrap_or_default(),
            host: snapshot.metadata.host.unwrap_or_default(),
            dns_mode: format!("{:?}", snapshot.metadata.dns_mode).to_ascii_lowercase(),
            uid: snapshot.metadata.uid.unwrap_or(0),
            process: snapshot.metadata.process,
            process_path: snapshot.metadata.process_path,
            special_proxy: snapshot.metadata.special_proxy,
            special_rules: snapshot.metadata.special_rules,
            remote_destination: snapshot.metadata.remote_destination,
            dscp: snapshot.metadata.dscp.unwrap_or(0),
            sniff_host: snapshot.metadata.sniff_host.unwrap_or_default(),
            inbound_name: snapshot.metadata.inbound_name,
            inbound_user: snapshot.metadata.inbound_user,
        },
    }
}

fn runtime_rule_snapshots_payload(runtime_tunnel: &RuntimeTunnel) -> Vec<ApiRuleSnapshot> {
    runtime_tunnel
        .runtime_rules_snapshot()
        .into_iter()
        .map(|snapshot| ApiRuleSnapshot {
            index: snapshot.index,
            rule_type: snapshot.definition.rule_type.as_str().to_owned(),
            payload: snapshot.definition.payload,
            target: snapshot.definition.target,
            size: -1,
            extra: Some(ApiRuleExtraSnapshot {
                disabled: snapshot.extra.disabled,
                hit_count: snapshot.extra.hit_count,
                hit_at: format_rule_time(snapshot.extra.hit_at_unix_ms),
                miss_count: snapshot.extra.miss_count,
                miss_at: format_rule_time(snapshot.extra.miss_at_unix_ms),
            }),
        })
        .collect()
}

fn format_rule_time(timestamp_unix_ms: u64) -> String {
    if timestamp_unix_ms == 0 {
        return "0001-01-01T00:00:00Z".to_owned();
    }
    let time = UNIX_EPOCH + Duration::from_millis(timestamp_unix_ms);
    DateTime::<Utc>::from(time).to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn write_http_response<W: Write>(stream: &mut W, response: &ApiHttpResponse) -> Result<(), ControllerError> {
    let reason = reason_phrase(response.status_code);
    write!(stream, "HTTP/1.1 {} {}\r\n", response.status_code, reason)?;
    for (name, value) in &response.headers {
        write!(stream, "{name}: {value}\r\n")?;
    }
    write!(stream, "Content-Length: {}\r\n", response.body.len())?;
    write!(stream, "Connection: close\r\n\r\n")?;
    stream.write_all(&response.body)?;
    stream.flush()?;
    Ok(())
}

fn parse_http_request(stream: &mut dyn Read) -> Result<ApiHttpRequest, ControllerError> {
    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line)? == 0 {
        return Err(ControllerError::InvalidHttpRequest(
            "empty request".into(),
        ));
    }

    let request_line = request_line.trim_end_matches(['\r', '\n']);
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| ControllerError::InvalidHttpRequest("missing method".into()))?
        .to_owned();
    let target = parts
        .next()
        .ok_or_else(|| ControllerError::InvalidHttpRequest("missing target".into()))?
        .to_owned();
    let version = parts
        .next()
        .ok_or_else(|| ControllerError::InvalidHttpRequest("missing version".into()))?;
    if !version.starts_with("HTTP/1.") {
        return Err(ControllerError::InvalidHttpRequest(format!(
            "unsupported version: {version}"
        )));
    }

    let mut headers = BTreeMap::new();
    loop {
        let mut line = String::new();
        let bytes = reader.read_line(&mut line)?;
        if bytes == 0 {
            break;
        }
        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            break;
        }
        let (name, value) = line.split_once(':').ok_or_else(|| {
            ControllerError::InvalidHttpRequest(format!("invalid header line: {line}"))
        })?;
        headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
    }

    let content_length = headers
        .get("content-length")
        .and_then(|raw| raw.parse::<usize>().ok())
        .unwrap_or_default();
    let mut body = vec![0; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body)?;
    }

    Ok(ApiHttpRequest {
        method,
        target,
        headers,
        body,
    })
}

fn reason_phrase(status_code: u16) -> &'static str {
    match status_code {
        200 => "OK",
        204 => "No Content",
        307 => "Temporary Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        405 => "Method Not Allowed",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "OK",
    }
}

fn split_target(target: &str) -> (&str, &str) {
    target
        .split_once('?')
        .map_or((target, ""), |(path, query)| (path, query))
}

fn dns_question_json(name: &str, query_type: DnsRecordType) -> JsonValue {
    let mut object = Map::new();
    object.insert("name".into(), JsonValue::String(dns_fqdn(name)));
    object.insert("qtype".into(), JsonValue::from(dns_record_type_code(query_type)));
    JsonValue::Object(object)
}

fn dns_answer_json(name: &str, query_type: DnsRecordType, ip: IpAddr) -> JsonValue {
    let mut object = Map::new();
    object.insert("name".into(), JsonValue::String(dns_fqdn(name)));
    object.insert("type".into(), JsonValue::from(dns_record_type_code(query_type)));
    object.insert("TTL".into(), JsonValue::from(600));
    object.insert("data".into(), JsonValue::String(ip.to_string()));
    JsonValue::Object(object)
}

fn dns_record_type_code(query_type: DnsRecordType) -> u16 {
    match query_type {
        DnsRecordType::A => 1,
        DnsRecordType::Aaaa => 28,
    }
}

fn dns_matches_query_type(ip: IpAddr, query_type: DnsRecordType) -> bool {
    matches!(
        (ip, query_type),
        (IpAddr::V4(_), DnsRecordType::A) | (IpAddr::V6(_), DnsRecordType::Aaaa)
    )
}

fn dns_fqdn(name: &str) -> String {
    if name.ends_with('.') {
        name.to_owned()
    } else {
        format!("{name}.")
    }
}

fn normalize_doh_path(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || !trimmed.starts_with('/') {
        return None;
    }
    Some(trimmed.trim_end_matches('/').to_owned())
}

fn normalize_optional_string(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_owned())
}

fn normalize_optional_path(raw: &str, home_dir: Option<&Path>) -> Option<PathBuf> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let candidate = PathBuf::from(trimmed);
    if candidate.is_absolute() {
        Some(candidate)
    } else {
        Some(home_dir.map_or(candidate.clone(), |home| home.join(candidate)))
    }
}

fn tls_string(extra: &BTreeMap<String, serde_yaml::Value>, key: &str) -> String {
    extra.get("tls")
        .and_then(serde_yaml::Value::as_mapping)
        .and_then(|mapping| mapping.get(&serde_yaml::Value::String(key.to_owned())))
        .and_then(serde_yaml::Value::as_str)
        .map(str::to_owned)
        .unwrap_or_default()
}

fn resolve_pem_source(raw: &str) -> io::Result<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    if trimmed.contains("-----BEGIN ") {
        return Ok(raw.to_owned());
    }
    fs::read_to_string(trimmed)
}

fn parse_certificates(pem: &str) -> io::Result<Vec<Certificate>> {
    if pem.trim().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "tls certificate is required when private key is set",
        ));
    }
    let mut reader = io::Cursor::new(pem.as_bytes());
    let certs = rustls_pemfile::certs(&mut reader)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;
    if certs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "failed to parse tls certificate",
        ));
    }
    Ok(certs.into_iter().map(Certificate).collect())
}

fn parse_private_key(pem: &str) -> io::Result<PrivateKey> {
    if pem.trim().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "tls private key is required when certificate is set",
        ));
    }
    let mut reader = io::Cursor::new(pem.as_bytes());
    if let Some(key) = rustls_pemfile::pkcs8_private_keys(&mut reader)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?
        .into_iter()
        .next()
    {
        return Ok(PrivateKey(key));
    }

    let mut reader = io::Cursor::new(pem.as_bytes());
    if let Some(key) = rustls_pemfile::rsa_private_keys(&mut reader)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?
        .into_iter()
        .next()
    {
        return Ok(PrivateKey(key));
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "failed to parse tls private key",
    ))
}

fn build_controller_tls_config(
    certificate: &str,
    private_key: &str,
    client_auth_type: &str,
    client_auth_cert: &str,
) -> Result<ServerConfig, ControllerError> {
    let cert_pem = resolve_pem_source(certificate)?;
    let key_pem = resolve_pem_source(private_key)?;
    let certs = parse_certificates(&cert_pem)?;
    let key = parse_private_key(&key_pem)?;

    let require_client_auth = !client_auth_type.trim().is_empty();
    if require_client_auth && client_auth_cert.trim().is_empty() {
        return Err(ControllerError::InvalidHttpRequest(
            "controller client-auth-cert is required when client-auth-type is set".into(),
        ));
    }
    if !require_client_auth && !client_auth_cert.trim().is_empty() {
        return Err(ControllerError::InvalidHttpRequest(
            "controller client-auth-type is required when client-auth-cert is set".into(),
        ));
    }

    let config = if require_client_auth {
        let client_auth_pem = resolve_pem_source(client_auth_cert)?;
        let client_auth_certs = parse_certificates(&client_auth_pem)?;
        let mut roots = rustls::RootCertStore::empty();
        for cert in client_auth_certs {
            roots
                .add(&cert)
                .map_err(|err| ControllerError::InvalidHttpRequest(err.to_string()))?;
        }
        let verifier = rustls::server::AllowAnyAuthenticatedClient::new(roots);
        ServerConfig::builder()
            .with_safe_defaults()
            .with_client_cert_verifier(Arc::new(verifier))
            .with_single_cert(certs, key)
            .map_err(|err| ControllerError::InvalidHttpRequest(err.to_string()))?
    } else {
        ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|err| ControllerError::InvalidHttpRequest(err.to_string()))?
    };
    Ok(config)
}

fn accept_tls_server_stream(
    stream: TcpStream,
    tls_config: Arc<ServerConfig>,
) -> io::Result<ServerTlsStream> {
    let conn = ServerConnection::new(tls_config)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;
    Ok(ServerTlsStream(StreamOwned::new(conn, stream)))
}

fn websocket_accept_key(key: &str) -> String {
    let mut sha1 = Sha1::new();
    sha1.update(key.as_bytes());
    sha1.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    base64::engine::general_purpose::STANDARD.encode(sha1.finalize())
}

fn parse_bearer_token(header: &str) -> Option<&str> {
    let (scheme, token) = header.split_once(' ')?;
    scheme.eq_ignore_ascii_case("bearer").then_some(token)
}

fn websocket_interval_ms(request: &ApiHttpRequest) -> Result<u64, ControllerError> {
    let (_, query) = split_target(&request.target);
    let params = parse_query(query);
    match params.get("interval") {
        Some(raw) => raw
            .parse::<u64>()
            .map_err(|_| ControllerError::InvalidHttpRequest("invalid interval".into())),
        None => Ok(1000),
    }
}

fn parse_query(query: &str) -> BTreeMap<String, String> {
    let mut parsed = BTreeMap::new();
    for pair in query.split('&').filter(|pair| !pair.is_empty()) {
        let (raw_key, raw_value) = pair.split_once('=').unwrap_or((pair, ""));
        parsed.insert(percent_decode(raw_key), percent_decode(raw_value));
    }
    parsed
}

fn percent_decode(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' if index + 2 < bytes.len() => {
                let hi = from_hex(bytes[index + 1]);
                let lo = from_hex(bytes[index + 2]);
                match (hi, lo) {
                    (Some(hi), Some(lo)) => {
                        decoded.push((hi << 4) | lo);
                        index += 3;
                        continue;
                    }
                    _ => decoded.push(bytes[index]),
                }
            }
            b'+' => decoded.push(b' '),
            byte => decoded.push(byte),
        }
        index += 1;
    }
    String::from_utf8_lossy(&decoded).into_owned()
}

fn from_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(10 + byte - b'a'),
        b'A'..=b'F' => Some(10 + byte - b'A'),
        _ => None,
    }
}

fn sanitize_ui_path(root: &Path, relative: &str) -> Option<PathBuf> {
    let mut path = root.to_path_buf();
    if relative.is_empty() {
        path.push("index.html");
        return Some(path);
    }

    for segment in relative.split('/') {
        let decoded = percent_decode(segment);
        if decoded.is_empty() {
            continue;
        }
        let candidate = Path::new(&decoded);
        if candidate
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
        {
            return None;
        }
        path.push(decoded);
    }
    Some(path)
}

fn content_type_for(path: &Path) -> &'static str {
    match path.extension().and_then(|extension| extension.to_str()) {
        Some("html") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("js") => "application/javascript; charset=utf-8",
        Some("json") => "application/json",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("ico") => "image/x-icon",
        _ => "application/octet-stream",
    }
}

fn parse_logs_query(query: &str) -> Result<(LogLevel, LogFormat), ApiHttpResponse> {
    let params = parse_query(query);
    let level = params
        .get("level")
        .map(String::as_str)
        .unwrap_or("info");
    let Some(level) = LogLevel::parse(level) else {
        return Err(error_response(400, "Body invalid"));
    };
    let format = match params.get("format").map(String::as_str).unwrap_or_default() {
        "" => LogFormat::Plain,
        "structured" => LogFormat::Structured,
        _ => return Err(error_response(400, "Body invalid")),
    };
    Ok((level, format))
}

fn encode_log_entry(entry: LogEntry, format: LogFormat) -> JsonValue {
    match format {
        LogFormat::Plain => JsonValue::Object(Map::from_iter([
            ("type".into(), JsonValue::String(entry.level.as_str().to_owned())),
            ("payload".into(), JsonValue::String(entry.message)),
        ])),
        LogFormat::Structured => JsonValue::Object(Map::from_iter([
            (
                "time".into(),
                JsonValue::String(format_log_time(entry.timestamp_unix_ms)),
            ),
            ("level".into(), JsonValue::String(entry.level.as_str().to_owned())),
            ("message".into(), JsonValue::String(entry.message)),
            ("fields".into(), JsonValue::Array(Vec::new())),
        ])),
    }
}

fn format_log_time(timestamp_unix_ms: u64) -> String {
    let seconds = (timestamp_unix_ms / 1000) % 86_400;
    let hour = seconds / 3600;
    let minute = (seconds % 3600) / 60;
    let second = seconds % 60;
    format!("{hour:02}:{minute:02}:{second:02}")
}

fn to_named_map<T, F>(entries: &[T], key: F) -> BTreeMap<String, T>
where
    T: Clone,
    F: Fn(&T) -> String,
{
    entries
        .iter()
        .map(|entry| (key(entry), entry.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::path::{Path, PathBuf};
    use std::sync::{mpsc, Arc};
    use std::thread;
    use std::time::Duration;

    use base64::Engine as _;
    use mihomo_config::parse_runtime_config_document;
    use mihomo_dns::DnsRecordType;
    use mihomo_transport::{TlsOptions, TransportTarget};
    use serde_json::Value;

    use super::{ApiControlCommand, ApiController, ApiHttpRequest};

    fn sample_document() -> mihomo_config::RuntimeConfigDocument {
        parse_runtime_config_document(
            r#"
mode: rule
secret: top-secret
external-ui: ./ui
external-controller: 127.0.0.1:9090
mixed-port: 7890
allow-lan: true
bind-address: "*"
inbound-tfo: true
inbound-mptcp: true
geox-url:
  geoip: https://geo.example/geoip.dat
  geosite: https://geo.example/geosite.dat
  mmdb: https://geo.example/geoip.mmdb
  asn: https://geo.example/asn.mmdb
geo-auto-update: true
geo-update-interval: 48
geodata-loader: standard
geosite-matcher: succinct
tuic-server:
  enable: true
  listen: 127.0.0.1:10443
  token:
    - tuic-token
  alpn:
    - h3
  max-udp-relay-packet-size: 1400
sniffer:
  enable: true
  override-destination: true
  sniffing:
    - tls
proxies:
  - type: direct
    name: direct-a
  - type: socks5
    name: edge-socks5
    server: 1.2.3.4
    port: 1080
    udp: true
    tfo: true
    mptcp: true
    interface-name: en0
    routing-mark: 9
    dialer-proxy: direct-a
    smux:
      enabled: true
proxy-groups:
  - name: auto
    type: url-test
    proxies: [direct-a, edge-socks5]
rules:
  - MATCH,auto
listeners:
  - type: socks
    name: edge-socks
    listen: 127.0.0.1
    port: "1080"
tun:
  enable: true
  stack: system
  auto-route: true
dns:
  enable: true
  listen: 0.0.0.0:53
  nameserver:
    - 8.8.8.8
"#,
        )
        .unwrap()
    }

    #[test]
    fn controller_requires_bearer_secret_on_api_routes() {
        let controller = ApiController::from_document(&sample_document()).unwrap();

        let unauthorized = controller.handle_request(&ApiHttpRequest::get("/version"));
        assert_eq!(unauthorized.status_code, 401);

        let authorized = controller.handle_request(
            &ApiHttpRequest::get("/version")
                .with_header("Authorization", "Bearer top-secret"),
        );
        assert_eq!(authorized.status_code, 200);
    }

    #[test]
    fn controller_exposes_core_json_routes() {
        let controller = ApiController::from_document(&sample_document()).unwrap();
        let request = ApiHttpRequest::get("/configs")
            .with_header("Authorization", "Bearer top-secret");
        let response = controller.handle_request(&request);
        assert_eq!(response.status_code, 200);
        assert_eq!(response.content_type(), Some("application/json"));

        let body: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body["mixed-port"], 7890);
        assert_eq!(body["mode"], "rule");
        assert!(body["bind-address"].is_string());
        assert_eq!(body["inbound-tfo"], true);
        assert_eq!(body["inbound-mptcp"], true);
        assert!(body["routing-mark"].is_i64());
        assert!(body["tcp-concurrent"].is_boolean());
        assert_eq!(body["geox-url"]["geoip"], "https://geo.example/geoip.dat");
        assert_eq!(body["geox-url"]["geosite"], "https://geo.example/geosite.dat");
        assert_eq!(body["geox-url"]["mmdb"], "https://geo.example/geoip.mmdb");
        assert_eq!(body["geox-url"]["asn"], "https://geo.example/asn.mmdb");
        assert_eq!(body["geo-auto-update"], true);
        assert_eq!(body["geo-update-interval"], 48);
        assert_eq!(body["geodata-loader"], "standard");
        assert_eq!(body["geosite-matcher"], "succinct");
        assert_eq!(body["sniffing"], true);
        assert_eq!(body["tuic-server"]["enable"], true);
        assert_eq!(body["tuic-server"]["listen"], "127.0.0.1:10443");
        assert_eq!(body["tuic-server"]["token"][0], "tuic-token");
        assert_eq!(body["tuic-server"]["alpn"][0], "h3");
        assert_eq!(body["tuic-server"]["max-udp-relay-packet-size"], 1400);
        assert_eq!(body["tun"]["stack"], "system");
        assert_eq!(body["tun"]["auto-route"], true);

        let proxies = controller.handle_request(
            &ApiHttpRequest::get("/proxies")
                .with_header("Authorization", "Bearer top-secret"),
        );
        let proxy_body: Value = serde_json::from_slice(&proxies.body).unwrap();
        assert!(proxy_body["proxies"]["direct-a"].is_object());
        assert_eq!(proxy_body["proxies"]["edge-socks5"]["type"], "socks5");
        assert_eq!(proxy_body["proxies"]["edge-socks5"]["udp"], true);
        assert_eq!(proxy_body["proxies"]["edge-socks5"]["tfo"], true);
        assert_eq!(proxy_body["proxies"]["edge-socks5"]["mptcp"], true);
        assert_eq!(proxy_body["proxies"]["edge-socks5"]["smux"], true);
        assert_eq!(proxy_body["proxies"]["edge-socks5"]["interface"], "en0");
        assert_eq!(proxy_body["proxies"]["edge-socks5"]["routing-mark"], 9);
        assert_eq!(proxy_body["proxies"]["edge-socks5"]["dialer-proxy"], "direct-a");
        assert_eq!(proxy_body["proxies"]["auto"]["type"], "url-test");
        assert_eq!(proxy_body["proxies"]["auto"]["all"][0], "direct-a");
        assert_eq!(
            proxy_body["proxies"]["auto"]["testUrl"],
            "https://www.gstatic.com/generate_204"
        );
        assert_eq!(proxy_body["proxies"]["auto"]["expectedStatus"], "*");

        let proxy = controller.handle_request(
            &ApiHttpRequest::get("/proxies/edge-socks5")
                .with_header("Authorization", "Bearer top-secret"),
        );
        let leaf_body: Value = serde_json::from_slice(&proxy.body).unwrap();
        assert_eq!(leaf_body["name"], "edge-socks5");
        assert_eq!(leaf_body["type"], "socks5");
        assert_eq!(leaf_body["udp"], true);
        assert_eq!(leaf_body["tfo"], true);
        assert_eq!(leaf_body["mptcp"], true);
        assert_eq!(leaf_body["smux"], true);
        assert_eq!(leaf_body["interface"], "en0");
        assert_eq!(leaf_body["routing-mark"], 9);
        assert_eq!(leaf_body["provider-name"], "");
        assert_eq!(leaf_body["dialer-proxy"], "direct-a");

        let rules = controller.handle_request(
            &ApiHttpRequest::get("/rules")
                .with_header("Authorization", "Bearer top-secret"),
        );
        let rule_body: Value = serde_json::from_slice(&rules.body).unwrap();
        assert_eq!(rule_body["rules"][0]["type"], "MATCH");
        assert_eq!(rule_body["rules"][0]["payload"], "");
        assert_eq!(rule_body["rules"][0]["proxy"], "auto");
        assert_eq!(rule_body["rules"][0]["size"], -1);

        let groups = controller.handle_request(
            &ApiHttpRequest::get("/group")
                .with_header("Authorization", "Bearer top-secret"),
        );
        let group_list_body: Value = serde_json::from_slice(&groups.body).unwrap();
        let groups = group_list_body["proxies"].as_array().unwrap();
        assert!(groups
            .iter()
            .any(|entry| entry["name"] == "auto" && entry["type"] == "url-test"));
    }

    #[test]
    fn controller_exposes_provider_routes() {
        let document = parse_runtime_config_document(
            r#"
secret: top-secret
proxy-providers:
  provider1:
    type: inline
    health-check:
      enable: true
      url: https://cp.example.com
      expected-status: 204
    payload:
      - name: provider-ss
        type: ss
        server: 1.2.3.4
        port: 8388
        cipher: aes-128-gcm
        password: secret
rule-providers:
  rule1:
    type: inline
    behavior: domain
    format: yaml
    payload:
      - DOMAIN-SUFFIX,example.com
proxies:
  - type: direct
    name: direct-a
"#,
        )
        .unwrap();
        let controller = ApiController::from_document(&document).unwrap();

        let proxy_providers = controller.handle_request(
            &ApiHttpRequest::get("/providers/proxies")
                .with_header("Authorization", "Bearer top-secret"),
        );
        assert_eq!(proxy_providers.status_code, 200);
        let proxy_providers_body: Value = serde_json::from_slice(&proxy_providers.body).unwrap();
        assert_eq!(proxy_providers_body["providers"]["provider1"]["type"], "Proxy");
        assert_eq!(
            proxy_providers_body["providers"]["provider1"]["vehicleType"],
            "Inline"
        );
        assert_eq!(
            proxy_providers_body["providers"]["provider1"]["testUrl"],
            "https://cp.example.com"
        );
        assert_eq!(
            proxy_providers_body["providers"]["provider1"]["expectedStatus"],
            "204"
        );
        assert_eq!(
            proxy_providers_body["providers"]["provider1"]["proxies"][0]["name"],
            "provider-ss"
        );

        let proxy_provider = controller.handle_request(
            &ApiHttpRequest::get("/providers/proxies/provider1")
                .with_header("Authorization", "Bearer top-secret"),
        );
        assert_eq!(proxy_provider.status_code, 200);
        let proxy_provider_body: Value = serde_json::from_slice(&proxy_provider.body).unwrap();
        assert_eq!(proxy_provider_body["name"], "provider1");
        assert_eq!(proxy_provider_body["proxies"][0]["type"], "ss");
        assert_eq!(proxy_provider_body["proxies"][0]["provider-name"], "provider1");
        assert_eq!(proxy_provider_body["proxies"][0]["dialer-proxy"], "");

        let provider_proxy = controller.handle_request(
            &ApiHttpRequest::get("/providers/proxies/provider1/provider-ss")
                .with_header("Authorization", "Bearer top-secret"),
        );
        assert_eq!(provider_proxy.status_code, 200);
        let provider_proxy_body: Value = serde_json::from_slice(&provider_proxy.body).unwrap();
        assert_eq!(provider_proxy_body["name"], "provider-ss");
        assert_eq!(provider_proxy_body["type"], "ss");
        assert_eq!(provider_proxy_body["provider-name"], "provider1");
        assert_eq!(provider_proxy_body["dialer-proxy"], "");

        let rule_providers = controller.handle_request(
            &ApiHttpRequest::get("/providers/rules")
                .with_header("Authorization", "Bearer top-secret"),
        );
        assert_eq!(rule_providers.status_code, 200);
        let rule_providers_body: Value = serde_json::from_slice(&rule_providers.body).unwrap();
        assert_eq!(rule_providers_body["providers"]["rule1"]["type"], "Rule");
        assert_eq!(rule_providers_body["providers"]["rule1"]["vehicleType"], "Inline");
        assert_eq!(rule_providers_body["providers"]["rule1"]["behavior"], "Domain");
        assert_eq!(rule_providers_body["providers"]["rule1"]["format"], "YamlRule");
        assert_eq!(rule_providers_body["providers"]["rule1"]["ruleCount"], 1);

        let rule_provider = controller.handle_request(
            &ApiHttpRequest::get("/providers/rules/rule1")
                .with_header("Authorization", "Bearer top-secret"),
        );
        assert_eq!(rule_provider.status_code, 200);
        let rule_provider_body: Value = serde_json::from_slice(&rule_provider.body).unwrap();
        assert_eq!(rule_provider_body["name"], "rule1");
        assert_eq!(rule_provider_body["behavior"], "Domain");
    }

    #[test]
    fn controller_bootstrap_rule_provider_routes_use_loaded_provider_content() {
        let temp = unique_temp_dir("mihomo-api-rule-provider-bootstrap");
        std::fs::create_dir_all(&temp).unwrap();
        std::fs::write(
            temp.join("rule-provider.yaml"),
            "payload:\n  - DOMAIN-SUFFIX,example.com\n  - DOMAIN,example.org\n",
        )
        .unwrap();

        let (document, provider_sources, registry) = mihomo_runtime::bootstrap_from_yaml(
            r#"
secret: top-secret
rule-providers:
  rule1:
    type: file
    behavior: classical
    format: yaml
    path: rule-provider.yaml
proxies:
  - type: direct
    name: direct-a
"#,
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
        let controller = ApiController::from_bootstrap(&state).unwrap();

        let rule_providers = controller.handle_request(
            &ApiHttpRequest::get("/providers/rules")
                .with_header("Authorization", "Bearer top-secret"),
        );
        assert_eq!(rule_providers.status_code, 200);
        let rule_providers_body: Value = serde_json::from_slice(&rule_providers.body).unwrap();
        assert_eq!(rule_providers_body["providers"]["rule1"]["type"], "Rule");
        assert_eq!(rule_providers_body["providers"]["rule1"]["vehicleType"], "File");
        assert_eq!(rule_providers_body["providers"]["rule1"]["behavior"], "Classical");
        assert_eq!(rule_providers_body["providers"]["rule1"]["format"], "YamlRule");
        assert_eq!(rule_providers_body["providers"]["rule1"]["ruleCount"], 2);

        let rule_provider = controller.handle_request(
            &ApiHttpRequest::get("/providers/rules/rule1")
                .with_header("Authorization", "Bearer top-secret"),
        );
        assert_eq!(rule_provider.status_code, 200);
        let rule_provider_body: Value = serde_json::from_slice(&rule_provider.body).unwrap();
        assert_eq!(rule_provider_body["name"], "rule1");
        assert_eq!(rule_provider_body["ruleCount"], 2);
    }

    #[test]
    fn controller_rule_provider_put_reloads_runtime_rules_and_dns() {
        let temp = unique_temp_dir("mihomo-api-rule-provider-reload");
        std::fs::create_dir_all(&temp).unwrap();
        let provider_path = temp.join("rule-provider.yaml");
        std::fs::write(&provider_path, "payload:\n  - .old.example\n").unwrap();

        let (document, provider_sources, registry) = mihomo_runtime::bootstrap_from_yaml(
            r#"
secret: top-secret
mode: rule
rule-providers:
  rule1:
    type: file
    behavior: domain
    format: yaml
    path: rule-provider.yaml
proxies:
  - type: direct
    name: direct-a
rules:
  - RULE-SET,rule1,direct-a
  - MATCH,DIRECT
dns:
  enable: true
  enhanced-mode: fake-ip
  fake-ip-filter-mode: rule
  fake-ip-filter:
    - RULE-SET,rule1,fake-ip
    - MATCH,real-ip
  nameserver:
    - 8.8.8.8
  default-nameserver:
    - 1.1.1.1
"#,
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
        let runtime_tunnel = Arc::new(state.build_runtime_tunnel().unwrap());
        let controller = ApiController::from_bootstrap(&state)
            .unwrap()
            .with_runtime_tunnel(Arc::clone(&runtime_tunnel));

        let old_metadata = mihomo_core::Metadata {
            host: Some("api.old.example".into()),
            ..mihomo_core::Metadata::default()
        };
        let new_metadata = mihomo_core::Metadata {
            host: Some("api.new.example".into()),
            ..mihomo_core::Metadata::default()
        };
        let before_old = runtime_tunnel.selected_target(&old_metadata);
        let before_new = runtime_tunnel.selected_target(&new_metadata);
        assert!(matches!(before_old.as_str(), "direct-a" | "DIRECT"));
        assert!(matches!(before_new.as_str(), "direct-a" | "DIRECT"));
        {
            let dns_runtime = runtime_tunnel.dns_runtime().unwrap();
            let dns_runtime = dns_runtime.lock().unwrap();
            assert!(dns_runtime.should_use_fake_ip("api.old.example"));
            assert!(!dns_runtime.should_use_fake_ip("api.new.example"));
        }

        std::fs::write(
            &provider_path,
            "payload:\n  - .new.example\n  - .fresh.example\n",
        )
        .unwrap();

        let update = controller.handle_request(&ApiHttpRequest {
            method: "PUT".into(),
            target: "/providers/rules/rule1".into(),
            headers: BTreeMap::from([("authorization".into(), "Bearer top-secret".into())]),
            body: Vec::new(),
        });
        assert_eq!(
            update.status_code,
            204,
            "{}",
            String::from_utf8_lossy(&update.body)
        );

        let rule_provider = controller.handle_request(
            &ApiHttpRequest::get("/providers/rules/rule1")
                .with_header("Authorization", "Bearer top-secret"),
        );
        assert_eq!(rule_provider.status_code, 200);
        let rule_provider_body: Value = serde_json::from_slice(&rule_provider.body).unwrap();
        assert_eq!(rule_provider_body["ruleCount"], 2);

        let after_old = runtime_tunnel.selected_target(&old_metadata);
        let after_new = runtime_tunnel.selected_target(&new_metadata);
        assert_ne!(before_old, after_old);
        assert_ne!(before_new, after_new);
        assert!(matches!(after_old.as_str(), "direct-a" | "DIRECT"));
        assert!(matches!(after_new.as_str(), "direct-a" | "DIRECT"));
        {
            let dns_runtime = runtime_tunnel.dns_runtime().unwrap();
            let dns_runtime = dns_runtime.lock().unwrap();
            assert!(!dns_runtime.should_use_fake_ip("api.old.example"));
            assert!(dns_runtime.should_use_fake_ip("api.new.example"));
        }
    }

    #[test]
    fn controller_http_rule_provider_put_fetches_remote_rules_and_updates_runtime() {
        let temp = unique_temp_dir("mihomo-api-http-rule-provider-reload");
        std::fs::create_dir_all(&temp).unwrap();
        let provider_path = temp.join("rule-provider.yaml");
        std::fs::write(&provider_path, "payload:\n  - .old.example\n").unwrap();
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
            assert!(request.starts_with("GET /rules.yaml HTTP/1.1\r\n"), "{request}");
            assert!(request.contains("X-Rule-Test: reload\r\n"), "{request}");
            let body = b"payload:\n  - .new.example\n  - .fresh.example\n";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(response.as_bytes()).unwrap();
            stream.write_all(body).unwrap();
        });

        let (document, provider_sources, registry) = mihomo_runtime::bootstrap_from_yaml(
            &format!(
                r#"
secret: top-secret
mode: rule
rule-providers:
  rule1:
    type: http
    behavior: domain
    format: yaml
    url: http://{addr}/rules.yaml
    path: rule-provider.yaml
    header:
      X-Rule-Test:
        - reload
proxies:
  - type: direct
    name: direct-a
rules:
  - RULE-SET,rule1,direct-a
  - MATCH,DIRECT
dns:
  enable: true
  enhanced-mode: fake-ip
  fake-ip-filter-mode: rule
  fake-ip-filter:
    - RULE-SET,rule1,fake-ip
    - MATCH,real-ip
  nameserver:
    - 8.8.8.8
  default-nameserver:
    - 1.1.1.1
"#,
                addr = addr,
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
        let runtime_tunnel = Arc::new(state.build_runtime_tunnel().unwrap());
        let controller = ApiController::from_bootstrap(&state)
            .unwrap()
            .with_runtime_tunnel(Arc::clone(&runtime_tunnel));

        let old_metadata = mihomo_core::Metadata {
            host: Some("api.old.example".into()),
            ..mihomo_core::Metadata::default()
        };
        let new_metadata = mihomo_core::Metadata {
            host: Some("api.new.example".into()),
            ..mihomo_core::Metadata::default()
        };
        let before_old = runtime_tunnel.selected_target(&old_metadata);
        let before_new = runtime_tunnel.selected_target(&new_metadata);
        assert!(matches!(before_old.as_str(), "direct-a" | "DIRECT"));
        assert!(matches!(before_new.as_str(), "direct-a" | "DIRECT"));

        let update = controller.handle_request(&ApiHttpRequest {
            method: "PUT".into(),
            target: "/providers/rules/rule1".into(),
            headers: BTreeMap::from([("authorization".into(), "Bearer top-secret".into())]),
            body: Vec::new(),
        });
        assert_eq!(
            update.status_code,
            204,
            "{}",
            String::from_utf8_lossy(&update.body)
        );
        worker.join().unwrap();

        let rule_provider = controller.handle_request(
            &ApiHttpRequest::get("/providers/rules/rule1")
                .with_header("Authorization", "Bearer top-secret"),
        );
        let rule_provider_body: Value = serde_json::from_slice(&rule_provider.body).unwrap();
        assert_eq!(rule_provider_body["ruleCount"], 2);
        assert!(matches!(before_old.as_str(), "direct-a" | "DIRECT"));
        assert!(matches!(before_new.as_str(), "direct-a" | "DIRECT"));
        assert!(runtime_tunnel
            .dns_runtime()
            .unwrap()
            .lock()
            .unwrap()
            .should_use_fake_ip("api.new.example"));
        assert!(std::fs::read_to_string(&provider_path)
            .unwrap()
            .contains(".fresh.example"));
    }

    #[test]
    fn controller_proxy_provider_put_reloads_runtime_registry_and_keeps_selection() {
        let temp = unique_temp_dir("mihomo-api-proxy-provider-reload");
        std::fs::create_dir_all(&temp).unwrap();
        let provider_path = temp.join("provider.yaml");
        std::fs::write(
            &provider_path,
            r#"
proxies:
  - name: provider-a
    type: direct
"#,
        )
        .unwrap();

        let (document, provider_sources, registry) = mihomo_runtime::bootstrap_from_yaml(
            r#"
secret: top-secret
mode: global
proxy-providers:
  provider1:
    type: file
    path: provider.yaml
proxy-groups:
  - name: selector
    type: select
    use: [provider1]
proxies:
  - type: direct
    name: local-a
"#,
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
        let runtime_tunnel = Arc::new(state.build_runtime_tunnel().unwrap());
        runtime_tunnel.set_mode("global").unwrap();
        runtime_tunnel
            .set_group_selected("selector", "provider-a")
            .unwrap();
        let controller = ApiController::from_bootstrap(&state)
            .unwrap()
            .with_runtime_tunnel(Arc::clone(&runtime_tunnel));

        let before = controller.handle_request(
            &ApiHttpRequest::get("/providers/proxies/provider1")
                .with_header("Authorization", "Bearer top-secret"),
        );
        assert_eq!(before.status_code, 200);
        let before_body: Value = serde_json::from_slice(&before.body).unwrap();
        assert_eq!(before_body["proxies"][0]["name"], "provider-a");
        assert_eq!(runtime_tunnel.group_selected("selector").as_deref(), Some("provider-a"));

        std::fs::write(
            &provider_path,
            r#"
proxies:
  - name: provider-a
    type: direct
  - name: provider-b
    type: direct
"#,
        )
        .unwrap();

        let update = controller.handle_request(&ApiHttpRequest {
            method: "PUT".into(),
            target: "/providers/proxies/provider1".into(),
            headers: BTreeMap::from([("authorization".into(), "Bearer top-secret".into())]),
            body: Vec::new(),
        });
        assert_eq!(
            update.status_code,
            204,
            "{}",
            String::from_utf8_lossy(&update.body)
        );

        let after = controller.handle_request(
            &ApiHttpRequest::get("/providers/proxies/provider1")
                .with_header("Authorization", "Bearer top-secret"),
        );
        assert_eq!(after.status_code, 200);
        let after_body: Value = serde_json::from_slice(&after.body).unwrap();
        assert_eq!(after_body["proxies"][0]["name"], "provider-a");
        assert_eq!(after_body["proxies"][1]["name"], "provider-b");

        let selector = controller.handle_request(
            &ApiHttpRequest::get("/proxies/selector")
                .with_header("Authorization", "Bearer top-secret"),
        );
        assert_eq!(selector.status_code, 200);
        let selector_body: Value = serde_json::from_slice(&selector.body).unwrap();
        assert_eq!(selector_body["all"][0], "provider-a");
        assert_eq!(selector_body["all"][1], "provider-b");
        assert_eq!(selector_body["now"], "provider-a");
        assert_eq!(selector_body["fixed"], "provider-a");
        assert_eq!(runtime_tunnel.group_selected("selector").as_deref(), Some("provider-a"));

        runtime_tunnel
            .set_group_selected("selector", "provider-b")
            .unwrap();
        let updated_selector = controller.handle_request(
            &ApiHttpRequest::get("/proxies/selector")
                .with_header("Authorization", "Bearer top-secret"),
        );
        let updated_selector_body: Value = serde_json::from_slice(&updated_selector.body).unwrap();
        assert_eq!(updated_selector_body["now"], "provider-b");
        assert_eq!(updated_selector_body["fixed"], "provider-b");
    }

    #[test]
    fn controller_http_proxy_provider_put_fetches_remote_proxies_and_updates_runtime() {
        let temp = unique_temp_dir("mihomo-api-http-proxy-provider-reload");
        std::fs::create_dir_all(&temp).unwrap();
        let provider_path = temp.join("provider.yaml");
        std::fs::write(
            &provider_path,
            r#"
proxies:
  - name: provider-a
    type: direct
"#,
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
            assert!(request.starts_with("GET /provider.yaml HTTP/1.1\r\n"), "{request}");
            assert!(request.contains("X-Test: reload\r\n"), "{request}");
            let body = b"proxies:\n  - name: provider-a\n    type: direct\n  - name: provider-b\n    type: direct\n";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(response.as_bytes()).unwrap();
            stream.write_all(body).unwrap();
        });

        let (document, provider_sources, registry) = mihomo_runtime::bootstrap_from_yaml(
            &format!(
                r#"
secret: top-secret
mode: global
proxy-providers:
  provider1:
    type: http
    url: http://{addr}/provider.yaml
    path: provider.yaml
    header:
      X-Test:
        - reload
proxy-groups:
  - name: selector
    type: select
    use: [provider1]
proxies:
  - type: direct
    name: local-a
"#,
                addr = addr,
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
        let runtime_tunnel = Arc::new(state.build_runtime_tunnel().unwrap());
        runtime_tunnel.set_mode("global").unwrap();
        runtime_tunnel
            .set_group_selected("selector", "provider-a")
            .unwrap();
        let controller = ApiController::from_bootstrap(&state)
            .unwrap()
            .with_runtime_tunnel(Arc::clone(&runtime_tunnel));

        let update = controller.handle_request(&ApiHttpRequest {
            method: "PUT".into(),
            target: "/providers/proxies/provider1".into(),
            headers: BTreeMap::from([("authorization".into(), "Bearer top-secret".into())]),
            body: Vec::new(),
        });
        assert_eq!(
            update.status_code,
            204,
            "{}",
            String::from_utf8_lossy(&update.body)
        );
        worker.join().unwrap();

        let provider = controller.handle_request(
            &ApiHttpRequest::get("/providers/proxies/provider1")
                .with_header("Authorization", "Bearer top-secret"),
        );
        let provider_body: Value = serde_json::from_slice(&provider.body).unwrap();
        assert_eq!(provider_body["proxies"][0]["name"], "provider-a");
        assert_eq!(provider_body["proxies"][1]["name"], "provider-b");
        assert_eq!(runtime_tunnel.group_selected("selector").as_deref(), Some("provider-a"));
        assert!(std::fs::read_to_string(&provider_path)
            .unwrap()
            .contains("provider-b"));
    }

    #[test]
    fn controller_rules_route_reports_runtime_extra_and_disable_updates_state() {
        let (document, _, registry) = mihomo_runtime::bootstrap_from_yaml(
            r#"
secret: top-secret
mode: rule
rules:
  - MATCH,DIRECT
proxies:
  - type: direct
    name: direct-a
"#,
            std::path::Path::new("/tmp"),
        )
        .unwrap();
        let state = mihomo_runtime::BootstrapState {
            resolved_boot: mihomo_config::BootOptions::default()
                .resolve(std::path::Path::new("/tmp"), &mihomo_config::BootEnvironment::default()),
            document,
            provider_sources: Default::default(),
            registry,
        };
        let runtime_tunnel = Arc::new(state.build_runtime_tunnel().unwrap());
        let controller = ApiController::from_bootstrap(&state)
            .unwrap()
            .with_runtime_tunnel(Arc::clone(&runtime_tunnel));

        let before = controller.handle_request(
            &ApiHttpRequest::get("/rules")
                .with_header("Authorization", "Bearer top-secret"),
        );
        let before_body: Value = serde_json::from_slice(&before.body).unwrap();
        assert_eq!(before_body["rules"][0]["type"], "MATCH");
        assert_eq!(before_body["rules"][0]["extra"]["disabled"], false);
        assert_eq!(before_body["rules"][0]["extra"]["hitCount"], 0);

        let metadata = mihomo_core::Metadata {
            host: Some("example.com".into()),
            dst_port: Some(443),
            ..mihomo_core::Metadata::default()
        };
        assert_eq!(runtime_tunnel.selected_target(&metadata), "DIRECT");

        let after_hit = controller.handle_request(
            &ApiHttpRequest::get("/rules")
                .with_header("Authorization", "Bearer top-secret"),
        );
        let after_hit_body: Value = serde_json::from_slice(&after_hit.body).unwrap();
        assert_eq!(after_hit_body["rules"][0]["extra"]["hitCount"], 1);
        assert!(after_hit_body["rules"][0]["extra"]["hitAt"].is_string());

        let disable = controller.handle_request(&ApiHttpRequest {
            method: "PATCH".into(),
            target: "/rules/disable".into(),
            headers: BTreeMap::from([(
                "authorization".into(),
                "Bearer top-secret".into(),
            )]),
            body: br#"{"0":true}"#.to_vec(),
        });
        assert_eq!(disable.status_code, 204);

        assert_eq!(runtime_tunnel.selected_target(&metadata), "COMPATIBLE");

        let after_disable = controller.handle_request(
            &ApiHttpRequest::get("/rules")
                .with_header("Authorization", "Bearer top-secret"),
        );
        let after_disable_body: Value = serde_json::from_slice(&after_disable.body).unwrap();
        assert_eq!(after_disable_body["rules"][0]["extra"]["disabled"], true);
        assert_eq!(after_disable_body["rules"][0]["extra"]["missCount"], 0);
    }

    #[test]
    fn controller_rules_route_reports_runtime_miss_counts() {
        let (document, _, registry) = mihomo_runtime::bootstrap_from_yaml(
            r#"
secret: top-secret
mode: rule
rules:
  - DOMAIN,example.com,DIRECT
proxies:
  - type: direct
    name: direct-a
"#,
            std::path::Path::new("/tmp"),
        )
        .unwrap();
        let state = mihomo_runtime::BootstrapState {
            resolved_boot: mihomo_config::BootOptions::default()
                .resolve(std::path::Path::new("/tmp"), &mihomo_config::BootEnvironment::default()),
            document,
            provider_sources: Default::default(),
            registry,
        };
        let runtime_tunnel = Arc::new(state.build_runtime_tunnel().unwrap());
        let controller = ApiController::from_bootstrap(&state)
            .unwrap()
            .with_runtime_tunnel(Arc::clone(&runtime_tunnel));

        let metadata = mihomo_core::Metadata {
            host: Some("other.example".into()),
            dst_port: Some(443),
            ..mihomo_core::Metadata::default()
        };
        assert_eq!(runtime_tunnel.selected_target(&metadata), "COMPATIBLE");

        let response = controller.handle_request(
            &ApiHttpRequest::get("/rules")
                .with_header("Authorization", "Bearer top-secret"),
        );
        let body: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body["rules"][0]["extra"]["hitCount"], 0);
        assert_eq!(body["rules"][0]["extra"]["missCount"], 1);
        assert!(body["rules"][0]["extra"]["missAt"].is_string());
    }

    #[test]
    fn controller_dns_query_route_uses_runtime_dns() {
        let (document, _, registry) = mihomo_runtime::bootstrap_from_yaml(
            r#"
secret: top-secret
hosts:
  example.com: 1.2.3.4
dns:
  enable: true
  use-hosts: true
proxies:
  - type: direct
    name: direct-a
"#,
            std::path::Path::new("/tmp"),
        )
        .unwrap();
        let state = mihomo_runtime::BootstrapState {
            resolved_boot: mihomo_config::BootOptions::default()
                .resolve(std::path::Path::new("/tmp"), &mihomo_config::BootEnvironment::default()),
            document,
            provider_sources: Default::default(),
            registry,
        };
        let runtime_tunnel = Arc::new(state.build_runtime_tunnel().unwrap());
        let controller = ApiController::from_bootstrap(&state)
            .unwrap()
            .with_runtime_tunnel(runtime_tunnel);

        let response = controller.handle_request(
            &ApiHttpRequest::get("/dns/query?name=example.com&type=A")
                .with_header("Authorization", "Bearer top-secret"),
        );
        assert_eq!(response.status_code, 200);
        let body: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body["Status"], 0);
        assert_eq!(body["Question"][0]["name"], "example.com.");
        assert_eq!(body["Question"][0]["qtype"], 1);
        assert_eq!(body["Answer"][0]["data"], "1.2.3.4");

        let invalid = controller.handle_request(
            &ApiHttpRequest::get("/dns/query?name=example.com&type=TXT")
                .with_header("Authorization", "Bearer top-secret"),
        );
        assert_eq!(invalid.status_code, 400);
    }

    #[test]
    fn controller_dns_query_route_reports_disabled_without_runtime_dns() {
        let controller = ApiController::from_document(&sample_document()).unwrap();
        let response = controller.handle_request(
            &ApiHttpRequest::get("/dns/query?name=example.com&type=A")
                .with_header("Authorization", "Bearer top-secret"),
        );
        assert_eq!(response.status_code, 500);
        let body: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body["message"], "DNS section is disabled");
    }

    #[test]
    fn controller_doh_route_uses_runtime_dns() {
        let (document, _, registry) = mihomo_runtime::bootstrap_from_yaml(
            r#"
secret: top-secret
external-doh-server: /dns-query
hosts:
  example.com: 1.2.3.4
dns:
  enable: true
  use-hosts: true
proxies:
  - type: direct
    name: direct-a
"#,
            std::path::Path::new("/tmp"),
        )
        .unwrap();
        let state = mihomo_runtime::BootstrapState {
            resolved_boot: mihomo_config::BootOptions::default()
                .resolve(std::path::Path::new("/tmp"), &mihomo_config::BootEnvironment::default()),
            document,
            provider_sources: Default::default(),
            registry,
        };
        let runtime_tunnel = Arc::new(state.build_runtime_tunnel().unwrap());
        let controller = ApiController::from_bootstrap(&state)
            .unwrap()
            .with_runtime_tunnel(runtime_tunnel);

        let query =
            mihomo_dns::build_dns_query_for_tests("example.com", DnsRecordType::A, 0x1234).unwrap();
        let query_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&query);

        let get_response = controller.handle_request(
            &ApiHttpRequest::get(format!("/dns-query?dns={query_b64}"))
                .with_header("Authorization", "Bearer top-secret"),
        );
        assert_eq!(get_response.status_code, 200);
        assert_eq!(
            get_response.content_type(),
            Some("application/dns-message")
        );
        let get_ips =
            mihomo_dns::parse_dns_response_for_tests(&get_response.body, 0x1234, DnsRecordType::A)
                .unwrap();
        assert_eq!(get_ips, vec!["1.2.3.4".parse::<std::net::IpAddr>().unwrap()]);

        let post_response = controller.handle_request(&ApiHttpRequest {
            method: "POST".into(),
            target: "/dns-query".into(),
            headers: BTreeMap::from([
                ("authorization".into(), "Bearer top-secret".into()),
                ("content-type".into(), "application/dns-message".into()),
            ]),
            body: query,
        });
        assert_eq!(post_response.status_code, 200);
        let post_ips = mihomo_dns::parse_dns_response_for_tests(
            &post_response.body,
            0x1234,
            DnsRecordType::A,
        )
        .unwrap();
        assert_eq!(post_ips, vec!["1.2.3.4".parse::<std::net::IpAddr>().unwrap()]);
    }

    #[test]
    fn controller_doh_route_reports_disabled_and_invalid_content_type() {
        let document = parse_runtime_config_document(
            r#"
secret: top-secret
external-doh-server: /dns-query
"#,
        )
        .unwrap();
        let controller = ApiController::from_document(&document).unwrap();

        let disabled = controller.handle_request(
            &ApiHttpRequest::get("/dns-query?dns=AA")
                .with_header("Authorization", "Bearer top-secret"),
        );
        assert_eq!(disabled.status_code, 500);
        assert_eq!(String::from_utf8(disabled.body).unwrap(), "DNS section is disabled");

        let (document, _, registry) = mihomo_runtime::bootstrap_from_yaml(
            r#"
secret: top-secret
external-doh-server: /dns-query
dns:
  enable: true
proxies:
  - type: direct
    name: direct-a
"#,
            std::path::Path::new("/tmp"),
        )
        .unwrap();
        let state = mihomo_runtime::BootstrapState {
            resolved_boot: mihomo_config::BootOptions::default()
                .resolve(std::path::Path::new("/tmp"), &mihomo_config::BootEnvironment::default()),
            document,
            provider_sources: Default::default(),
            registry,
        };
        let runtime_tunnel = Arc::new(state.build_runtime_tunnel().unwrap());
        let controller = ApiController::from_bootstrap(&state)
            .unwrap()
            .with_runtime_tunnel(runtime_tunnel);

        let invalid = controller.handle_request(&ApiHttpRequest {
            method: "POST".into(),
            target: "/dns-query".into(),
            headers: BTreeMap::from([("authorization".into(), "Bearer top-secret".into())]),
            body: vec![0, 1, 2],
        });
        assert_eq!(invalid.status_code, 500);
        assert_eq!(String::from_utf8(invalid.body).unwrap(), "invalid content-type");
    }

    #[test]
    fn controller_doh_route_is_not_mounted_without_external_doh_server() {
        let controller = ApiController::from_document(&sample_document()).unwrap();
        let response = controller.handle_request(
            &ApiHttpRequest::get("/dns-query?dns=AA")
                .with_header("Authorization", "Bearer top-secret"),
        );
        assert_eq!(response.status_code, 404);
    }

    #[test]
    fn controller_mounts_external_doh_server_without_bearer_auth() {
        let (document, _, registry) = mihomo_runtime::bootstrap_from_yaml(
            r#"
secret: top-secret
external-doh-server: /dns-over-https
hosts:
  example.com: 1.2.3.4
dns:
  enable: true
  use-hosts: true
proxies:
  - type: direct
    name: direct-a
"#,
            std::path::Path::new("/tmp"),
        )
        .unwrap();
        let state = mihomo_runtime::BootstrapState {
            resolved_boot: mihomo_config::BootOptions::default()
                .resolve(std::path::Path::new("/tmp"), &mihomo_config::BootEnvironment::default()),
            document,
            provider_sources: Default::default(),
            registry,
        };
        let runtime_tunnel = Arc::new(state.build_runtime_tunnel().unwrap());
        let controller = ApiController::from_bootstrap(&state)
            .unwrap()
            .with_runtime_tunnel(runtime_tunnel);

        let query =
            mihomo_dns::build_dns_query_for_tests("example.com", DnsRecordType::A, 0x2233).unwrap();
        let query_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&query);
        let response = controller.handle_request(&ApiHttpRequest::get(format!(
            "/dns-over-https?dns={query_b64}"
        )));
        assert_eq!(response.status_code, 200);
        assert_eq!(response.content_type(), Some("application/dns-message"));
        let ips =
            mihomo_dns::parse_dns_response_for_tests(&response.body, 0x2233, DnsRecordType::A)
                .unwrap();
        assert_eq!(ips, vec!["1.2.3.4".parse::<std::net::IpAddr>().unwrap()]);

        let unauthorized = controller.handle_request(&ApiHttpRequest::get("/version"));
        assert_eq!(unauthorized.status_code, 401);
    }

    #[test]
    fn controller_cache_flush_routes_use_dns_runtime() {
        let (document, _, registry) = mihomo_runtime::bootstrap_from_yaml(
            r#"
secret: top-secret
dns:
  enable: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  use-hosts: false
  nameserver: [8.8.8.8]
proxies:
  - type: direct
    name: direct-a
"#,
            std::path::Path::new("/tmp"),
        )
        .unwrap();
        let state = mihomo_runtime::BootstrapState {
            resolved_boot: mihomo_config::BootOptions::default()
                .resolve(std::path::Path::new("/tmp"), &mihomo_config::BootEnvironment::default()),
            document,
            provider_sources: Default::default(),
            registry,
        };
        let runtime_tunnel = Arc::new(state.build_runtime_tunnel().unwrap());
        {
            let runtime = runtime_tunnel.dns_runtime().unwrap();
            let mut guard = runtime.lock().unwrap();
            let _ = guard.resolve_host("fake.example").unwrap();
            let fake = guard.resolve_host("fake.example").unwrap().unwrap();
            assert!(guard.reverse_lookup(fake).is_some());
            guard
                .clear_cache();
            guard.resolve_host_via_system("localhost").ok();
            let _ = guard.cached_answer("localhost");
        }
        let controller = ApiController::from_bootstrap(&state)
            .unwrap()
            .with_runtime_tunnel(Arc::clone(&runtime_tunnel));

        let flush_dns = controller.handle_request(&ApiHttpRequest {
            method: "POST".into(),
            target: "/cache/dns/flush".into(),
            headers: BTreeMap::from([(
                "authorization".into(),
                "Bearer top-secret".into(),
            )]),
            body: Vec::new(),
        });
        assert_eq!(flush_dns.status_code, 204);
        {
            let runtime = runtime_tunnel.dns_runtime().unwrap();
            let guard = runtime.lock().unwrap();
            assert!(guard.cached_answer("localhost").is_none());
        }

        let flush_fakeip = controller.handle_request(&ApiHttpRequest {
            method: "POST".into(),
            target: "/cache/fakeip/flush".into(),
            headers: BTreeMap::from([(
                "authorization".into(),
                "Bearer top-secret".into(),
            )]),
            body: Vec::new(),
        });
        assert_eq!(flush_fakeip.status_code, 204);
        {
            let runtime = runtime_tunnel.dns_runtime().unwrap();
            let mut guard = runtime.lock().unwrap();
            let fake = guard.resolve_host("fake.example").unwrap().unwrap();
            assert_eq!(guard.reverse_lookup(fake), Some("fake.example"));
            guard.flush_fake_ip();
            assert!(guard.reverse_lookup(fake).is_none());
        }
    }

    #[test]
    fn controller_cache_flush_routes_require_runtime_dns() {
        let controller = ApiController::from_document(&sample_document()).unwrap();

        let flush_dns = controller.handle_request(&ApiHttpRequest {
            method: "POST".into(),
            target: "/cache/dns/flush".into(),
            headers: BTreeMap::from([(
                "authorization".into(),
                "Bearer top-secret".into(),
            )]),
            body: Vec::new(),
        });
        assert_eq!(flush_dns.status_code, 503);

        let flush_fakeip = controller.handle_request(&ApiHttpRequest {
            method: "POST".into(),
            target: "/cache/fakeip/flush".into(),
            headers: BTreeMap::from([(
                "authorization".into(),
                "Bearer top-secret".into(),
            )]),
            body: Vec::new(),
        });
        assert_eq!(flush_fakeip.status_code, 503);
    }

    #[test]
    fn controller_memory_route_reports_process_usage_shape() {
        let controller = ApiController::from_document(&sample_document()).unwrap();
        let response = controller.handle_request(
            &ApiHttpRequest::get("/memory")
                .with_header("Authorization", "Bearer top-secret"),
        );
        assert_eq!(response.status_code, 200);

        let body: Value = serde_json::from_slice(&response.body).unwrap();
        assert!(body["inuse"].is_u64());
        assert_eq!(body["oslimit"], 0);
    }

    #[test]
    fn controller_logs_route_reports_recent_entries() {
        mihomo_core::push_log(mihomo_core::LogLevel::Info, "recent-info-log");
        mihomo_core::push_log(mihomo_core::LogLevel::Error, "recent-error-log");

        let controller = ApiController::from_document(&sample_document()).unwrap();
        let response = controller.handle_request(
            &ApiHttpRequest::get("/logs?level=info")
                .with_header("Authorization", "Bearer top-secret"),
        );
        assert_eq!(response.status_code, 200);
        let body: Value = serde_json::from_slice(&response.body).unwrap();
        assert!(body["logs"].is_array());
        let logs = body["logs"].as_array().unwrap();
        assert!(logs.iter().any(|entry| entry["payload"] == "recent-info-log"));
        assert!(logs.iter().any(|entry| entry["payload"] == "recent-error-log"));
    }

    #[test]
    fn controller_storage_routes_roundtrip_json_payload() {
        let temp = unique_temp_dir("mihomo-api-storage-controller");
        let (document, _, registry) = mihomo_runtime::bootstrap_from_yaml(
            r#"
secret: top-secret
proxies:
  - type: direct
    name: direct-a
"#,
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
            provider_sources: Default::default(),
            registry,
        };
        let controller = ApiController::from_bootstrap(&state).unwrap();

        let put = controller.handle_request(&ApiHttpRequest {
            method: "PUT".into(),
            target: "/storage/theme".into(),
            headers: BTreeMap::from([(
                "authorization".into(),
                "Bearer top-secret".into(),
            )]),
            body: br#"{"mode":"dark"}"#.to_vec(),
        });
        assert_eq!(put.status_code, 204);

        let get = controller.handle_request(
            &ApiHttpRequest::get("/storage/theme")
                .with_header("Authorization", "Bearer top-secret"),
        );
        assert_eq!(get.status_code, 200);
        assert_eq!(get.content_type(), Some("application/json"));
        let body: Value = serde_json::from_slice(&get.body).unwrap();
        assert_eq!(body["mode"], "dark");

        let delete = controller.handle_request(&ApiHttpRequest {
            method: "DELETE".into(),
            target: "/storage/theme".into(),
            headers: BTreeMap::from([(
                "authorization".into(),
                "Bearer top-secret".into(),
            )]),
            body: Vec::new(),
        });
        assert_eq!(delete.status_code, 204);

        let missing = controller.handle_request(
            &ApiHttpRequest::get("/storage/theme")
                .with_header("Authorization", "Bearer top-secret"),
        );
        assert_eq!(missing.status_code, 200);
        assert_eq!(String::from_utf8(missing.body).unwrap(), "null");

        let _ = fs::remove_dir_all(temp);
    }

    #[test]
    fn controller_storage_routes_reject_invalid_input() {
        let temp = unique_temp_dir("mihomo-api-storage-invalid");
        let (document, _, registry) = mihomo_runtime::bootstrap_from_yaml(
            r#"
secret: top-secret
proxies:
  - type: direct
    name: direct-a
"#,
            &temp,
        )
        .unwrap();
        let state = mihomo_runtime::BootstrapState {
            resolved_boot: mihomo_config::BootOptions {
                home_dir: Some(temp.to_string_lossy().into_owned()),
                ..Default::default()
            }
            .resolve(&temp, &mihomo_config::BootEnvironment::default()),
            document,
            provider_sources: Default::default(),
            registry,
        };
        let controller = ApiController::from_bootstrap(&state).unwrap();

        let invalid_json = controller.handle_request(&ApiHttpRequest {
            method: "PUT".into(),
            target: "/storage/good".into(),
            headers: BTreeMap::from([(
                "authorization".into(),
                "Bearer top-secret".into(),
            )]),
            body: b"not-json".to_vec(),
        });
        assert_eq!(invalid_json.status_code, 400);

        let invalid_key = controller.handle_request(&ApiHttpRequest {
            method: "PUT".into(),
            target: "/storage/bad/key".into(),
            headers: BTreeMap::from([(
                "authorization".into(),
                "Bearer top-secret".into(),
            )]),
            body: br#"{"ok":true}"#.to_vec(),
        });
        assert_eq!(invalid_key.status_code, 400);

        let too_large = controller.handle_request(&ApiHttpRequest {
            method: "PUT".into(),
            target: "/storage/large".into(),
            headers: BTreeMap::from([(
                "authorization".into(),
                "Bearer top-secret".into(),
            )]),
            body: format!("\"{}\"", "a".repeat(1024 * 1024)).into_bytes(),
        });
        assert_eq!(too_large.status_code, 413);

        let _ = fs::remove_dir_all(temp);
    }

    #[test]
    fn controller_redirects_and_serves_ui_assets() {
        let temp_dir = unique_temp_dir("mihomo-api-ui");
        fs::create_dir_all(&temp_dir).unwrap();
        fs::write(temp_dir.join("index.html"), "<html>mihomo</html>").unwrap();

        let mut document = sample_document();
        document.external_ui = temp_dir.to_string_lossy().into_owned();
        let controller = ApiController::from_document(&document).unwrap();

        let redirect = controller.handle_request(&ApiHttpRequest::get("/ui"));
        assert_eq!(redirect.status_code, 307);
        assert_eq!(redirect.headers.get("Location"), Some(&"/ui/".to_owned()));

        let page = controller.handle_request(&ApiHttpRequest::get("/ui/"));
        assert_eq!(page.status_code, 200);
        assert_eq!(page.content_type(), Some("text/html; charset=utf-8"));
        assert_eq!(String::from_utf8(page.body).unwrap(), "<html>mihomo</html>");

        let _ = fs::remove_dir_all(temp_dir);
    }

    #[test]
    fn controller_serves_over_tcp_http() {
        let controller = ApiController::from_document(&sample_document()).unwrap();
        let mut server = controller.serve("127.0.0.1:0").unwrap();

        let mut stream = TcpStream::connect(server.local_addr()).unwrap();
        stream
            .write_all(
                b"GET /version HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer top-secret\r\nConnection: close\r\n\r\n",
            )
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();

        assert!(response.contains("HTTP/1.1 200 OK"));
        assert!(response.contains("\"meta\":\"mihomo-rust\""));

        server.shutdown();
    }

    #[cfg(unix)]
    #[test]
    fn controller_serves_over_unix_http() {
        use std::os::unix::net::UnixStream;

        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let socket_path = std::env::temp_dir().join(format!("mhapi-{nanos}.sock"));
        let document = parse_runtime_config_document(&format!(
            r#"
secret: top-secret
external-controller-unix: {}
proxies:
  - type: direct
    name: direct-a
"#,
            socket_path.display()
        ))
        .unwrap();
        let controller = ApiController::from_document(&document).unwrap();
        let mut server = controller.serve_unix(&socket_path).unwrap();

        let mut stream = UnixStream::connect(&socket_path).unwrap();
        stream
            .write_all(
                b"GET /version HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer top-secret\r\nConnection: close\r\n\r\n",
            )
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();

        assert!(response.contains("HTTP/1.1 200 OK"));
        assert!(response.contains("\"meta\":\"mihomo-rust\""));

        server.shutdown();
        let _ = fs::remove_file(socket_path);
    }

    #[cfg(unix)]
    #[test]
    fn controller_serves_connections_over_unix_websocket() {
        let (document, _, registry) = mihomo_runtime::bootstrap_from_yaml(
            r#"
secret: top-secret
proxies:
  - type: direct
    name: direct-a
"#,
            std::path::Path::new("/tmp"),
        )
        .unwrap();
        let state = mihomo_runtime::BootstrapState {
            resolved_boot: mihomo_config::BootOptions::default()
                .resolve(std::path::Path::new("/tmp"), &mihomo_config::BootEnvironment::default()),
            document,
            provider_sources: Default::default(),
            registry,
        };
        let runtime_tunnel = Arc::new(state.build_runtime_tunnel().unwrap());
        let controller = ApiController::from_bootstrap(&state)
            .unwrap()
            .with_runtime_tunnel(runtime_tunnel);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let socket_path = std::env::temp_dir().join(format!("mhapi-unix-ws-connections-{nanos}.sock"));
        let mut server = controller.serve_unix(&socket_path).unwrap();

        let payload = unix_websocket_first_json_frame(
            &socket_path,
            b"GET /connections?token=top-secret HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGVzdC1rZXk=\r\n\r\n",
        );
        assert!(payload["connections"].is_array());
        assert!(payload["downloadTotal"].is_u64());
        assert!(payload["uploadTotal"].is_u64());

        server.shutdown();
        let _ = fs::remove_file(socket_path);
    }

    #[cfg(unix)]
    #[test]
    fn controller_serves_traffic_over_unix_websocket() {
        let (document, _, registry) = mihomo_runtime::bootstrap_from_yaml(
            r#"
secret: top-secret
proxies:
  - type: direct
    name: direct-a
"#,
            std::path::Path::new("/tmp"),
        )
        .unwrap();
        let state = mihomo_runtime::BootstrapState {
            resolved_boot: mihomo_config::BootOptions::default()
                .resolve(std::path::Path::new("/tmp"), &mihomo_config::BootEnvironment::default()),
            document,
            provider_sources: Default::default(),
            registry,
        };
        let runtime_tunnel = Arc::new(state.build_runtime_tunnel().unwrap());
        let controller = ApiController::from_bootstrap(&state)
            .unwrap()
            .with_runtime_tunnel(runtime_tunnel);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let socket_path = std::env::temp_dir().join(format!("mhapi-unix-ws-traffic-{nanos}.sock"));
        let mut server = controller.serve_unix(&socket_path).unwrap();

        let payload = unix_websocket_first_json_frame(
            &socket_path,
            b"GET /traffic?token=top-secret HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGVzdC1rZXk=\r\n\r\n",
        );
        assert!(payload["up"].is_u64());
        assert!(payload["down"].is_u64());
        assert!(payload["upTotal"].is_u64());
        assert!(payload["downTotal"].is_u64());

        server.shutdown();
        let _ = fs::remove_file(socket_path);
    }

    #[cfg(unix)]
    #[test]
    fn controller_streams_memory_over_unix_plain_http_keepalive() {
        let controller = ApiController::from_document(&sample_document()).unwrap();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let socket_path = std::env::temp_dir().join(format!("mhapi-unix-http-memory-{nanos}.sock"));
        let mut server = controller.serve_unix(&socket_path).unwrap();

        let (headers, chunks) = unix_http_chunked_json_chunks(
            &socket_path,
            b"GET /memory HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer top-secret\r\nConnection: keep-alive\r\n\r\n",
            2,
        );
        assert!(headers.contains("HTTP/1.1 200 OK"));
        assert!(headers.contains("Transfer-Encoding: chunked"));
        assert!(chunks[0]["inuse"].is_u64());
        assert_eq!(chunks[0]["oslimit"], 0);
        assert!(chunks[1]["inuse"].is_u64());

        server.shutdown();
        let _ = fs::remove_file(socket_path);
    }

    #[cfg(unix)]
    #[test]
    fn controller_unix_does_not_require_bearer_auth() {
        use std::os::unix::net::UnixStream;

        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let socket_path = std::env::temp_dir().join(format!("mhapi-noauth-{nanos}.sock"));
        let document = parse_runtime_config_document(&format!(
            r#"
secret: top-secret
external-controller-unix: {}
proxies:
  - type: direct
    name: direct-a
"#,
            socket_path.display()
        ))
        .unwrap();
        let controller = ApiController::from_document(&document).unwrap();
        let mut server = controller.serve_unix(&socket_path).unwrap();

        let mut stream = UnixStream::connect(&socket_path).unwrap();
        stream
            .write_all(b"GET /version HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();

        assert!(response.contains("HTTP/1.1 200 OK"));
        assert!(response.contains("\"meta\":\"mihomo-rust\""));

        server.shutdown();
        let _ = fs::remove_file(socket_path);
    }

    #[cfg(unix)]
    #[test]
    fn controller_bootstrap_resolves_relative_unix_path_from_home_dir() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let temp = PathBuf::from(format!("/private/tmp/mh{nanos}"));
        let (document, _, registry) = mihomo_runtime::bootstrap_from_yaml(
            r#"
secret: top-secret
external-controller-unix: sockets/controller.sock
proxies:
  - type: direct
    name: direct-a
"#,
            &temp,
        )
        .unwrap();
        let state = mihomo_runtime::BootstrapState {
            resolved_boot: mihomo_config::BootOptions {
                home_dir: Some(temp.to_string_lossy().into_owned()),
                ..Default::default()
            }
            .resolve(&temp, &mihomo_config::BootEnvironment::default()),
            document,
            provider_sources: Default::default(),
            registry,
        };
        let mut server = ApiController::serve_unix_bootstrap(&state).unwrap();
        let socket_path = temp.join("sockets").join("controller.sock");
        assert!(socket_path.exists());
        server.shutdown();
        let _ = fs::remove_dir_all(temp);
    }

    #[test]
    fn controller_serves_connections_over_websocket() {
        let (document, _, registry) = mihomo_runtime::bootstrap_from_yaml(
            r#"
secret: top-secret
proxies:
  - type: direct
    name: direct-a
"#,
            std::path::Path::new("/tmp"),
        )
        .unwrap();
        let state = mihomo_runtime::BootstrapState {
            resolved_boot: mihomo_config::BootOptions::default()
                .resolve(std::path::Path::new("/tmp"), &mihomo_config::BootEnvironment::default()),
            document,
            provider_sources: Default::default(),
            registry,
        };
        let runtime_tunnel = Arc::new(state.build_runtime_tunnel().unwrap());
        let controller = ApiController::from_bootstrap(&state)
            .unwrap()
            .with_runtime_tunnel(runtime_tunnel);
        let mut server = controller.serve("127.0.0.1:0").unwrap();

        let mut stream = TcpStream::connect(server.local_addr()).unwrap();
        stream
            .write_all(
                b"GET /connections?token=top-secret HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGVzdC1rZXk=\r\n\r\n",
            )
            .unwrap();

        let mut response = Vec::new();
        let mut chunk = [0_u8; 2048];
        loop {
            let read = stream.read(&mut chunk).unwrap();
            assert!(read > 0);
            response.extend_from_slice(&chunk[..read]);
            if response.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        let text = String::from_utf8_lossy(&response);
        assert!(text.contains("HTTP/1.1 101 Switching Protocols"));
        assert!(text.contains("Sec-WebSocket-Accept: q1afNcDAAG7OEvwNq1HTIQYA1EM="));

        let frame_start = response
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|offset| offset + 4)
            .unwrap();
        while response.len() == frame_start {
            let read = stream.read(&mut chunk).unwrap();
            assert!(read > 0);
            response.extend_from_slice(&chunk[..read]);
        }
        while response.len() < frame_start + websocket_server_frame_len(&response[frame_start..]) {
            let read = stream.read(&mut chunk).unwrap();
            assert!(read > 0);
            response.extend_from_slice(&chunk[..read]);
        }
        let frame = &response[frame_start..];
        let payload = decode_server_websocket_text_frame(frame);
        let body: Value = serde_json::from_slice(&payload).unwrap();
        assert!(body["connections"].is_array());
        assert!(body["downloadTotal"].is_u64());
        assert!(body["uploadTotal"].is_u64());

        server.shutdown();
    }

    #[test]
    fn controller_serves_traffic_over_websocket() {
        let (document, _, registry) = mihomo_runtime::bootstrap_from_yaml(
            r#"
secret: top-secret
proxies:
  - type: direct
    name: direct-a
"#,
            std::path::Path::new("/tmp"),
        )
        .unwrap();
        let state = mihomo_runtime::BootstrapState {
            resolved_boot: mihomo_config::BootOptions::default()
                .resolve(std::path::Path::new("/tmp"), &mihomo_config::BootEnvironment::default()),
            document,
            provider_sources: Default::default(),
            registry,
        };
        let runtime_tunnel = Arc::new(state.build_runtime_tunnel().unwrap());
        let controller = ApiController::from_bootstrap(&state)
            .unwrap()
            .with_runtime_tunnel(runtime_tunnel);
        let mut server = controller.serve("127.0.0.1:0").unwrap();

        let payload = websocket_first_json_frame(
            server.local_addr(),
            b"GET /traffic?token=top-secret HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGVzdC1rZXk=\r\n\r\n",
        );
        assert!(payload["up"].is_u64());
        assert!(payload["down"].is_u64());
        assert!(payload["upTotal"].is_u64());
        assert!(payload["downTotal"].is_u64());

        server.shutdown();
    }

    #[test]
    fn controller_serves_logs_over_websocket() {
        let controller = ApiController::from_document(&sample_document()).unwrap();
        let mut server = controller.serve("127.0.0.1:0").unwrap();

        let addr = server.local_addr();
        let join = thread::spawn(|| {
            thread::sleep(Duration::from_millis(50));
            mihomo_core::push_log(mihomo_core::LogLevel::Warn, "ws-log-entry");
        });

        let first = websocket_first_json_frame(
            addr,
            b"GET /logs?level=info&token=top-secret HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGVzdC1rZXk=\r\n\r\n",
        );
        assert!(first["payload"].is_string());
        assert!(first["type"].is_string());

        join.join().unwrap();
        server.shutdown();
    }

    #[test]
    fn controller_serves_memory_over_websocket() {
        let controller = ApiController::from_document(&sample_document()).unwrap();
        let mut server = controller.serve("127.0.0.1:0").unwrap();

        let payload = websocket_first_json_frame(
            server.local_addr(),
            b"GET /memory?token=top-secret HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGVzdC1rZXk=\r\n\r\n",
        );
        assert!(payload["inuse"].is_u64());
        assert_eq!(payload["oslimit"], 0);

        server.shutdown();
    }

    #[test]
    fn controller_streams_traffic_over_plain_http_keepalive() {
        let (document, _, registry) = mihomo_runtime::bootstrap_from_yaml(
            r#"
secret: top-secret
proxies:
  - type: direct
    name: direct-a
"#,
            std::path::Path::new("/tmp"),
        )
        .unwrap();
        let state = mihomo_runtime::BootstrapState {
            resolved_boot: mihomo_config::BootOptions::default()
                .resolve(std::path::Path::new("/tmp"), &mihomo_config::BootEnvironment::default()),
            document,
            provider_sources: Default::default(),
            registry,
        };
        let runtime_tunnel = Arc::new(state.build_runtime_tunnel().unwrap());
        let controller = ApiController::from_bootstrap(&state)
            .unwrap()
            .with_runtime_tunnel(runtime_tunnel);
        let mut server = controller.serve("127.0.0.1:0").unwrap();

        let (headers, chunks) = http_chunked_json_chunks(
            server.local_addr(),
            b"GET /traffic HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer top-secret\r\nConnection: keep-alive\r\n\r\n",
            2,
        );
        assert!(headers.contains("HTTP/1.1 200 OK"));
        assert!(headers.contains("Transfer-Encoding: chunked"));
        assert!(chunks[0]["up"].is_u64());
        assert!(chunks[0]["down"].is_u64());
        assert!(chunks[0]["upTotal"].is_u64());
        assert!(chunks[0]["downTotal"].is_u64());
        assert!(chunks[1]["up"].is_u64());

        server.shutdown();
    }

    #[test]
    fn controller_streams_memory_over_plain_http_keepalive() {
        let controller = ApiController::from_document(&sample_document()).unwrap();
        let mut server = controller.serve("127.0.0.1:0").unwrap();

        let (headers, chunks) = http_chunked_json_chunks(
            server.local_addr(),
            b"GET /memory HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer top-secret\r\nConnection: keep-alive\r\n\r\n",
            2,
        );
        assert!(headers.contains("HTTP/1.1 200 OK"));
        assert!(headers.contains("Transfer-Encoding: chunked"));
        assert!(chunks[0]["inuse"].is_u64());
        assert_eq!(chunks[0]["oslimit"], 0);
        assert!(chunks[1]["inuse"].is_u64());

        server.shutdown();
    }

    #[test]
    fn controller_streams_logs_over_plain_http_keepalive() {
        let controller = ApiController::from_document(&sample_document()).unwrap();
        let mut server = controller.serve("127.0.0.1:0").unwrap();
        let addr = server.local_addr();
        let join = thread::spawn(|| {
            thread::sleep(Duration::from_millis(50));
            mihomo_core::push_log(mihomo_core::LogLevel::Error, "http-log-entry");
        });

        let (headers, chunks) = http_chunked_json_chunks(
            addr,
            b"GET /logs?level=info HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer top-secret\r\nConnection: keep-alive\r\n\r\n",
            2,
        );
        assert!(headers.contains("HTTP/1.1 200 OK"));
        assert!(headers.contains("Transfer-Encoding: chunked"));
        assert!(chunks.iter().all(|chunk| chunk["payload"].is_string()));
        assert!(chunks.iter().all(|chunk| chunk["type"].is_string()));
        assert!(chunks.iter().any(|chunk| chunk["payload"] == "http-log-entry"));

        join.join().unwrap();
        server.shutdown();
    }

    #[test]
    fn controller_serves_connections_over_tls_websocket() {
        let temp = unique_temp_dir("mihomo-api-tls-ws-connections");
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();
        let (document, _, registry) = mihomo_runtime::bootstrap_from_yaml(
            &format!(
                r#"
secret: top-secret
external-controller-tls: 127.0.0.1:0
tls:
  certificate: |
{cert}
  private-key: |
{key}
proxies:
  - type: direct
    name: direct-a
"#,
                cert = indent_pem(&cert_pem),
                key = indent_pem(&key_pem),
            ),
            &temp,
        )
        .unwrap();
        mihomo_transport::register_test_root_certificate(&cert_pem).unwrap();
        let state = mihomo_runtime::BootstrapState {
            resolved_boot: mihomo_config::BootOptions::default()
                .resolve(&temp, &mihomo_config::BootEnvironment::default()),
            document,
            provider_sources: Default::default(),
            registry,
        };
        let runtime_tunnel = Arc::new(state.build_runtime_tunnel().unwrap());
        let controller = ApiController::from_bootstrap(&state)
            .unwrap()
            .with_runtime_tunnel(runtime_tunnel);
        let mut server = controller.serve_tls("127.0.0.1:0").unwrap();

        let payload = tls_websocket_first_json_frame(
            server.local_addr(),
            b"GET /connections?token=top-secret HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGVzdC1rZXk=\r\n\r\n",
        );
        assert!(payload["connections"].is_array());
        assert!(payload["downloadTotal"].is_u64());
        assert!(payload["uploadTotal"].is_u64());

        server.shutdown();
        let _ = fs::remove_dir_all(temp);
    }

    #[test]
    fn controller_serves_traffic_over_tls_websocket() {
        let temp = unique_temp_dir("mihomo-api-tls-ws-traffic");
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();
        let (document, _, registry) = mihomo_runtime::bootstrap_from_yaml(
            &format!(
                r#"
secret: top-secret
external-controller-tls: 127.0.0.1:0
tls:
  certificate: |
{cert}
  private-key: |
{key}
proxies:
  - type: direct
    name: direct-a
"#,
                cert = indent_pem(&cert_pem),
                key = indent_pem(&key_pem),
            ),
            &temp,
        )
        .unwrap();
        mihomo_transport::register_test_root_certificate(&cert_pem).unwrap();
        let state = mihomo_runtime::BootstrapState {
            resolved_boot: mihomo_config::BootOptions::default()
                .resolve(&temp, &mihomo_config::BootEnvironment::default()),
            document,
            provider_sources: Default::default(),
            registry,
        };
        let runtime_tunnel = Arc::new(state.build_runtime_tunnel().unwrap());
        let controller = ApiController::from_bootstrap(&state)
            .unwrap()
            .with_runtime_tunnel(runtime_tunnel);
        let mut server = controller.serve_tls("127.0.0.1:0").unwrap();

        let payload = tls_websocket_first_json_frame(
            server.local_addr(),
            b"GET /traffic?token=top-secret HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGVzdC1rZXk=\r\n\r\n",
        );
        assert!(payload["up"].is_u64());
        assert!(payload["down"].is_u64());
        assert!(payload["upTotal"].is_u64());
        assert!(payload["downTotal"].is_u64());

        server.shutdown();
        let _ = fs::remove_dir_all(temp);
    }

    #[test]
    fn controller_streams_memory_over_tls_plain_http_keepalive() {
        let temp = unique_temp_dir("mihomo-api-tls-http-memory");
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();
        let document = parse_runtime_config_document(&format!(
            r#"
secret: top-secret
external-controller-tls: 127.0.0.1:0
tls:
  certificate: |
{cert}
  private-key: |
{key}
"#,
            cert = indent_pem(&cert_pem),
            key = indent_pem(&key_pem),
        ))
        .unwrap();
        mihomo_transport::register_test_root_certificate(&cert_pem).unwrap();
        let controller = ApiController::from_document(&document).unwrap();
        let mut server = controller.serve_tls("127.0.0.1:0").unwrap();

        let (headers, chunks) = tls_http_chunked_json_chunks(
            server.local_addr(),
            b"GET /memory HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer top-secret\r\nConnection: keep-alive\r\n\r\n",
            2,
        );
        assert!(headers.contains("HTTP/1.1 200 OK"));
        assert!(headers.contains("Transfer-Encoding: chunked"));
        assert!(chunks[0]["inuse"].is_u64());
        assert_eq!(chunks[0]["oslimit"], 0);
        assert!(chunks[1]["inuse"].is_u64());

        server.shutdown();
        let _ = fs::remove_dir_all(temp);
    }

    #[test]
    fn controller_put_proxy_updates_runtime_backed_snapshot() {
        let (document, _, registry) = mihomo_runtime::bootstrap_from_yaml(
            r#"
secret: top-secret
proxy-groups:
  - name: selector
    type: select
    proxies: [leaf-a, leaf-b]
proxies:
  - type: direct
    name: leaf-a
  - type: direct
    name: leaf-b
"#,
            std::path::Path::new("/tmp"),
        )
        .unwrap();
        let state = mihomo_runtime::BootstrapState {
            resolved_boot: mihomo_config::BootOptions::default()
                .resolve(std::path::Path::new("/tmp"), &mihomo_config::BootEnvironment::default()),
            document,
            provider_sources: Default::default(),
            registry,
        };
        let runtime_tunnel = Arc::new(state.build_runtime_tunnel().unwrap());
        let controller = ApiController::from_bootstrap(&state)
            .unwrap()
            .with_runtime_tunnel(Arc::clone(&runtime_tunnel));

        let update = controller.handle_request(&ApiHttpRequest {
            method: "PUT".into(),
            target: "/proxies/selector".into(),
            headers: BTreeMap::from([(
                "authorization".into(),
                "Bearer top-secret".into(),
            )]),
            body: br#"{"name":"leaf-b"}"#.to_vec(),
        });
        assert_eq!(update.status_code, 204);

        let current = controller.handle_request(
            &ApiHttpRequest::get("/proxies/selector")
                .with_header("Authorization", "Bearer top-secret"),
        );
        let body: Value = serde_json::from_slice(&current.body).unwrap();
        assert_eq!(body["type"], "select");
        assert_eq!(body["all"][0], "leaf-a");
        assert_eq!(body["all"][1], "leaf-b");
        assert_eq!(body["now"], "leaf-b");
        assert_eq!(body["fixed"], "leaf-b");

        let group = controller.handle_request(
            &ApiHttpRequest::get("/group/selector")
                .with_header("Authorization", "Bearer top-secret"),
        );
        let group_body: Value = serde_json::from_slice(&group.body).unwrap();
        assert_eq!(group_body["type"], "select");
        assert_eq!(group_body["all"][0], "leaf-a");
        assert_eq!(group_body["all"][1], "leaf-b");
        assert_eq!(group_body["now"], "leaf-b");
        assert_eq!(group_body["fixed"], "leaf-b");
        assert_eq!(group_body["testUrl"], "");
        assert_eq!(group_body["expectedStatus"], "*");
    }

    #[test]
    fn controller_delete_proxy_clears_runtime_backed_url_test_selection() {
        let (document, _, registry) = mihomo_runtime::bootstrap_from_yaml(
            r#"
secret: top-secret
proxy-groups:
  - name: auto
    type: url-test
    proxies: [leaf-a, leaf-b]
proxies:
  - type: direct
    name: leaf-a
  - type: direct
    name: leaf-b
"#,
            std::path::Path::new("/tmp"),
        )
        .unwrap();
        let state = mihomo_runtime::BootstrapState {
            resolved_boot: mihomo_config::BootOptions::default()
                .resolve(std::path::Path::new("/tmp"), &mihomo_config::BootEnvironment::default()),
            document,
            provider_sources: Default::default(),
            registry,
        };
        let runtime_tunnel = Arc::new(state.build_runtime_tunnel().unwrap());
        let controller = ApiController::from_bootstrap(&state)
            .unwrap()
            .with_runtime_tunnel(Arc::clone(&runtime_tunnel));

        let update = controller.handle_request(&ApiHttpRequest {
            method: "PUT".into(),
            target: "/proxies/auto".into(),
            headers: BTreeMap::from([(
                "authorization".into(),
                "Bearer top-secret".into(),
            )]),
            body: br#"{"name":"leaf-b"}"#.to_vec(),
        });
        assert_eq!(update.status_code, 204);
        assert_eq!(runtime_tunnel.group_selected("auto").as_deref(), Some("leaf-b"));

        let delete = controller.handle_request(&ApiHttpRequest {
            method: "DELETE".into(),
            target: "/proxies/auto".into(),
            headers: BTreeMap::from([(
                "authorization".into(),
                "Bearer top-secret".into(),
            )]),
            body: Vec::new(),
        });
        assert_eq!(delete.status_code, 204);
        assert_eq!(runtime_tunnel.group_selected("auto"), None);

        let current = controller.handle_request(
            &ApiHttpRequest::get("/proxies/auto")
                .with_header("Authorization", "Bearer top-secret"),
        );
        let body: Value = serde_json::from_slice(&current.body).unwrap();
        assert_eq!(body["type"], "url-test");
        assert_eq!(body["all"][0], "leaf-a");
        assert_eq!(body["all"][1], "leaf-b");
        assert_eq!(body["now"], "leaf-a");
        assert!(body["fixed"].is_null());
        assert_eq!(body["testUrl"], "https://www.gstatic.com/generate_204");
        assert_eq!(body["expectedStatus"], "*");

        let group = controller.handle_request(
            &ApiHttpRequest::get("/group/auto")
                .with_header("Authorization", "Bearer top-secret"),
        );
        let group_body: Value = serde_json::from_slice(&group.body).unwrap();
        assert_eq!(group_body["type"], "url-test");
        assert_eq!(group_body["all"][0], "leaf-a");
        assert_eq!(group_body["all"][1], "leaf-b");
        assert_eq!(group_body["now"], "leaf-a");
        assert!(group_body["fixed"].is_null());
        assert_eq!(group_body["testUrl"], "https://www.gstatic.com/generate_204");
        assert_eq!(group_body["expectedStatus"], "*");
    }

    #[test]
    fn controller_delete_proxy_rejects_non_selector() {
        let (document, _, registry) = mihomo_runtime::bootstrap_from_yaml(
            r#"
secret: top-secret
proxies:
  - type: direct
    name: direct-a
"#,
            std::path::Path::new("/tmp"),
        )
        .unwrap();
        let state = mihomo_runtime::BootstrapState {
            resolved_boot: mihomo_config::BootOptions::default()
                .resolve(std::path::Path::new("/tmp"), &mihomo_config::BootEnvironment::default()),
            document,
            provider_sources: Default::default(),
            registry,
        };
        let runtime_tunnel = Arc::new(state.build_runtime_tunnel().unwrap());
        let controller = ApiController::from_bootstrap(&state)
            .unwrap()
            .with_runtime_tunnel(runtime_tunnel);

        let response = controller.handle_request(&ApiHttpRequest {
            method: "DELETE".into(),
            target: "/proxies/direct-a".into(),
            headers: BTreeMap::from([(
                "authorization".into(),
                "Bearer top-secret".into(),
            )]),
            body: Vec::new(),
        });
        assert_eq!(response.status_code, 400);
        let body: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body["message"], "Must be a Selector");
    }

    #[test]
    fn controller_delete_proxy_rejects_select_group() {
        let (document, _, registry) = mihomo_runtime::bootstrap_from_yaml(
            r#"
secret: top-secret
proxy-groups:
  - name: selector
    type: select
    proxies: [leaf-a, leaf-b]
proxies:
  - type: direct
    name: leaf-a
  - type: direct
    name: leaf-b
"#,
            std::path::Path::new("/tmp"),
        )
        .unwrap();
        let state = mihomo_runtime::BootstrapState {
            resolved_boot: mihomo_config::BootOptions::default()
                .resolve(std::path::Path::new("/tmp"), &mihomo_config::BootEnvironment::default()),
            document,
            provider_sources: Default::default(),
            registry,
        };
        let runtime_tunnel = Arc::new(state.build_runtime_tunnel().unwrap());
        let controller = ApiController::from_bootstrap(&state)
            .unwrap()
            .with_runtime_tunnel(runtime_tunnel);

        let response = controller.handle_request(&ApiHttpRequest {
            method: "DELETE".into(),
            target: "/proxies/selector".into(),
            headers: BTreeMap::from([(
                "authorization".into(),
                "Bearer top-secret".into(),
            )]),
            body: Vec::new(),
        });
        assert_eq!(response.status_code, 400);
        let body: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body["message"], "Must be a Selector");
    }

    #[test]
    fn controller_post_restart_emits_control_command() {
        let (control_tx, control_rx) = mpsc::channel();
        let controller = ApiController::from_document(&sample_document())
            .unwrap()
            .with_control_tx(control_tx);

        let response = controller.handle_request(&ApiHttpRequest {
            method: "POST".into(),
            target: "/restart".into(),
            headers: BTreeMap::from([(
                "authorization".into(),
                "Bearer top-secret".into(),
            )]),
            body: Vec::new(),
        });
        assert_eq!(response.status_code, 200);
        let body: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body["status"], "ok");
        assert_eq!(
            control_rx.recv_timeout(Duration::from_secs(1)).unwrap(),
            ApiControlCommand::Restart
        );
    }

    #[test]
    fn controller_patch_configs_updates_runtime_mode_snapshot() {
        let (document, _, registry) = mihomo_runtime::bootstrap_from_yaml(
            r#"
mode: direct
secret: top-secret
proxies:
  - type: direct
    name: direct-a
"#,
            std::path::Path::new("/tmp"),
        )
        .unwrap();
        let state = mihomo_runtime::BootstrapState {
            resolved_boot: mihomo_config::BootOptions::default()
                .resolve(std::path::Path::new("/tmp"), &mihomo_config::BootEnvironment::default()),
            document,
            provider_sources: Default::default(),
            registry,
        };
        let runtime_tunnel = Arc::new(state.build_runtime_tunnel().unwrap());
        let controller = ApiController::from_bootstrap(&state)
            .unwrap()
            .with_runtime_tunnel(Arc::clone(&runtime_tunnel));

        let update = controller.handle_request(&ApiHttpRequest {
            method: "PATCH".into(),
            target: "/configs".into(),
            headers: BTreeMap::from([(
                "authorization".into(),
                "Bearer top-secret".into(),
            )]),
            body: br#"{"mode":"global"}"#.to_vec(),
        });
        assert_eq!(update.status_code, 204);
        assert_eq!(runtime_tunnel.current_mode(), "global");

        let current = controller.handle_request(
            &ApiHttpRequest::get("/configs")
                .with_header("Authorization", "Bearer top-secret"),
        );
        let body: Value = serde_json::from_slice(&current.body).unwrap();
        assert_eq!(body["mode"], "global");
    }

    #[test]
    fn controller_delete_connections_requires_runtime_tunnel() {
        let controller = ApiController::from_document(&sample_document()).unwrap();

        let delete_all = controller.handle_request(&ApiHttpRequest {
            method: "DELETE".into(),
            target: "/connections".into(),
            headers: BTreeMap::from([(
                "authorization".into(),
                "Bearer top-secret".into(),
            )]),
            body: Vec::new(),
        });
        assert_eq!(delete_all.status_code, 503);

        let delete_one = controller.handle_request(&ApiHttpRequest {
            method: "DELETE".into(),
            target: "/connections/1".into(),
            headers: BTreeMap::from([(
                "authorization".into(),
                "Bearer top-secret".into(),
            )]),
            body: Vec::new(),
        });
        assert_eq!(delete_one.status_code, 503);
    }

    #[test]
    fn controller_delete_connection_rejects_invalid_id() {
        let (document, _, registry) = mihomo_runtime::bootstrap_from_yaml(
            r#"
secret: top-secret
proxies:
  - type: direct
    name: direct-a
"#,
            std::path::Path::new("/tmp"),
        )
        .unwrap();
        let state = mihomo_runtime::BootstrapState {
            resolved_boot: mihomo_config::BootOptions::default()
                .resolve(std::path::Path::new("/tmp"), &mihomo_config::BootEnvironment::default()),
            document,
            provider_sources: Default::default(),
            registry,
        };
        let runtime_tunnel = Arc::new(state.build_runtime_tunnel().unwrap());
        let controller = ApiController::from_bootstrap(&state)
            .unwrap()
            .with_runtime_tunnel(runtime_tunnel);

        let response = controller.handle_request(&ApiHttpRequest {
            method: "DELETE".into(),
            target: "/connections/not-a-number".into(),
            headers: BTreeMap::from([(
                "authorization".into(),
                "Bearer top-secret".into(),
            )]),
            body: Vec::new(),
        });
        assert_eq!(response.status_code, 400);
        let body: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body["message"], "invalid connection id");
    }

    #[test]
    fn controller_memory_route_works_with_runtime_tunnel() {
        let (document, _, registry) = mihomo_runtime::bootstrap_from_yaml(
            r#"
secret: top-secret
proxies:
  - type: direct
    name: direct-a
"#,
            std::path::Path::new("/tmp"),
        )
        .unwrap();
        let state = mihomo_runtime::BootstrapState {
            resolved_boot: mihomo_config::BootOptions::default()
                .resolve(std::path::Path::new("/tmp"), &mihomo_config::BootEnvironment::default()),
            document,
            provider_sources: Default::default(),
            registry,
        };
        let runtime_tunnel = Arc::new(state.build_runtime_tunnel().unwrap());
        let controller = ApiController::from_bootstrap(&state)
            .unwrap()
            .with_runtime_tunnel(runtime_tunnel);

        let response = controller.handle_request(
            &ApiHttpRequest::get("/memory")
                .with_header("Authorization", "Bearer top-secret"),
        );
        assert_eq!(response.status_code, 200);

        let body: Value = serde_json::from_slice(&response.body).unwrap();
        assert!(body["inuse"].is_u64());
        assert_eq!(body["oslimit"], 0);
    }

    fn unique_temp_dir(prefix: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{nanos}"))
    }

    fn websocket_first_json_frame(addr: SocketAddr, request: &[u8]) -> Value {
        let mut stream = TcpStream::connect(addr).unwrap();
        stream.write_all(request).unwrap();

        let mut response = Vec::new();
        let mut chunk = [0_u8; 2048];
        loop {
            let read = stream.read(&mut chunk).unwrap();
            assert!(read > 0);
            response.extend_from_slice(&chunk[..read]);
            if response.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        let text = String::from_utf8_lossy(&response);
        assert!(text.contains("HTTP/1.1 101 Switching Protocols"));
        assert!(text.contains("Sec-WebSocket-Accept: q1afNcDAAG7OEvwNq1HTIQYA1EM="));

        let frame_start = response
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|offset| offset + 4)
            .unwrap();
        while response.len() == frame_start {
            let read = stream.read(&mut chunk).unwrap();
            assert!(read > 0);
            response.extend_from_slice(&chunk[..read]);
        }
        while response.len() < frame_start + websocket_server_frame_len(&response[frame_start..]) {
            let read = stream.read(&mut chunk).unwrap();
            assert!(read > 0);
            response.extend_from_slice(&chunk[..read]);
        }
        let frame = &response[frame_start..];
        let payload = decode_server_websocket_text_frame(frame);
        serde_json::from_slice(&payload).unwrap()
    }

    fn tls_websocket_first_json_frame(addr: SocketAddr, request: &[u8]) -> Value {
        let mut stream = tls_client_stream(addr);
        stream.write_all(request).unwrap();

        let mut response = Vec::new();
        let mut chunk = [0_u8; 2048];
        loop {
            let read = stream.read(&mut chunk).unwrap();
            assert!(read > 0);
            response.extend_from_slice(&chunk[..read]);
            if response.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        let text = String::from_utf8_lossy(&response);
        assert!(text.contains("HTTP/1.1 101 Switching Protocols"));
        assert!(text.contains("Sec-WebSocket-Accept: q1afNcDAAG7OEvwNq1HTIQYA1EM="));

        let frame_start = response
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|offset| offset + 4)
            .unwrap();
        while response.len() == frame_start {
            let read = stream.read(&mut chunk).unwrap();
            assert!(read > 0);
            response.extend_from_slice(&chunk[..read]);
        }
        while response.len() < frame_start + websocket_server_frame_len(&response[frame_start..]) {
            let read = stream.read(&mut chunk).unwrap();
            assert!(read > 0);
            response.extend_from_slice(&chunk[..read]);
        }
        let frame = &response[frame_start..];
        let payload = decode_server_websocket_text_frame(frame);
        serde_json::from_slice(&payload).unwrap()
    }

    fn http_chunked_json_chunks(
        addr: SocketAddr,
        request: &[u8],
        expected_chunks: usize,
    ) -> (String, Vec<Value>) {
        let mut stream = TcpStream::connect(addr).unwrap();
        stream.write_all(request).unwrap();

        let mut header_buf = Vec::new();
        let mut byte = [0_u8; 1];
        loop {
            stream.read_exact(&mut byte).unwrap();
            header_buf.push(byte[0]);
            if header_buf.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        let headers = String::from_utf8(header_buf).unwrap();

        let mut chunks = Vec::new();
        for _ in 0..expected_chunks {
            let len = read_chunk_len(&mut stream);
            let mut payload = vec![0_u8; len];
            stream.read_exact(&mut payload).unwrap();
            let mut crlf = [0_u8; 2];
            stream.read_exact(&mut crlf).unwrap();
            assert_eq!(&crlf, b"\r\n");
            let payload = if payload.ends_with(b"\n") {
                &payload[..payload.len() - 1]
            } else {
                &payload[..]
            };
            chunks.push(serde_json::from_slice(payload).unwrap());
        }

        (headers, chunks)
    }

    fn tls_http_chunked_json_chunks(
        addr: SocketAddr,
        request: &[u8],
        expected_chunks: usize,
    ) -> (String, Vec<Value>) {
        let mut stream = tls_client_stream(addr);
        stream.write_all(request).unwrap();

        let mut header_buf = Vec::new();
        let mut byte = [0_u8; 1];
        loop {
            stream.read_exact(&mut byte).unwrap();
            header_buf.push(byte[0]);
            if header_buf.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        let headers = String::from_utf8(header_buf).unwrap();

        let mut chunks = Vec::new();
        for _ in 0..expected_chunks {
            let len = read_chunk_len(&mut *stream);
            let mut payload = vec![0_u8; len];
            stream.read_exact(&mut payload).unwrap();
            let mut crlf = [0_u8; 2];
            stream.read_exact(&mut crlf).unwrap();
            assert_eq!(&crlf, b"\r\n");
            let payload = if payload.ends_with(b"\n") {
                &payload[..payload.len() - 1]
            } else {
                &payload[..]
            };
            chunks.push(serde_json::from_slice(payload).unwrap());
        }

        (headers, chunks)
    }

    #[cfg(unix)]
    fn unix_websocket_first_json_frame(socket_path: &Path, request: &[u8]) -> Value {
        use std::os::unix::net::UnixStream;

        let mut stream = UnixStream::connect(socket_path).unwrap();
        stream.write_all(request).unwrap();

        let mut response = Vec::new();
        let mut chunk = [0_u8; 2048];
        loop {
            let read = stream.read(&mut chunk).unwrap();
            assert!(read > 0);
            response.extend_from_slice(&chunk[..read]);
            if response.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }

        let text = String::from_utf8_lossy(&response);
        assert!(text.contains("101 Switching Protocols"));
        assert!(text.contains("Sec-WebSocket-Accept: q1afNcDAAG7OEvwNq1HTIQYA1EM="));

        let frame_start = response
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|offset| offset + 4)
            .unwrap();
        while response.len() == frame_start {
            let read = stream.read(&mut chunk).unwrap();
            assert!(read > 0);
            response.extend_from_slice(&chunk[..read]);
        }
        while response.len() < frame_start + websocket_server_frame_len(&response[frame_start..]) {
            let read = stream.read(&mut chunk).unwrap();
            assert!(read > 0);
            response.extend_from_slice(&chunk[..read]);
        }
        let frame = &response[frame_start..];
        let payload = decode_server_websocket_text_frame(frame);
        serde_json::from_slice(&payload).unwrap()
    }

    #[cfg(unix)]
    fn unix_http_chunked_json_chunks(
        socket_path: &Path,
        request: &[u8],
        expected_chunks: usize,
    ) -> (String, Vec<Value>) {
        use std::os::unix::net::UnixStream;

        let mut stream = UnixStream::connect(socket_path).unwrap();
        stream.write_all(request).unwrap();

        let mut header_buf = Vec::new();
        let mut byte = [0_u8; 1];
        loop {
            stream.read_exact(&mut byte).unwrap();
            header_buf.push(byte[0]);
            if header_buf.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        let headers = String::from_utf8(header_buf).unwrap();

        let mut chunks = Vec::new();
        for _ in 0..expected_chunks {
            let len = read_chunk_len(&mut stream);
            let mut payload = vec![0_u8; len];
            stream.read_exact(&mut payload).unwrap();
            let mut crlf = [0_u8; 2];
            stream.read_exact(&mut crlf).unwrap();
            assert_eq!(&crlf, b"\r\n");
            let payload = if payload.ends_with(b"\n") {
                &payload[..payload.len() - 1]
            } else {
                &payload[..]
            };
            chunks.push(serde_json::from_slice(payload).unwrap());
        }

        (headers, chunks)
    }

    fn tls_client_stream(addr: SocketAddr) -> mihomo_core::BoxedTcpStream {
        let socket = TcpStream::connect(addr).unwrap();
        mihomo_transport::wrap_tls_proxy_stream(
            Box::new(socket),
            TransportTarget::new("localhost", addr.port()),
            &TlsOptions {
                enabled: true,
                sni: "localhost".into(),
                skip_cert_verify: false,
                fingerprint: String::new(),
                certificate: String::new(),
                private_key: String::new(),
            },
            &[],
        )
        .unwrap()
    }

    fn indent_pem(pem: &str) -> String {
        pem.lines()
            .map(|line| format!("    {line}"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn read_chunk_len(stream: &mut dyn Read) -> usize {
        let mut line = Vec::new();
        let mut byte = [0_u8; 1];
        loop {
            stream.read_exact(&mut byte).unwrap();
            line.push(byte[0]);
            if line.ends_with(b"\r\n") {
                break;
            }
        }
        let line = String::from_utf8(line).unwrap();
        usize::from_str_radix(line.trim(), 16).unwrap()
    }

    fn decode_server_websocket_text_frame(frame: &[u8]) -> Vec<u8> {
        assert!(frame.len() >= 2);
        assert_eq!(frame[0] & 0x0f, 0x1);
        assert_eq!(frame[1] & 0x80, 0);
        let mut len = usize::from(frame[1] & 0x7f);
        let mut offset = 2;
        if len == 126 {
            len = usize::from(u16::from_be_bytes([frame[2], frame[3]]));
            offset = 4;
        } else if len == 127 {
            len = u64::from_be_bytes(frame[2..10].try_into().unwrap()) as usize;
            offset = 10;
        }
        frame[offset..offset + len].to_vec()
    }

    fn websocket_server_frame_len(frame: &[u8]) -> usize {
        assert!(frame.len() >= 2);
        let len = usize::from(frame[1] & 0x7f);
        match len {
            126 => 4 + usize::from(u16::from_be_bytes([frame[2], frame[3]])),
            127 => 10 + u64::from_be_bytes(frame[2..10].try_into().unwrap()) as usize,
            other => 2 + other,
        }
    }
}
