#[derive(Clone)]
pub(super) struct Hy2RealmServer {
    state: Arc<Mutex<RealmServerState>>,
    realm_token: String,
    max_realms: usize,
    max_realms_per_ip: usize,
    proxy_header: String,
    realm_id_pattern: Regex,
}

impl std::fmt::Debug for Hy2RealmServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hy2RealmServer")
            .field("max_realms", &self.max_realms)
            .field("max_realms_per_ip", &self.max_realms_per_ip)
            .field("proxy_header", &self.proxy_header)
            .field("realm_id_pattern", &self.realm_id_pattern.as_str())
            .finish()
    }
}

struct RealmServerState {
    realms: HashMap<String, Arc<RealmSession>>,
    sessions: HashMap<String, Arc<RealmSession>>,
    ip_counts: HashMap<String, usize>,
}

struct RealmSession {
    id: String,
    realm_id: String,
    inner: Mutex<RealmSessionInner>,
    event_ready: Condvar,
}

struct RealmSessionInner {
    addresses: Vec<String>,
    expires_at: Instant,
    closed: bool,
    client_ip: String,
    events: VecDeque<SessionEvent>,
    pending: BTreeMap<String, std::sync::mpsc::SyncSender<PunchResponsePayload>>,
}

#[derive(Clone)]
struct SessionEvent {
    kind: String,
    data: serde_json::Value,
}

#[derive(Clone, Default)]
struct PunchResponsePayload {
    addresses: Vec<String>,
}

#[derive(Serialize)]
struct PunchEvent<'a> {
    addresses: &'a [String],
    nonce: &'a str,
    obfs: &'a str,
}

impl Hy2RealmServer {
    pub(super) fn new(config: &Hy2RealmListenerConfig) -> Result<Self, io::Error> {
        Ok(Self {
            state: Arc::new(Mutex::new(RealmServerState {
                realms: HashMap::new(),
                sessions: HashMap::new(),
                ip_counts: HashMap::new(),
            })),
            realm_token: config.token.clone(),
            max_realms: config.max_realms,
            max_realms_per_ip: config.max_realms_per_ip,
            proxy_header: config.trusted_proxy_header.clone(),
            realm_id_pattern: Regex::new(&config.realm_name_pattern)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?,
        })
    }

    pub(super) fn handle_stream(&self, stream: &mut dyn MihomoTcpStream) -> io::Result<()> {
        let request = parse_http_request(stream)?;
        let response = self.handle_request(&request, peer_ip_from_request(&request, &self.proxy_header));
        write_http_response(stream, response)
    }

    fn handle_request(&self, request: &SimpleHttpRequest, remote_ip: String) -> SimpleHttpResponse {
        let (path, _) = split_target(&request.target);
        let segments = path.trim_start_matches('/').split('/').collect::<Vec<_>>();
        match (request.method.as_str(), segments.as_slice()) {
            ("POST", ["v1", realm_id]) => self.register(realm_id, request, &remote_ip),
            ("DELETE", ["v1", realm_id]) => self.deregister(realm_id, request, &remote_ip),
            ("GET", ["v1", realm_id, "events"]) => self.events(realm_id, request, &remote_ip),
            ("POST", ["v1", realm_id, "heartbeat"]) => self.heartbeat(realm_id, request, &remote_ip),
            ("POST", ["v1", realm_id, "connect"]) => self.connect(realm_id, request, &remote_ip),
            ("POST", ["v1", realm_id, "connects", nonce]) => {
                self.connect_response(realm_id, nonce, request, &remote_ip)
            }
            ("POST" | "GET" | "DELETE", _) => http_response(404, &json_error("not_found", "unknown path")),
            _ => http_response(405, &json_error("bad_request", "method not allowed")),
        }
    }

    fn register(&self, realm_id: &str, request: &SimpleHttpRequest, remote_ip: &str) -> SimpleHttpResponse {
        if !self.realm_id_pattern.is_match(realm_id) {
            return http_response(400, &json_error("bad_request", "invalid realm name"));
        }
        if bearer_token(request) != self.realm_token {
            return http_response(401, &json_error("invalid_token", "invalid realm token"));
        }
        let body: AddressesBody = match serde_json::from_slice(&request.body) {
            Ok(body) => body,
            Err(_) => return http_response(400, &json_error("bad_request", "invalid json")),
        };
        if let Err(err) = validate_addresses(&body.addresses) {
            return http_response(400, &json_error("bad_request", &err));
        }

        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(_) => return http_response(500, &json_error("bad_request", "server state poisoned")),
        };
        if state.realms.contains_key(realm_id) {
            return http_response(409, &json_error("realm_taken", "realm already registered"));
        }
        if self.max_realms > 0 && state.realms.len() >= self.max_realms {
            return http_response(429, &json_error("realm_limit_reached", "global realm limit reached"));
        }
        if self.max_realms_per_ip > 0
            && state.ip_counts.get(remote_ip).copied().unwrap_or_default() >= self.max_realms_per_ip
        {
            return http_response(429, &json_error("ip_limit_reached", "per-ip realm limit reached"));
        }

        let session = Arc::new(RealmSession {
            id: hex_token(),
            realm_id: realm_id.to_owned(),
            inner: Mutex::new(RealmSessionInner {
                addresses: body.addresses.clone(),
                expires_at: Instant::now() + SESSION_TTL,
                closed: false,
                client_ip: remote_ip.to_owned(),
                events: VecDeque::new(),
                pending: BTreeMap::new(),
            }),
            event_ready: Condvar::new(),
        });
        state.realms.insert(realm_id.to_owned(), Arc::clone(&session));
        state.sessions.insert(session.id.clone(), Arc::clone(&session));
        *state.ip_counts.entry(remote_ip.to_owned()).or_default() += 1;
        drop(state);

        json_response(200, &serde_json::json!({
            "session_id": session.id,
            "ttl": SESSION_TTL.as_secs(),
        }))
    }

    fn deregister(&self, realm_id: &str, request: &SimpleHttpRequest, _remote_ip: &str) -> SimpleHttpResponse {
        let Some(session) = self.get_session_by_bearer(request) else {
            return http_response(401, &json_error("invalid_token", "invalid session token"));
        };
        if session.realm_id != realm_id {
            return http_response(401, &json_error("invalid_token", "invalid session token"));
        }
        self.remove_session(&session);
        http_response(204, "")
    }

    fn heartbeat(&self, realm_id: &str, request: &SimpleHttpRequest, _remote_ip: &str) -> SimpleHttpResponse {
        let Some(session) = self.get_session_by_bearer(request) else {
            return http_response(401, &json_error("invalid_token", "invalid session token"));
        };
        if session.realm_id != realm_id {
            return http_response(401, &json_error("invalid_token", "invalid session token"));
        }
        let body = if request.body.is_empty() {
            HeartbeatBody { addresses: None }
        } else {
            match serde_json::from_slice::<HeartbeatBody>(&request.body) {
                Ok(body) => body,
                Err(_) => return http_response(400, &json_error("bad_request", "invalid json")),
            }
        };
        if let Some(addresses) = &body.addresses {
            if let Err(err) = validate_addresses(addresses) {
                return http_response(400, &json_error("bad_request", &err));
            }
        }
        let mut inner = match session.inner.lock() {
            Ok(inner) => inner,
            Err(_) => return http_response(500, &json_error("bad_request", "server state poisoned")),
        };
        if inner.closed {
            return http_response(401, &json_error("invalid_token", "invalid session token"));
        }
        inner.expires_at = Instant::now() + SESSION_TTL;
        if let Some(addresses) = body.addresses {
            inner.addresses = addresses;
        }
        inner.events.push_back(SessionEvent {
            kind: "heartbeat_ack".to_owned(),
            data: serde_json::json!({ "ttl": SESSION_TTL.as_secs() }),
        });
        while inner.events.len() > EVENTS_BUFFER_SIZE {
            inner.events.pop_front();
        }
        session.event_ready.notify_all();
        drop(inner);
        json_response(200, &serde_json::json!({ "ttl": SESSION_TTL.as_secs() }))
    }

    fn events(&self, realm_id: &str, request: &SimpleHttpRequest, _remote_ip: &str) -> SimpleHttpResponse {
        let Some(session) = self.get_session_by_bearer(request) else {
            return http_response(401, &json_error("invalid_token", "invalid session token"));
        };
        if session.realm_id != realm_id {
            return http_response(401, &json_error("invalid_token", "invalid session token"));
        }
        let mut inner = match session.inner.lock() {
            Ok(inner) => inner,
            Err(_) => return http_response(500, &json_error("bad_request", "server state poisoned")),
        };
        if inner.closed {
            return http_response(401, &json_error("invalid_token", "invalid session token"));
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        while inner.events.is_empty() && !inner.closed {
            let wait_for = deadline.saturating_duration_since(Instant::now());
            if wait_for.is_zero() {
                break;
            }
            let (next_inner, _) = session
                .event_ready
                .wait_timeout(inner, wait_for)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            inner = next_inner;
        }
        if inner.closed {
            return http_response(401, &json_error("invalid_token", "invalid session token"));
        }
        let mut body = String::new();
        while let Some(event) = inner.events.pop_front() {
            body.push_str("event: ");
            body.push_str(&event.kind);
            body.push_str("\ndata: ");
            body.push_str(&event.data.to_string());
            body.push_str("\n\n");
        }
        SimpleHttpResponse {
            status_code: 200,
            headers: vec![
                ("Content-Type".to_owned(), "text/event-stream".to_owned()),
                ("Cache-Control".to_owned(), "no-cache".to_owned()),
                ("Connection".to_owned(), "close".to_owned()),
            ],
            body: body.into_bytes(),
        }
    }

    fn connect(&self, realm_id: &str, request: &SimpleHttpRequest, _remote_ip: &str) -> SimpleHttpResponse {
        if !self.realm_id_pattern.is_match(realm_id) {
            return http_response(400, &json_error("bad_request", "invalid realm name"));
        }
        if bearer_token(request) != self.realm_token {
            return http_response(401, &json_error("invalid_token", "invalid realm token"));
        }
        let body: ConnectBody = match serde_json::from_slice(&request.body) {
            Ok(body) => body,
            Err(_) => return http_response(400, &json_error("bad_request", "invalid json")),
        };
        if let Err(err) = validate_addresses(&body.addresses) {
            return http_response(400, &json_error("bad_request", &err));
        }
        if let Err(err) = validate_hex_field("nonce", &body.nonce, NONCE_HEX_LEN) {
            return http_response(400, &json_error("bad_request", &err));
        }
        if let Err(err) = validate_hex_field("obfs", &body.obfs, OBFS_HEX_LEN) {
            return http_response(400, &json_error("bad_request", &err));
        }

        let Some(session) = self.get_realm_session(realm_id) else {
            return http_response(404, &json_error("realm_not_found", "realm not registered"));
        };
        let server_addresses = {
            let inner = match session.inner.lock() {
                Ok(inner) => inner,
                Err(_) => return http_response(500, &json_error("bad_request", "server state poisoned")),
            };
            if inner.closed || Instant::now() > inner.expires_at {
                return http_response(404, &json_error("realm_not_found", "realm not registered"));
            }
            inner.addresses.clone()
        };

        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        {
            let mut inner = match session.inner.lock() {
                Ok(inner) => inner,
                Err(_) => return http_response(500, &json_error("bad_request", "server state poisoned")),
            };
            if inner.pending.len() >= MAX_PENDING_ATTEMPTS {
                return http_response(
                    503,
                    &json_error("rate_limited", "too many in-flight connect attempts"),
                );
            }
            if inner.pending.contains_key(&body.nonce) {
                return http_response(
                    503,
                    &json_error("rate_limited", "too many in-flight connect attempts"),
                );
            }
            inner.pending.insert(body.nonce.clone(), tx);
            inner.events.push_back(SessionEvent {
                kind: "punch".to_owned(),
                data: serde_json::to_value(PunchEvent {
                    addresses: &body.addresses,
                    nonce: &body.nonce,
                    obfs: &body.obfs,
                })
                .unwrap_or(serde_json::json!({})),
            });
            while inner.events.len() > EVENTS_BUFFER_SIZE {
                inner.events.pop_front();
            }
            session.event_ready.notify_all();
        }

        let response = match rx.recv_timeout(CONNECT_RESPONSE_TIMEOUT) {
            Ok(payload) if !payload.addresses.is_empty() => payload.addresses,
            Ok(_) | Err(std::sync::mpsc::RecvTimeoutError::Timeout) => server_addresses,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                return http_response(404, &json_error("realm_not_found", "realm not registered"))
            }
        };
        {
            if let Ok(mut inner) = session.inner.lock() {
                inner.pending.remove(&body.nonce);
            }
        }
        json_response(
            200,
            &serde_json::json!({
                "addresses": response,
                "nonce": body.nonce,
                "obfs": body.obfs,
            }),
        )
    }

    fn connect_response(
        &self,
        realm_id: &str,
        nonce: &str,
        request: &SimpleHttpRequest,
        _remote_ip: &str,
    ) -> SimpleHttpResponse {
        if let Err(err) = validate_hex_field("nonce", nonce, NONCE_HEX_LEN) {
            return http_response(400, &json_error("bad_request", &err));
        }
        let Some(session) = self.get_session_by_bearer(request) else {
            return http_response(401, &json_error("invalid_token", "invalid session token"));
        };
        if session.realm_id != realm_id {
            return http_response(401, &json_error("invalid_token", "invalid session token"));
        }
        let body: AddressesBody = match serde_json::from_slice(&request.body) {
            Ok(body) => body,
            Err(_) => return http_response(400, &json_error("bad_request", "invalid json")),
        };
        if let Err(err) = validate_addresses(&body.addresses) {
            return http_response(400, &json_error("bad_request", &err));
        }
        let mut inner = match session.inner.lock() {
            Ok(inner) => inner,
            Err(_) => return http_response(500, &json_error("bad_request", "server state poisoned")),
        };
        let Some(sender) = inner.pending.remove(nonce) else {
            return http_response(
                404,
                &json_error("attempt_not_found", "no pending attempt for nonce"),
            );
        };
        let _ = sender.send(PunchResponsePayload {
            addresses: body.addresses,
        });
        http_response(204, "")
    }

    fn get_realm_session(&self, realm_id: &str) -> Option<Arc<RealmSession>> {
        let state = self.state.lock().ok()?;
        let session = state.realms.get(realm_id)?.clone();
        drop(state);
        if self.session_expired(&session) {
            self.remove_session(&session);
            return None;
        }
        Some(session)
    }

    fn get_session_by_bearer(&self, request: &SimpleHttpRequest) -> Option<Arc<RealmSession>> {
        let token = bearer_token(request);
        if token.is_empty() {
            return None;
        }
        let state = self.state.lock().ok()?;
        let session = state.sessions.get(&token)?.clone();
        drop(state);
        if self.session_expired(&session) {
            self.remove_session(&session);
            return None;
        }
        Some(session)
    }

    fn session_expired(&self, session: &Arc<RealmSession>) -> bool {
        let inner = match session.inner.lock() {
            Ok(inner) => inner,
            Err(_) => return true,
        };
        inner.closed || Instant::now() > inner.expires_at
    }

    fn remove_session(&self, session: &Arc<RealmSession>) {
        let client_ip = {
            let mut inner = match session.inner.lock() {
                Ok(inner) => inner,
                Err(_) => return,
            };
            if inner.closed {
                return;
            }
            inner.closed = true;
            session.event_ready.notify_all();
            inner.client_ip.clone()
        };
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(_) => return,
        };
        state.realms.remove(&session.realm_id);
        state.sessions.remove(&session.id);
        if let Some(count) = state.ip_counts.get_mut(&client_ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                state.ip_counts.remove(&client_ip);
            }
        }
    }
}
