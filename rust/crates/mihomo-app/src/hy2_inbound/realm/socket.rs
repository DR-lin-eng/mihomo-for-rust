struct Hy2RealmServerSocket {
    io: tokio::net::UdpSocket,
    local_addr: SocketAddr,
    obfs_password: Vec<u8>,
    realm: Hy2RealmOptions,
    runtime_state: Option<Arc<Hy2RealmRuntimeState>>,
}

impl std::fmt::Debug for Hy2RealmServerSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hy2RealmServerSocket")
            .field("local_addr", &self.local_addr)
            .field("obfs_password_len", &self.obfs_password.len())
            .field("realm_enabled", &self.realm.enabled)
            .field("has_runtime_state", &self.runtime_state.is_some())
            .finish()
    }
}

impl Hy2RealmServerSocket {
    fn bind(
        bind_addr: SocketAddr,
        obfs_password: Vec<u8>,
        realm: Hy2RealmOptions,
        tunnel: Arc<RuntimeTunnel>,
    ) -> io::Result<Self> {
        let socket = StdUdpSocket::bind(bind_addr)?;
        Self::new(socket, obfs_password, realm, tunnel)
    }

    fn new(
        socket: StdUdpSocket,
        obfs_password: Vec<u8>,
        realm: Hy2RealmOptions,
        tunnel: Arc<RuntimeTunnel>,
    ) -> io::Result<Self> {
        let local_addr = socket.local_addr()?;
        let std_clone = socket.try_clone()?;
        let runtime_state = if realm.enabled {
            Some(Self::build_realm_runtime(&std_clone, &realm, tunnel)?)
        } else {
            None
        };
        socket.set_nonblocking(true)?;
        let io = tokio::net::UdpSocket::from_std(socket)?;
        let instance = Self {
            io,
            local_addr,
            obfs_password,
            realm: realm.clone(),
            runtime_state,
        };
        if let Some(state) = instance.runtime_state.clone() {
            instance.spawn_realm_background(std_clone, state)?;
        }
        Ok(instance)
    }

    fn build_realm_runtime(
        socket: &StdUdpSocket,
        realm: &Hy2RealmOptions,
        tunnel: Arc<RuntimeTunnel>,
    ) -> io::Result<Arc<Hy2RealmRuntimeState>> {
        let control = Hy2RealmControlClient::new(realm)
            .map(|client| {
                client.with_connector(Arc::new(move |target, tls, alpn, proxy| {
                    connect_realm_http_with_runtime_tunnel(&tunnel, target, tls, alpn, proxy)
                }))
            })
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;
        let addresses = discover_hy2_realm_stun_addresses(socket, &realm.stun_servers)
            .map_err(|err| io::Error::other(err.to_string()))?;
        let registration = control
            .register(&realm.realm_id, &addresses)
            .map_err(|err| io::Error::other(err.to_string()))?;
        Ok(Arc::new(Hy2RealmRuntimeState {
            control,
            realm_id: realm.realm_id.clone(),
            stun_servers: realm.stun_servers.clone(),
            session_id: Mutex::new(registration.session_id),
            ttl_secs: Mutex::new(registration.ttl_secs),
            published_addresses: Mutex::new(addresses),
            stun_waiters: Mutex::new(BTreeMap::new()),
            punch_waiters: Mutex::new(Vec::new()),
        }))
    }

    fn spawn_realm_background(
        &self,
        socket: StdUdpSocket,
        state: Arc<Hy2RealmRuntimeState>,
    ) -> io::Result<()> {
        thread::spawn(move || {
            let mut last_heartbeat = Instant::now();
            loop {
                let session_id = match state.session_id.lock() {
                    Ok(value) => value.clone(),
                    Err(_) => return,
                };
                let event = match state.control.events(&state.realm_id, &session_id) {
                    Ok(events) => events.into_iter().next(),
                    Err(_) => None,
                };
                if let Some(event) = event {
                    if let Ok(fresh) =
                        discover_realm_addresses_via_waiters(&socket, &state, &state.published_addresses)
                    {
                        let _ = state.control.connect_response(
                            &state.realm_id,
                            &session_id,
                            &hex::encode(event.punch_metadata.nonce),
                            &fresh,
                        );
                        if let Ok(peer) = respond_realm_punch_via_waiters(
                            &socket,
                            &state,
                            &fresh,
                            &event.addresses,
                            event.punch_metadata,
                        ) {
                            let _ = peer;
                            if let Ok(mut published) = state.published_addresses.lock() {
                                *published = fresh;
                            }
                        }
                    }
                }
                let ttl_secs = state.ttl_secs.lock().map(|value| *value).unwrap_or(60);
                let heartbeat_interval = Duration::from_secs((ttl_secs / 2).max(1));
                if last_heartbeat.elapsed() >= heartbeat_interval {
                    let published = state
                        .published_addresses
                        .lock()
                        .map(|value| value.clone())
                        .unwrap_or_default();
                    if let Ok(ttl) =
                        state.control.heartbeat(&state.realm_id, &session_id, &published)
                    {
                        if let Ok(mut value) = state.ttl_secs.lock() {
                            *value = ttl;
                        }
                    }
                    last_heartbeat = Instant::now();
                }
                thread::sleep(Duration::from_millis(200));
            }
        });
        Ok(())
    }

    fn maybe_decode_recv(&self, meta: &mut RecvMeta, buf: &mut [u8]) {
        if self.obfs_password.is_empty() || meta.len <= SALAMANDER_SALT_LEN {
            return;
        }
        let payload_len = meta.len - SALAMANDER_SALT_LEN;
        let salt = buf[..SALAMANDER_SALT_LEN].to_vec();
        buf.copy_within(SALAMANDER_SALT_LEN..meta.len, 0);
        let payload = &mut buf[..payload_len];
        apply_salamander_obfs(&self.obfs_password, &salt, payload);
        meta.len = payload_len;
        meta.stride = payload_len;
    }
}

impl AsyncUdpSocket for Hy2RealmServerSocket {
    fn create_io_poller(self: Arc<Self>) -> std::pin::Pin<Box<dyn UdpPoller>> {
        Box::pin(Hy2RealmServerPoller { socket: self })
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        let mut owned;
        let tx = if self.obfs_password.is_empty() {
            transmit.clone()
        } else {
            let mut salt = [0_u8; SALAMANDER_SALT_LEN];
            rand_core::OsRng.fill_bytes(&mut salt);
            owned = Vec::with_capacity(SALAMANDER_SALT_LEN + transmit.contents.len());
            owned.extend_from_slice(&salt);
            owned.extend_from_slice(transmit.contents);
            apply_salamander_obfs(
                &self.obfs_password,
                &salt,
                &mut owned[SALAMANDER_SALT_LEN..],
            );
            Transmit {
                destination: transmit.destination,
                ecn: transmit.ecn,
                contents: &owned,
                segment_size: None,
                src_ip: transmit.src_ip,
            }
        };
        self.io.try_send_to(tx.contents, tx.destination).map(|_| ())
    }

    fn poll_recv(
        &self,
        cx: &mut std::task::Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> std::task::Poll<io::Result<usize>> {
        loop {
            match self.io.poll_recv_ready(cx) {
                std::task::Poll::Ready(Ok(())) => {}
                std::task::Poll::Ready(Err(err)) => return std::task::Poll::Ready(Err(err)),
                std::task::Poll::Pending => return std::task::Poll::Pending,
            }
            let buf = match bufs.first_mut() {
                Some(buf) => buf,
                None => return std::task::Poll::Ready(Ok(0)),
            };
            let mut recv_buf = vec![0_u8; buf.len()];
            match self.io.try_recv_from(&mut recv_buf) {
                Ok((len, addr)) => {
                    if let Some(state) = &self.runtime_state {
                        if is_hy2_realm_stun_message(&recv_buf[..len]) {
                            if let Ok(message) = decode_hy2_realm_stun_message(&recv_buf[..len]) {
                                if let Ok(mapped) =
                                    resolve_hy2_realm_stun_mapped_address(&message)
                                {
                                    if let Ok(mut waiters) = state.stun_waiters.lock() {
                                        if let Some(sender) =
                                            waiters.remove(&message.transaction_id)
                                        {
                                            let _ = sender.send(mapped);
                                        }
                                    }
                                }
                            }
                            continue;
                        }
                        if let Ok(mut waiters) = state.punch_waiters.lock() {
                            if let Some(index) = waiters.iter().position(|(metadata, _)| {
                                decode_hy2_realm_punch_packet(&recv_buf[..len], *metadata).is_ok()
                            }) {
                                let (metadata, sender) = waiters.remove(index);
                                if let Ok(packet_type) =
                                    decode_hy2_realm_punch_packet(&recv_buf[..len], metadata)
                                {
                                    let _ = sender.send((addr, packet_type));
                                    continue;
                                }
                            }
                        }
                    }
                    let dst = &mut buf[..len];
                    dst.copy_from_slice(&recv_buf[..len]);
                    meta[0] = RecvMeta {
                        addr,
                        len,
                        stride: len,
                        ecn: None,
                        dst_ip: None,
                    };
                    self.maybe_decode_recv(&mut meta[0], dst);
                    return std::task::Poll::Ready(Ok(1));
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => continue,
                Err(err) => return std::task::Poll::Ready(Err(err)),
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }

    fn may_fragment(&self) -> bool {
        true
    }
}

const SALAMANDER_SALT_LEN: usize = 8;

fn apply_salamander_obfs(password: &[u8], salt: &[u8], payload: &mut [u8]) {
    let mut hasher = Blake2b::<U32>::new();
    hasher.update(password);
    hasher.update(salt);
    let key = hasher.finalize();
    for (index, byte) in payload.iter_mut().enumerate() {
        *byte ^= key[index % key.len()];
    }
}

#[derive(Debug)]
struct Hy2RealmServerPoller {
    socket: Arc<Hy2RealmServerSocket>,
}

impl UdpPoller for Hy2RealmServerPoller {
    fn poll_writable(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        self.socket.io.poll_send_ready(cx)
    }
}
