pub(super) fn build_endpoint_with_optional_realm(
    bind_addr: SocketAddr,
    server_config: QuinnServerConfig,
    obfs_password: Vec<u8>,
    tunnel: Arc<RuntimeTunnel>,
    realm: Hy2RealmOptions,
) -> io::Result<QuinnEndpoint> {
    if realm.enabled {
        let socket = Arc::new(Hy2RealmServerSocket::bind(
            bind_addr,
            obfs_password,
            realm,
            tunnel,
        )?);
        let runtime = Arc::new(Hy2RealmServerRuntime);
        QuinnEndpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            Some(server_config),
            socket,
            runtime,
        )
        .map_err(io::Error::other)
    } else if obfs_password.is_empty() {
        QuinnEndpoint::server(server_config, bind_addr).map_err(io::Error::other)
    } else {
        let runtime = Arc::new(Hy2RealmServerRuntime);
        let socket = Arc::new(Hy2RealmServerSocket::bind(
            bind_addr,
            obfs_password,
            Hy2RealmOptions::default(),
            tunnel,
        )?);
        QuinnEndpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            Some(server_config),
            socket,
            runtime,
        )
        .map_err(io::Error::other)
    }
}

#[derive(Debug)]
struct Hy2RealmServerRuntime;

impl QuinnRuntime for Hy2RealmServerRuntime {
    fn new_timer(&self, i: std::time::Instant) -> std::pin::Pin<Box<dyn quinn::AsyncTimer>> {
        Box::pin(tokio::time::sleep_until(tokio::time::Instant::from_std(i)))
    }

    fn spawn(&self, future: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>) {
        tokio::spawn(future);
    }

    fn wrap_udp_socket(&self, socket: StdUdpSocket) -> io::Result<Arc<dyn AsyncUdpSocket>> {
        let document = mihomo_config::parse_runtime_config_document("proxies: []\n")
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;
        let registry =
            mihomo_runtime::build_runtime_registry(&document).map_err(io::Error::other)?;
        Ok(Arc::new(Hy2RealmServerSocket::new(
            socket,
            Vec::new(),
            Hy2RealmOptions::default(),
            Arc::new(RuntimeTunnel::new("direct", registry)),
        )?))
    }

    fn now(&self) -> std::time::Instant {
        std::time::Instant::now()
    }
}
