use std::io;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;
use std::thread;

use mihomo_buf::ByteWindow;
use mihomo_core::{BoxedTcpStream, Metadata, UdpSession};
use mihomo_dns::{DnsError, DnsPacketTransport, DnsRuntime};
use mihomo_runtime::RuntimeTunnel;
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{ClientConfig as QuinnClientConfig, Endpoint as QuinnEndpoint};
use rustls::{ClientConfig, ClientConnection, ServerName, StreamOwned};
use rustls023::crypto::aws_lc_rs;
use rustls023::{ClientConfig as RustlsClientConfig, RootCertStore as RootCertStore023};
use tokio::runtime::Builder as TokioRuntimeBuilder;
use url::Url;

use crate::listener_service::SystemUdpSession;

#[derive(Clone)]
pub(crate) struct TunnelDnsPacketTransport {
    tunnel: Arc<RuntimeTunnel>,
    dns_runtime: Option<DnsRuntime>,
    special_proxy: String,
}

impl TunnelDnsPacketTransport {
    pub(crate) fn new(
        tunnel: Arc<RuntimeTunnel>,
        dns_runtime: Option<DnsRuntime>,
        special_proxy: impl Into<String>,
    ) -> Self {
        Self {
            tunnel,
            dns_runtime,
            special_proxy: special_proxy.into(),
        }
    }
}

impl DnsPacketTransport for TunnelDnsPacketTransport {
    fn fork(&self) -> Option<Box<dyn DnsPacketTransport + Send>> {
        Some(Box::new(self.clone()))
    }
    fn exchange(&mut self, server: &str, payload: &[u8]) -> Result<Vec<u8>, DnsError> {
        if server.starts_with("system") || server.starts_with("rcode://") {
            return mihomo_dns::SystemDnsPacketTransport.exchange(server, payload);
        }
        let nameserver = parse_tunnel_nameserver_with_runtime(server, &self.special_proxy, self.dns_runtime.as_mut())?;
        match nameserver.transport {
            TunnelDnsTransport::Udp(target) => self.exchange_udp(target, &nameserver.special_proxy, payload),
            TunnelDnsTransport::Tcp(target) => self.exchange_tcp(target, &nameserver.special_proxy, payload),
            TunnelDnsTransport::Tls { endpoint, server_name } => {
                self.exchange_tls(endpoint, &server_name, &nameserver.special_proxy, payload)
            }
            TunnelDnsTransport::Http(url) => {
                self.exchange_http(&url, false, &nameserver.special_proxy, payload)
            }
            TunnelDnsTransport::Https(url) => {
                self.exchange_http(&url, true, &nameserver.special_proxy, payload)
            }
            TunnelDnsTransport::Quic { endpoints, server_name } => {
                self.exchange_quic(&endpoints, &server_name, &nameserver.special_proxy, payload)
            }
        }
    }
}

impl TunnelDnsPacketTransport {
    fn exchange_udp(
        &mut self,
        target: SocketAddr,
        special_proxy: &str,
        payload: &[u8],
    ) -> Result<Vec<u8>, DnsError> {
        let mut metadata = Metadata {
            network: mihomo_core::NetworkKind::Udp,
            host: Some(target.ip().to_string()),
            dst_ip: Some(target.ip()),
            dst_port: Some(target.port()),
            special_proxy: special_proxy.to_owned(),
            ..Metadata::default()
        };
        let mut session = SystemUdpSession::new(self.tunnel.clone(), self.dns_runtime.clone())
            .map_err(|err| DnsError::Io(err.to_string()))?;
        session
            .prepare_send(&mut metadata)
            .map_err(|err| DnsError::Io(err.to_string()))?;
        session
            .send_to(ByteWindow::freeze(payload.to_vec()), target)
            .map_err(|err| DnsError::Io(err.to_string()))?;
        session
            .recv_once()
            .map_err(|err| DnsError::Io(err.to_string()))?
            .map(|(payload, _)| payload)
            .ok_or_else(|| DnsError::Io("dns tunnel response timed out".to_owned()))
    }

    fn exchange_tcp(
        &mut self,
        target: SocketAddr,
        special_proxy: &str,
        payload: &[u8],
    ) -> Result<Vec<u8>, DnsError> {
        let mut stream = self.connect_tcp_stream(target, special_proxy)?;
        let length = u16::try_from(payload.len())
            .map_err(|_| DnsError::DnsProtocol("dns tcp query too large".to_owned()))?;
        stream.write_all(&length.to_be_bytes())?;
        stream.write_all(payload)?;
        stream.flush()?;

        let mut header = [0_u8; 2];
        stream.read_exact(&mut header)?;
        let response_len = u16::from_be_bytes(header) as usize;
        let mut response = vec![0_u8; response_len];
        stream.read_exact(&mut response)?;
        Ok(response)
    }

    fn exchange_tls(
        &mut self,
        endpoint: SocketAddr,
        server_name: &str,
        special_proxy: &str,
        payload: &[u8],
    ) -> Result<Vec<u8>, DnsError> {
        let stream = self.connect_tcp_stream(endpoint, special_proxy)?;
        let server_name = ServerName::try_from(server_name.trim_matches(['[', ']']))
            .map_err(|_| DnsError::UnsupportedNameserver(server_name.to_owned()))?;
        let config = ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(
                mihomo_transport::tls_root_store_for_tests_and_runtime()
                    .map_err(|err| DnsError::Io(err.to_string()))?,
            )
            .with_no_client_auth();
        let connection = ClientConnection::new(Arc::new(config), server_name)
            .map_err(|err| DnsError::Io(err.to_string()))?;
        let mut tls = StreamOwned::new(connection, stream);
        exchange_dns_payload_over_stream(&mut tls, payload)
    }

    fn exchange_http(
        &mut self,
        url: &Url,
        tls: bool,
        special_proxy: &str,
        payload: &[u8],
    ) -> Result<Vec<u8>, DnsError> {
        let host = url
            .host_str()
            .ok_or_else(|| DnsError::UnsupportedNameserver(url.as_str().to_owned()))?;
        let port = url
            .port_or_known_default()
            .ok_or_else(|| DnsError::UnsupportedNameserver(url.as_str().to_owned()))?;
        let endpoint = resolve_dns_endpoint(host, port, self.dns_runtime.as_mut())?
            .into_iter().next().ok_or_else(|| DnsError::ResolveFailed(host.into()))?;
        let default_port = if tls { 443 } else { 80 };
        let host_header = if port == default_port {
            host.to_owned()
        } else {
            format!("{host}:{port}")
        };
        let path = if url.path().is_empty() { "/" } else { url.path() };
        let request_target = if let Some(query) = url.query() {
            format!("{path}?{query}")
        } else {
            path.to_owned()
        };
        let stream = self.connect_tcp_stream(endpoint, special_proxy)?;
        if tls {
            let server_name = ServerName::try_from(host.trim_matches(['[', ']']))
                .map_err(|_| DnsError::UnsupportedNameserver(url.as_str().to_owned()))?;
            let config = ClientConfig::builder()
                .with_safe_defaults()
                .with_root_certificates(
                    mihomo_transport::tls_root_store_for_tests_and_runtime()
                        .map_err(|err| DnsError::Io(err.to_string()))?,
                )
                .with_no_client_auth();
            let connection = ClientConnection::new(Arc::new(config), server_name)
                .map_err(|err| DnsError::Io(err.to_string()))?;
            let mut tls_stream = StreamOwned::new(connection, stream);
            return exchange_http_over_stream(&mut tls_stream, &request_target, &host_header, payload);
        }
        let mut plain = stream;
        exchange_http_over_stream(&mut plain, &request_target, &host_header, payload)
    }

    fn exchange_quic(
        &mut self,
        endpoints: &[SocketAddr],
        server_name: &str,
        special_proxy: &str,
        payload: &[u8],
    ) -> Result<Vec<u8>, DnsError> {
        ensure_quic_crypto_provider();
        let payload = payload.to_vec();
        let server_name = server_name.to_owned();
        let endpoints = endpoints.to_vec();
        let special_proxy = special_proxy.to_owned();
        let tunnel = Arc::clone(&self.tunnel);
        let dns_runtime = self.dns_runtime.clone();
        let runtime = TokioRuntimeBuilder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|err| DnsError::Io(err.to_string()))?;
        runtime
            .block_on(async move {
                let relay_bind_addr = if endpoints.iter().all(SocketAddr::is_ipv6) {
                    "[::1]:0"
                } else {
                    "127.0.0.1:0"
                };
                let relay_socket = std::net::UdpSocket::bind(relay_bind_addr).map_err(io::Error::other)?;
                relay_socket
                    .set_read_timeout(Some(Duration::from_millis(20)))
                    .map_err(io::Error::other)?;
                relay_socket
                    .set_write_timeout(Some(Duration::from_millis(20)))
                    .map_err(io::Error::other)?;
                let relay_addr = relay_socket.local_addr().map_err(io::Error::other)?;
                let stop = Arc::new(AtomicBool::new(false));
                let worker_stop = Arc::clone(&stop);
                let worker = thread::spawn(move || -> io::Result<()> {
                    let mut peer_addr = None;
                    let mut idle_ticks = 0u32;
                    if endpoints.is_empty() {
                        return Err(io::Error::new(
                            io::ErrorKind::NotFound,
                            "doq relay has no resolved target addresses",
                        ));
                    }
                    let mut session_groups = Vec::new();
                    let v4_targets = endpoints
                        .iter()
                        .copied()
                        .filter(SocketAddr::is_ipv4)
                        .collect::<Vec<_>>();
                    let v6_targets = endpoints
                        .iter()
                        .copied()
                        .filter(SocketAddr::is_ipv6)
                        .collect::<Vec<_>>();
                    if !v4_targets.is_empty() {
                        session_groups.push((
                            SystemUdpSession::new_with_bind_addr_and_timeout(
                                "0.0.0.0:0",
                                Duration::from_millis(50),
                                Arc::clone(&tunnel),
                                dns_runtime.clone(),
                            )?,
                            v4_targets,
                        ));
                    }
                    if !v6_targets.is_empty() {
                        session_groups.push((
                            SystemUdpSession::new_with_bind_addr_and_timeout(
                                "[::]:0",
                                Duration::from_millis(50),
                                tunnel,
                                dns_runtime,
                            )?,
                            v6_targets,
                        ));
                    }
                    let prepare_route = |target: SocketAddr, session: &mut SystemUdpSession| -> io::Result<()> {
                        let mut metadata = Metadata {
                            network: mihomo_core::NetworkKind::Udp,
                            host: Some(target.ip().to_string()),
                            dst_ip: Some(target.ip()),
                            dst_port: Some(target.port()),
                            special_proxy: special_proxy.clone(),
                            ..Metadata::default()
                        };
                        session.prepare_send(&mut metadata)
                    };

                    for (session, targets) in &mut session_groups {
                        if let Some(target) = targets.first().copied() {
                            prepare_route(target, session)?;
                        }
                    }
                    let mut buf = [0_u8; 64 * 1024];
                    loop {
                        match relay_socket.recv_from(&mut buf) {
                            Ok((read, peer)) => {
                                peer_addr = Some(peer);
                                idle_ticks = 0;
                                let payload = ByteWindow::freeze(buf[..read].to_vec());
                                for (session, targets) in &mut session_groups {
                                    for target in targets {
                                        session.send_to(payload.clone(), *target)?;
                                    }
                                }
                            }
                            Err(err)
                                if matches!(
                                    err.kind(),
                                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                                ) => {}
                            Err(err) => return Err(err),
                        }

                        let mut received = false;
                        for (session, _) in &mut session_groups {
                            if let Some((payload, _source)) = session.recv_once()? {
                                if let Some(peer) = peer_addr {
                                    relay_socket.send_to(&payload, peer)?;
                                }
                                idle_ticks = 0;
                                received = true;
                                break;
                            }
                        }
                        if !received {
                            idle_ticks += 1;
                        }

                        if worker_stop.load(Ordering::Relaxed) && idle_ticks > 10 {
                            break;
                        }
                    }
                    Ok(())
                });

                let transport_result = async {
                    let bind_addr = if relay_addr.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
                    let local_addr = bind_addr.parse::<SocketAddr>().map_err(io::Error::other)?;
                    let mut endpoint_client =
                        QuinnEndpoint::new(Default::default(), None, mihomo_core::bind_outbound_udp(local_addr)?, Arc::new(quinn::TokioRuntime)).map_err(io::Error::other)?;
                    let client_crypto = build_quic_client_config().map_err(io::Error::other)?;
                    let client_config = QuinnClientConfig::new(Arc::new(
                        QuicClientConfig::try_from(client_crypto).map_err(io::Error::other)?,
                    ));
                    endpoint_client.set_default_client_config(client_config);
                    let connection = connect_quic_endpoint(
                        &endpoint_client,
                        &[relay_addr],
                        server_name.trim_matches(['[', ']']),
                    )
                    .await?;
                    let (mut send, mut recv) = connection.open_bi().await.map_err(io::Error::other)?;
                    let length = u16::try_from(payload.len()).map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidData, "dns quic query too large")
                    })?;
                    send.write_all(&length.to_be_bytes()).await.map_err(io::Error::other)?;
                    send.write_all(&payload).await.map_err(io::Error::other)?;
                    send.finish().map_err(io::Error::other)?;
                    let _ = send.stopped().await;
                    let mut header = [0_u8; 2];
                    recv.read_exact(&mut header).await.map_err(io::Error::other)?;
                    let response_len = u16::from_be_bytes(header) as usize;
                    let mut response = vec![0_u8; response_len];
                    recv.read_exact(&mut response).await.map_err(io::Error::other)?;
                    connection.close(0u32.into(), b"");
                    endpoint_client.wait_idle().await;
                    Ok::<Vec<u8>, io::Error>(response)
                }
                .await;

                stop.store(true, Ordering::Relaxed);
                let worker_result = worker
                    .join()
                    .map_err(|_| io::Error::other("doq relay worker panicked"))?;

                match (transport_result, worker_result) {
                    (Ok(response), Ok(())) => Ok(response),
                    (Err(err), _) => Err(err),
                    (Ok(_), Err(err)) => Err(err),
                }
            })
            .map_err(DnsError::from)
    }

    fn connect_tcp_stream(
        &mut self,
        target: SocketAddr,
        special_proxy: &str,
    ) -> Result<BoxedTcpStream, DnsError> {
        let mut metadata = Metadata {
            network: mihomo_core::NetworkKind::Tcp,
            host: Some(target.ip().to_string()),
            dst_ip: Some(target.ip()),
            dst_port: Some(target.port()),
            special_proxy: special_proxy.to_owned(),
            ..Metadata::default()
        };
        if let Some(runtime) = self.dns_runtime.as_mut() {
            runtime
                .resolve_metadata(&mut metadata)
                .map_err(|err| DnsError::Io(err.to_string()))?;
        }
        self.tunnel
            .connect_tcp_with_system_dialer(&metadata)
            .map(|(stream, _)| stream)
            .map_err(|err| DnsError::Io(err.to_string()))
    }
}

/// Share local allocation/cache state, never a resolver lock across proxy I/O.
pub(crate) fn relay_shared_query_packet(
    tunnel: Arc<RuntimeTunnel>, payload: &[u8],
) -> Result<Option<Vec<u8>>, DnsError> {
    let shared = tunnel.dns_runtime().ok_or_else(|| DnsError::Io("DNS runtime unavailable".into()))?;
    {
        let mut guard = shared.lock().unwrap();
        if let Some(response) = guard.local_query_packet(payload)? {
            return Ok(Some(response));
        }
    }
    let scope = Arc::as_ptr(&shared) as usize;
    let query_tunnel = Arc::clone(&tunnel);
    tunnel.coalesce_dns_query(scope, payload, || {
        let mut runtime = shared.lock().unwrap().clone().without_fake_ip_persistence();
        let default_proxy = if runtime.config.respect_rules { "RULES" } else { "DIRECT" };
        let transport = TunnelDnsPacketTransport::new(query_tunnel, Some(runtime.clone()), default_proxy);
        let mut upstream = mihomo_dns::NetworkDnsUpstream::new(transport);
        let response = runtime.exchange_query_packet(payload, &mut upstream)?;
        shared.lock().unwrap().merge_cache_from(&runtime);
        Ok(Some(response))
    })
}
