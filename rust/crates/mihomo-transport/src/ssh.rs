use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream as NetTcpStream};
use std::thread;

use base64::Engine;
use mihomo_core::{BoxedTcpStream, TcpStream};
use rand::Rng;
use ssh2::{Channel, MethodType, Session};

use crate::{TransportError, TransportTarget};

pub(crate) fn wrap_stream(
    stream: BoxedTcpStream,
    username: &str,
    password: &str,
    private_key: &str,
    private_key_passphrase: &str,
    host_keys: &[String],
    host_key_algorithms: &[String],
    target: &TransportTarget,
) -> Result<BoxedTcpStream, TransportError> {
    if username.trim().is_empty() {
        return Err(TransportError::InvalidPlan(
            "ssh transport requires username".to_owned(),
        ));
    }
    if password.trim().is_empty() && private_key.trim().is_empty() {
        return Err(TransportError::InvalidPlan(
            "ssh transport requires password or private-key".to_owned(),
        ));
    }

    let allowed_host_keys = parse_host_keys(host_keys)?;
    let (session_stream, bridge_stream) = local_stream_pair()?;
    let upstream = stream;
    upstream.try_clone_box().map_err(|_| TransportError::UnsupportedFeature {
        proxy: "<ssh>".to_owned(),
        feature: "non-cloneable upstream stream".to_owned(),
    })?;
    thread::spawn(move || {
        let _ = relay_bridge_streams(bridge_stream, upstream);
    });

    let mut session = Session::new()
        .map_err(|err| TransportError::invalid_proxy_response(format!("ssh session init failed: {err}")))?;
    session
        .set_banner(&random_client_id())
        .map_err(|err| TransportError::InvalidPlan(format!("invalid ssh client banner: {err}")))?;
    if !host_key_algorithms.is_empty() {
        session
            .method_pref(MethodType::HostKey, &host_key_algorithms.join(","))
            .map_err(|err| {
                TransportError::InvalidPlan(format!("invalid ssh host-key-algorithms: {err}"))
            })?;
    }
    session.set_tcp_stream(session_stream);
    session
        .handshake()
        .map_err(|err| TransportError::invalid_proxy_response(format!("ssh handshake failed: {err}")))?;
    verify_host_key(&session, &allowed_host_keys)?;
    authenticate(&session, username, password, private_key, private_key_passphrase)?;
    let channel = session
        .channel_direct_tcpip(&target.host, target.port, Some(("127.0.0.1", 0)))
        .map_err(|err| TransportError::invalid_proxy_response(format!("ssh direct-tcpip failed: {err}")))?;

    Ok(Box::new(SshTcpStream { channel }))
}

fn authenticate(
    session: &Session,
    username: &str,
    password: &str,
    private_key: &str,
    private_key_passphrase: &str,
) -> Result<(), TransportError> {
    let mut authenticated = false;
    let mut last_error = None;

    if !private_key.trim().is_empty() {
        let key_material = load_private_key_material(private_key)?;
        if let Err(err) = session.userauth_pubkey_memory(
            username,
            None,
            &key_material,
            (!private_key_passphrase.trim().is_empty()).then_some(private_key_passphrase),
        ) {
            last_error = Some(err.to_string());
        } else if session.authenticated() {
            authenticated = true;
        }
    }

    if !authenticated && !password.trim().is_empty() {
        if let Err(err) = session.userauth_password(username, password) {
            last_error = Some(err.to_string());
        } else if session.authenticated() {
            authenticated = true;
        }
    }

    if authenticated {
        Ok(())
    } else {
        Err(TransportError::invalid_proxy_response(format!(
            "ssh authentication failed{}",
            last_error
                .as_deref()
                .map(|value| format!(": {value}"))
                .unwrap_or_default()
        )))
    }
}

fn verify_host_key(session: &Session, allowed_host_keys: &[Vec<u8>]) -> Result<(), TransportError> {
    if allowed_host_keys.is_empty() {
        return Ok(());
    }
    let Some((host_key, _)) = session.host_key() else {
        return Err(TransportError::invalid_proxy_response(
            "ssh server did not present a host key",
        ));
    };
    if allowed_host_keys.iter().any(|value| value.as_slice() == host_key) {
        Ok(())
    } else {
        Err(TransportError::invalid_proxy_response(
            "ssh host key mismatch",
        ))
    }
}

fn local_stream_pair() -> Result<(NetTcpStream, NetTcpStream), TransportError> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let client = NetTcpStream::connect(addr)?;
    let (server, _) = listener.accept()?;
    client.set_nodelay(true)?;
    server.set_nodelay(true)?;
    Ok((client, server))
}

fn relay_bridge_streams(
    mut local: NetTcpStream,
    mut upstream: BoxedTcpStream,
) -> io::Result<()> {
    let mut local_writer = local.try_clone()?;
    let mut upstream_writer = upstream.try_clone_box()?;
    thread::scope(|scope| -> io::Result<()> {
        let upstream_to_local = scope.spawn(|| -> io::Result<()> {
            io::copy(&mut *upstream, &mut local_writer)?;
            local_writer.shutdown(Shutdown::Write)?;
            Ok(())
        });

        io::copy(&mut local, &mut *upstream_writer)?;
        upstream_writer.shutdown_write()?;
        match upstream_to_local.join() {
            Ok(result) => result,
            Err(_) => Err(io::Error::new(
                io::ErrorKind::Other,
                "ssh bridge worker panicked",
            )),
        }
    })
}

fn load_private_key_material(private_key: &str) -> Result<String, TransportError> {
    if private_key.contains("PRIVATE KEY") {
        Ok(private_key.to_owned())
    } else {
        std::fs::read_to_string(private_key)
            .map_err(|err| TransportError::InvalidPlan(format!("failed to read ssh private-key: {err}")))
    }
}

fn parse_host_keys(host_keys: &[String]) -> Result<Vec<Vec<u8>>, TransportError> {
    host_keys
        .iter()
        .map(|value| {
            let key = value
                .split_whitespace()
                .nth(1)
                .unwrap_or(value.as_str())
                .trim();
            base64::engine::general_purpose::STANDARD
                .decode(key)
                .map_err(|err| TransportError::InvalidPlan(format!("invalid ssh host-key: {err}")))
        })
        .collect()
}

fn random_client_id() -> String {
    let mut rng = rand::thread_rng();
    let major = if rng.gen_bool(0.5) { 7 } else { 8 };
    let upper = if major == 7 { 9 } else { 8 };
    format!("SSH-2.0-OpenSSH_{major}.{}", rng.gen_range(0..=upper))
}

struct SshTcpStream {
    channel: Channel,
}

impl Read for SshTcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.channel.read(buf)
    }
}

impl Write for SshTcpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.channel.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.channel.flush()
    }
}

impl TcpStream for SshTcpStream {
    fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
        Ok(Box::new(Self {
            channel: self.channel.clone(),
        }))
    }

    fn shutdown_write(&mut self) -> io::Result<()> {
        self.channel.send_eof().map_err(to_io_error)
    }

    fn shutdown_all(&mut self) -> io::Result<()> {
        self.channel.send_eof().map_err(to_io_error)?;
        self.channel.close().map_err(to_io_error)?;
        self.channel.wait_close().map_err(to_io_error)?;
        Ok(())
    }
}

fn to_io_error(err: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::Other, err.to_string())
}

#[cfg(all(test, feature = "ssh-transport-tests"))]
mod tests {
    use std::io::{Read, Write};
    use std::net::Shutdown;
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::sync::Arc;
    use std::thread;

    use rand_010::rng;
    use russh::keys::{self, PrivateKey, PublicKeyBase64};
    use russh::server::{self, Msg, Server as _, Session};
    use tokio::io::{copy_bidirectional, AsyncWriteExt};
    use tokio::net::{TcpListener as TokioTcpListener, TcpStream as TokioTcpStream};

    use crate::{
        SocketOptions, SystemTcpDialer, TcpTransportExecutor, TransportAction, TransportHop,
        TransportPlan, TransportPlanRunner, TransportTarget,
    };

    #[test]
    fn ssh_transport_executes_password_authenticated_direct_tcpip() {
        let target_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let target_addr = target_listener.local_addr().unwrap();
        let target_worker = thread::spawn(move || {
            let (mut stream, _) = target_listener.accept().unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-ssh").unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let server = TestSshServer::start(TestAuthMode::Password);
        let mut executor = TcpTransportExecutor::new(SystemTcpDialer);
        let plan = TransportPlan {
            requested: "edge-ssh".into(),
            selected_path: vec!["edge-ssh".into()],
            leaf_name: "edge-ssh".into(),
            hops: vec![TransportHop {
                name: "edge-ssh".into(),
                action: TransportAction::SshConnect {
                    proxy: TransportTarget::new("127.0.0.1", server.addr.port()),
                    username: "user".into(),
                    password: "secret".into(),
                    private_key: String::new(),
                    private_key_passphrase: String::new(),
                    host_keys: vec![server.host_key.clone()],
                    host_key_algorithms: vec!["ssh-ed25519".into()],
                    socket: SocketOptions::default(),
                    target: TransportTarget::new("127.0.0.1", target_addr.port()),
                },
            }],
        };

        let mut stream = executor.run_plan(&plan).unwrap();
        stream.write_all(b"ping").unwrap();
        stream.shutdown_write().unwrap();
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"pong-ssh");

        server.shutdown();
        target_worker.join().unwrap();
    }

    #[test]
    fn ssh_transport_executes_private_key_authenticated_direct_tcpip() {
        let target_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let target_addr = target_listener.local_addr().unwrap();
        let target_worker = thread::spawn(move || {
            let (mut stream, _) = target_listener.accept().unwrap();
            let mut payload = [0_u8; 5];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"hello");
            stream.write_all(b"world").unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let mut rng = rng();
        let client_key = PrivateKey::random(&mut rng, keys::Algorithm::Ed25519).unwrap();
        let server = TestSshServer::start(TestAuthMode::PublicKey {
            allowed: client_key.public_key().clone(),
        });
        let mut executor = TcpTransportExecutor::new(SystemTcpDialer);
        let plan = TransportPlan {
            requested: "edge-ssh".into(),
            selected_path: vec!["edge-ssh".into()],
            leaf_name: "edge-ssh".into(),
            hops: vec![TransportHop {
                name: "edge-ssh".into(),
                action: TransportAction::SshConnect {
                    proxy: TransportTarget::new("127.0.0.1", server.addr.port()),
                    username: "user".into(),
                    password: String::new(),
                    private_key: client_key
                        .to_openssh(keys::ssh_key::LineEnding::LF)
                        .unwrap()
                        .to_string(),
                    private_key_passphrase: String::new(),
                    host_keys: vec![server.host_key.clone()],
                    host_key_algorithms: vec!["ssh-ed25519".into()],
                    socket: SocketOptions::default(),
                    target: TransportTarget::new("127.0.0.1", target_addr.port()),
                },
            }],
        };

        let mut stream = executor.run_plan(&plan).unwrap();
        stream.write_all(b"hello").unwrap();
        stream.shutdown_write().unwrap();
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"world");

        server.shutdown();
        target_worker.join().unwrap();
    }

    #[derive(Clone)]
    enum TestAuthMode {
        Password,
        PublicKey { allowed: keys::PublicKey },
    }

    struct TestSshServer {
        addr: std::net::SocketAddr,
        host_key: String,
        shutdown: russh::server::RunningServerHandle,
        thread: Option<thread::JoinHandle<()>>,
    }

    impl TestSshServer {
        fn start(auth: TestAuthMode) -> Self {
            let (tx, rx) = mpsc::channel();
            let thread = thread::spawn(move || {
                let runtime = tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .build()
                    .unwrap();
                runtime.block_on(async move {
                    let mut rng = rng();
                    let host_key = PrivateKey::random(&mut rng, keys::Algorithm::Ed25519).unwrap();
                    let host_key_blob = host_key.public_key_base64();
                    let config = Arc::new(russh::server::Config {
                        auth_rejection_time_initial: Some(std::time::Duration::from_secs(0)),
                        keys: vec![host_key],
                        ..Default::default()
                    });
                    let listener = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
                    let addr = listener.local_addr().unwrap();
                    let mut server = TestServer { auth };
                    let running = server.run_on_socket(config, &listener);
                    let handle = running.handle();
                    tx.send((addr, host_key_blob, handle)).unwrap();
                    running.await.unwrap();
                });
            });
            let (addr, host_key, shutdown) = rx.recv().unwrap();
            Self {
                addr,
                host_key,
                shutdown,
                thread: Some(thread),
            }
        }

        fn shutdown(mut self) {
            self.shutdown.shutdown("test complete".into());
            if let Some(thread) = self.thread.take() {
                thread.join().unwrap();
            }
        }
    }

    #[derive(Clone)]
    struct TestServer {
        auth: TestAuthMode,
    }

    impl server::Server for TestServer {
        type Handler = Self;

        fn new_client(&mut self, _addr: Option<std::net::SocketAddr>) -> Self {
            self.clone()
        }
    }

    impl server::Handler for TestServer {
        type Error = russh::Error;

        async fn auth_password(
            &mut self,
            user: &str,
            password: &str,
        ) -> Result<server::Auth, Self::Error> {
            match &self.auth {
                TestAuthMode::Password if user == "user" && password == "secret" => {
                    Ok(server::Auth::Accept)
                }
                _ => Ok(server::Auth::reject()),
            }
        }

        async fn auth_publickey_offered(
            &mut self,
            user: &str,
            public_key: &keys::PublicKey,
        ) -> Result<server::Auth, Self::Error> {
            match &self.auth {
                TestAuthMode::PublicKey { allowed }
                    if user == "user" && public_key == allowed =>
                {
                    Ok(server::Auth::Accept)
                }
                _ => Ok(server::Auth::reject()),
            }
        }

        async fn auth_publickey(
            &mut self,
            user: &str,
            public_key: &keys::PublicKey,
        ) -> Result<server::Auth, Self::Error> {
            match &self.auth {
                TestAuthMode::PublicKey { allowed }
                    if user == "user" && public_key == allowed =>
                {
                    Ok(server::Auth::Accept)
                }
                _ => Ok(server::Auth::reject()),
            }
        }

        async fn channel_open_direct_tcpip(
            &mut self,
            channel: russh::Channel<Msg>,
            host_to_connect: &str,
            port_to_connect: u32,
            _originator_address: &str,
            _originator_port: u32,
            _session: &mut Session,
        ) -> Result<bool, Self::Error> {
            let target = format!("{host_to_connect}:{port_to_connect}");
            tokio::spawn(async move {
                let mut channel = channel.into_stream();
                let mut upstream = TokioTcpStream::connect(&target).await.unwrap();
                copy_bidirectional(&mut channel, &mut upstream).await.unwrap();
                channel.shutdown().await.unwrap();
            });
            Ok(true)
        }
    }
}
