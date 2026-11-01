use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Condvar, Mutex,
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::listener_service::SystemUdpSession;
use mihomo_buf::ByteWindow;
use mihomo_core::{BoxedTcpStream, PacketEnvelope, TcpStream};
use mihomo_runtime::RuntimeTunnel;

pub(super) type TunUdpEgress = Arc<dyn Fn(&[u8]) -> io::Result<()> + Send + Sync>;

struct ReceiveState {
    cancelled: AtomicBool,
    closed: Option<Arc<AtomicBool>>,
    last_activity: Mutex<Instant>,
    idle_timeout: Duration,
    mappings: Mutex<HashMap<SocketAddr, PacketEnvelope>>,
    mapping_ready: Condvar,
    finished: (Mutex<bool>, Condvar),
}

impl ReceiveState {
    fn stopped(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
            || self
                .closed
                .as_ref()
                .is_some_and(|closed| closed.load(Ordering::Acquire))
            || self.last_activity.lock().unwrap().elapsed() >= self.idle_timeout
    }
}

/// At most one receiver per cached TUN UDP association (cache capacity: 256).
/// It receives independently of outbound packets and never holds the sending
/// session's mutex. Eviction, route changes and TUN shutdown cancel and join it.
pub(super) struct LiveUdpReceiver {
    state: Arc<ReceiveState>,
    generation: u64,
    worker: Option<JoinHandle<()>>,
    shutdown_handle: Option<BoxedTcpStream>,
}

impl LiveUdpReceiver {
    pub fn start(
        session: &mut SystemUdpSession,
        target: SocketAddr,
        packet: PacketEnvelope,
        tunnel: Arc<RuntimeTunnel>,
        idle_timeout: Duration,
    ) -> io::Result<Option<Self>> {
        if !session.receive_ready() {
            return Ok(None);
        }
        let mut reader = session.split_for_receive()?;
        let shutdown_handle = reader.receive_shutdown_handle()?;
        let state = Arc::new(ReceiveState {
            cancelled: AtomicBool::new(false),
            closed: session.receiver_close_signal(),
            last_activity: Mutex::new(Instant::now()),
            idle_timeout,
            mappings: Mutex::new(HashMap::from([(target, packet)])),
            mapping_ready: Condvar::new(),
            finished: (Mutex::new(false), Condvar::new()),
        });
        let reading_state = state.clone();
        reader.wrap_receive_stream(|inner| {
            Box::new(CancellableReader {
                inner,
                state: reading_state,
            })
        });
        let receiving_state = state.clone();
        let worker = thread::Builder::new()
            .name("tun-udp-recv".into())
            .stack_size(256 * 1024)
            .spawn(move || {
                let _completed = ReceiveCompletion(receiving_state.clone());
                while !receiving_state.stopped() {
                    match reader.recv_once() {
                        Ok(Some((payload, remote))) => {
                            if receiving_state.stopped() {
                                break;
                            }
                            let packet = {
                                let mut mappings = receiving_state.mappings.lock().unwrap();
                                if !mappings.contains_key(&remote) {
                                    // A very fast reply can beat the sender adding
                                    // this resolved target immediately after send.
                                    mappings = receiving_state
                                        .mapping_ready
                                        .wait_timeout(mappings, Duration::from_millis(100))
                                        .unwrap()
                                        .0;
                                }
                                mappings.get(&remote).cloned().or_else(|| {
                                    let mut by_ip = mappings
                                        .iter()
                                        .filter(|(target, _)| target.ip() == remote.ip());
                                    let first = by_ip.next()?.1.clone();
                                    by_ip.next().is_none().then_some(first)
                                })
                            };
                            if let Some(packet) = packet {
                                if let Err(error) = tunnel.write_back_udp(
                                    &packet,
                                    ByteWindow::freeze(payload),
                                    remote,
                                ) {
                                    mihomo_core::push_log(
                                        mihomo_core::LogLevel::Warn,
                                        format!("TUN UDP write-back: {error}"),
                                    );
                                    break;
                                }
                                *receiving_state.last_activity.lock().unwrap() = Instant::now();
                            }
                        }
                        Ok(None) => {}
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                        Err(error) => {
                            if !receiving_state.stopped() {
                                mihomo_core::push_log(
                                    mihomo_core::LogLevel::Debug,
                                    format!("TUN UDP receive ended: {error}"),
                                );
                            }
                            break;
                        }
                    }
                }
                receiving_state.cancelled.store(true, Ordering::Release);
            })?;
        let route_state = state.clone();
        session.set_receive_barrier(Arc::new(move || {
            route_state.cancelled.store(true, Ordering::Release);
            route_state.mapping_ready.notify_all();
            let (done, ready) = &route_state.finished;
            let mut finished = done.lock().unwrap();
            while !*finished {
                finished = ready.wait(finished).unwrap();
            }
        }));
        Ok(Some(Self {
            state,
            generation: session.receive_generation,
            worker: Some(worker),
            shutdown_handle,
        }))
    }

    pub fn matches(&self, session: &SystemUdpSession) -> bool {
        self.generation == session.receive_generation && !self.state.stopped()
    }

    pub fn last_activity(&self) -> Instant {
        *self.state.last_activity.lock().unwrap()
    }

    pub fn stopped(&self) -> bool {
        self.state.stopped()
    }

    pub fn cancel(&self) {
        self.state.cancelled.store(true, Ordering::Release);
        self.state.mapping_ready.notify_all();
    }

    pub fn add_mapping(&self, target: SocketAddr, packet: PacketEnvelope) {
        let mut mappings = self.state.mappings.lock().unwrap();
        if mappings.len() >= 256 && !mappings.contains_key(&target) {
            if let Some(old) = mappings.keys().next().copied() {
                mappings.remove(&old);
            }
        }
        mappings.insert(target, packet);
        self.state.mapping_ready.notify_all();
        *self.state.last_activity.lock().unwrap() = Instant::now();
    }
}

struct ReceiveCompletion(Arc<ReceiveState>);
impl Drop for ReceiveCompletion {
    fn drop(&mut self) {
        self.0.cancelled.store(true, Ordering::Release);
        *self.0.finished.0.lock().unwrap() = true;
        self.0.finished.1.notify_all();
    }
}

impl Drop for LiveUdpReceiver {
    fn drop(&mut self) {
        self.cancel();
        if let Some(handle) = &mut self.shutdown_handle {
            let _ = handle.shutdown_all();
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

/// Preserve partial protocol frames across socket timeouts while still waking
/// for shutdown and idle expiry. Returning a timeout halfway through read_exact
/// would discard the frame prefix in the UDP protocol decoder.
struct CancellableReader {
    inner: BoxedTcpStream,
    state: Arc<ReceiveState>,
}
impl Read for CancellableReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            if self.state.stopped() {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "TUN UDP receiver closed",
                ));
            }
            match self.inner.read(buf) {
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                            | io::ErrorKind::Interrupted
                    ) =>
                {
                    continue
                }
                result => return result,
            }
        }
    }
}
impl Write for CancellableReader {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
impl TcpStream for CancellableReader {
    fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
        Ok(Box::new(Self {
            inner: self.inner.try_clone_box()?,
            state: self.state.clone(),
        }))
    }
    fn shutdown_all(&mut self) -> io::Result<()> {
        self.inner.shutdown_all()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_frame_prefix_survives_a_socket_timeout_between_fragments() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        server
            .set_read_timeout(Some(Duration::from_millis(20)))
            .unwrap();
        let state = Arc::new(ReceiveState {
            cancelled: AtomicBool::new(false),
            closed: None,
            last_activity: Mutex::new(Instant::now()),
            idle_timeout: Duration::from_secs(3),
            mappings: Mutex::new(HashMap::new()),
            mapping_ready: Condvar::new(),
            finished: (Mutex::new(false), Condvar::new()),
        });
        let worker = thread::spawn(move || {
            let mut reader = CancellableReader {
                inner: Box::new(server),
                state,
            };
            let mut frame = [0_u8; 9];
            reader.read_exact(&mut frame).unwrap();
            frame
        });
        client.write_all(b"udp").unwrap();
        thread::sleep(Duration::from_millis(80));
        client.write_all(b"-frame").unwrap();
        assert_eq!(&worker.join().unwrap(), b"udp-frame");
    }
}
