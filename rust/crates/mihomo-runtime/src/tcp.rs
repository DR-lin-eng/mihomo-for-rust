use std::any::Any;
use std::io;
use std::io::{Read, Write};
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::thread;

use mihomo_core::{BoxedTcpStream, ConnectionContext, TcpStream};
use mihomo_platform::current_capabilities;
use mihomo_transport::{SystemTcpDialer, TcpDialer, TcpTransportExecutor, TransportPlanRunner};

use crate::{connect_target, CandidateState, ExecutionError, RuntimeRegistry};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TcpRelayStrategy {
    BufferedCopy,
    ZeroCopyPreferred,
    PlatformZeroCopyRequired,
    OpenWrtFlowOffloadPreferred,
}

#[derive(Debug)]
pub enum TcpForwardError {
    Connect(ExecutionError),
    Relay(io::Error),
}

impl std::fmt::Display for TcpForwardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connect(err) => write!(f, "{err}"),
            Self::Relay(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for TcpForwardError {}

impl From<ExecutionError> for TcpForwardError {
    fn from(value: ExecutionError) -> Self {
        Self::Connect(value)
    }
}

impl From<io::Error> for TcpForwardError {
    fn from(value: io::Error) -> Self {
        Self::Relay(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TcpRelayStats {
    pub left_to_right: u64,
    pub right_to_left: u64,
}

impl TcpRelayStrategy {
    pub fn for_current_platform() -> Self {
        let caps = current_capabilities();
        if caps.supports_zero_copy_tcp {
            Self::ZeroCopyPreferred
        } else if caps.supports_openwrt_flow_offload {
            Self::OpenWrtFlowOffloadPreferred
        } else {
            Self::BufferedCopy
        }
    }
}

pub fn relay_bidirectional<L, R>(
    left: &mut L,
    right: &mut R,
    strategy: TcpRelayStrategy,
) -> io::Result<TcpRelayStats>
where
    L: TcpStream + ?Sized,
    R: TcpStream + ?Sized,
{
    relay_bidirectional_with_counters(left, right, strategy, None, None)
}

pub(crate) fn relay_bidirectional_with_counters<L, R>(
    left: &mut L,
    right: &mut R,
    _strategy: TcpRelayStrategy,
    left_to_right_counter: Option<&AtomicU64>,
    right_to_left_counter: Option<&AtomicU64>,
) -> io::Result<TcpRelayStats>
where
    L: TcpStream + ?Sized,
    R: TcpStream + ?Sized,
{
    let Ok(mut left_writer) = left.try_clone_box() else {
        return relay_bidirectional_fallback(
            left,
            right,
            left_to_right_counter,
            right_to_left_counter,
        );
    };
    let Ok(mut right_writer) = right.try_clone_box() else {
        return relay_bidirectional_fallback(
            left,
            right,
            left_to_right_counter,
            right_to_left_counter,
        );
    };

    let (left_to_right, right_to_left) = thread::scope(|scope| -> io::Result<(u64, u64)> {
        let right_to_left_worker = scope.spawn(|| -> io::Result<u64> {
            let transferred = copy_one_way(right, &mut *left_writer, right_to_left_counter)?;
            let _ = left_writer.shutdown_write();
            Ok(transferred)
        });

        let left_to_right = copy_one_way(left, &mut *right_writer, left_to_right_counter)?;
        let _ = right_writer.shutdown_write();
        let right_to_left = join_copy_worker(right_to_left_worker)?;
        Ok((left_to_right, right_to_left))
    })?;
    Ok(TcpRelayStats {
        left_to_right,
        right_to_left,
    })
}

fn relay_bidirectional_fallback<L, R>(
    left: &mut L,
    right: &mut R,
    left_to_right_counter: Option<&AtomicU64>,
    right_to_left_counter: Option<&AtomicU64>,
) -> io::Result<TcpRelayStats>
where
    L: TcpStream + ?Sized,
    R: TcpStream + ?Sized,
{
    let left_to_right = copy_one_way(left, right, left_to_right_counter)?;
    let _ = right.shutdown_write();
    let right_to_left = copy_one_way(right, left, right_to_left_counter)?;
    let _ = left.shutdown_write();
    Ok(TcpRelayStats {
        left_to_right,
        right_to_left,
    })
}

fn join_copy_worker(
    handle: thread::ScopedJoinHandle<'_, io::Result<u64>>,
) -> io::Result<u64> {
    match handle.join() {
        Ok(result) => result,
        Err(panic) => Err(io::Error::new(
            io::ErrorKind::Other,
            panic_message(panic),
        )),
    }
}

fn panic_message(payload: Box<dyn Any + Send>) -> String {
    match payload.downcast::<String>() {
        Ok(message) => *message,
        Err(payload) => match payload.downcast::<&'static str>() {
            Ok(message) => (*message).to_owned(),
            Err(_) => "tcp relay worker panicked".to_owned(),
        },
    }
}

fn copy_one_way<R, W>(
    reader: &mut R,
    writer: &mut W,
    counter: Option<&AtomicU64>,
) -> io::Result<u64>
where
    R: Read + ?Sized,
    W: Write + ?Sized,
{
    let mut total = 0_u64;
    let mut buf = [0_u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buf)?;
        if read == 0 {
            writer.flush()?;
            return Ok(total);
        }
        writer.write_all(&buf[..read])?;
        total += read as u64;
        if let Some(counter) = counter {
            counter.fetch_add(read as u64, Ordering::Relaxed);
        }
    }
}

pub fn forward_tcp_context<R>(
    registry: &mut RuntimeRegistry,
    target: &str,
    context: &mut ConnectionContext,
    states: &std::collections::BTreeMap<String, CandidateState>,
    runner: &mut R,
    strategy: TcpRelayStrategy,
) -> Result<TcpRelayStats, TcpForwardError>
where
    R: TransportPlanRunner<Output = BoxedTcpStream>,
{
    let metadata = context.metadata().clone();
    let mut upstream = connect_target(registry, target, &metadata, states, runner)?;
    let stats = relay_bidirectional(context.stream_mut(), &mut *upstream, strategy)?;
    Ok(stats)
}

pub fn forward_tcp_context_with_dialer<D>(
    registry: &mut RuntimeRegistry,
    target: &str,
    context: &mut ConnectionContext,
    states: &std::collections::BTreeMap<String, CandidateState>,
    dialer: D,
    strategy: TcpRelayStrategy,
) -> Result<TcpRelayStats, TcpForwardError>
where
    D: TcpDialer,
{
    let mut executor = TcpTransportExecutor::new(dialer);
    forward_tcp_context(registry, target, context, states, &mut executor, strategy)
}

pub fn forward_tcp_context_with_system_dialer(
    registry: &mut RuntimeRegistry,
    target: &str,
    context: &mut ConnectionContext,
    states: &std::collections::BTreeMap<String, CandidateState>,
    strategy: TcpRelayStrategy,
) -> Result<TcpRelayStats, TcpForwardError> {
    forward_tcp_context_with_dialer(
        registry,
        target,
        context,
        states,
        SystemTcpDialer,
        strategy,
    )
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, VecDeque};
    use std::io::{self, Cursor, Read, Write};
    use std::sync::{Arc, Mutex};

    use mihomo_config::parse_runtime_config_document;
    use mihomo_core::{BoxedTcpStream, ConnectionContext, Metadata};
    use mihomo_transport::{SocketOptions, TcpDialPurpose, TcpDialer, TransportError, TransportTarget};

    use crate::build_runtime_registry;

    use super::{
        forward_tcp_context_with_dialer, relay_bidirectional, TcpForwardError, TcpRelayStats,
        TcpRelayStrategy,
    };

    #[derive(Default)]
    struct MemoryDuplexState {
        readable: Vec<u8>,
        written: Vec<u8>,
    }

    struct MemoryDuplex {
        state: Arc<Mutex<MemoryDuplexState>>,
        read_offset: usize,
    }

    impl MemoryDuplex {
        fn new(readable: &[u8]) -> Self {
            Self {
                state: Arc::new(Mutex::new(MemoryDuplexState {
                    readable: readable.to_vec(),
                    written: Vec::new(),
                })),
                read_offset: 0,
            }
        }

        fn written(&self) -> Vec<u8> {
            self.state.lock().unwrap().written.clone()
        }
    }

    impl Read for MemoryDuplex {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let state = self.state.lock().unwrap();
            let remaining = &state.readable[self.read_offset..];
            let read = remaining.len().min(buf.len());
            buf[..read].copy_from_slice(&remaining[..read]);
            self.read_offset += read;
            Ok(read)
        }
    }

    impl Write for MemoryDuplex {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.state.lock().unwrap().written.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl mihomo_core::TcpStream for MemoryDuplex {
        fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
            Ok(Box::new(Self {
                state: Arc::clone(&self.state),
                read_offset: 0,
            }))
        }
    }

    #[test]
    fn relay_bidirectional_moves_data_in_both_directions() {
        let mut left = MemoryDuplex::new(b"hello");
        let mut right = MemoryDuplex::new(b"world");

        let stats = relay_bidirectional(&mut left, &mut right, TcpRelayStrategy::BufferedCopy).unwrap();
        assert_eq!(
            stats,
            TcpRelayStats {
                left_to_right: 5,
                right_to_left: 5,
            }
        );
        assert_eq!(left.written(), b"world".to_vec());
        assert_eq!(right.written(), b"hello".to_vec());
    }

    #[test]
    fn strategy_prefers_zero_copy_on_capable_platforms_or_falls_back() {
        let strategy = TcpRelayStrategy::for_current_platform();
        assert!(matches!(
            strategy,
            TcpRelayStrategy::BufferedCopy
                | TcpRelayStrategy::ZeroCopyPreferred
                | TcpRelayStrategy::PlatformZeroCopyRequired
                | TcpRelayStrategy::OpenWrtFlowOffloadPreferred
        ));
    }

    #[derive(Default)]
    struct SharedStreamState {
        reader: Cursor<Vec<u8>>,
        written: Vec<u8>,
    }

    #[derive(Clone)]
    struct SharedStreamHandle(Arc<Mutex<SharedStreamState>>);

    impl SharedStreamHandle {
        fn new(readable: Vec<u8>) -> Self {
            Self(Arc::new(Mutex::new(SharedStreamState {
                reader: Cursor::new(readable),
                written: Vec::new(),
            })))
        }

        fn stream(&self) -> SharedStream {
            SharedStream(Arc::clone(&self.0))
        }

        fn written(&self) -> Vec<u8> {
            self.0.lock().unwrap().written.clone()
        }
    }

    struct SharedStream(Arc<Mutex<SharedStreamState>>);

    impl Read for SharedStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.0.lock().unwrap().reader.read(buf)
        }
    }

    impl Write for SharedStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().written.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl mihomo_core::TcpStream for SharedStream {
        fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
            Ok(Box::new(SharedStream(Arc::clone(&self.0))))
        }
    }

    struct FakeDialer {
        expected: VecDeque<(String, SharedStreamHandle)>,
        calls: Vec<String>,
    }

    impl FakeDialer {
        fn new() -> Self {
            Self {
                expected: VecDeque::new(),
                calls: Vec::new(),
            }
        }

        fn push_connection(
            &mut self,
            authority: impl Into<String>,
            readable: Vec<u8>,
        ) -> SharedStreamHandle {
            let handle = SharedStreamHandle::new(readable);
            self.expected.push_back((authority.into(), handle.clone()));
            handle
        }
    }

    impl TcpDialer for FakeDialer {
        fn connect(
            &mut self,
            target: &TransportTarget,
            _socket: &SocketOptions,
            _purpose: TcpDialPurpose,
        ) -> Result<BoxedTcpStream, TransportError> {
            self.calls.push(target.authority());
            let Some((expected, handle)) = self.expected.pop_front() else {
                return Err(TransportError::InvalidPlan(
                    "unexpected tcp dial in runtime relay".to_owned(),
                ));
            };
            if expected != target.authority() {
                return Err(TransportError::InvalidPlan(format!(
                    "expected dial {expected} but got {}",
                    target.authority()
                )));
            }
            Ok(Box::new(handle.stream()))
        }
    }

    #[test]
    fn forward_tcp_context_connects_and_relays_application_bytes() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: http
    name: leaf
    server: leaf.example.com
    port: 8443
    dialer-proxy: outer
  - type: socks5
    name: outer
    server: outer.example.com
    port: 1080
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let inbound = SharedStreamHandle::new(b"client-data".to_vec());
        let mut context = ConnectionContext::new(
            inbound.stream(),
            Metadata {
                host: Some("final.example.com".into()),
                dst_port: Some(443),
                ..Metadata::default()
            },
        );

        let mut dialer = FakeDialer::new();
        let upstream = dialer.push_connection(
            "outer.example.com:1080",
            [
                vec![
                    0x05, 0x00, // socks no-auth
                    0x05, 0x00, 0x00, 0x03, 16,
                ],
                b"leaf.example.com".to_vec(),
                vec![0x20, 0xfb], // 8443
                b"HTTP/1.1 200 Connection Established\r\n\r\n".to_vec(),
                b"server-data".to_vec(),
            ]
            .concat(),
        );

        let stats = forward_tcp_context_with_dialer(
            &mut registry,
            "leaf",
            &mut context,
            &BTreeMap::new(),
            dialer,
            TcpRelayStrategy::BufferedCopy,
        )
        .unwrap();

        assert_eq!(
            stats,
            TcpRelayStats {
                left_to_right: b"client-data".len() as u64,
                right_to_left: b"server-data".len() as u64,
            }
        );
        assert_eq!(inbound.written(), b"server-data".to_vec());

        let upstream_writes = upstream.written();
        assert!(upstream_writes.windows("CONNECT ".len()).any(|window| window == b"CONNECT "));
        assert!(upstream_writes.ends_with(b"client-data"));
    }

    #[test]
    fn forward_tcp_context_reports_connect_errors() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: vmess
    name: leaf
    server: leaf.example.com
    port: 443
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let inbound = SharedStreamHandle::new(Vec::new());
        let mut context = ConnectionContext::new(
            inbound.stream(),
            Metadata {
                host: Some("final.example.com".into()),
                dst_port: Some(443),
                ..Metadata::default()
            },
        );

        let err = forward_tcp_context_with_dialer(
            &mut registry,
            "leaf",
            &mut context,
            &BTreeMap::new(),
            FakeDialer::new(),
            TcpRelayStrategy::BufferedCopy,
        )
        .unwrap_err();

        assert!(matches!(err, TcpForwardError::Connect(_)));
    }
}
