use std::io;
use std::os::fd::RawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use mihomo_core::TcpStream;

struct Pipe([RawFd; 2]);
const PIPE_CAPACITY: usize = 64 * 1024;

/// Keep nonblocking socket flags for the entire duplex relay. A per-direction
/// guard could restore blocking mode while the other direction is still using
/// splice, leaving a congested socket impossible to cancel.
pub(crate) struct NonblockingMode(Vec<(RawFd, libc::c_int)>);

impl NonblockingMode {
    pub(crate) fn new<L: TcpStream + ?Sized, R: TcpStream + ?Sized>(
        left: &L,
        right: &R,
    ) -> Option<Self> {
        let descriptors = [
            left.splice_socket_fd()?,
            left.splice_write_fd()?,
            right.splice_socket_fd()?,
            right.splice_write_fd()?,
        ];
        let mut flags = Vec::new();
        for fd in descriptors {
            if flags.iter().any(|(previous, _)| *previous == fd) {
                continue;
            }
            let original = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            if original < 0 {
                return None;
            }
            flags.push((fd, original));
        }
        let guard = Self(flags);
        for (fd, original) in &guard.0 {
            if unsafe { libc::fcntl(*fd, libc::F_SETFL, original | libc::O_NONBLOCK) } < 0 {
                return None;
            }
        }
        Some(guard)
    }
}

impl Drop for NonblockingMode {
    fn drop(&mut self) {
        for (fd, original) in &self.0 {
            unsafe {
                libc::fcntl(*fd, libc::F_SETFL, *original);
            }
        }
    }
}

impl Pipe {
    fn new() -> io::Result<Self> {
        let mut fds = [-1; 2];
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } < 0 {
            return Err(io::Error::last_os_error());
        }
        // Best effort. The kernel can retain its smaller default; neither
        // correctness nor fallback depends on permission to enlarge a pipe.
        unsafe {
            libc::fcntl(fds[1], libc::F_SETPIPE_SZ, PIPE_CAPACITY as libc::c_int);
        }
        Ok(Self(fds))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{Shutdown, TcpListener, TcpStream as Socket};
    use std::sync::mpsc;
    use std::sync::Arc;
    use std::thread;

    fn pair() -> (Socket, Socket) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = Socket::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        (client, server)
    }

    #[test]
    fn fast_relay_preserves_half_close_bytes_and_counters() {
        let (mut left, mut inbound) = pair();
        let (mut outbound, mut right) = pair();
        let worker = thread::spawn(move || {
            crate::tcp::relay_bidirectional(
                &mut inbound,
                &mut outbound,
                crate::TcpRelayStrategy::ZeroCopyPreferred,
            )
            .unwrap()
        });
        let payload = vec![0x5a; 256 * 1024];
        left.write_all(&payload).unwrap();
        left.shutdown(Shutdown::Write).unwrap();
        let mut received = Vec::new();
        right.read_to_end(&mut received).unwrap();
        assert_eq!(received, payload);
        right.write_all(b"response").unwrap();
        right.shutdown(Shutdown::Write).unwrap();
        received.clear();
        left.read_to_end(&mut received).unwrap();
        assert_eq!(received, b"response");
        let stats = worker.join().unwrap();
        assert_eq!(
            (stats.left_to_right, stats.right_to_left),
            (payload.len() as u64, 8)
        );
    }

    #[test]
    fn fast_read_respects_socket_timeout() {
        let (_client, source) = pair();
        let (destination, _peer) = pair();
        source
            .set_read_timeout(Some(Duration::from_millis(40)))
            .unwrap();
        let _mode = NonblockingMode::new(&source, &destination).unwrap();
        let started = Instant::now();
        let error = try_copy(&source, &destination, &AtomicBool::new(false), |_| {})
            .unwrap()
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn replayed_prefix_is_sent_once_before_splice_and_flags_are_restored() {
        struct Replay {
            prefix: std::io::Cursor<Vec<u8>>,
            inner: Socket,
        }
        impl Read for Replay {
            fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
                let count = self.prefix.read(bytes)?;
                if count > 0 {
                    Ok(count)
                } else {
                    self.inner.read(bytes)
                }
            }
        }
        impl Write for Replay {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.inner.write(bytes)
            }
            fn flush(&mut self) -> io::Result<()> {
                self.inner.flush()
            }
        }
        impl TcpStream for Replay {
            fn splice_socket_fd(&self) -> Option<RawFd> {
                self.inner.splice_socket_fd()
            }
            fn splice_write_fd(&self) -> Option<RawFd> {
                self.inner.splice_write_fd()
            }
            fn splice_read_fd(&self) -> Option<RawFd> {
                (self.prefix.position() as usize == self.prefix.get_ref().len())
                    .then(|| self.inner.splice_read_fd())
                    .flatten()
            }
            fn try_clone_box(&self) -> io::Result<mihomo_core::BoxedTcpStream> {
                Ok(Box::new(self.inner.try_clone()?))
            }
            fn shutdown_write(&mut self) -> io::Result<()> {
                self.inner.shutdown(Shutdown::Write)
            }
        }
        let (mut client, mut incoming) = pair();
        let (mut outgoing, mut target) = pair();
        let inspect_incoming = incoming.try_clone().unwrap();
        let inspect_outgoing = outgoing.try_clone().unwrap();
        let mut sending = client.try_clone().unwrap();
        let payload = vec![0x7e; 256 * 1024];
        let expected = payload.clone();
        let producer = thread::spawn(move || {
            sending.write_all(&payload).unwrap();
            sending.shutdown(Shutdown::Write).unwrap();
        });
        let mut prefix = vec![0; 1024];
        incoming.read_exact(&mut prefix).unwrap();
        let mut incoming = Replay {
            prefix: std::io::Cursor::new(prefix),
            inner: incoming,
        };
        let copy = thread::spawn(move || {
            crate::tcp::relay_bidirectional(
                &mut incoming,
                &mut outgoing,
                crate::TcpRelayStrategy::ZeroCopyPreferred,
            )
            .unwrap()
        });
        let mut actual = Vec::new();
        target.read_to_end(&mut actual).unwrap();
        assert_eq!(actual, expected);
        target.write_all(b"done").unwrap();
        target.shutdown(Shutdown::Write).unwrap();
        actual.clear();
        client.read_to_end(&mut actual).unwrap();
        assert_eq!(actual, b"done");
        let stats = copy.join().unwrap();
        assert_eq!(
            (stats.left_to_right, stats.right_to_left),
            (expected.len() as u64, 4)
        );
        producer.join().unwrap();
        for socket in [inspect_incoming, inspect_outgoing] {
            let flags = unsafe { libc::fcntl(socket.splice_socket_fd().unwrap(), libc::F_GETFL) };
            assert_eq!(flags & libc::O_NONBLOCK, 0);
        }
    }

    #[test]
    fn blocked_destination_can_be_cancelled_without_losing_a_worker() {
        let (mut producer, source) = pair();
        let (destination, peer) = pair();
        let size: libc::c_int = 4096;
        unsafe {
            libc::setsockopt(
                destination.splice_write_fd().unwrap(),
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                &size as *const _ as *const libc::c_void,
                std::mem::size_of_val(&size) as _,
            );
        }
        let cancelled = Arc::new(AtomicBool::new(false));
        let copy_cancelled = cancelled.clone();
        let (done, receive) = mpsc::channel();
        let worker = thread::spawn(move || {
            let _mode = NonblockingMode::new(&source, &destination).unwrap();
            let result = try_copy(&source, &destination, &copy_cancelled, |_| {}).unwrap();
            done.send(result).unwrap();
        });
        let sender = thread::spawn(move || {
            let _ = producer.write_all(&vec![0x33; 8 * 1024 * 1024]);
        });
        thread::sleep(Duration::from_millis(100));
        cancelled.store(true, Ordering::Release);
        let result = receive.recv_timeout(Duration::from_secs(2));
        drop(peer);
        let error = result
            .expect("blocked splice must observe cancellation")
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        worker.join().unwrap();
        sender.join().unwrap();
    }
}

impl Drop for Pipe {
    fn drop(&mut self) {
        for fd in self.0 {
            unsafe {
                libc::close(fd);
            }
        }
    }
}

fn socket_timeout(fd: RawFd, option: libc::c_int) -> Option<Duration> {
    let mut value: libc::timeval = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of_val(&value) as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            option,
            &mut value as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if result == 0 && (value.tv_sec > 0 || value.tv_usec > 0) {
        Some(
            Duration::from_secs(value.tv_sec.max(0) as u64)
                + Duration::from_micros(value.tv_usec.max(0) as u64),
        )
    } else {
        None
    }
}

fn wait(
    fd: RawFd,
    events: libc::c_short,
    deadline: Option<Instant>,
    cancel: &AtomicBool,
) -> io::Result<()> {
    loop {
        if cancel.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "TCP relay cancelled",
            ));
        }
        let timeout = match deadline {
            Some(deadline) => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "TCP relay socket timed out",
                    ));
                }
                remaining.as_millis().clamp(1, 100) as i32
            }
            None => 100,
        };
        let mut poll = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut poll, 1, timeout) };
        if result > 0 {
            if poll.revents & libc::POLLNVAL != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "TCP relay socket closed",
                ));
            }
            // HUP/ERR must reach splice too, so EOF and the socket's actual
            // error are reported rather than repeatedly polling a dead peer.
            return Ok(());
        }
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }
}

pub(crate) fn wait_for_io(fd: RawFd, reading: bool, cancel: &AtomicBool) -> io::Result<()> {
    let timeout = socket_timeout(
        fd,
        if reading {
            libc::SO_RCVTIMEO
        } else {
            libc::SO_SNDTIMEO
        },
    );
    wait(
        fd,
        if reading { libc::POLLIN } else { libc::POLLOUT },
        timeout.map(|duration| Instant::now() + duration),
        cancel,
    )
}

/// None means no bytes were consumed and the ordinary copy is still safe.
/// Callers retain both streams throughout; descriptors are never unwrapped
/// through a TLS, framing or accounting layer without that layer opting in.
pub(crate) fn try_copy<R: TcpStream + ?Sized, W: TcpStream + ?Sized>(
    reader: &R,
    writer: &W,
    cancel: &AtomicBool,
    mut record: impl FnMut(usize),
) -> Option<io::Result<u64>> {
    let (source, destination) = (reader.splice_read_fd()?, writer.splice_write_fd()?);
    for fd in [source, destination] {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 || flags & libc::O_NONBLOCK == 0 {
            return None;
        }
    }
    let pipe = Pipe::new().ok()?;
    let read_timeout = socket_timeout(source, libc::SO_RCVTIMEO);
    let write_timeout = socket_timeout(destination, libc::SO_SNDTIMEO);
    let mut total = 0;
    let mut consumed = false;
    let result = (|| {
        loop {
            let deadline = read_timeout.map(|duration| Instant::now() + duration);
            let received = loop {
                if cancel.load(Ordering::Acquire) {
                    return Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "TCP relay cancelled",
                    ));
                }
                let count = unsafe {
                    libc::splice(
                        source,
                        std::ptr::null_mut(),
                        pipe.0[1],
                        std::ptr::null_mut(),
                        PIPE_CAPACITY,
                        libc::SPLICE_F_MOVE | libc::SPLICE_F_NONBLOCK,
                    )
                };
                if count >= 0 {
                    break count as usize;
                }
                let error = io::Error::last_os_error();
                match error.kind() {
                    io::ErrorKind::Interrupted => continue,
                    io::ErrorKind::WouldBlock => wait(source, libc::POLLIN, deadline, cancel)?,
                    _ => return Err(error),
                }
            };
            if received == 0 {
                return Ok(total);
            }
            consumed = true;
            let mut remaining = received;
            let mut deadline = write_timeout.map(|duration| Instant::now() + duration);
            while remaining > 0 {
                if cancel.load(Ordering::Acquire) {
                    return Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "TCP relay cancelled",
                    ));
                }
                // Do not use SPLICE_F_MORE: short request/response exchanges
                // must not wait for a later write to uncork their data.
                let count = unsafe {
                    libc::splice(
                        pipe.0[0],
                        std::ptr::null_mut(),
                        destination,
                        std::ptr::null_mut(),
                        remaining,
                        libc::SPLICE_F_MOVE | libc::SPLICE_F_NONBLOCK,
                    )
                };
                if count > 0 {
                    remaining -= count as usize;
                    total += count as u64;
                    record(count as usize);
                    deadline = write_timeout.map(|duration| Instant::now() + duration);
                } else if count == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "TCP splice returned zero",
                    ));
                } else {
                    let error = io::Error::last_os_error();
                    match error.kind() {
                        io::ErrorKind::Interrupted => continue,
                        io::ErrorKind::WouldBlock => {
                            wait(destination, libc::POLLOUT, deadline, cancel)?
                        }
                        _ => return Err(error),
                    }
                }
            }
        }
    })();
    if !consumed
        && result.as_ref().err().is_some_and(|error| {
            matches!(
                error.raw_os_error(),
                Some(libc::EINVAL | libc::ENOSYS | libc::EOPNOTSUPP)
            )
        })
    {
        None
    } else {
        Some(result)
    }
}
