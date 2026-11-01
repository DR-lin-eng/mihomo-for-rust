use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::sync::{Arc, Condvar, Mutex};

use mihomo_core::BoxedTcpStream;

#[derive(Default)]
pub(in crate::listener_service) struct PendingXhttpSession {
    pub download_stream: Option<BoxedTcpStream>,
    pub upload_stream: Option<BoxedTcpStream>,
    pub packet_up: Option<Arc<PacketUpSequenceState>>,
}

impl std::fmt::Debug for PendingXhttpSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingXhttpSession")
            .field("has_download_stream", &self.download_stream.is_some())
            .field("has_upload_stream", &self.upload_stream.is_some())
            .field("has_packet_up_state", &self.packet_up.is_some())
            .finish()
    }
}

#[derive(Clone)]
pub(in crate::listener_service) struct SharedReadHalf(pub Arc<Mutex<BoxedTcpStream>>);

#[derive(Clone)]
pub(in crate::listener_service) struct SharedWriteHalf(pub Arc<Mutex<BoxedTcpStream>>);

pub(in crate::listener_service) struct SplitTcpStream {
    pub reader: SharedReadHalf,
    pub writer: SharedWriteHalf,
    pub packet_up_close_state: Option<Arc<PacketUpSequenceState>>,
}

impl Read for SplitTcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut guard = self
            .reader
            .0
            .lock()
            .map_err(|_| io::Error::other("split tcp reader mutex poisoned"))?;
        guard.read(buf)
    }
}

impl Write for SplitTcpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut guard = self
            .writer
            .0
            .lock()
            .map_err(|_| io::Error::other("split tcp writer mutex poisoned"))?;
        guard.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut guard = self
            .writer
            .0
            .lock()
            .map_err(|_| io::Error::other("split tcp writer mutex poisoned"))?;
        guard.flush()
    }
}

impl mihomo_core::TcpStream for SplitTcpStream {
    fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
        Ok(Box::new(Self {
            reader: self.reader.clone(),
            writer: self.writer.clone(),
            packet_up_close_state: self.packet_up_close_state.clone(),
        }))
    }

    fn shutdown_write(&mut self) -> io::Result<()> {
        let mut guard = self
            .writer
            .0
            .lock()
            .map_err(|_| io::Error::other("split tcp writer mutex poisoned"))?;
        let result = guard.shutdown_write();
        drop(guard);
        self.close_packet_up_reader();
        result
    }

    fn shutdown_all(&mut self) -> io::Result<()> {
        {
            let mut writer = self
                .writer
                .0
                .lock()
                .map_err(|_| io::Error::other("split tcp writer mutex poisoned"))?;
            writer.shutdown_write()?;
        }
        self.close_packet_up_reader();
        let mut reader = self
            .reader
            .0
            .lock()
            .map_err(|_| io::Error::other("split tcp reader mutex poisoned"))?;
        reader.shutdown_all()
    }
}

impl SplitTcpStream {
    fn close_packet_up_reader(&self) {
        let Some(state) = &self.packet_up_close_state else {
            return;
        };
        if let Ok(mut guard) = state.inner.lock() {
            guard.closed = true;
            state.ready.notify_all();
        }
    }
}

#[derive(Default)]
pub(in crate::listener_service) struct PacketUpSequenceInner {
    pub streams: HashMap<u64, BoxedTcpStream>,
    pub closed: bool,
}

pub(in crate::listener_service) struct PacketUpSequenceState {
    pub inner: Mutex<PacketUpSequenceInner>,
    pub ready: Condvar,
}

pub(in crate::listener_service) struct PacketUpSequenceReader {
    state: Arc<PacketUpSequenceState>,
    next_seq: u64,
    current: Option<BoxedTcpStream>,
}

impl PacketUpSequenceReader {
    pub(in crate::listener_service) fn new(state: Arc<PacketUpSequenceState>) -> Self {
        Self {
            state,
            next_seq: 0,
            current: None,
        }
    }

    fn take_next_stream(&mut self) -> io::Result<Option<BoxedTcpStream>> {
        let mut guard = self
            .state
            .inner
            .lock()
            .map_err(|_| io::Error::other("xhttp packet-up sequence mutex poisoned"))?;
        loop {
            if let Some(stream) = guard.streams.remove(&self.next_seq) {
                self.next_seq = self
                    .next_seq
                    .checked_add(1)
                    .ok_or_else(|| io::Error::other("xhttp packet-up seq overflow"))?;
                return Ok(Some(stream));
            }
            if guard.closed {
                return Ok(None);
            }
            guard = self
                .state
                .ready
                .wait(guard)
                .map_err(|_| io::Error::other("xhttp packet-up sequence mutex poisoned"))?;
        }
    }
}

impl Read for PacketUpSequenceReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            if self.current.is_none() {
                self.current = self.take_next_stream()?;
                if self.current.is_none() {
                    return Ok(0);
                }
            }
            let read = self.current.as_mut().unwrap().read(buf)?;
            if read != 0 {
                return Ok(read);
            }
            self.current = None;
        }
    }
}

impl Write for PacketUpSequenceReader {
    fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "packet-up sequence reader is read-only",
        ))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl mihomo_core::TcpStream for PacketUpSequenceReader {
    fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "packet-up sequence reader does not support cloning",
        ))
    }

    fn shutdown_write(&mut self) -> io::Result<()> {
        Ok(())
    }

    fn shutdown_all(&mut self) -> io::Result<()> {
        let mut guard = self
            .state
            .inner
            .lock()
            .map_err(|_| io::Error::other("xhttp packet-up sequence mutex poisoned"))?;
        guard.closed = true;
        self.state.ready.notify_all();
        Ok(())
    }
}
