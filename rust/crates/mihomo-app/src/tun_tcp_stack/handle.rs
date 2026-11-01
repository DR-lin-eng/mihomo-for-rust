use std::collections::VecDeque;
use std::io;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

use mihomo_core::{BoxedTcpStream, TcpStream as CoreTcpStream};
use smoltcp::socket::tcp::State as SmolTcpState;

use super::stack::{TunTcpPassiveStack, TunTcpPassiveStackSignal};

type EgressFn = Arc<dyn Fn(Vec<Vec<u8>>) -> io::Result<()> + Send + Sync>;

#[derive(Clone)]
pub(crate) struct TunTcpStreamHandle {
    stack: Arc<Mutex<TunTcpPassiveStack>>,
    pending_read: Arc<Mutex<VecDeque<u8>>>,
    signal: TunTcpPassiveStackSignal,
    egress: Option<EgressFn>,
    read_timeout: Arc<Mutex<Option<std::time::Duration>>>,
    write_timeout: Arc<Mutex<Option<std::time::Duration>>>,
}

impl TunTcpStreamHandle {
    fn from_parts(stack: TunTcpPassiveStack, egress: Option<EgressFn>) -> Self {
        let signal = stack.signal();
        Self {
            stack: Arc::new(Mutex::new(stack)),
            pending_read: Arc::new(Mutex::new(VecDeque::new())),
            signal,
            egress,
            read_timeout: Arc::new(Mutex::new(None)),
            write_timeout: Arc::new(Mutex::new(None)),
        }
    }

    #[cfg(test)]
    pub(crate) fn new(stack: TunTcpPassiveStack) -> Self {
        Self::from_parts(stack, None)
    }

    pub(crate) fn with_egress(stack: TunTcpPassiveStack, egress: EgressFn) -> Self {
        Self::from_parts(stack, Some(egress))
    }

    pub(crate) fn with_egress_from_handle(handle: &Self, egress: EgressFn) -> Self {
        Self {
            stack: Arc::clone(&handle.stack),
            pending_read: Arc::clone(&handle.pending_read),
            signal: handle.signal.clone(),
            egress: Some(egress),
            read_timeout: handle.read_timeout.clone(),
            write_timeout: handle.write_timeout.clone(),
        }
    }

    pub(crate) fn stack(&self) -> Arc<Mutex<TunTcpPassiveStack>> {
        Arc::clone(&self.stack)
    }

    fn emit_outgoing(&self, stack: &mut TunTcpPassiveStack) -> io::Result<()> {
        let Some(egress) = self.egress.as_ref() else {
            return Ok(());
        };
        let packets = stack.drain_outgoing();
        if packets.is_empty() {
            return Ok(());
        }
        egress(packets)
    }

    fn copy_pending_read(&self, buf: &mut [u8]) -> io::Result<Option<usize>> {
        let mut pending = self
            .pending_read
            .lock()
            .map_err(|_| io::Error::other("tun tcp pending-read mutex poisoned"))?;
        if pending.is_empty() {
            return Ok(None);
        }
        let copied = pending.len().min(buf.len());
        let (head, tail) = pending.as_slices();
        let first_len = head.len().min(copied);
        buf[..first_len].copy_from_slice(&head[..first_len]);
        let second_len = copied - first_len;
        if second_len > 0 {
            buf[first_len..copied].copy_from_slice(&tail[..second_len]);
        }
        pending.drain(..copied);
        Ok(Some(copied))
    }
}

impl Read for TunTcpStreamHandle {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let deadline = self
            .read_timeout
            .lock()
            .unwrap()
            .map(|timeout| std::time::Instant::now() + timeout);
        loop {
            if let Some(copied) = self.copy_pending_read(buf)? {
                return Ok(copied);
            }

            let generation = self.signal.current_generation()?;
            {
                let mut stack = self
                    .stack
                    .lock()
                    .map_err(|_| io::Error::other("tun tcp stack mutex poisoned"))?;
                stack.poll();
                if let Some(bytes) = stack.recv_application()? {
                    // Consuming data reopens the TCP receive window. Publish the
                    // update even if the peer is waiting for that window.
                    stack.poll();
                    self.emit_outgoing(&mut stack)?;
                    drop(stack);
                    let mut pending = self
                        .pending_read
                        .lock()
                        .map_err(|_| io::Error::other("tun tcp pending-read mutex poisoned"))?;
                    pending.extend(bytes);
                    continue;
                } else if stack.receive_closed()
                    || matches!(
                        stack.state(),
                        SmolTcpState::CloseWait | SmolTcpState::LastAck | SmolTcpState::Closed
                    )
                {
                    return Ok(0);
                }
            }
            self.signal.wait_for_change_until(generation, deadline)?;
        }
    }
}

impl Write for TunTcpStreamHandle {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let deadline = self
            .write_timeout
            .lock()
            .unwrap()
            .map(|timeout| std::time::Instant::now() + timeout);
        loop {
            let generation = self.signal.current_generation()?;
            {
                let mut stack = self
                    .stack
                    .lock()
                    .map_err(|_| io::Error::other("tun tcp stack mutex poisoned"))?;
                stack.poll();
                let written = stack.send_application(buf)?;
                stack.poll();
                self.emit_outgoing(&mut stack)?;
                if written > 0 {
                    return Ok(written);
                }
            }
            // A full smoltcp buffer is backpressure, not an EOF/write-zero.
            // ACK processing wakes us after freeing space; release the stack
            // mutex before waiting so the packet worker can process that ACK.
            self.signal.wait_for_change_until(generation, deadline)?;
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut stack = self
            .stack
            .lock()
            .map_err(|_| io::Error::other("tun tcp stack mutex poisoned"))?;
        stack.poll();
        self.emit_outgoing(&mut stack)?;
        Ok(())
    }
}

impl CoreTcpStream for TunTcpStreamHandle {
    fn read_timeout(&self) -> io::Result<Option<std::time::Duration>> {
        Ok(*self.read_timeout.lock().unwrap())
    }
    fn set_read_timeout(&self, timeout: Option<std::time::Duration>) -> io::Result<()> {
        *self.read_timeout.lock().unwrap() = timeout;
        Ok(())
    }
    fn set_timeouts(
        &self,
        read: Option<std::time::Duration>,
        write: Option<std::time::Duration>,
    ) -> io::Result<()> {
        *self.read_timeout.lock().unwrap() = read;
        *self.write_timeout.lock().unwrap() = write;
        self.signal.notify();
        Ok(())
    }
    fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
        Ok(Box::new(self.clone()))
    }

    fn shutdown_write(&mut self) -> io::Result<()> {
        let mut stack = self
            .stack
            .lock()
            .map_err(|_| io::Error::other("tun tcp stack mutex poisoned"))?;
        stack.close();
        stack.poll();
        self.emit_outgoing(&mut stack)?;
        Ok(())
    }

    fn shutdown_all(&mut self) -> io::Result<()> {
        let mut stack = self
            .stack
            .lock()
            .map_err(|_| io::Error::other("tun tcp stack mutex poisoned"))?;
        stack.abort();
        stack.poll();
        self.emit_outgoing(&mut stack)
    }
}
