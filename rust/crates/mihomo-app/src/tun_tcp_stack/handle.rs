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
}

impl TunTcpStreamHandle {
    fn from_parts(stack: TunTcpPassiveStack, egress: Option<EgressFn>) -> Self {
        let signal = stack.signal();
        Self {
            stack: Arc::new(Mutex::new(stack)),
            pending_read: Arc::new(Mutex::new(VecDeque::new())),
            signal,
            egress,
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
            self.signal.wait_for_change(generation)?;
        }
    }
}

impl Write for TunTcpStreamHandle {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut stack = self
            .stack
            .lock()
            .map_err(|_| io::Error::other("tun tcp stack mutex poisoned"))?;
        let written = stack.send_application(buf)?;
        stack.poll();
        self.emit_outgoing(&mut stack)?;
        Ok(written)
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
}
