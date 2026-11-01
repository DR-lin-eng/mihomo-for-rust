//! XTLS Vision padding and per-direction TLS passthrough.
use std::io::{self, Read, Write};
use std::sync::{Arc, Mutex};

use mihomo_core::{BoxedTcpStream, TcpStream};
use rand::Rng;

mod tls;
use tls::VisionTlsState;

const UUID_LEN: usize = 16;
const COMMAND_PADDING_CONTINUE: u8 = 0;
const COMMAND_PADDING_END: u8 = 1;
const COMMAND_PADDING_DIRECT: u8 = 2;
const TLS_APPLICATION_DATA_START: &[u8] = &[0x17, 0x03, 0x03];
// Match the reference implementation's 8 KiB buffers, including the UUID.
const BUFFER_LIMIT: usize = 8192 - UUID_LEN - 5;

struct WriteState {
    padding: bool,
    uuid: Option<[u8; UUID_LEN]>,
}

pub(crate) struct VisionStream {
    inner: BoxedTcpStream,
    tls_state: Arc<Mutex<VisionTlsState>>,
    write_state: Arc<Mutex<WriteState>>,
    tls13: bool,
    user_uuid: [u8; UUID_LEN],
    readable: bool,
    read_process: bool,
    read_filter_uuid: bool,
    read_header: Vec<u8>,
    read_last_command: u8,
    read_remaining_content: usize,
    read_remaining_padding: usize,
}

impl VisionStream {
    pub(crate) fn new(inner: BoxedTcpStream, tls13: bool, user_uuid: [u8; UUID_LEN]) -> Self {
        Self {
            inner,
            tls_state: Arc::new(Mutex::new(VisionTlsState::default())),
            write_state: Arc::new(Mutex::new(WriteState {
                padding: true,
                uuid: Some(user_uuid),
            })),
            tls13,
            user_uuid,
            readable: true,
            read_process: true,
            read_filter_uuid: true,
            read_header: Vec::new(),
            read_last_command: COMMAND_PADDING_CONTINUE,
            read_remaining_content: 0,
            read_remaining_padding: 0,
        }
    }

    pub(crate) fn start(&mut self) -> io::Result<()> {
        let mut state = self.write_state.lock().unwrap();
        if state.uuid.is_some() {
            // Dispatch the VLESS request even for protocols whose server speaks
            // first. Long padding also conceals the initial request's length.
            let frame = frame_payload(&mut state.uuid, COMMAND_PADDING_CONTINUE, &[], true);
            self.inner.write_all(&frame)?;
            self.inner.flush()?;
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn tls13(&self) -> bool {
        self.tls13
    }

    #[cfg(test)]
    pub(crate) fn xtls_enabled(&self) -> bool {
        self.tls_state.lock().unwrap().enable_xtls
    }

    #[cfg(test)]
    pub(crate) fn get_mut(&mut self) -> &mut dyn TcpStream {
        &mut *self.inner
    }

    fn read_frame_header(&mut self) -> io::Result<bool> {
        let need = if self.read_filter_uuid {
            UUID_LEN + 5
        } else {
            5
        };
        while self.read_header.len() < need {
            let mut part = [0_u8; UUID_LEN + 5];
            let n = match self.inner.read(&mut part[..need - self.read_header.len()]) {
                Ok(0) if self.read_header.is_empty() && !self.read_filter_uuid => return Ok(false),
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "truncated Vision header",
                    ))
                }
                Ok(n) => n,
                Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                Err(err) => return Err(err),
            };
            self.read_header.extend_from_slice(&part[..n]);
        }
        let offset = if self.read_filter_uuid {
            if self.read_header[..UUID_LEN] != self.user_uuid {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Vision peer UUID mismatch",
                ));
            }
            self.read_filter_uuid = false;
            UUID_LEN
        } else {
            0
        };
        let header = &self.read_header[offset..];
        if header[0] > COMMAND_PADDING_DIRECT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unknown Vision padding command",
            ));
        }
        self.read_last_command = header[0];
        self.read_remaining_content = u16::from_be_bytes([header[1], header[2]]) as usize;
        self.read_remaining_padding = u16::from_be_bytes([header[3], header[4]]) as usize;
        self.read_header.clear();
        Ok(true)
    }
}

impl Read for VisionStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if !self.readable {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Vision clone is write-only",
            ));
        }
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            if !self.read_process {
                return self.inner.read(buf);
            }
            if self.read_remaining_content > 0 {
                let need = buf.len().min(self.read_remaining_content);
                let n = self.inner.read(&mut buf[..need])?;
                if n == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "truncated Vision content",
                    ));
                }
                self.read_remaining_content -= n;
                self.tls_state.lock().unwrap().filter_read_tls(&buf[..n]);
                // Return content immediately. Padding may arrive later or time out.
                return Ok(n);
            }
            while self.read_remaining_padding > 0 {
                let mut padding = [0_u8; 1024];
                let need = padding.len().min(self.read_remaining_padding);
                match self.inner.read(&mut padding[..need]) {
                    Ok(0) => {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "truncated Vision padding",
                        ))
                    }
                    Ok(n) => self.read_remaining_padding -= n,
                    Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                    Err(err) => return Err(err),
                }
            }
            match self.read_last_command {
                COMMAND_PADDING_END => self.read_process = false,
                COMMAND_PADDING_DIRECT => {
                    self.inner.start_tls_passthrough_read()?;
                    self.read_process = false;
                }
                _ => {
                    if !self.read_frame_header()? {
                        return Ok(0);
                    }
                }
            }
        }
    }
}

fn frame_payload(
    uuid: &mut Option<[u8; UUID_LEN]>,
    command: u8,
    payload: &[u8],
    tls: bool,
) -> Vec<u8> {
    let padding_len = if payload.len() < 900 {
        if tls {
            rand::thread_rng().gen_range(900..1400) - payload.len()
        } else {
            rand::thread_rng().gen_range(0..256)
        }
    } else {
        0
    };
    let mut frame = Vec::with_capacity(UUID_LEN + 5 + payload.len() + padding_len);
    if let Some(uuid) = uuid.take() {
        frame.extend_from_slice(&uuid);
    }
    frame.push(command);
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    frame.extend_from_slice(&(padding_len as u16).to_be_bytes());
    frame.extend_from_slice(payload);
    frame.resize(frame.len() + padding_len, 0);
    frame
}

impl Write for VisionStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut state = self.write_state.lock().unwrap();
        if !state.padding {
            return self.inner.write(buf);
        }
        self.tls_state.lock().unwrap().filter_tls(buf);
        let mut remaining = buf;
        while !remaining.is_empty() {
            if !state.padding {
                self.inner.write_all(remaining)?;
                break;
            }
            let len = if remaining.len() < BUFFER_LIMIT {
                remaining.len()
            } else {
                remaining
                    .windows(3)
                    .rposition(|p| p == TLS_APPLICATION_DATA_START)
                    .filter(|&n| (21..=BUFFER_LIMIT).contains(&n))
                    .unwrap_or(4096)
            };
            let payload = &remaining[..len];
            let tls = self.tls_state.lock().unwrap();
            let command = if tls.is_tls
                && payload.len() > 6
                && payload.starts_with(TLS_APPLICATION_DATA_START)
            {
                if tls.enable_xtls && self.tls13 && self.inner.supports_tls_passthrough() {
                    COMMAND_PADDING_DIRECT
                } else {
                    COMMAND_PADDING_END
                }
            } else if !tls.is_tls12_or_above && tls.packets_to_filter <= 1 {
                COMMAND_PADDING_END
            } else {
                COMMAND_PADDING_CONTINUE
            };
            let frame = frame_payload(&mut state.uuid, command, payload, tls.is_tls);
            drop(tls);
            self.inner.write_all(&frame)?;
            if command != COMMAND_PADDING_CONTINUE {
                state.padding = false;
            }
            if command == COMMAND_PADDING_DIRECT {
                // The command and its padding must be fully flushed through TLS
                // before the next byte bypasses TLS in this direction.
                self.inner.start_tls_passthrough_write()?;
            }
            remaining = &remaining[len..];
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        let _state = self.write_state.lock().unwrap();
        self.inner.flush()
    }
}

impl TcpStream for VisionStream {
    fn tcp_stats(&self)->Option<mihomo_core::TcpStats>{self.inner.tcp_stats()}
    fn set_timeouts(&self,read:Option<std::time::Duration>,write:Option<std::time::Duration>)->io::Result<()>{self.inner.set_timeouts(read,write)}
    fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
        Ok(Box::new(Self {
            inner: self.inner.try_clone_box()?,
            tls_state: Arc::clone(&self.tls_state),
            write_state: Arc::clone(&self.write_state),
            tls13: self.tls13,
            user_uuid: self.user_uuid,
            readable: false,
            read_process: true,
            read_filter_uuid: true,
            read_header: Vec::new(),
            read_last_command: COMMAND_PADDING_CONTINUE,
            read_remaining_content: 0,
            read_remaining_padding: 0,
        }))
    }
    fn shutdown_write(&mut self) -> io::Result<()> {
        let _state = self.write_state.lock().unwrap();
        self.inner.shutdown_write()
    }
    fn shutdown_all(&mut self) -> io::Result<()> {
        self.inner.shutdown_all()
    }
}

#[cfg(test)]
mod tests;
