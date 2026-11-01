mod config;
mod tcp_stack;
mod test_server;
mod udp_bridge;

use std::io;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream as NetTcpStream, UdpSocket as NetUdpSocket};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aes::Aes256;
use aes_gcm::aead::{AeadInPlace, KeyInit as AeadKeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce, Tag};
use ctr::cipher::{KeyIvInit, StreamCipher};
use hmac::{Hmac, Mac};
use mihomo_core::{BoxedTcpStream, TcpStream as MihomoTcpStream};
use rand::Rng;
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerName, StreamOwned};
use sha1::Sha1;
use sha2::Sha256;
use crate::{stream_prefix::PrefixedTcpStream, TransportError};
pub use test_server::OpenVpnTestServer;

pub const PROTO_UDP: &str = "udp";
pub const PROTO_TCP: &str = "tcp";
pub const CIPHER_AES_128_GCM: &str = "AES-128-GCM";
pub const CIPHER_AES_256_GCM: &str = "AES-256-GCM";
pub const AUTH_SHA256: &str = "SHA256";

pub const TLS_CRYPT_HEADER_SIZE: usize = 1 + 8;
pub const TLS_CRYPT_PID_SIZE: usize = 4 + 4;
pub const TLS_CRYPT_TAG_SIZE: usize = 32;
pub const SESSION_ID_SIZE: usize = 8;
pub const KEY_METHOD_2: u8 = 2;
pub const PACKET_MUX_CONTROL_CAPACITY: usize = 64;
pub const PACKET_MUX_DATA_CAPACITY: usize = 256;
pub const PEER_ID_UNSET: u32 = 0x00ff_ffff;
pub const PUSH_REQUEST: &str = "PUSH_REQUEST";
pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
pub const DATA_AES_GCM_TAG_SIZE: usize = 16;
pub const DATA_AES_GCM_NONCE_SIZE: usize = 12;
pub(crate) const OPENVPN_UDP_SOURCE_PORT: u16 = 24000;
const OPENVPN_TEST_CA_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIDSTCCAjGgAwIBAgIUB0hPySAWj1EX3N2sAkaERvkIhr4wDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDUyNDIzMjA0NVoXDTM2MDUy
MTIzMjA0NVowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEA0JI73eSCOWjmdskPmMrXy0icejyF2F/m2z+sKZsHMlw7
2x5pcvWSLBhMz/lBODdEXEc/62OxUED3CkcC4CFc60uJVxt2FH8cXNcn27k0jGnY
6oPmg8E2rzArE1QYbTdePqUWmld8EC59jyulf5LNuA+7kfDdQoiwq9cSxIQMBNlg
eHs5xla60DfDz1LQI1ST0tt3C0GsT211G5GcE53+IrgVc1TsS8E7XA+tfM72czr7
1NkFu79Usw0xQTYjicZsBc29U1babdwsB7E4qtTodOrCs1pWqGWWG6JvTE7K0k+o
5e/YJuUOo2X6jV/zJPfA2fRBDXb5+aykn/kl2zR+WwIDAQABo4GSMIGPMB0GA1Ud
DgQWBBQQM7CRZJAgIEVKo8aln7OPYRip2zAfBgNVHSMEGDAWgBQQM7CRZJAgIEVK
o8aln7OPYRip2zAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIFoDATBgNVHSUE
DDAKBggrBgEFBQcDATAaBgNVHREEEzARgglsb2NhbGhvc3SHBH8AAAEwDQYJKoZI
hvcNAQELBQADggEBAD2wfet2ymg8GAghPIQbIpexTGItxEDWn1XOgetQlWwCMyWN
P6yYSUkOnA5EhI6VEy3sQPAPOZU1qremm9NOF5jo+29MZaHhk0J1vDqGhHd7Pqpg
W8FE8imhblDC5+v8VqZ+MDBf0j7qt7MGOVaEVNllGhj9th199iHCgqI+mGwc0gJo
FkAwaddzG3c41Ti0N8DP8Pdzp/UbLzJOGnBmPECYKhJ4bCEYPAlsif/UHV6XIk5F
wPP5oCnd1DiKgkHDPQXNYCHAbd0Yes41L6pnDEBUe+U3XB5Eh0C/uq+EeScl7ppy
3oAYX6vTUdjc3d0NaIMQ6gQETXFe7yL9tH1sTLw=
-----END CERTIFICATE-----"#;

const OPENVPN_TEST_KEY_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDQkjvd5II5aOZ2
yQ+YytfLSJx6PIXYX+bbP6wpmwcyXDvbHmly9ZIsGEzP+UE4N0RcRz/rY7FQQPcK
RwLgIVzrS4lXG3YUfxxc1yfbuTSMadjqg+aDwTavMCsTVBhtN14+pRaaV3wQLn2P
K6V/ks24D7uR8N1CiLCr1xLEhAwE2WB4eznGVrrQN8PPUtAjVJPS23cLQaxPbXUb
kZwTnf4iuBVzVOxLwTtcD618zvZzOvvU2QW7v1SzDTFBNiOJxmwFzb1TVtpt3CwH
sTiq1Oh06sKzWlaoZZYbom9MTsrST6jl79gm5Q6jZfqNX/Mk98DZ9EENdvn5rKSf
+SXbNH5bAgMBAAECggEACfRw1w5pCMRw+4ptLCXCVvmIPm1VFha9tgk79mBn34d3
c+Xnsoz2BRTD1clXy48XvC/KZTnE5Me1AtCQ2pG9FZ3tWDL/V8sZV3UNefdFAs6q
g8b34aH/Mi1iYPHKmKvj26mVgphaW4tcgtDafVRMbVSS50xPwzUy+YCybJ7A1BpV
2N58PHG/LG6mtQ8KtF2WBa5Uca1Hi5NNS83s4XhDNy5hZiZnLra7u7mmHo5UEaRN
IqyjOeHlWyAjVZGa8l5AN6kwYtyb/qbls90C3PMuwdY+FADLvfaVhkuB/YudW8OE
ZSruGXQA1qmk5fhlCvbwvx7Y8gmuL/YM7F4rEXurwQKBgQD5jfpkH3bCwfs9ijtg
ygTlRCt9dmYrFAP1g6M4nAt4FP37uiz95mB3A7bNUgbSY6j7OtCl4w3/jKRB/t0R
9Fx46hWo3viWcGt6EXg3BIUCtE97BsWt8IGiqiFJW9uUv70H3ji5bvYtBiWAn16K
LfUt8s8I1bc0fFNa+Y5DdGfbRwKBgQDV9Ud0gwecitA8oucBEzswlODn5zZpl38I
gWgczjsPl76i2JlrB+wGRZL+7DfilxHGahea5Lah/1TDlHCYybHCLKCBdpQMEiep
4QyWxJb1tbi/9gC16h1IKL6raxSxNoLnB8VBtxs3Knh948BYUlix1YA4zNAfDbKW
DkRNJr0mTQKBgBPP7MgUI2aU5fBd0BcAEuFsxxMf2j6jSSktuUCeSt7Os9dPUZEa
wB/SwKmOUJJVbS383mG9I/hc3xGKPVzWjJzg4LVWdl/jLvUy+9tKVZEAZar7v6fu
hyw124yqaUVm74f3YYN/RrYOXd3XSTcpLOTn+P3XkcLt9+QqGdxLGo+zAoGAXJBW
DpkVdOs1NdaAPB3W0KjIOGv2RW5uXf6mTTgHozJSHl+41+5AdWIqOzF06AnVfdKu
Tau/O4ycXlTc9azkw43NDtV/LU25bSxY5u08JictO5cxLYKQkoRWIREdjaF4tnzN
ISYXlyE/qa8bqtpNVvp4E5rAO38QkQyxDfPBh00CgYALwK237DTnLM4z4VzBPqkw
tsgYHEagqL0wdg5xuREkALNEy0queVv9zPIlFY0rh7oTFtXPFlGaMU5FjjzNIYuU
dS7F37hjKsxZ3KAabm9SChpApNqAX8TZSws1PE0wL08DpkRdyVxgW7xVpqum5XkD
12xnweIiRM1+46qc7dpHUQ==
-----END PRIVATE KEY-----"#;

const OPENVPN_TEST_TLS_CRYPT_PEM: &str = r#"-----BEGIN OpenVPN Static key V1-----
11111111111111111111111111111111
11111111111111111111111111111111
11111111111111111111111111111111
11111111111111111111111111111111
11111111111111111111111111111111
11111111111111111111111111111111
11111111111111111111111111111111
11111111111111111111111111111111
11111111111111111111111111111111
11111111111111111111111111111111
11111111111111111111111111111111
11111111111111111111111111111111
11111111111111111111111111111111
11111111111111111111111111111111
11111111111111111111111111111111
11111111111111111111111111111111
-----END OpenVPN Static key V1-----"#;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenVpnOptions {
    pub server: String,
    pub port: u16,
    pub proto: String,
    pub dev: String,
    pub cipher: String,
    pub auth: String,
    pub ca: String,
    pub cert: String,
    pub key: String,
    pub tls_crypt: String,
    pub username: String,
    pub password: String,
    pub remote_dns_resolve: bool,
    pub dns: Vec<String>,
    pub mtu: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenVpnConfig {
    pub remote_host: String,
    pub remote_port: u16,
    pub proto: String,
    pub dev: String,
    pub cipher: String,
    pub auth: String,
    pub ca: Vec<u8>,
    pub cert: Vec<u8>,
    pub key: Vec<u8>,
    pub tls_crypt: Vec<u8>,
    pub username: String,
    pub password: String,
    pub tls_crypt_key: Vec<u8>,
    pub mtu: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TlsCryptKeys {
    pub encrypt_cipher_key: Vec<u8>,
    pub encrypt_hmac_key: Vec<u8>,
    pub decrypt_cipher_key: Vec<u8>,
    pub decrypt_hmac_key: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpenVpnOpcode {
    ControlHardResetClientV2 = 7,
    ControlHardResetServerV2 = 8,
    ControlV1 = 4,
    AckV1 = 5,
    DataV1 = 6,
    DataV2 = 9,
}

impl OpenVpnOpcode {
    pub fn is_control(self) -> bool {
        matches!(
            self,
            Self::ControlHardResetClientV2 | Self::ControlHardResetServerV2 | Self::ControlV1 | Self::AckV1
        )
    }

    pub fn has_message_id(self) -> bool {
        self.is_control() && !matches!(self, Self::AckV1)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenVpnControlPacket {
    pub opcode: OpenVpnOpcode,
    pub key_id: u8,
    pub local_session: [u8; SESSION_ID_SIZE],
    pub ack_ids: Vec<u32>,
    pub ack_remote_session: [u8; SESSION_ID_SIZE],
    pub message_id: u32,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeySource {
    pub pre_master: [u8; 48],
    pub random1: [u8; 32],
    pub random2: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeySource2 {
    pub client: KeySource,
    pub server: KeySource,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyMethod2Record {
    pub sources: KeySource2,
    pub options: String,
    pub username: String,
    pub password: String,
    pub peer_info: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyMaterial {
    pub send_cipher_key: Vec<u8>,
    pub send_hmac_key: Vec<u8>,
    pub recv_cipher_key: Vec<u8>,
    pub recv_hmac_key: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenVpnPushReply {
    pub raw: String,
    pub prefixes: Vec<String>,
    pub dns: Vec<String>,
    pub peer_id: u32,
    pub redirect: bool,
    pub block_ipv6: bool,
}

pub(crate) trait PacketIo: Send + 'static {
    fn read_packet(&mut self, timeout: Option<Duration>) -> io::Result<Vec<u8>>;
    fn write_packet(&mut self, packet: &[u8]) -> io::Result<()>;
    fn close(&mut self) -> io::Result<()>;
    fn local_addr(&self) -> io::Result<SocketAddr>;
    fn remote_addr(&self) -> io::Result<SocketAddr>;
}

pub(crate) struct DatagramPacketIo {
    socket: NetUdpSocket,
}

pub(crate) struct StreamPacketIo {
    stream: NetTcpStream,
}

pub(crate) struct BoxedStreamPacketIo {
    stream: BoxedTcpStream,
    read_rx: mpsc::Receiver<io::Result<Vec<u8>>>,
    reader: Option<thread::JoinHandle<()>>,
}

pub(crate) struct PacketMux {
    control_rx: mpsc::Receiver<Vec<u8>>,
    data_rx: mpsc::Receiver<Vec<u8>>,
    write_tx: mpsc::Sender<WriteRequest>,
    close_tx: mpsc::Sender<()>,
    worker: Option<thread::JoinHandle<()>>,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
}

struct WriteRequest {
    packet: Vec<u8>,
    result_tx: mpsc::Sender<io::Result<()>>,
}

type HmacSha256 = Hmac<Sha256>;
type Aes256Ctr = ctr::Ctr128BE<Aes256>;

#[derive(Clone)]
enum OpenVpnAead {
    Aes128(Box<Aes128Gcm>),
    Aes256(Box<Aes256Gcm>),
}

pub(crate) struct DataChannel {
    send: OpenVpnAead,
    recv: OpenVpnAead,
    send_implicit_iv: [u8; DATA_AES_GCM_NONCE_SIZE],
    recv_implicit_iv: [u8; DATA_AES_GCM_NONCE_SIZE],
    key_id: u8,
    peer_id: u32,
    send_packet_id: u32,
    recv_highest: u32,
    recv_seen: bool,
}

#[derive(Clone)]
pub(crate) struct ControlChannel {
    mux: Arc<Mutex<PacketMux>>,
    crypt: TlsCryptKeys,
    key_id: u8,
    local: [u8; SESSION_ID_SIZE],
    state: Arc<Mutex<ControlChannelState>>,
}

struct ControlChannelState {
    remote: [u8; SESSION_ID_SIZE],
    send_packet_id: u32,
    send_message: u32,
    ack_pending: Vec<u32>,
    pending: std::collections::BTreeMap<u32, OpenVpnControlPacket>,
}

pub(crate) struct ControlConn {
    channel: ControlChannel,
    read_buf: Vec<u8>,
    closed: bool,
}

pub(crate) struct OpenVpnClient {
    config: OpenVpnConfig,
    mux: Arc<Mutex<PacketMux>>,
    control: ControlChannel,
    data: Option<DataChannel>,
    push: Option<OpenVpnPushReply>,
}

pub(crate) fn new_tls_crypt_keys(
    static_key: &[u8],
    client: bool,
) -> Result<TlsCryptKeys, TransportError> {
    if static_key.len() != 256 {
        return Err(TransportError::InvalidPlan(format!(
            "invalid tls-crypt static key length {}, expected 256",
            static_key.len()
        )));
    }
    let (key0, key1) = static_key.split_at(128);
    let (encrypt, decrypt) = if client { (key1, key0) } else { (key0, key1) };
    Ok(TlsCryptKeys {
        encrypt_cipher_key: encrypt[..32].to_vec(),
        encrypt_hmac_key: encrypt[64..96].to_vec(),
        decrypt_cipher_key: decrypt[..32].to_vec(),
        decrypt_hmac_key: decrypt[64..96].to_vec(),
    })
}

impl DatagramPacketIo {
    pub(crate) fn new(socket: NetUdpSocket) -> Self {
        Self { socket }
    }
}

impl PacketIo for DatagramPacketIo {
    fn read_packet(&mut self, timeout: Option<Duration>) -> io::Result<Vec<u8>> {
        self.socket.set_read_timeout(timeout)?;
        let mut buf = [0_u8; 64 * 1024];
        let read = self.socket.recv(&mut buf)?;
        Ok(buf[..read].to_vec())
    }

    fn write_packet(&mut self, packet: &[u8]) -> io::Result<()> {
        self.socket.send(packet).map(|_| ())
    }

    fn close(&mut self) -> io::Result<()> {
        Ok(())
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    fn remote_addr(&self) -> io::Result<SocketAddr> {
        self.socket.peer_addr()
    }
}
impl StreamPacketIo {
    pub(crate) fn new(stream: NetTcpStream) -> Self {
        Self { stream }
    }
}

impl BoxedStreamPacketIo {
    pub(crate) fn new(stream: BoxedTcpStream) -> io::Result<Self> {
        let mut reader_stream = stream.try_clone_box()?;
        let (read_tx, read_rx) = mpsc::channel();
        let reader = thread::spawn(move || {
            loop {
                match read_len_prefixed_packet(&mut *reader_stream) {
                    Ok(packet) => {
                        if read_tx.send(Ok(packet)).is_err() {
                            break;
                        }
                    }
                    Err(err) => {
                        let _ = read_tx.send(Err(err));
                        break;
                    }
                }
            }
        });
        Ok(Self {
            stream,
            read_rx,
            reader: Some(reader),
        })
    }
}

impl PacketIo for StreamPacketIo {
    fn read_packet(&mut self, timeout: Option<Duration>) -> io::Result<Vec<u8>> {
        self.stream.set_read_timeout(timeout)?;
        let mut len = [0_u8; 2];
        std::io::Read::read_exact(&mut self.stream, &mut len)?;
        let size = u16::from_be_bytes(len) as usize;
        if size == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "empty openvpn tcp packet",
            ));
        }
        let mut packet = vec![0_u8; size];
        std::io::Read::read_exact(&mut self.stream, &mut packet)?;
        Ok(packet)
    }

    fn write_packet(&mut self, packet: &[u8]) -> io::Result<()> {
        if packet.len() > u16::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("openvpn tcp packet too large: {}", packet.len()),
            ));
        }
        self.stream
            .write_all(&(packet.len() as u16).to_be_bytes())?;
        self.stream.write_all(packet)?;
        self.stream.flush()
    }

    fn close(&mut self) -> io::Result<()> {
        self.stream.shutdown(std::net::Shutdown::Both)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.stream.local_addr()
    }

    fn remote_addr(&self) -> io::Result<SocketAddr> {
        self.stream.peer_addr()
    }
}

impl PacketIo for BoxedStreamPacketIo {
    fn read_packet(&mut self, timeout: Option<Duration>) -> io::Result<Vec<u8>> {
        let recv = match timeout {
            Some(timeout) => self
                .read_rx
                .recv_timeout(timeout)
                .map_err(|err| match err {
                    mpsc::RecvTimeoutError::Timeout => {
                        io::Error::new(io::ErrorKind::TimedOut, "openvpn tcp packet receive timed out")
                    }
                    mpsc::RecvTimeoutError::Disconnected => {
                        io::Error::new(io::ErrorKind::BrokenPipe, "openvpn tcp packet channel closed")
                    }
                })?,
            None => self
                .read_rx
                .recv()
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "openvpn tcp packet channel closed"))?,
        };
        recv
    }

    fn write_packet(&mut self, packet: &[u8]) -> io::Result<()> {
        if packet.len() > u16::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("openvpn tcp packet too large: {}", packet.len()),
            ));
        }
        self.stream
            .write_all(&(packet.len() as u16).to_be_bytes())?;
        self.stream.write_all(packet)?;
        self.stream.flush()
    }

    fn close(&mut self) -> io::Result<()> {
        let _ = self.stream.shutdown_all();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
        Ok(())
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        boxed_stream_addr(self.stream.as_ref(), true)
    }

    fn remote_addr(&self) -> io::Result<SocketAddr> {
        boxed_stream_addr(self.stream.as_ref(), false)
    }
}

fn boxed_stream_addr(stream: &dyn MihomoTcpStream, local: bool) -> io::Result<SocketAddr> {
    let any = stream as &dyn std::any::Any;
    if let Some(net) = any.downcast_ref::<NetTcpStream>() {
        return if local {
            net.local_addr()
        } else {
            net.peer_addr()
        };
    }
    if let Some(prefixed) = any.downcast_ref::<PrefixedTcpStream>() {
        return boxed_stream_addr(prefixed.inner(), local);
    }
    if let Some(boxed) = any.downcast_ref::<BoxedTcpStream>() {
        return boxed_stream_addr(boxed.as_ref(), local);
    }
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "openvpn boxed tcp stream address inspection is not supported",
    ))
}

fn read_len_prefixed_packet(stream: &mut dyn Read) -> io::Result<Vec<u8>> {
    let mut len = [0_u8; 2];
    std::io::Read::read_exact(stream, &mut len)?;
    let size = u16::from_be_bytes(len) as usize;
    if size == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "empty openvpn tcp packet",
        ));
    }
    let mut packet = vec![0_u8; size];
    std::io::Read::read_exact(stream, &mut packet)?;
    Ok(packet)
}

impl PacketMux {
    pub(crate) fn new(io: Box<dyn PacketIo>) -> Self {
        let (control_tx, control_rx) = mpsc::sync_channel(PACKET_MUX_CONTROL_CAPACITY);
        let (data_tx, data_rx) = mpsc::sync_channel(PACKET_MUX_DATA_CAPACITY);
        let (write_tx, write_rx) = mpsc::channel::<WriteRequest>();
        let (close_tx, close_rx) = mpsc::channel();
        let local_addr = io.local_addr().unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap());
        let remote_addr = io.remote_addr().unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap());
        let worker = thread::spawn(move || {
            let mut io = io;
            loop {
                if close_rx.try_recv().is_ok() {
                    break;
                }
                while let Ok(request) = write_rx.try_recv() {
                    let result = io.write_packet(&request.packet);
                    let _ = request.result_tx.send(result);
                }
                let packet = io.read_packet(Some(Duration::from_millis(100)));
                let packet = match packet {
                    Ok(packet) if !packet.is_empty() => packet,
                    Ok(_) => continue,
                    Err(err)
                        if matches!(
                            err.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                        ) =>
                    {
                        continue;
                    }
                    Err(_) => break,
                };
                let target = if is_control_opcode(packet[0]) {
                    &control_tx
                } else {
                    &data_tx
                };
                if target.send(packet).is_err() {
                    break;
                }
            }
            let _ = io.close();
        });
        Self {
            control_rx,
            data_rx,
            write_tx,
            close_tx,
            worker: Some(worker),
            local_addr,
            remote_addr,
        }
    }

    pub(crate) fn read_control_packet(
        &self,
        timeout: Option<Duration>,
    ) -> io::Result<Vec<u8>> {
        recv_channel(&self.control_rx, timeout)
    }

    pub(crate) fn read_data_packet(
        &self,
        timeout: Option<Duration>,
    ) -> io::Result<Vec<u8>> {
        recv_channel(&self.data_rx, timeout)
    }

    pub(crate) fn write_packet(&self, packet: &[u8]) -> io::Result<()> {
        let (result_tx, result_rx) = mpsc::channel();
        self.write_tx
            .send(WriteRequest {
                packet: packet.to_vec(),
                result_tx,
            })
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "openvpn packet mux closed"))?;
        result_rx
            .recv()
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "openvpn packet mux closed"))?
    }

    pub(crate) fn close(&mut self) -> io::Result<()> {
        let _ = self.close_tx.send(());
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
        Ok(())
    }

    pub(crate) fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }

    pub(crate) fn remote_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.remote_addr)
    }
}

impl OpenVpnAead {
    fn new(key: &[u8]) -> Result<Self, TransportError> {
        match key.len() {
            16 => Ok(Self::Aes128(Box::new(
                Aes128Gcm::new_from_slice(key).map_err(|err| {
                    TransportError::InvalidPlan(format!("openvpn aes-128-gcm init failed: {err}"))
                })?,
            ))),
            32 => Ok(Self::Aes256(Box::new(
                Aes256Gcm::new_from_slice(key).map_err(|err| {
                    TransportError::InvalidPlan(format!("openvpn aes-256-gcm init failed: {err}"))
                })?,
            ))),
            other => Err(TransportError::InvalidPlan(format!(
                "unsupported openvpn data cipher key length {other}"
            ))),
        }
    }

    fn encrypt_in_place_detached(
        &self,
        nonce: &[u8; DATA_AES_GCM_NONCE_SIZE],
        aad: &[u8],
        buffer: &mut Vec<u8>,
    ) -> Result<[u8; DATA_AES_GCM_TAG_SIZE], TransportError> {
        let nonce = Nonce::from_slice(nonce);
        let tag = match self {
            Self::Aes128(cipher) => cipher.encrypt_in_place_detached(nonce, aad, buffer),
            Self::Aes256(cipher) => cipher.encrypt_in_place_detached(nonce, aad, buffer),
        }
        .map_err(|err| {
            TransportError::InvalidPlan(format!("openvpn data encryption failed: {err}"))
        })?;
        let mut out = [0_u8; DATA_AES_GCM_TAG_SIZE];
        out.copy_from_slice(tag.as_slice());
        Ok(out)
    }

    fn decrypt_in_place_detached(
        &self,
        nonce: &[u8; DATA_AES_GCM_NONCE_SIZE],
        aad: &[u8],
        buffer: &mut Vec<u8>,
        tag: &[u8],
    ) -> Result<(), TransportError> {
        let nonce = Nonce::from_slice(nonce);
        let tag = Tag::from_slice(tag);
        match self {
            Self::Aes128(cipher) => cipher.decrypt_in_place_detached(nonce, aad, buffer, tag),
            Self::Aes256(cipher) => cipher.decrypt_in_place_detached(nonce, aad, buffer, tag),
        }
        .map_err(|err| {
            TransportError::InvalidPlan(format!("openvpn data decryption failed: {err}"))
        })
    }
}

impl DataChannel {
    pub(crate) fn new(
        keys: &KeyMaterial,
        peer_id: u32,
    ) -> Result<Self, TransportError> {
        if keys.send_hmac_key.len() < DATA_AES_GCM_NONCE_SIZE - 4
            || keys.recv_hmac_key.len() < DATA_AES_GCM_NONCE_SIZE - 4
        {
            return Err(TransportError::InvalidPlan(
                "openvpn implicit IV keys are too short".to_owned(),
            ));
        }
        let mut send_implicit_iv = [0_u8; DATA_AES_GCM_NONCE_SIZE];
        let mut recv_implicit_iv = [0_u8; DATA_AES_GCM_NONCE_SIZE];
        send_implicit_iv[4..].copy_from_slice(&keys.send_hmac_key[..DATA_AES_GCM_NONCE_SIZE - 4]);
        recv_implicit_iv[4..].copy_from_slice(&keys.recv_hmac_key[..DATA_AES_GCM_NONCE_SIZE - 4]);
        Ok(Self {
            send: OpenVpnAead::new(&keys.send_cipher_key)?,
            recv: OpenVpnAead::new(&keys.recv_cipher_key)?,
            send_implicit_iv,
            recv_implicit_iv,
            key_id: 0,
            peer_id,
            send_packet_id: 0,
            recv_highest: 0,
            recv_seen: false,
        })
    }

    fn nonce(&self, packet_id: u32, implicit: &[u8; DATA_AES_GCM_NONCE_SIZE]) -> [u8; DATA_AES_GCM_NONCE_SIZE] {
        let mut nonce = *implicit;
        let prefix = u32::from_be_bytes(nonce[..4].try_into().unwrap()) ^ packet_id;
        nonce[..4].copy_from_slice(&prefix.to_be_bytes());
        nonce
    }

    fn data_header(&self) -> Vec<u8> {
        if self.peer_id != PEER_ID_UNSET {
            vec![
                opcode_key_id(OpenVpnOpcode::DataV2, self.key_id),
                (self.peer_id >> 16) as u8,
                (self.peer_id >> 8) as u8,
                self.peer_id as u8,
            ]
        } else {
            vec![opcode_key_id(OpenVpnOpcode::DataV1, self.key_id)]
        }
    }

    pub(crate) fn encrypt(&mut self, packet: &[u8]) -> Result<Vec<u8>, TransportError> {
        self.send_packet_id = self.send_packet_id.wrapping_add(1);
        let packet_id = self.send_packet_id;
        let header = self.data_header();
        let packet_id_bytes = packet_id.to_be_bytes();
        let mut aad = Vec::with_capacity(header.len() + packet_id_bytes.len());
        aad.extend_from_slice(&header);
        aad.extend_from_slice(&packet_id_bytes);

        let nonce = self.nonce(packet_id, &self.send_implicit_iv);
        let mut ciphertext = packet.to_vec();
        let tag = self
            .send
            .encrypt_in_place_detached(&nonce, &aad, &mut ciphertext)?;

        let mut out =
            Vec::with_capacity(header.len() + 4 + DATA_AES_GCM_TAG_SIZE + ciphertext.len());
        out.extend_from_slice(&header);
        out.extend_from_slice(&packet_id_bytes);
        out.extend_from_slice(&tag);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    pub(crate) fn decrypt(&mut self, packet: &[u8]) -> Result<Vec<u8>, TransportError> {
        if packet.is_empty() {
            return Err(TransportError::InvalidPlan(
                "empty openvpn data packet".to_owned(),
            ));
        }
        let (opcode, _) = parse_opcode_key_id(packet[0])?;
        let header_size = match opcode {
            OpenVpnOpcode::DataV1 => 1,
            OpenVpnOpcode::DataV2 => 4,
            _ => {
                return Err(TransportError::InvalidPlan(format!(
                    "not an openvpn data packet: {:?}",
                    opcode
                )))
            }
        };
        if packet.len() < header_size + 4 + DATA_AES_GCM_TAG_SIZE + 1 {
            return Err(TransportError::InvalidPlan(
                "openvpn data packet too short".to_owned(),
            ));
        }
        let header = &packet[..header_size];
        let packet_id_bytes = &packet[header_size..header_size + 4];
        let packet_id = u32::from_be_bytes(packet_id_bytes.try_into().unwrap());
        let tag = &packet[header_size + 4..header_size + 4 + DATA_AES_GCM_TAG_SIZE];
        let mut ciphertext = packet[header_size + 4 + DATA_AES_GCM_TAG_SIZE..].to_vec();
        let mut aad = Vec::with_capacity(header.len() + packet_id_bytes.len());
        aad.extend_from_slice(header);
        aad.extend_from_slice(packet_id_bytes);
        let nonce = self.nonce(packet_id, &self.recv_implicit_iv);
        self.recv
            .decrypt_in_place_detached(&nonce, &aad, &mut ciphertext, tag)?;
        if self.recv_seen && packet_id <= self.recv_highest {
            return Err(TransportError::InvalidPlan(format!(
                "openvpn replayed data packet id {packet_id}"
            )));
        }
        self.recv_highest = packet_id;
        self.recv_seen = true;
        Ok(ciphertext)
    }
}

impl ControlChannel {
    pub(crate) fn new(
        mux: Arc<Mutex<PacketMux>>,
        crypt: TlsCryptKeys,
        local: [u8; SESSION_ID_SIZE],
    ) -> Self {
        Self {
            mux,
            crypt,
            key_id: 0,
            local,
            state: Arc::new(Mutex::new(ControlChannelState {
                remote: [0_u8; SESSION_ID_SIZE],
                send_packet_id: 0,
                send_message: 0,
                ack_pending: Vec::new(),
                pending: std::collections::BTreeMap::new(),
            })),
        }
    }

    pub(crate) fn local_session_id(&self) -> [u8; SESSION_ID_SIZE] {
        self.local
    }

    pub(crate) fn remote_session_id(&self) -> [u8; SESSION_ID_SIZE] {
        self.state.lock().unwrap().remote
    }

    pub(crate) fn set_remote_session_id(&self, remote: [u8; SESSION_ID_SIZE]) {
        self.state.lock().unwrap().remote = remote;
    }

    pub(crate) fn send_reset(&self) -> io::Result<()> {
        self.send(OpenVpnOpcode::ControlHardResetClientV2, &[]).map(|_| ())
    }

    pub(crate) fn send(
        &self,
        opcode: OpenVpnOpcode,
        payload: &[u8],
    ) -> io::Result<u32> {
        if !opcode.has_message_id() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("opcode {:?} cannot carry a reliable message", opcode),
            ));
        }
        let (packet, message_id) = {
            let mut state = self.state.lock().unwrap();
            let message_id = state.send_message;
            state.send_message = state.send_message.wrapping_add(1);
            let packet = OpenVpnControlPacket {
                opcode,
                key_id: self.key_id,
                local_session: self.local,
                ack_ids: std::mem::take(&mut state.ack_pending),
                ack_remote_session: state.remote,
                message_id,
                payload: payload.to_vec(),
            };
            state.pending.insert(message_id, packet.clone());
            (packet, message_id)
        };
        self.write_control_packet(&packet)?;
        Ok(message_id)
    }

    pub(crate) fn send_ack(&self) -> io::Result<()> {
        let packet = {
            let mut state = self.state.lock().unwrap();
            if state.ack_pending.is_empty() {
                return Ok(());
            }
            OpenVpnControlPacket {
                opcode: OpenVpnOpcode::AckV1,
                key_id: self.key_id,
                local_session: self.local,
                ack_ids: std::mem::take(&mut state.ack_pending),
                ack_remote_session: state.remote,
                message_id: 0,
                payload: Vec::new(),
            }
        };
        self.write_control_packet(&packet)
    }

    pub(crate) fn read(
        &self,
        timeout: Option<Duration>,
    ) -> io::Result<OpenVpnControlPacket> {
        loop {
            let raw = self
                .mux
                .lock()
                .map_err(|_| io::Error::other("openvpn packet mux mutex poisoned"))?
                .read_control_packet(timeout)?;
            let packet = decode_control_packet(&self.crypt, &raw)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;

            {
                let mut state = self.state.lock().unwrap();
                if state.remote == [0_u8; SESSION_ID_SIZE] && packet.local_session != self.local {
                    state.remote = packet.local_session;
                }
                for ack_id in &packet.ack_ids {
                    state.pending.remove(ack_id);
                }
                if packet.opcode.has_message_id() && !state.ack_pending.contains(&packet.message_id) {
                    state.ack_pending.push(packet.message_id);
                }
            }

            if packet.opcode == OpenVpnOpcode::AckV1 {
                continue;
            }
            return Ok(packet);
        }
    }

    pub(crate) fn pending_messages(&self) -> usize {
        self.state.lock().unwrap().pending.len()
    }

    pub(crate) fn retransmit_pending(&self) -> io::Result<()> {
        let packets = {
            let mut state = self.state.lock().unwrap();
            let ack_ids = std::mem::take(&mut state.ack_pending);
            state
                .pending
                .values()
                .cloned()
                .map(|mut packet| {
                    packet.ack_ids = ack_ids.clone();
                    packet.ack_remote_session = state.remote;
                    packet
                })
                .collect::<Vec<_>>()
        };
        for packet in &packets {
            self.write_control_packet(packet)?;
        }
        Ok(())
    }

    fn write_control_packet(&self, packet: &OpenVpnControlPacket) -> io::Result<()> {
        let (packet_id, unix_time) = {
            let mut state = self.state.lock().unwrap();
            state.send_packet_id = state.send_packet_id.wrapping_add(1);
            (state.send_packet_id, current_unix_time())
        };

        let plain = encode_control_plain(packet)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
        let mut header = vec![0_u8; TLS_CRYPT_HEADER_SIZE];
        header[0] = opcode_key_id(packet.opcode, packet.key_id);
        header[1..].copy_from_slice(&packet.local_session);
        let encoded = tls_crypt_wrap(&self.crypt, &header, packet_id, unix_time, &plain)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
        self.mux
            .lock()
            .map_err(|_| io::Error::other("openvpn packet mux mutex poisoned"))?
            .write_packet(&encoded)
    }
}

impl ControlConn {
    pub(crate) fn new(channel: ControlChannel) -> Self {
        Self {
            channel,
            read_buf: Vec::new(),
            closed: false,
        }
    }
}

impl io::Read for ControlConn {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.closed {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "openvpn control conn closed"));
        }
        if !self.read_buf.is_empty() {
            let copied = self.read_buf.len().min(buf.len());
            buf[..copied].copy_from_slice(&self.read_buf[..copied]);
            self.read_buf.drain(..copied);
            return Ok(copied);
        }

        loop {
            let packet = self.channel.read(None)?;
            if packet.opcode != OpenVpnOpcode::ControlV1 {
                self.channel.send_ack()?;
                continue;
            }
            self.channel.send_ack()?;
            if packet.payload.is_empty() {
                continue;
            }
            let copied = packet.payload.len().min(buf.len());
            buf[..copied].copy_from_slice(&packet.payload[..copied]);
            if copied < packet.payload.len() {
                self.read_buf.extend_from_slice(&packet.payload[copied..]);
            }
            return Ok(copied);
        }
    }
}

impl io::Write for ControlConn {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.closed {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "openvpn control conn closed"));
        }
        self.channel.send(OpenVpnOpcode::ControlV1, buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl OpenVpnClient {
    pub(crate) fn new(
        config: OpenVpnConfig,
        io: Box<dyn PacketIo>,
    ) -> Result<Self, TransportError> {
        let crypt = new_tls_crypt_keys(&config.tls_crypt_key, true)?;
        let local = new_session_id()?;
        let mux = Arc::new(Mutex::new(PacketMux::new(io)));
        let control = ControlChannel::new(Arc::clone(&mux), crypt, local);
        Ok(Self {
            config,
            mux,
            control,
            data: None,
            push: None,
        })
    }

    pub(crate) fn handshake(&mut self) -> Result<OpenVpnPushReply, TransportError> {
        self.control.send_reset().map_err(TransportError::from)?;
        self.wait_server_reset()?;

        let tls_config = build_openvpn_tls_client_config(&self.config)?;
        let server_name = openvpn_server_name(&self.config)?;
        let mut conn = ClientConnection::new(Arc::new(tls_config), server_name)
            .map_err(|err| TransportError::InvalidPlan(err.to_string()))?;
        let mut io = ControlConn::new(self.control.clone());
        while conn.is_handshaking() {
            conn.complete_io(&mut io)?;
        }
        let mut tls = StreamOwned::new(conn, io);

        let client_record = new_client_key_method2_record(
            &install_script_options_string(&self.config.proto, &self.config.cipher, &self.config.auth),
            &install_script_peer_info(&self.config.cipher),
            self.config.username.trim(),
            &self.config.password,
        )?;
        let client_record_bytes = marshal_client_key_method2_record(&client_record)?;
        tls.write_all(&client_record_bytes)?;
        tls.flush()?;

        let server_record = read_server_key_method2_record_from_tls(&mut tls)?;
        let mut sources = client_record.sources.clone();
        sources.server = server_record.sources.server;
        let cipher_key_len = data_cipher_key_len(&self.config.cipher)?;
        let keys = derive_client_key_material(
            &sources,
            &self.control.local_session_id(),
            &self.control.remote_session_id(),
            cipher_key_len,
        )?;

        tls.write_all(PUSH_REQUEST.as_bytes())?;
        tls.write_all(&[0])?;
        tls.flush()?;
        let push = read_push_reply_from_tls(&mut tls)?;
        let peer_id = if push.peer_id == 0 {
            PEER_ID_UNSET
        } else {
            push.peer_id
        };
        self.data = Some(DataChannel::new(&keys, peer_id)?);
        self.push = Some(push.clone());
        Ok(push)
    }

    pub(crate) fn write_ip_packet(&mut self, packet: &[u8]) -> Result<(), TransportError> {
        let encrypted = self
            .data
            .as_mut()
            .ok_or_else(|| TransportError::InvalidPlan("openvpn data channel is not ready".to_owned()))?
            .encrypt(packet)?;
        self.mux
            .lock()
            .map_err(|_| io::Error::other("openvpn packet mux mutex poisoned"))?
            .write_packet(&encrypted)
            .map_err(TransportError::from)
    }

    pub(crate) fn read_ip_packet(&mut self) -> Result<Vec<u8>, TransportError> {
        self.read_ip_packet_timeout(DEFAULT_HANDSHAKE_TIMEOUT)
    }

    pub(crate) fn read_ip_packet_timeout(
        &mut self,
        timeout: Duration,
    ) -> Result<Vec<u8>, TransportError> {
        let data = self
            .data
            .as_mut()
            .ok_or_else(|| TransportError::InvalidPlan("openvpn data channel is not ready".to_owned()))?;
        loop {
            let packet = self
                .mux
                .lock()
                .map_err(|_| io::Error::other("openvpn packet mux mutex poisoned"))?
                .read_data_packet(Some(timeout))
                .map_err(TransportError::from)?;
            match data.decrypt(&packet) {
                Ok(plain) => return Ok(plain),
                Err(_) => continue,
            }
        }
    }

    pub(crate) fn close(&mut self) -> io::Result<()> {
        self.mux
            .lock()
            .map_err(|_| io::Error::other("openvpn packet mux mutex poisoned"))?
            .close()
    }

    fn wait_server_reset(&self) -> Result<(), TransportError> {
        loop {
            let packet = self
                .control
                .read(Some(DEFAULT_HANDSHAKE_TIMEOUT))
                .map_err(TransportError::from)?;
            match packet.opcode {
                OpenVpnOpcode::ControlHardResetServerV2 => {
                    self.control.send_ack().map_err(TransportError::from)?;
                    return Ok(());
                }
                _ => continue,
            }
        }
    }
}

fn decode_control_packet(
    keys: &TlsCryptKeys,
    packet: &[u8],
) -> Result<OpenVpnControlPacket, TransportError> {
    let (header, _packet_id, _unix_time, plain) = tls_crypt_unwrap(keys, packet)?;
    if header.len() != TLS_CRYPT_HEADER_SIZE {
        return Err(TransportError::InvalidPlan(format!(
            "invalid control header length {}",
            header.len()
        )));
    }
    let (opcode, key_id) = parse_opcode_key_id(header[0])?;
    if !opcode.is_control() {
        return Err(TransportError::InvalidPlan(format!(
            "opcode {:?} is not a control opcode",
            opcode
        )));
    }
    let mut local_session = [0_u8; SESSION_ID_SIZE];
    local_session.copy_from_slice(&header[1..]);
    let (ack_ids, ack_remote_session, message_id, payload) =
        decode_control_plain(opcode, &plain)?;
    Ok(OpenVpnControlPacket {
        opcode,
        key_id,
        local_session,
        ack_ids,
        ack_remote_session,
        message_id,
        payload,
    })
}

fn build_openvpn_tls_client_config(
    config: &OpenVpnConfig,
) -> Result<ClientConfig, TransportError> {
    let mut roots = RootCertStore::empty();
    let mut ca_reader = std::io::Cursor::new(&config.ca);
    let certs = rustls_pemfile::certs(&mut ca_reader)
        .map_err(|err| TransportError::InvalidPlan(format!("parse openvpn ca: {err}")))?;
    if certs.is_empty() {
        return Err(TransportError::InvalidPlan(
            "parse openvpn ca certificate".to_owned(),
        ));
    }
    for cert in certs {
        roots
            .add(&rustls::Certificate(cert))
            .map_err(|err| TransportError::InvalidPlan(format!("parse openvpn ca: {err}")))?;
    }

    let client_auth = if !config.cert.is_empty() && !config.key.is_empty() {
        let mut cert_reader = std::io::Cursor::new(&config.cert);
        let certs = rustls_pemfile::certs(&mut cert_reader)
            .map_err(|err| TransportError::InvalidPlan(format!("parse openvpn cert: {err}")))?
            .into_iter()
            .map(rustls::Certificate)
            .collect::<Vec<_>>();
        if certs.is_empty() {
            return Err(TransportError::InvalidPlan(
                "parse openvpn client certificate".to_owned(),
            ));
        }
        let mut key_reader = std::io::Cursor::new(&config.key);
        let key = rustls_pemfile::pkcs8_private_keys(&mut key_reader)
            .map_err(|err| TransportError::InvalidPlan(format!("parse openvpn key: {err}")))?
            .into_iter()
            .next()
            .map(rustls::PrivateKey)
            .or_else(|| {
                let mut key_reader = std::io::Cursor::new(&config.key);
                rustls_pemfile::rsa_private_keys(&mut key_reader)
                    .ok()?
                    .into_iter()
                    .next()
                    .map(rustls::PrivateKey)
            })
            .ok_or_else(|| {
                TransportError::InvalidPlan("parse openvpn client private key".to_owned())
            })?;
        Some((certs, key))
    } else {
        None
    };

    let mut tls = if let Some((certs, key)) = client_auth {
        ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(roots)
            .with_client_auth_cert(certs, key)
            .map_err(|err| TransportError::InvalidPlan(format!("openvpn tls config: {err}")))?
    } else {
        ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(roots)
            .with_no_client_auth()
    };
    tls.alpn_protocols.clear();
    Ok(tls)
}

fn openvpn_server_name(config: &OpenVpnConfig) -> Result<ServerName, TransportError> {
    ServerName::try_from(config.remote_host.as_str()).map_err(|_| {
        TransportError::InvalidPlan(format!(
            "invalid openvpn tls server name {:?}",
            config.remote_host
        ))
    })
}

fn read_server_key_method2_record_from_tls(
    tls: &mut StreamOwned<ClientConnection, ControlConn>,
) -> Result<KeyMethod2Record, TransportError> {
    let mut buf = Vec::new();
    let mut tmp = [0_u8; 4096];
    loop {
        let read = tls.read(&mut tmp)?;
        if read == 0 {
            return Err(TransportError::InvalidPlan(
                "read key method 2 server record: unexpected eof".to_owned(),
            ));
        }
        buf.extend_from_slice(&tmp[..read]);
        match parse_server_key_method2_record(&buf) {
            Ok(record) => return Ok(record),
            Err(err) if err.to_string().contains("truncated") => continue,
            Err(err) => return Err(err),
        }
    }
}

fn read_push_reply_from_tls(
    tls: &mut StreamOwned<ClientConnection, ControlConn>,
) -> Result<OpenVpnPushReply, TransportError> {
    let mut buf = Vec::new();
    let mut tmp = [0_u8; 4096];
    loop {
        let read = tls.read(&mut tmp)?;
        if read == 0 && !buf.is_empty() {
            break;
        }
        if read == 0 {
            return Err(TransportError::InvalidPlan(
                "read push reply: unexpected eof".to_owned(),
            ));
        }
        buf.extend_from_slice(&tmp[..read]);
        let msg = String::from_utf8_lossy(&buf);
        let msg = if let Some(end) = msg.find('\0') {
            &msg[..end]
        } else {
            &msg
        };
        if msg.contains("PUSH_REPLY") {
            if let Ok(reply) = parse_push_reply(msg) {
                return Ok(reply);
            }
        }
    }
    parse_push_reply(&String::from_utf8_lossy(&buf)).map_err(Into::into)
}

fn parse_client_key_method2_record(packet: &[u8]) -> Result<KeyMethod2Record, TransportError> {
    if packet.len() < 4 + 1 + 48 + 32 + 32 {
        return Err(TransportError::InvalidPlan(
            "openvpn client key method 2 packet too short".to_owned(),
        ));
    }
    if &packet[..4] != &[0, 0, 0, 0] {
        return Err(TransportError::InvalidPlan(
            "invalid openvpn client key method 2 prefix".to_owned(),
        ));
    }
    if packet[4] & 0x0f != KEY_METHOD_2 {
        return Err(TransportError::InvalidPlan(format!(
            "unsupported openvpn key method {}",
            packet[4]
        )));
    }
    let mut offset = 5;
    let mut record = KeyMethod2Record {
        sources: KeySource2 {
            client: KeySource {
                pre_master: [0_u8; 48],
                random1: [0_u8; 32],
                random2: [0_u8; 32],
            },
            server: KeySource {
                pre_master: [0_u8; 48],
                random1: [0_u8; 32],
                random2: [0_u8; 32],
            },
        },
        options: String::new(),
        username: String::new(),
        password: String::new(),
        peer_info: String::new(),
    };
    record
        .sources
        .client
        .pre_master
        .copy_from_slice(&packet[offset..offset + 48]);
    offset += 48;
    record
        .sources
        .client
        .random1
        .copy_from_slice(&packet[offset..offset + 32]);
    offset += 32;
    record
        .sources
        .client
        .random2
        .copy_from_slice(&packet[offset..offset + 32]);
    offset += 32;
    record.options = read_openvpn_string(packet, &mut offset)?;
    record.username = read_openvpn_string(packet, &mut offset)?;
    record.password = read_openvpn_string(packet, &mut offset)?;
    record.peer_info = read_openvpn_string(packet, &mut offset)?;
    Ok(record)
}

fn marshal_server_key_method2_record(
    random1: [u8; 32],
    random2: [u8; 32],
    options: &str,
    peer_info: &str,
) -> Vec<u8> {
    let mut out = vec![0_u8; 4];
    out.push(KEY_METHOD_2);
    out.extend_from_slice(&random1);
    out.extend_from_slice(&random2);
    append_openvpn_string(&mut out, options);
    append_openvpn_string(&mut out, "");
    append_openvpn_string(&mut out, "");
    append_openvpn_string(&mut out, peer_info);
    out
}

fn swap_key_material(keys: &KeyMaterial) -> KeyMaterial {
    KeyMaterial {
        send_cipher_key: keys.recv_cipher_key.clone(),
        send_hmac_key: keys.recv_hmac_key.clone(),
        recv_cipher_key: keys.send_cipher_key.clone(),
        recv_hmac_key: keys.send_hmac_key.clone(),
    }
}

fn read_null_terminated_message(stream: &mut dyn Read) -> io::Result<String> {
    let mut buf = Vec::new();
    loop {
        let mut byte = [0_u8; 1];
        stream.read_exact(&mut byte)?;
        if byte[0] == 0 {
            break;
        }
        buf.push(byte[0]);
    }
    String::from_utf8(buf)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))
}

fn data_cipher_key_len(cipher: &str) -> Result<usize, TransportError> {
    match cipher {
        CIPHER_AES_128_GCM => Ok(16),
        CIPHER_AES_256_GCM => Ok(32),
        other => Err(TransportError::InvalidPlan(format!(
            "unsupported openvpn cipher {other:?}"
        ))),
    }
}

fn new_session_id() -> Result<[u8; SESSION_ID_SIZE], TransportError> {
    let mut id = [0_u8; SESSION_ID_SIZE];
    fill_random(&mut id)?;
    Ok(id)
}

fn current_unix_time() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32
}

pub(crate) fn tls_crypt_wrap(
    keys: &TlsCryptKeys,
    header: &[u8],
    packet_id: u32,
    unix_time: u32,
    plaintext: &[u8],
) -> Result<Vec<u8>, TransportError> {
    if header.len() != TLS_CRYPT_HEADER_SIZE {
        return Err(TransportError::InvalidPlan(format!(
            "invalid tls-crypt header length {}, expected {}",
            header.len(),
            TLS_CRYPT_HEADER_SIZE
        )));
    }
    let mut ad = Vec::with_capacity(header.len() + TLS_CRYPT_PID_SIZE);
    ad.extend_from_slice(header);
    let mut pid = [0_u8; TLS_CRYPT_PID_SIZE];
    pid[..4].copy_from_slice(&packet_id.to_be_bytes());
    pid[4..].copy_from_slice(&unix_time.to_be_bytes());
    ad.extend_from_slice(&pid);

    let tag = hmac_sha256(&keys.encrypt_hmac_key, &[&ad, plaintext])?;
    let ciphertext = aes256ctr_xor(&keys.encrypt_cipher_key, &tag[..16], plaintext)?;

    let mut out = Vec::with_capacity(ad.len() + tag.len() + ciphertext.len());
    out.extend_from_slice(&ad);
    out.extend_from_slice(&tag);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

pub(crate) fn tls_crypt_unwrap(
    keys: &TlsCryptKeys,
    packet: &[u8],
) -> Result<(Vec<u8>, u32, u32, Vec<u8>), TransportError> {
    if packet.len() < TLS_CRYPT_HEADER_SIZE + TLS_CRYPT_PID_SIZE + TLS_CRYPT_TAG_SIZE {
        return Err(TransportError::InvalidPlan(
            "tls-crypt packet too short".to_owned(),
        ));
    }
    let header = packet[..TLS_CRYPT_HEADER_SIZE].to_vec();
    let ad_end = TLS_CRYPT_HEADER_SIZE + TLS_CRYPT_PID_SIZE;
    let tag_end = ad_end + TLS_CRYPT_TAG_SIZE;
    let ad = &packet[..ad_end];
    let tag = &packet[ad_end..tag_end];
    let ciphertext = &packet[tag_end..];
    let plaintext = aes256ctr_xor(&keys.decrypt_cipher_key, &tag[..16], ciphertext)?;
    let tag_check = hmac_sha256(&keys.decrypt_hmac_key, &[ad, &plaintext])?;
    if tag_check.as_slice() != tag {
        return Err(TransportError::InvalidPlan(
            "tls-crypt authentication failed".to_owned(),
        ));
    }
    let packet_id = u32::from_be_bytes(
        packet[TLS_CRYPT_HEADER_SIZE..TLS_CRYPT_HEADER_SIZE + 4]
            .try_into()
            .unwrap(),
    );
    let unix_time = u32::from_be_bytes(packet[TLS_CRYPT_HEADER_SIZE + 4..ad_end].try_into().unwrap());
    Ok((header, packet_id, unix_time, plaintext))
}

pub(crate) fn opcode_key_id(opcode: OpenVpnOpcode, key_id: u8) -> u8 {
    ((opcode as u8) << 3) | (key_id & 0x07)
}

pub(crate) fn parse_opcode_key_id(byte: u8) -> Result<(OpenVpnOpcode, u8), TransportError> {
    let opcode = match byte >> 3 {
        4 => OpenVpnOpcode::ControlV1,
        5 => OpenVpnOpcode::AckV1,
        6 => OpenVpnOpcode::DataV1,
        7 => OpenVpnOpcode::ControlHardResetClientV2,
        8 => OpenVpnOpcode::ControlHardResetServerV2,
        9 => OpenVpnOpcode::DataV2,
        other => {
            return Err(TransportError::InvalidPlan(format!(
                "unsupported openvpn opcode {other}"
            )))
        }
    };
    Ok((opcode, byte & 0x07))
}

pub(crate) fn encode_control_plain(
    packet: &OpenVpnControlPacket,
) -> Result<Vec<u8>, TransportError> {
    if !packet.opcode.is_control() {
        return Err(TransportError::InvalidPlan(
            "openvpn control packet requires control opcode".to_owned(),
        ));
    }
    if packet.ack_ids.len() > u8::MAX as usize {
        return Err(TransportError::InvalidPlan(format!(
            "too many openvpn ack ids: {}",
            packet.ack_ids.len()
        )));
    }
    let mut out = Vec::with_capacity(1 + packet.ack_ids.len() * 4 + packet.payload.len() + 16);
    out.push(packet.ack_ids.len() as u8);
    for ack in &packet.ack_ids {
        out.extend_from_slice(&ack.to_be_bytes());
    }
    if !packet.ack_ids.is_empty() {
        out.extend_from_slice(&packet.ack_remote_session);
    }
    if packet.opcode.has_message_id() {
        out.extend_from_slice(&packet.message_id.to_be_bytes());
        out.extend_from_slice(&packet.payload);
    }
    Ok(out)
}

pub(crate) fn decode_control_plain(
    opcode: OpenVpnOpcode,
    plain: &[u8],
) -> Result<(Vec<u32>, [u8; SESSION_ID_SIZE], u32, Vec<u8>), TransportError> {
    if plain.is_empty() {
        return Err(TransportError::InvalidPlan(
            "openvpn control payload too short".to_owned(),
        ));
    }
    let ack_len = plain[0] as usize;
    let mut offset = 1;
    if plain.len() < offset + ack_len * 4 {
        return Err(TransportError::InvalidPlan(
            "openvpn control ack array truncated".to_owned(),
        ));
    }
    let mut ack_ids = Vec::with_capacity(ack_len);
    for _ in 0..ack_len {
        ack_ids.push(u32::from_be_bytes(
            plain[offset..offset + 4]
                .try_into()
                .map_err(|_| TransportError::InvalidPlan("openvpn ack decode failed".to_owned()))?,
        ));
        offset += 4;
    }
    let mut ack_remote = [0_u8; SESSION_ID_SIZE];
    if ack_len > 0 {
        if plain.len() < offset + SESSION_ID_SIZE {
            return Err(TransportError::InvalidPlan(
                "openvpn ack remote session truncated".to_owned(),
            ));
        }
        ack_remote.copy_from_slice(&plain[offset..offset + SESSION_ID_SIZE]);
        offset += SESSION_ID_SIZE;
    }
    let mut message_id = 0;
    let mut payload = Vec::new();
    if opcode.has_message_id() {
        if plain.len() < offset + 4 {
            return Err(TransportError::InvalidPlan(
                "openvpn control message id truncated".to_owned(),
            ));
        }
        message_id = u32::from_be_bytes(
            plain[offset..offset + 4]
                .try_into()
                .map_err(|_| TransportError::InvalidPlan("openvpn message id decode failed".to_owned()))?,
        );
        offset += 4;
        payload.extend_from_slice(&plain[offset..]);
    } else if plain.len() != offset {
        return Err(TransportError::InvalidPlan(
            "openvpn ack packet has trailing payload".to_owned(),
        ));
    }
    Ok((ack_ids, ack_remote, message_id, payload))
}

pub(crate) fn new_client_key_method2_record(
    options: &str,
    peer_info: &str,
    username: &str,
    password: &str,
) -> Result<KeyMethod2Record, TransportError> {
    let mut record = KeyMethod2Record {
        sources: KeySource2 {
            client: KeySource {
                pre_master: [0_u8; 48],
                random1: [0_u8; 32],
                random2: [0_u8; 32],
            },
            server: KeySource {
                pre_master: [0_u8; 48],
                random1: [0_u8; 32],
                random2: [0_u8; 32],
            },
        },
        options: options.to_owned(),
        username: username.to_owned(),
        password: password.to_owned(),
        peer_info: peer_info.to_owned(),
    };
    fill_random(&mut record.sources.client.pre_master)?;
    fill_random(&mut record.sources.client.random1)?;
    fill_random(&mut record.sources.client.random2)?;
    Ok(record)
}

pub(crate) fn marshal_client_key_method2_record(
    record: &KeyMethod2Record,
) -> Result<Vec<u8>, TransportError> {
    let mut out = Vec::with_capacity(128 + record.options.len() + record.peer_info.len());
    out.extend_from_slice(&0_u32.to_be_bytes());
    out.push(KEY_METHOD_2);
    out.extend_from_slice(&record.sources.client.pre_master);
    out.extend_from_slice(&record.sources.client.random1);
    out.extend_from_slice(&record.sources.client.random2);
    append_openvpn_string(&mut out, &record.options);
    append_openvpn_string(&mut out, &record.username);
    append_openvpn_string(&mut out, &record.password);
    append_openvpn_string(&mut out, &record.peer_info);
    Ok(out)
}

pub(crate) fn parse_server_key_method2_record(
    packet: &[u8],
) -> Result<KeyMethod2Record, TransportError> {
    if packet.len() < 4 + 1 + 32 + 32 {
        return Err(TransportError::InvalidPlan(
            "openvpn key method 2 packet too short".to_owned(),
        ));
    }
    if packet[..4] != [0, 0, 0, 0] {
        return Err(TransportError::InvalidPlan(
            "invalid openvpn key method 2 prefix".to_owned(),
        ));
    }
    if packet[4] & 0x0f != KEY_METHOD_2 {
        return Err(TransportError::InvalidPlan(format!(
            "unsupported openvpn key method {}",
            packet[4]
        )));
    }
    let mut offset = 5;
    let mut record = KeyMethod2Record {
        sources: KeySource2 {
            client: KeySource {
                pre_master: [0_u8; 48],
                random1: [0_u8; 32],
                random2: [0_u8; 32],
            },
            server: KeySource {
                pre_master: [0_u8; 48],
                random1: [0_u8; 32],
                random2: [0_u8; 32],
            },
        },
        options: String::new(),
        username: String::new(),
        password: String::new(),
        peer_info: String::new(),
    };
    record.sources.server.random1.copy_from_slice(&packet[offset..offset + 32]);
    offset += 32;
    record.sources.server.random2.copy_from_slice(&packet[offset..offset + 32]);
    offset += 32;
    record.options = read_openvpn_string(packet, &mut offset)?;
    record.username = read_openvpn_string(packet, &mut offset).unwrap_or_default();
    record.password = read_openvpn_string(packet, &mut offset).unwrap_or_default();
    record.peer_info = read_openvpn_string(packet, &mut offset).unwrap_or_default();
    Ok(record)
}

pub(crate) fn derive_client_key_material(
    sources: &KeySource2,
    client_session: &[u8; SESSION_ID_SIZE],
    server_session: &[u8; SESSION_ID_SIZE],
    cipher_key_len: usize,
) -> Result<KeyMaterial, TransportError> {
    if cipher_key_len != 16 && cipher_key_len != 32 {
        return Err(TransportError::InvalidPlan(format!(
            "unsupported data cipher key length {cipher_key_len}"
        )));
    }
    let mut master = [0_u8; 48];
    openvpn_prf(
        &sources.client.pre_master,
        b"OpenVPN master secret",
        &sources.client.random1,
        &sources.server.random1,
        None,
        None,
        &mut master,
    )?;

    let mut key_block = vec![0_u8; 2 * (64 + 64)];
    openvpn_prf(
        &master,
        b"OpenVPN key expansion",
        &sources.client.random2,
        &sources.server.random2,
        Some(client_session),
        Some(server_session),
        &mut key_block,
    )?;

    let split = 64 + 64;
    let client_to_server = &key_block[..split];
    let server_to_client = &key_block[split..];
    Ok(KeyMaterial {
        send_cipher_key: client_to_server[..cipher_key_len].to_vec(),
        send_hmac_key: client_to_server[64..128].to_vec(),
        recv_cipher_key: server_to_client[..cipher_key_len].to_vec(),
        recv_hmac_key: server_to_client[64..128].to_vec(),
    })
}

pub(crate) fn install_script_options_string(proto: &str, cipher: &str, auth: &str) -> String {
    let proto_name = if proto == PROTO_TCP {
        "TCPv4_CLIENT"
    } else {
        "UDPv4"
    };
    let keysize = if cipher == CIPHER_AES_256_GCM { "256" } else { "128" };
    format!(
        "V4,dev-type tun,link-mtu 1550,tun-mtu 1500,proto {proto_name},cipher {cipher},auth {auth},keysize {keysize},key-method 2,tls-client"
    )
}

pub(crate) fn install_script_peer_info(cipher: &str) -> String {
    format!("IV_VER=mihomo-openvpn\nIV_PROTO=6\nIV_CIPHERS={cipher}\n")
}

pub(crate) fn parse_push_reply(message: &str) -> Result<OpenVpnPushReply, TransportError> {
    let message = message.trim_end_matches('\0');
    if !message.starts_with("PUSH_REPLY") {
        return Err(TransportError::InvalidPlan(format!(
            "unexpected openvpn push message {message:?}"
        )));
    }
    let mut reply = OpenVpnPushReply {
        raw: message.to_owned(),
        prefixes: Vec::new(),
        dns: Vec::new(),
        peer_id: 0x00ff_ffff,
        redirect: false,
        block_ipv6: false,
    };
    for option in split_push_options(message) {
        let fields = option.split_whitespace().collect::<Vec<_>>();
        if fields.is_empty() {
            continue;
        }
        match fields[0] {
            "ifconfig" if fields.len() >= 3 => {
                reply.prefixes.push(parse_ipv4_ifconfig(fields[1], fields[2])?);
            }
            "ifconfig-ipv6" if fields.len() >= 2 => {
                reply.prefixes.push(fields[1].to_owned());
            }
            "dhcp-option" if fields.len() >= 3 && fields[1] == "DNS" => {
                reply.dns.push(fields[2].to_owned());
            }
            "peer-id" if fields.len() >= 2 => {
                reply.peer_id = fields[1].parse::<u32>().map_err(|err| {
                    TransportError::InvalidPlan(format!("parse pushed peer-id {:?}: {err}", fields[1]))
                })?;
            }
            "redirect-gateway" => reply.redirect = true,
            "block-ipv6" => reply.block_ipv6 = true,
            _ => {}
        }
    }
    if reply.prefixes.is_empty() {
        return Err(TransportError::InvalidPlan(
            "openvpn push reply missing ifconfig address".to_owned(),
        ));
    }
    Ok(reply)
}

fn split_push_options(message: &str) -> Vec<&str> {
    let trimmed = message.trim_end_matches('\0');
    let parts = trimmed
        .split(',')
        .filter(|part| *part != "PUSH_REPLY")
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    parts
}

fn parse_ipv4_ifconfig(address: &str, mask: &str) -> Result<String, TransportError> {
    let addr: std::net::Ipv4Addr = address.parse().map_err(|err| {
        TransportError::InvalidPlan(format!("parse pushed ipv4 address {address:?}: {err}"))
    })?;
    let mask: std::net::Ipv4Addr = mask.parse().map_err(|err| {
        TransportError::InvalidPlan(format!("parse pushed ipv4 mask {mask:?}: {err}"))
    })?;
    let ones = mask
        .octets()
        .iter()
        .fold(0_u8, |acc, byte| acc + byte.count_ones() as u8);
    Ok(format!("{addr}/{ones}"))
}

fn append_openvpn_string(out: &mut Vec<u8>, value: &str) {
    if value.is_empty() {
        out.extend_from_slice(&0_u16.to_be_bytes());
        return;
    }
    let value = if value.len() + 1 > u16::MAX as usize {
        &value[..u16::MAX as usize - 1]
    } else {
        value
    };
    out.extend_from_slice(&((value.len() + 1) as u16).to_be_bytes());
    out.extend_from_slice(value.as_bytes());
    out.push(0);
}

fn read_openvpn_string(packet: &[u8], offset: &mut usize) -> Result<String, TransportError> {
    if *offset + 2 > packet.len() {
        return Err(TransportError::InvalidPlan(
            "openvpn string truncated".to_owned(),
        ));
    }
    let size = u16::from_be_bytes(packet[*offset..*offset + 2].try_into().unwrap()) as usize;
    *offset += 2;
    if size == 0 {
        return Ok(String::new());
    }
    if *offset + size > packet.len() {
        return Err(TransportError::InvalidPlan(
            "openvpn string truncated".to_owned(),
        ));
    }
    let mut raw = packet[*offset..*offset + size].to_vec();
    *offset += size;
    if raw.last() == Some(&0) {
        raw.pop();
    }
    String::from_utf8(raw)
        .map_err(|err| TransportError::InvalidPlan(format!("openvpn string decode failed: {err}")))
}

fn fill_random(buf: &mut [u8]) -> Result<(), TransportError> {
    rand::thread_rng().fill(buf);
    Ok(())
}

fn recv_channel(
    rx: &mpsc::Receiver<Vec<u8>>,
    timeout: Option<Duration>,
) -> io::Result<Vec<u8>> {
    match timeout {
        Some(timeout) => match rx.recv_timeout(timeout) {
            Ok(packet) => Ok(packet),
            Err(mpsc::RecvTimeoutError::Timeout) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "openvpn packet receive timed out",
            )),
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "openvpn packet channel closed",
            )),
        },
        None => rx.recv().map_err(|_| {
            io::Error::new(io::ErrorKind::BrokenPipe, "openvpn packet channel closed")
        }),
    }
}

fn is_control_opcode(first_byte: u8) -> bool {
    parse_opcode_key_id(first_byte)
        .map(|(opcode, _)| opcode.is_control())
        .unwrap_or(false)
}

fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> Result<Vec<u8>, TransportError> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key)
        .map_err(|err| TransportError::InvalidPlan(format!("openvpn hmac init failed: {err}")))?;
    for part in parts {
        mac.update(part);
    }
    Ok(mac.finalize().into_bytes().to_vec())
}

fn aes256ctr_xor(key: &[u8], iv: &[u8], input: &[u8]) -> Result<Vec<u8>, TransportError> {
    let mut output = input.to_vec();
    let mut cipher = Aes256Ctr::new_from_slices(key, iv)
        .map_err(|err| TransportError::InvalidPlan(format!("openvpn aes-ctr init failed: {err}")))?;
    cipher.apply_keystream(&mut output);
    Ok(output)
}

fn openvpn_prf(
    secret: &[u8],
    label: &[u8],
    client_seed: &[u8],
    server_seed: &[u8],
    client_session: Option<&[u8]>,
    server_session: Option<&[u8]>,
    out: &mut [u8],
) -> Result<(), TransportError> {
    let mut seed = Vec::new();
    seed.extend_from_slice(label);
    seed.extend_from_slice(client_seed);
    seed.extend_from_slice(server_seed);
    if let Some(client_session) = client_session {
        seed.extend_from_slice(client_session);
    }
    if let Some(server_session) = server_session {
        seed.extend_from_slice(server_session);
    }

    let split = secret.len().div_ceil(2);
    let s1 = &secret[..split];
    let s2 = &secret[secret.len() - split..];

    let md5_out = p_hash_md5(s1, &seed, out.len())?;
    let sha1_out = p_hash_sha1(s2, &seed, out.len())?;
    for index in 0..out.len() {
        out[index] = md5_out[index] ^ sha1_out[index];
    }
    Ok(())
}

fn p_hash_md5(secret: &[u8], seed: &[u8], size: usize) -> Result<Vec<u8>, TransportError> {
    p_hash(secret, seed, size, |key, data| {
        let mut mac = <Hmac<md5::Md5> as Mac>::new_from_slice(key)
            .map_err(|err| TransportError::InvalidPlan(format!("openvpn md5 hmac init failed: {err}")))?;
        mac.update(data);
        Ok(mac.finalize().into_bytes().to_vec())
    })
}

fn p_hash_sha1(secret: &[u8], seed: &[u8], size: usize) -> Result<Vec<u8>, TransportError> {
    p_hash(secret, seed, size, |key, data| {
        let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(key)
            .map_err(|err| TransportError::InvalidPlan(format!("openvpn sha1 hmac init failed: {err}")))?;
        mac.update(data);
        Ok(mac.finalize().into_bytes().to_vec())
    })
}

fn p_hash<F>(
    secret: &[u8],
    seed: &[u8],
    size: usize,
    mut hmac_fn: F,
) -> Result<Vec<u8>, TransportError>
where
    F: FnMut(&[u8], &[u8]) -> Result<Vec<u8>, TransportError>,
{
    let mut output = Vec::with_capacity(size);
    let mut a = hmac_fn(secret, seed)?;
    while output.len() < size {
        let mut chunk_input = Vec::with_capacity(a.len() + seed.len());
        chunk_input.extend_from_slice(&a);
        chunk_input.extend_from_slice(seed);
        output.extend_from_slice(&hmac_fn(secret, &chunk_input)?);
        a = hmac_fn(secret, &a)?;
    }
    output.truncate(size);
    Ok(output)
}

pub(crate) fn connect_stream(
    options: &OpenVpnOptions,
    target: &crate::TransportTarget,
) -> Result<BoxedTcpStream, TransportError> {
    let config = config::prepare_config(options)?;
    let io = connect_packet_io(&config)?;
    let mut client = OpenVpnClient::new(config, io)?;
    let push = client.handshake()?;
    let source_ip = udp_bridge::first_ipv4_from_prefixes(&push.prefixes)
        .map_err(TransportError::from)?;
    let target = resolve_target_over_openvpn_if_needed(&mut client, source_ip, options, target)?;
    let client = Arc::new(Mutex::new(client));
    tcp_stack::connect_stream(Arc::clone(&client), source_ip, options.mtu.max(1500), &target)
}

pub(crate) fn connect_stream_with_boxed_tcp(
    options: &OpenVpnOptions,
    stream: BoxedTcpStream,
    target: &crate::TransportTarget,
) -> Result<BoxedTcpStream, TransportError> {
    let config = config::prepare_config(options)?;
    if config.proto != PROTO_TCP {
        return Err(TransportError::UnsupportedFeature {
            proxy: format!("{}:{}", config.remote_host, config.remote_port),
            feature: "openvpn chained stream requires proto=tcp".to_owned(),
        });
    }
    let io = BoxedStreamPacketIo::new(stream).map_err(TransportError::from)?;
    let mut client = OpenVpnClient::new(config, Box::new(io))?;
    let push = client.handshake()?;
    let source_ip = udp_bridge::first_ipv4_from_prefixes(&push.prefixes)
        .map_err(TransportError::from)?;
    let target = resolve_target_over_openvpn_if_needed(&mut client, source_ip, options, target)?;
    let client = Arc::new(Mutex::new(client));
    tcp_stack::connect_stream(Arc::clone(&client), source_ip, options.mtu.max(1500), &target)
}

pub(crate) fn connect_stream_with_socks5_stream(
    options: &OpenVpnOptions,
    stream: BoxedTcpStream,
    auth: Option<crate::BasicAuth>,
    target: &crate::TransportTarget,
) -> Result<BoxedTcpStream, TransportError> {
    let config = config::prepare_config(options)?;
    let remote_addr = udp_bridge::resolve_openvpn_udp_remote_addr(&config)?;
    let io = udp_bridge::Socks5UdpPacketIo::new(stream, auth, remote_addr)
        .map_err(TransportError::from)?;
    let mut client = OpenVpnClient::new(config, Box::new(io))?;
    let push = client.handshake()?;
    let source_ip = udp_bridge::first_ipv4_from_prefixes(&push.prefixes)
        .map_err(TransportError::from)?;
    let target = resolve_target_over_openvpn_if_needed(&mut client, source_ip, options, target)?;
    let client = Arc::new(Mutex::new(client));
    tcp_stack::connect_stream(Arc::clone(&client), source_ip, options.mtu.max(1500), &target)
}

pub(crate) fn open_udp_stream(
    options: &OpenVpnOptions,
) -> Result<BoxedTcpStream, TransportError> {
    udp_bridge::open_udp_stream(options)
}

pub(crate) fn open_udp_stream_with_boxed_tcp(
    options: &OpenVpnOptions,
    stream: BoxedTcpStream,
) -> Result<BoxedTcpStream, TransportError> {
    udp_bridge::open_udp_stream_with_boxed_tcp(options, stream)
}

pub(crate) fn open_udp_stream_with_socks5_stream(
    options: &OpenVpnOptions,
    stream: BoxedTcpStream,
    auth: Option<crate::BasicAuth>,
) -> Result<BoxedTcpStream, TransportError> {
    udp_bridge::open_udp_stream_with_socks5_stream(options, stream, auth)
}

pub(crate) fn resolve_remote_target_host(
    client: &mut OpenVpnClient,
    source_ip: Ipv4Addr,
    options: &OpenVpnOptions,
    host: &str,
) -> Result<Ipv4Addr, TransportError> {
    let mut io = udp_bridge::OpenVpnIpPacketIoForDns { client, source_ip };
    crate::tunnel_dns::resolve_ipv4_host_with_datagram_io(
        &mut io,
        &options.dns,
        host,
        "<openvpn>",
    )
}

pub(crate) fn resolve_remote_target_host_via_udp_stream(
    stream: &mut dyn mihomo_core::TcpStream,
    options: &OpenVpnOptions,
    host: &str,
) -> Result<Ipv4Addr, TransportError> {
    let mut io = udp_bridge::OpenVpnUdpStreamDnsIo { stream };
    crate::tunnel_dns::resolve_ipv4_host_with_datagram_io(
        &mut io,
        &options.dns,
        host,
        "<openvpn>",
    )
}

fn resolve_target_over_openvpn_if_needed(
    client: &mut OpenVpnClient,
    source_ip: Ipv4Addr,
    options: &OpenVpnOptions,
    target: &crate::TransportTarget,
) -> Result<crate::TransportTarget, TransportError> {
    if !options.remote_dns_resolve || options.dns.is_empty() {
        return Ok(target.clone());
    }
    if target.host.parse::<Ipv4Addr>().is_ok() {
        return Ok(target.clone());
    }
    if target.host.parse::<std::net::Ipv6Addr>().is_ok() {
        return Err(TransportError::UnsupportedFeature {
            proxy: "<openvpn>".to_owned(),
            feature: format!("openvpn remote dns ipv6 targets are not implemented: {}", target.host),
        });
    }
    let resolved = resolve_remote_target_host(client, source_ip, options, &target.host)?;
    Ok(crate::TransportTarget::new(resolved.to_string(), target.port))
}

pub(crate) fn write_udp_packet(
    stream: &mut dyn std::io::Write,
    target: std::net::SocketAddr,
    payload: &[u8],
) -> io::Result<usize> {
    udp_bridge::write_udp_packet(stream, target, payload)
}

pub(crate) fn read_udp_packet(
    stream: &mut dyn std::io::Read,
) -> io::Result<(std::net::SocketAddr, Vec<u8>)> {
    udp_bridge::read_udp_packet(stream)
}

pub(crate) fn prepare_config(options: &OpenVpnOptions) -> Result<OpenVpnConfig, TransportError> {
    config::prepare_config(options)
}

pub(crate) fn normalize_proto(proto: &str) -> String {
    config::normalize_proto(proto)
}

pub(crate) fn decode_static_key(block: &[u8]) -> Result<Vec<u8>, TransportError> {
    config::decode_static_key(block)
}

fn connect_packet_io(config: &OpenVpnConfig) -> Result<Box<dyn PacketIo>, TransportError> {
    if config.proto == PROTO_TCP {
        let stream = NetTcpStream::connect((config.remote_host.as_str(), config.remote_port))
            .map_err(TransportError::from)?;
        Ok(Box::new(StreamPacketIo::new(stream)))
    } else {
        let socket = mihomo_core::bind_outbound_udp("0.0.0.0:0").map_err(TransportError::from)?;
        socket
            .connect((config.remote_host.as_str(), config.remote_port))
            .map_err(TransportError::from)?;
        Ok(Box::new(DatagramPacketIo::new(socket)))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ControlChannel, ControlConn, DataChannel, KeyMaterial, OpenVpnClient,
        decode_control_plain, decode_static_key, encode_control_plain, install_script_options_string,
        install_script_peer_info, marshal_client_key_method2_record, new_client_key_method2_record,
        connect_stream_with_boxed_tcp, connect_stream_with_socks5_stream,
        open_udp_stream_with_boxed_tcp,
        open_udp_stream_with_socks5_stream,
        new_tls_crypt_keys, normalize_proto, parse_push_reply, parse_server_key_method2_record,
        prepare_config, tls_crypt_unwrap, tls_crypt_wrap, derive_client_key_material,
        DatagramPacketIo, KeySource, KeySource2, OpenVpnControlPacket, OpenVpnOpcode, OpenVpnOptions,
        PacketIo, PacketMux, StreamPacketIo, AUTH_SHA256, CIPHER_AES_128_GCM,
        DEFAULT_HANDSHAKE_TIMEOUT, PUSH_REQUEST, PROTO_TCP, PROTO_UDP, SESSION_ID_SIZE,
        resolve_remote_target_host,
    };
    use rcgen::generate_simple_self_signed;
    use rustls::{Certificate, PrivateKey, ServerConfig, ServerConnection, StreamOwned};
    use std::collections::VecDeque;
    use std::io;
    use std::io::{Read, Write};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;
    use crate::{OpenVpnTestServer, TransportError};
    use crate::openvpn_stream::{
        connect_stream, marshal_server_key_method2_record, open_udp_stream,
        parse_client_key_method2_record, read_null_terminated_message, read_udp_packet,
        swap_key_material, write_udp_packet, udp_bridge,
    };
    use smoltcp::wire::{IpProtocol as SmolIpProtocol, Ipv4Packet as SmolIpv4Packet, TcpPacket as SmolTcpPacket};

    fn static_key_pem() -> String {
        let line = "11".repeat(16);
        format!(
            "-----BEGIN OpenVPN Static key V1-----\n{0}\n{0}\n{0}\n{0}\n{0}\n{0}\n{0}\n{0}\n{0}\n{0}\n{0}\n{0}\n{0}\n{0}\n{0}\n{0}\n-----END OpenVPN Static key V1-----\n",
            line
        )
    }

    fn base_options() -> OpenVpnOptions {
        OpenVpnOptions {
            server: "1.2.3.4".into(),
            port: 1194,
            proto: "udp".into(),
            dev: "tun".into(),
            cipher: "AES-128-GCM".into(),
            auth: "SHA256".into(),
            ca: "test-ca".into(),
            cert: String::new(),
            key: String::new(),
            tls_crypt: static_key_pem(),
            username: "demo".into(),
            password: "secret".into(),
            remote_dns_resolve: false,
            dns: Vec::new(),
            mtu: 1500,
        }
    }

    struct MemoryPacketIo {
        in_rx: std::sync::mpsc::Receiver<Vec<u8>>,
        out_tx: std::sync::mpsc::SyncSender<Vec<u8>>,
        local: std::net::SocketAddr,
        remote: std::net::SocketAddr,
        closed: bool,
    }

    fn memory_packet_pair() -> (MemoryPacketIo, MemoryPacketIo) {
        let (a_tx, a_rx) = std::sync::mpsc::sync_channel(64);
        let (b_tx, b_rx) = std::sync::mpsc::sync_channel(64);
        (
            MemoryPacketIo {
                in_rx: b_rx,
                out_tx: a_tx,
                local: "127.0.0.1:10001".parse().unwrap(),
                remote: "127.0.0.1:10002".parse().unwrap(),
                closed: false,
            },
            MemoryPacketIo {
                in_rx: a_rx,
                out_tx: b_tx,
                local: "127.0.0.1:10002".parse().unwrap(),
                remote: "127.0.0.1:10001".parse().unwrap(),
                closed: false,
            },
        )
    }

    impl PacketIo for MemoryPacketIo {
        fn read_packet(&mut self, timeout: Option<Duration>) -> io::Result<Vec<u8>> {
            if self.closed {
                return Err(io::Error::new(io::ErrorKind::BrokenPipe, "memory packet io closed"));
            }
            match timeout {
                Some(timeout) => self.in_rx.recv_timeout(timeout).map_err(|err| match err {
                    std::sync::mpsc::RecvTimeoutError::Timeout => {
                        io::Error::new(io::ErrorKind::TimedOut, "memory packet receive timed out")
                    }
                    std::sync::mpsc::RecvTimeoutError::Disconnected => io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "memory packet channel closed",
                    ),
                }),
                None => self
                    .in_rx
                    .recv()
                    .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "memory packet channel closed")),
            }
        }

        fn write_packet(&mut self, packet: &[u8]) -> io::Result<()> {
            if self.closed {
                return Err(io::Error::new(io::ErrorKind::BrokenPipe, "memory packet io closed"));
            }
            self.out_tx
                .send(packet.to_vec())
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "memory packet channel closed"))
        }

        fn close(&mut self) -> io::Result<()> {
            self.closed = true;
            Ok(())
        }

        fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
            Ok(self.local)
        }

        fn remote_addr(&self) -> io::Result<std::net::SocketAddr> {
            Ok(self.remote)
        }
    }

    fn build_test_server_tls() -> (OpenVpnOptions, Arc<ServerConfig>) {
        let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_pem = cert.cert.pem();
        let cert_der = cert.cert.der().to_vec();
        let key_der = cert.key_pair.serialize_der();
        let server = Arc::new(
            ServerConfig::builder()
                .with_safe_defaults()
                .with_no_client_auth()
                .with_single_cert(vec![Certificate(cert_der)], PrivateKey(key_der))
                .unwrap(),
        );
        let mut options = base_options();
        options.server = "localhost".into();
        options.ca = cert_pem;
        (options, server)
    }

    fn build_openvpn_client_cert_pair() -> (String, String, Vec<u8>) {
        let cert = generate_simple_self_signed(vec!["client.local".into()]).unwrap();
        let cert_pem = cert.cert.pem();
        let cert_der = cert.cert.der().to_vec();
        let key_pem = cert.key_pair.serialize_pem();
        (cert_pem, key_pem, cert_der)
    }

    #[test]
    fn prepare_config_normalizes_openvpn_happy_path() {
        let config = prepare_config(&base_options()).unwrap();
        assert_eq!(config.remote_host, "1.2.3.4");
        assert_eq!(config.remote_port, 1194);
        assert_eq!(config.proto, PROTO_UDP);
        assert_eq!(config.dev, "tun");
        assert_eq!(config.cipher, CIPHER_AES_128_GCM);
        assert_eq!(config.auth, AUTH_SHA256);
        assert_eq!(config.username, "demo");
        assert_eq!(config.password, "secret");
        assert_eq!(config.tls_crypt_key.len(), 256);
    }

    #[test]
    fn normalize_proto_accepts_udp_and_tcp_aliases() {
        assert_eq!(normalize_proto(""), PROTO_UDP);
        assert_eq!(normalize_proto("udp4"), PROTO_UDP);
        assert_eq!(normalize_proto("tcp-client"), PROTO_TCP);
        assert_eq!(normalize_proto("tcp4-client"), PROTO_TCP);
    }

    #[test]
    fn decode_static_key_strips_pem_wrapper() {
        let key = decode_static_key(static_key_pem().as_bytes()).unwrap();
        assert_eq!(key.len(), 256);
        assert!(key.iter().all(|byte| *byte == 0x11));
    }

    #[test]
    fn tls_crypt_key_derivation_swaps_direction_for_client() {
        let raw = vec![0x11; 128]
            .into_iter()
            .chain(vec![0x22; 128])
            .collect::<Vec<_>>();
        let client = new_tls_crypt_keys(&raw, true).unwrap();
        let server = new_tls_crypt_keys(&raw, false).unwrap();
        assert_eq!(client.encrypt_cipher_key, vec![0x22; 32]);
        assert_eq!(server.encrypt_cipher_key, vec![0x11; 32]);
    }

    #[test]
    fn tls_crypt_wrap_and_unwrap_roundtrip() {
        let raw = vec![0x11; 128]
            .into_iter()
            .chain(vec![0x22; 128])
            .collect::<Vec<_>>();
        let client = new_tls_crypt_keys(&raw, true).unwrap();
        let server = new_tls_crypt_keys(&raw, false).unwrap();
        let header = [0x38, 1, 2, 3, 4, 5, 6, 7, 8];
        let wrapped = tls_crypt_wrap(&client, &header, 7, 42, b"payload").unwrap();
        let (decoded_header, packet_id, unix_time, plaintext) =
            tls_crypt_unwrap(&server, &wrapped).unwrap();
        assert_eq!(decoded_header, header);
        assert_eq!(packet_id, 7);
        assert_eq!(unix_time, 42);
        assert_eq!(plaintext, b"payload");
    }

    #[test]
    fn encode_and_decode_control_plain_roundtrip() {
        let packet = OpenVpnControlPacket {
            opcode: OpenVpnOpcode::ControlV1,
            key_id: 0,
            local_session: [1_u8; SESSION_ID_SIZE],
            ack_ids: vec![7, 9],
            ack_remote_session: [2_u8; SESSION_ID_SIZE],
            message_id: 42,
            payload: b"payload".to_vec(),
        };
        let encoded = encode_control_plain(&packet).unwrap();
        let (acks, ack_remote, message_id, payload) =
            decode_control_plain(packet.opcode, &encoded).unwrap();
        assert_eq!(acks, vec![7, 9]);
        assert_eq!(ack_remote, [2_u8; SESSION_ID_SIZE]);
        assert_eq!(message_id, 42);
        assert_eq!(payload, b"payload");
    }

    #[test]
    fn key_method2_roundtrip_parses_server_record_shape() {
        let mut record = new_client_key_method2_record(
            &install_script_options_string(PROTO_UDP, CIPHER_AES_128_GCM, AUTH_SHA256),
            &install_script_peer_info(CIPHER_AES_128_GCM),
            "demo",
            "secret",
        )
        .unwrap();
        record.sources.server.random1 = [3_u8; 32];
        record.sources.server.random2 = [4_u8; 32];

        let mut encoded = vec![0_u8; 4];
        encoded.push(2);
        encoded.extend_from_slice(&record.sources.server.random1);
        encoded.extend_from_slice(&record.sources.server.random2);
        encoded.extend_from_slice(&marshal_client_key_method2_record(&record).unwrap()[4 + 1 + 48 + 32 + 32..]);

        let parsed = parse_server_key_method2_record(&encoded).unwrap();
        assert_eq!(parsed.options, record.options);
        assert_eq!(parsed.username, "demo");
        assert_eq!(parsed.password, "secret");
    }

    #[test]
    fn derive_client_key_material_produces_symmetric_lengths() {
        let mut record = new_client_key_method2_record(
            &install_script_options_string(PROTO_UDP, CIPHER_AES_128_GCM, AUTH_SHA256),
            &install_script_peer_info(CIPHER_AES_128_GCM),
            "demo",
            "secret",
        )
        .unwrap();
        record.sources.server.random1 = [3_u8; 32];
        record.sources.server.random2 = [4_u8; 32];
        let material = derive_client_key_material(
            &KeySource2 {
                client: record.sources.client.clone(),
                server: record.sources.server.clone(),
            },
            &[1_u8; SESSION_ID_SIZE],
            &[2_u8; SESSION_ID_SIZE],
            16,
        )
        .unwrap();
        assert_eq!(material.send_cipher_key.len(), 16);
        assert_eq!(material.recv_cipher_key.len(), 16);
        assert_eq!(material.send_hmac_key.len(), 64);
        assert_eq!(material.recv_hmac_key.len(), 64);
    }

    #[test]
    fn parse_push_reply_extracts_prefix_dns_and_flags() {
        let reply = parse_push_reply(
            "PUSH_REPLY,ifconfig 10.0.0.2 255.255.255.0,dhcp-option DNS 1.1.1.1,peer-id 7,redirect-gateway,block-ipv6",
        )
        .unwrap();
        assert_eq!(reply.prefixes, vec!["10.0.0.2/24"]);
        assert_eq!(reply.dns, vec!["1.1.1.1"]);
        assert_eq!(reply.peer_id, 7);
        assert!(reply.redirect);
        assert!(reply.block_ipv6);
    }

    #[test]
    fn stream_packet_io_uses_two_byte_length_prefix() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut len = [0_u8; 2];
            stream.read_exact(&mut len).unwrap();
            let size = u16::from_be_bytes(len) as usize;
            let mut payload = vec![0_u8; size];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(payload, b"hello");
            stream.write_all(&5_u16.to_be_bytes()).unwrap();
            stream.write_all(b"world").unwrap();
        });

        let stream = TcpStream::connect(addr).unwrap();
        let mut io = StreamPacketIo::new(stream);
        io.write_packet(b"hello").unwrap();
        let packet = io.read_packet(Some(Duration::from_secs(2))).unwrap();
        assert_eq!(packet, b"world");
        worker.join().unwrap();
    }

    #[test]
    fn datagram_packet_io_roundtrips_payload() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_addr = server.local_addr().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client.connect(server_addr).unwrap();
        let client_addr = client.local_addr().unwrap();
        server.connect(client_addr).unwrap();

        let worker = thread::spawn(move || {
            let mut io = DatagramPacketIo::new(server);
            let packet = io.read_packet(Some(Duration::from_secs(2))).unwrap();
            assert_eq!(packet, b"ping");
            io.write_packet(b"pong").unwrap();
        });

        let mut io = DatagramPacketIo::new(client);
        io.write_packet(b"ping").unwrap();
        let packet = io.read_packet(Some(Duration::from_secs(2))).unwrap();
        assert_eq!(packet, b"pong");
        worker.join().unwrap();
    }

    #[test]
    fn packet_mux_splits_control_and_data_packets() {
        struct ScriptedIo {
            packets: std::sync::Mutex<VecDeque<Vec<u8>>>,
        }

        impl PacketIo for ScriptedIo {
            fn read_packet(&mut self, _timeout: Option<Duration>) -> io::Result<Vec<u8>> {
                self.packets
                    .lock()
                    .unwrap()
                    .pop_front()
                    .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "done"))
            }

            fn write_packet(&mut self, _packet: &[u8]) -> io::Result<()> {
                Ok(())
            }

            fn close(&mut self) -> io::Result<()> {
                Ok(())
            }

            fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
                Ok("127.0.0.1:1".parse().unwrap())
            }

            fn remote_addr(&self) -> io::Result<std::net::SocketAddr> {
                Ok("127.0.0.1:2".parse().unwrap())
            }
        }

        let control = vec![super::opcode_key_id(OpenVpnOpcode::ControlV1, 0), 0];
        let data = vec![super::opcode_key_id(OpenVpnOpcode::DataV1, 0), 1];
        let mut mux = PacketMux::new(Box::new(ScriptedIo {
            packets: std::sync::Mutex::new(VecDeque::from(vec![control.clone(), data.clone()])),
        }));
        assert_eq!(mux.read_control_packet(Some(Duration::from_secs(2))).unwrap(), control);
        assert_eq!(mux.read_data_packet(Some(Duration::from_secs(2))).unwrap(), data);
        mux.close().unwrap();
    }

    #[test]
    fn control_channel_reset_and_ack_roundtrip() {
        let static_key = decode_static_key(static_key_pem().as_bytes()).unwrap();
        let client_crypt = new_tls_crypt_keys(&static_key, true).unwrap();
        let server_crypt = new_tls_crypt_keys(&static_key, false).unwrap();
        let (client_io, server_io) = memory_packet_pair();
        let client_mux = Arc::new(Mutex::new(PacketMux::new(Box::new(client_io))));
        let server_mux = Arc::new(Mutex::new(PacketMux::new(Box::new(server_io))));
        let client = ControlChannel::new(client_mux.clone(), client_crypt, *b"client01");
        let server = ControlChannel::new(server_mux.clone(), server_crypt, *b"server01");

        client.send_reset().unwrap();
        let packet = server
            .read(Some(DEFAULT_HANDSHAKE_TIMEOUT))
            .unwrap();
        assert_eq!(packet.opcode, OpenVpnOpcode::ControlHardResetClientV2);
        assert_eq!(packet.local_session, *b"client01");
        server.set_remote_session_id(packet.local_session);
        server.send_ack().unwrap();

        let client_mux = client_mux.clone();
        let client_reader = client.clone();
        let worker = thread::spawn(move || client_reader.read(Some(Duration::from_millis(200))));
        let result = worker.join().unwrap();
        let err = result.unwrap_err();
        assert!(matches!(err.kind(), io::ErrorKind::TimedOut));
        assert_eq!(client.pending_messages(), 0);
        client_mux.lock().unwrap().close().unwrap();
        server_mux.lock().unwrap().close().unwrap();
    }

    #[test]
    fn data_channel_roundtrip_encrypts_and_decrypts_packets() {
        let client_keys = KeyMaterial {
            send_cipher_key: vec![0x11; 16],
            send_hmac_key: vec![0x22; 64],
            recv_cipher_key: vec![0x33; 16],
            recv_hmac_key: vec![0x44; 64],
        };
        let server_keys = swap_key_material(&client_keys);
        let mut client = DataChannel::new(&client_keys, 7).unwrap();
        let mut server = DataChannel::new(&server_keys, 7).unwrap();

        let ip_packet = vec![0x45, 0, 0, 20, 1, 2, 3, 4, 64, 6, 0, 0, 10, 8, 0, 2, 1, 1, 1, 1];
        let encrypted = client.encrypt(&ip_packet).unwrap();
        assert_eq!(encrypted[0] >> 3, OpenVpnOpcode::DataV2 as u8);
        let plain = server.decrypt(&encrypted).unwrap();
        assert_eq!(plain, ip_packet);
    }

    #[test]
    fn openvpn_client_handshake_and_data_channel_roundtrip() {
        let (options, server_tls) = build_test_server_tls();
        let config = prepare_config(&options).unwrap();
        let server_config = config.clone();
        let (client_io, server_io) = memory_packet_pair();

        let worker = thread::spawn(move || {
            let static_key = server_config.tls_crypt_key.clone();
            let server_crypt = new_tls_crypt_keys(&static_key, false).unwrap();
            let server_mux = Arc::new(Mutex::new(PacketMux::new(Box::new(server_io))));
            let server_control =
                ControlChannel::new(Arc::clone(&server_mux), server_crypt, *b"server01");

            let reset = server_control
                .read(Some(DEFAULT_HANDSHAKE_TIMEOUT))
                .unwrap();
            assert_eq!(reset.opcode, OpenVpnOpcode::ControlHardResetClientV2);
            server_control.set_remote_session_id(reset.local_session);
            server_control
                .send(OpenVpnOpcode::ControlHardResetServerV2, &[])
                .unwrap();

            let mut tls = StreamOwned::new(
                ServerConnection::new(server_tls).unwrap(),
                ControlConn::new(server_control.clone()),
            );
            while tls.conn.is_handshaking() {
                tls.conn.complete_io(&mut tls.sock).unwrap();
            }

            let mut km2_buf = vec![0_u8; 1024];
            let read = tls.read(&mut km2_buf).unwrap();
            let client_record = parse_client_key_method2_record(&km2_buf[..read]).unwrap();
            let server_random1 = [0x31_u8; 32];
            let server_random2 = [0x41_u8; 32];
            let server_record = marshal_server_key_method2_record(
                server_random1,
                server_random2,
                &client_record.options,
                "IV_VER=server\n",
            );
            tls.write_all(&server_record).unwrap();
            tls.flush().unwrap();

            let keys = derive_client_key_material(
                &KeySource2 {
                    client: client_record.sources.client.clone(),
                    server: super::KeySource {
                        pre_master: [0_u8; 48],
                        random1: server_random1,
                        random2: server_random2,
                    }
                    .into(),
                },
                &reset.local_session,
                &server_control.local_session_id(),
                16,
            )
            .unwrap();
            let server_keys = swap_key_material(&keys);

            let push_request = read_null_terminated_message(&mut tls).unwrap();
            assert_eq!(push_request, PUSH_REQUEST);
            tls.write_all(
                b"PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0,dhcp-option DNS 1.1.1.1,peer-id 7\0",
            )
            .unwrap();
            tls.flush().unwrap();

            let mut server_data = DataChannel::new(&server_keys, 7).unwrap();
            let encrypted = server_mux
                .lock()
                .unwrap()
                .read_data_packet(Some(DEFAULT_HANDSHAKE_TIMEOUT))
                .unwrap();
            let plain = server_data.decrypt(&encrypted).unwrap();
            assert_eq!(plain, b"ip-ping");
            let response = server_data.encrypt(b"ip-pong").unwrap();
            server_mux.lock().unwrap().write_packet(&response).unwrap();
            server_mux.lock().unwrap().close().unwrap();
        });

        let mut client = OpenVpnClient::new(config, Box::new(client_io)).unwrap();
        let push = client.handshake().unwrap();
        assert_eq!(push.prefixes, vec!["10.8.0.2/24"]);
        assert_eq!(push.dns, vec!["1.1.1.1"]);
        assert_eq!(push.peer_id, 7);
        client.write_ip_packet(b"ip-ping").unwrap();
        let response = client.read_ip_packet().unwrap();
        assert_eq!(response, b"ip-pong");
        client.close().unwrap();
        worker.join().unwrap();
    }

    #[test]
    fn openvpn_udp_bridge_roundtrip_over_local_test_server() {
        let server = OpenVpnTestServer::start().unwrap();
        let mut options = base_options();
        options.server = "127.0.0.1".into();
        options.port = server.addr().port();
        options.ca = server.ca_pem().to_owned();
        options.tls_crypt = server.tls_crypt_pem().to_owned();

        let mut stream = open_udp_stream(&options).unwrap();
        write_udp_packet(&mut *stream, "8.8.8.8:53".parse().unwrap(), b"via-openvpn").unwrap();
        let (source, payload) = read_udp_packet(&mut *stream).unwrap();
        assert_eq!(source.ip(), IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        assert_eq!(payload, b"openvpn-ok");

        server.shutdown();
    }

    #[test]
    fn openvpn_tcp_transport_udp_bridge_roundtrip_over_local_test_server() {
        let server = OpenVpnTestServer::start_tcp().unwrap();
        let mut options = base_options();
        options.server = "127.0.0.1".into();
        options.port = server.addr().port();
        options.proto = "tcp".into();
        options.ca = server.ca_pem().to_owned();
        options.tls_crypt = server.tls_crypt_pem().to_owned();

        let mut stream = open_udp_stream(&options).unwrap();
        write_udp_packet(&mut *stream, "8.8.8.8:53".parse().unwrap(), b"via-openvpn").unwrap();
        let (source, payload) = read_udp_packet(&mut *stream).unwrap();
        assert_eq!(source.ip(), IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        assert_eq!(payload, b"openvpn-ok");

        server.shutdown();
    }

    #[test]
    fn openvpn_connect_stream_returns_tcp_stack_for_ipv4_target() {
        let server = OpenVpnTestServer::start().unwrap();
        let mut options = base_options();
        options.server = "127.0.0.1".into();
        options.port = server.addr().port();
        options.ca = server.ca_pem().to_owned();
        options.tls_crypt = server.tls_crypt_pem().to_owned();

        let target = crate::TransportTarget::new("8.8.8.8", 443);
        let mut stream = connect_stream(&options, &target).unwrap();
        stream.write_all(b"ping").unwrap();
        let mut reply = [0_u8; 4];
        let read = stream.read(&mut reply).unwrap();
        assert_eq!(read, 4);
        assert_eq!(&reply, b"pong");

        server.shutdown();
    }

    #[test]
    fn openvpn_connect_stream_resolves_remote_dns_over_tunnel() {
        let server = OpenVpnTestServer::start().unwrap();
        let mut options = base_options();
        options.server = "127.0.0.1".into();
        options.port = server.addr().port();
        options.ca = server.ca_pem().to_owned();
        options.tls_crypt = server.tls_crypt_pem().to_owned();
        options.remote_dns_resolve = true;
        options.dns = vec!["udp://10.8.0.1:5353".into()];

        let target = crate::TransportTarget::new("edge.example.com", 443);
        let mut stream = connect_stream(&options, &target).unwrap();
        stream.write_all(b"ping").unwrap();
        let mut reply = [0_u8; 4];
        let read = stream.read(&mut reply).unwrap();
        assert_eq!(read, 4);
        assert_eq!(&reply, b"pong");

        server.shutdown();
    }

    #[test]
    fn openvpn_tcp_transport_connect_stream_returns_tcp_stack_for_ipv4_target() {
        let server = OpenVpnTestServer::start_tcp().unwrap();
        let mut options = base_options();
        options.server = "127.0.0.1".into();
        options.port = server.addr().port();
        options.proto = "tcp".into();
        options.ca = server.ca_pem().to_owned();
        options.tls_crypt = server.tls_crypt_pem().to_owned();

        let target = crate::TransportTarget::new("8.8.8.8", 443);
        let mut stream = connect_stream(&options, &target).unwrap();
        stream.write_all(b"ping").unwrap();
        let mut reply = [0_u8; 4];
        let read = stream.read(&mut reply).unwrap();
        assert_eq!(read, 4);
        assert_eq!(&reply, b"pong");

        server.shutdown();
    }

    #[test]
    fn openvpn_tcp_transport_connect_stream_resolves_localhost_target() {
        let server = OpenVpnTestServer::start_tcp().unwrap();
        let mut options = base_options();
        options.server = "127.0.0.1".into();
        options.port = server.addr().port();
        options.proto = "tcp".into();
        options.ca = server.ca_pem().to_owned();
        options.tls_crypt = server.tls_crypt_pem().to_owned();

        let target = crate::TransportTarget::new("localhost", 443);
        let mut stream = connect_stream(&options, &target).unwrap();
        stream.write_all(b"ping").unwrap();
        let mut reply = [0_u8; 4];
        let read = stream.read(&mut reply).unwrap();
        assert_eq!(read, 4);
        assert_eq!(&reply, b"pong");

        server.shutdown();
    }

    #[test]
    fn openvpn_udp_bridge_roundtrip_with_client_cert_auth_over_local_test_server() {
        let (cert_pem, key_pem, cert_der) = build_openvpn_client_cert_pair();
        let server = OpenVpnTestServer::start_with_client_auth(cert_der).unwrap();
        let mut options = base_options();
        options.server = "127.0.0.1".into();
        options.port = server.addr().port();
        options.ca = server.ca_pem().to_owned();
        options.tls_crypt = server.tls_crypt_pem().to_owned();
        options.username.clear();
        options.password.clear();
        options.cert = cert_pem;
        options.key = key_pem;

        let mut stream = open_udp_stream(&options).unwrap();
        write_udp_packet(&mut *stream, "8.8.8.8:53".parse().unwrap(), b"via-openvpn").unwrap();
        let (source, payload) = read_udp_packet(&mut *stream).unwrap();
        assert_eq!(source.ip(), IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        assert_eq!(payload, b"openvpn-ok");

        server.shutdown();
    }

    #[test]
    fn openvpn_tcp_transport_connect_stream_with_client_cert_auth_returns_tcp_stack() {
        let (cert_pem, key_pem, cert_der) = build_openvpn_client_cert_pair();
        let server = OpenVpnTestServer::start_tcp_with_client_auth(cert_der).unwrap();
        let mut options = base_options();
        options.server = "127.0.0.1".into();
        options.port = server.addr().port();
        options.proto = "tcp".into();
        options.ca = server.ca_pem().to_owned();
        options.tls_crypt = server.tls_crypt_pem().to_owned();
        options.username.clear();
        options.password.clear();
        options.cert = cert_pem;
        options.key = key_pem;

        let target = crate::TransportTarget::new("8.8.8.8", 443);
        let mut stream = connect_stream(&options, &target).unwrap();
        stream.write_all(b"ping").unwrap();
        let mut reply = [0_u8; 4];
        let read = stream.read(&mut reply).unwrap();
        assert_eq!(read, 4);
        assert_eq!(&reply, b"pong");

        server.shutdown();
    }

    #[test]
    fn openvpn_tcp_transport_connect_stream_with_boxed_tcp_returns_tcp_stack() {
        let server = OpenVpnTestServer::start_tcp().unwrap();
        let mut options = base_options();
        options.server = "127.0.0.1".into();
        options.port = server.addr().port();
        options.proto = "tcp".into();
        options.ca = server.ca_pem().to_owned();
        options.tls_crypt = server.tls_crypt_pem().to_owned();

        let relay = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let relay_addr = relay.local_addr().unwrap();
        let server_addr = server.addr();
        let worker = std::thread::spawn(move || {
            let (mut downstream, _) = relay.accept().unwrap();
            let mut upstream = std::net::TcpStream::connect(server_addr).unwrap();
            let _ = downstream.set_read_timeout(Some(Duration::from_secs(1)));
            let _ = downstream.set_write_timeout(Some(Duration::from_secs(1)));
            let _ = upstream.set_read_timeout(Some(Duration::from_secs(1)));
            let _ = upstream.set_write_timeout(Some(Duration::from_secs(1)));
            relay_tcp_bidirectional(downstream, upstream);
        });

        let stream = std::net::TcpStream::connect(relay_addr).unwrap();
        let target = crate::TransportTarget::new("8.8.8.8", 443);
        let mut stream = connect_stream_with_boxed_tcp(&options, Box::new(stream), &target).unwrap();
        stream.write_all(b"ping").unwrap();
        let mut reply = [0_u8; 4];
        let read = stream.read(&mut reply).unwrap();
        assert_eq!(read, 4);
        assert_eq!(&reply, b"pong");

        drop(stream);
        server.shutdown();
        worker.join().unwrap();
    }

    #[test]
    fn openvpn_tcp_transport_open_udp_stream_with_boxed_tcp_roundtrips() {
        let server = OpenVpnTestServer::start_tcp().unwrap();
        let mut options = base_options();
        options.server = "127.0.0.1".into();
        options.port = server.addr().port();
        options.proto = "tcp".into();
        options.ca = server.ca_pem().to_owned();
        options.tls_crypt = server.tls_crypt_pem().to_owned();

        let relay = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let relay_addr = relay.local_addr().unwrap();
        let server_addr = server.addr();
        let worker = std::thread::spawn(move || {
            let (mut downstream, _) = relay.accept().unwrap();
            let mut upstream = std::net::TcpStream::connect(server_addr).unwrap();
            let _ = downstream.set_read_timeout(Some(Duration::from_secs(1)));
            let _ = downstream.set_write_timeout(Some(Duration::from_secs(1)));
            let _ = upstream.set_read_timeout(Some(Duration::from_secs(1)));
            let _ = upstream.set_write_timeout(Some(Duration::from_secs(1)));
            relay_tcp_bidirectional(downstream, upstream);
        });

        let stream = std::net::TcpStream::connect(relay_addr).unwrap();
        let mut stream = open_udp_stream_with_boxed_tcp(&options, Box::new(stream)).unwrap();
        write_udp_packet(&mut *stream, "8.8.8.8:53".parse().unwrap(), b"via-openvpn").unwrap();
        let (source, payload) = read_udp_packet(&mut *stream).unwrap();
        assert_eq!(source.ip(), IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        assert_eq!(payload, b"openvpn-ok");

        stream.shutdown_all().unwrap();
        drop(stream);
        server.shutdown();
        worker.join().unwrap();
    }

    #[test]
    fn openvpn_tcp_transport_open_udp_stream_with_client_cert_and_boxed_tcp_roundtrips() {
        let (cert_pem, key_pem, cert_der) = build_openvpn_client_cert_pair();
        let server = OpenVpnTestServer::start_tcp_with_client_auth(cert_der).unwrap();
        let mut options = base_options();
        options.server = "127.0.0.1".into();
        options.port = server.addr().port();
        options.proto = "tcp".into();
        options.ca = server.ca_pem().to_owned();
        options.tls_crypt = server.tls_crypt_pem().to_owned();
        options.username.clear();
        options.password.clear();
        options.cert = cert_pem;
        options.key = key_pem;

        let relay = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let relay_addr = relay.local_addr().unwrap();
        let server_addr = server.addr();
        let worker = std::thread::spawn(move || {
            let (mut downstream, _) = relay.accept().unwrap();
            let mut upstream = std::net::TcpStream::connect(server_addr).unwrap();
            let _ = downstream.set_read_timeout(Some(Duration::from_secs(1)));
            let _ = downstream.set_write_timeout(Some(Duration::from_secs(1)));
            let _ = upstream.set_read_timeout(Some(Duration::from_secs(1)));
            let _ = upstream.set_write_timeout(Some(Duration::from_secs(1)));
            relay_tcp_bidirectional(downstream, upstream);
        });

        let stream = std::net::TcpStream::connect(relay_addr).unwrap();
        let mut stream = open_udp_stream_with_boxed_tcp(&options, Box::new(stream)).unwrap();
        write_udp_packet(&mut *stream, "8.8.8.8:53".parse().unwrap(), b"via-openvpn").unwrap();
        let (source, payload) = read_udp_packet(&mut *stream).unwrap();
        assert_eq!(source.ip(), IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        assert_eq!(payload, b"openvpn-ok");

        stream.shutdown_all().unwrap();
        drop(stream);
        server.shutdown();
        worker.join().unwrap();
    }

    #[test]
    fn openvpn_udp_transport_open_udp_stream_with_socks5_stream_roundtrips() {
        let server = OpenVpnTestServer::start().unwrap();
        let mut options = base_options();
        options.server = "127.0.0.1".into();
        options.port = server.addr().port();
        options.proto = "udp".into();
        options.ca = server.ca_pem().to_owned();
        options.tls_crypt = server.tls_crypt_pem().to_owned();

        let outer_socks = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let outer_socks_addr = outer_socks.local_addr().unwrap();
        let server_addr = server.addr();
        let outer_worker = std::thread::spawn(move || {
            let relay = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            relay
                .set_read_timeout(Some(Duration::from_millis(200)))
                .unwrap();
            let relay_addr = relay.local_addr().unwrap();

            let (mut control, _) = outer_socks.accept().unwrap();
            let mut greeting = [0_u8; 3];
            control.read_exact(&mut greeting).unwrap();
            assert_eq!(greeting, [0x05, 0x01, 0x00]);
            control.write_all(&[0x05, 0x00]).unwrap();

            let mut header = [0_u8; 4];
            control.read_exact(&mut header).unwrap();
            assert_eq!(header, [0x05, 0x03, 0x00, 0x01]);
            let mut bind_ip = [0_u8; 4];
            control.read_exact(&mut bind_ip).unwrap();
            let mut bind_port = [0_u8; 2];
            control.read_exact(&mut bind_port).unwrap();
            let announced_client_addr = SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::from(bind_ip)),
                u16::from_be_bytes(bind_port),
            );

            let mut reply = vec![0x05, 0x00, 0x00, 0x01];
            if let SocketAddr::V4(relay_addr) = relay_addr {
                reply.extend_from_slice(&relay_addr.ip().octets());
                reply.extend_from_slice(&relay_addr.port().to_be_bytes());
            } else {
                panic!("expected ipv4 relay addr");
            }
            control.write_all(&reply).unwrap();
            control.flush().unwrap();

            let mut packet = [0_u8; 4096];
            let mut client_peer = None;
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            while std::time::Instant::now() < deadline {
                let (read, peer) = match relay.recv_from(&mut packet) {
                    Ok(value) => value,
                    Err(err)
                        if matches!(
                            err.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                        ) =>
                    {
                        continue;
                    }
                    Err(err) => panic!("outer socks udp relay failed: {err}"),
                };
                if client_peer.is_none() || client_peer == Some(peer) {
                    client_peer = Some(peer);
                    assert_eq!(peer.port(), announced_client_addr.port());
                    assert!(read > 10);
                    let target = SocketAddr::new(
                        std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                            packet[4], packet[5], packet[6], packet[7],
                        )),
                        u16::from_be_bytes([packet[8], packet[9]]),
                    );
                    assert_eq!(target, server_addr);
                    let payload = &packet[10..read];
                    relay.send_to(payload, target).unwrap();
                } else {
                    let mut framed = vec![0x00, 0x00, 0x00, 0x01];
                    if let SocketAddr::V4(source) = peer {
                        framed.extend_from_slice(&source.ip().octets());
                        framed.extend_from_slice(&source.port().to_be_bytes());
                    } else {
                        panic!("expected ipv4 source addr");
                    }
                    framed.extend_from_slice(&packet[..read]);
                    relay.send_to(&framed, client_peer.unwrap()).unwrap();
                }
            }
        });

        let stream = std::net::TcpStream::connect(outer_socks_addr).unwrap();
        let mut stream =
            open_udp_stream_with_socks5_stream(&options, Box::new(stream), None).unwrap();
        write_udp_packet(&mut *stream, "8.8.8.8:53".parse().unwrap(), b"via-openvpn").unwrap();
        let (source, payload) = read_udp_packet(&mut *stream).unwrap();
        assert_eq!(source.ip(), IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        assert_eq!(payload, b"openvpn-ok");

        stream.shutdown_all().unwrap();
        drop(stream);
        server.shutdown();
        outer_worker.join().unwrap();
    }

    #[test]
    fn openvpn_udp_transport_connect_stream_with_socks5_stream_returns_tcp_stack() {
        let server = OpenVpnTestServer::start().unwrap();
        let mut options = base_options();
        options.server = "127.0.0.1".into();
        options.port = server.addr().port();
        options.proto = "udp".into();
        options.ca = server.ca_pem().to_owned();
        options.tls_crypt = server.tls_crypt_pem().to_owned();

        let outer_socks = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let outer_socks_addr = outer_socks.local_addr().unwrap();
        let server_addr = server.addr();
        let outer_worker = std::thread::spawn(move || {
            let relay = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            relay
                .set_read_timeout(Some(Duration::from_millis(200)))
                .unwrap();
            let relay_addr = relay.local_addr().unwrap();

            let (mut control, _) = outer_socks.accept().unwrap();
            let mut greeting = [0_u8; 3];
            control.read_exact(&mut greeting).unwrap();
            assert_eq!(greeting, [0x05, 0x01, 0x00]);
            control.write_all(&[0x05, 0x00]).unwrap();

            let mut header = [0_u8; 4];
            control.read_exact(&mut header).unwrap();
            assert_eq!(header, [0x05, 0x03, 0x00, 0x01]);
            let mut bind_ip = [0_u8; 4];
            control.read_exact(&mut bind_ip).unwrap();
            let mut bind_port = [0_u8; 2];
            control.read_exact(&mut bind_port).unwrap();
            let announced_client_addr = SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::from(bind_ip)),
                u16::from_be_bytes(bind_port),
            );

            let mut reply = vec![0x05, 0x00, 0x00, 0x01];
            if let SocketAddr::V4(relay_addr) = relay_addr {
                reply.extend_from_slice(&relay_addr.ip().octets());
                reply.extend_from_slice(&relay_addr.port().to_be_bytes());
            } else {
                panic!("expected ipv4 relay addr");
            }
            control.write_all(&reply).unwrap();
            control.flush().unwrap();

            let mut packet = [0_u8; 4096];
            let mut client_peer = None;
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            while std::time::Instant::now() < deadline {
                let (read, peer) = match relay.recv_from(&mut packet) {
                    Ok(value) => value,
                    Err(err)
                        if matches!(
                            err.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                        ) =>
                    {
                        continue;
                    }
                    Err(err) => panic!("outer socks udp relay failed: {err}"),
                };
                if client_peer.is_none() || client_peer == Some(peer) {
                    client_peer = Some(peer);
                    assert_eq!(peer.port(), announced_client_addr.port());
                    assert!(read > 10);
                    let target = SocketAddr::new(
                        std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                            packet[4], packet[5], packet[6], packet[7],
                        )),
                        u16::from_be_bytes([packet[8], packet[9]]),
                    );
                    assert_eq!(target, server_addr);
                    let payload = &packet[10..read];
                    relay.send_to(payload, target).unwrap();
                } else {
                    let mut framed = vec![0x00, 0x00, 0x00, 0x01];
                    if let SocketAddr::V4(source) = peer {
                        framed.extend_from_slice(&source.ip().octets());
                        framed.extend_from_slice(&source.port().to_be_bytes());
                    } else {
                        panic!("expected ipv4 source addr");
                    }
                    framed.extend_from_slice(&packet[..read]);
                    relay.send_to(&framed, client_peer.unwrap()).unwrap();
                }
            }
        });

        let stream = std::net::TcpStream::connect(outer_socks_addr).unwrap();
        let target = crate::TransportTarget::new("8.8.8.8", 443);
        let mut stream =
            connect_stream_with_socks5_stream(&options, Box::new(stream), None, &target).unwrap();
        stream.write_all(b"ping").unwrap();
        let mut reply = [0_u8; 4];
        let read = stream.read(&mut reply).unwrap();
        assert_eq!(read, 4);
        assert_eq!(&reply, b"pong");

        drop(stream);
        server.shutdown();
        outer_worker.join().unwrap();
    }

    fn relay_tcp_bidirectional(downstream: TcpStream, upstream: TcpStream) {
        let mut downstream_read = downstream.try_clone().unwrap();
        let mut downstream_write = downstream;
        let mut upstream_read = upstream.try_clone().unwrap();
        let mut upstream_write = upstream;
        let a = std::thread::spawn(move || {
            let _ = std::io::copy(&mut downstream_read, &mut upstream_write);
        });
        let b = std::thread::spawn(move || {
            let _ = std::io::copy(&mut upstream_read, &mut downstream_write);
        });
        let _ = a.join();
        let _ = b.join();
    }
}
