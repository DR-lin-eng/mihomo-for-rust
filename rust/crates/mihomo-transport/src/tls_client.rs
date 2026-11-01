use std::io::{self, Cursor, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::{Mutex, OnceLock};

use mihomo_core::{BoxedTcpStream, TcpStream};
use rustls::client::{ServerCertVerified, ServerCertVerifier, WebPkiVerifier};
use rustls::{
    Certificate, CertificateError, ClientConfig, ClientConnection, Error as RustlsError,
    OwnedTrustAnchor, RootCertStore, ServerName, SupportedCipherSuite,
};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::client::TlsStream as TokioTlsStream;
use tokio_rustls::TlsConnector;
use x509_parser::parse_x509_certificate;

use crate::{TlsOptions, TransportError, TransportTarget};

pub(crate) fn wrap_stream(
    stream: BoxedTcpStream,
    proxy: &TransportTarget,
    tls: &TlsOptions,
    alpn: &[String],
) -> Result<BoxedTcpStream, TransportError> {
    Ok(Box::new(wrap_client_stream(
        stream, proxy, tls, alpn, false,
    )?))
}

pub(crate) fn wrap_stream_for_vision(
    stream: BoxedTcpStream,
    proxy: &TransportTarget,
    tls: &TlsOptions,
    alpn: &[String],
) -> Result<TlsClientStream, TransportError> {
    wrap_client_stream(stream, proxy, tls, alpn, true)
}

fn wrap_client_stream(
    stream: BoxedTcpStream,
    proxy: &TransportTarget,
    tls: &TlsOptions,
    alpn: &[String],
    vision: bool,
) -> Result<TlsClientStream, TransportError> {
    let config = build_client_config(proxy, tls, alpn)?;
    let server_name = server_name(proxy, tls)?;
    let connection =
        ClientConnection::new(config, server_name).map_err(|err| TransportError::InvalidPlan(err.to_string()))?;
    let mut stream = TlsClientStream {
        core: Arc::new(TlsClientCore {
            conn: Mutex::new(connection),
            write_direct: AtomicBool::new(false),
            vision,
        }),
        socket: stream,
        record: TlsRecordBuffer::default(),
        read_direct: false,
    };
    stream.complete_handshake().map_err(TransportError::from)?;
    Ok(stream)
}

pub(crate) async fn wrap_tokio_stream<S>(
    stream: S,
    proxy: &TransportTarget,
    tls: &TlsOptions,
    alpn: &[String],
) -> Result<TokioTlsStream<S>, TransportError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let config = build_client_config(proxy, tls, alpn)?;
    let server_name = server_name(proxy, tls)?;
    let connector = TlsConnector::from(config);
    connector
        .connect(server_name, stream)
        .await
        .map_err(TransportError::from)
}

fn build_client_config(
    proxy: &TransportTarget,
    tls: &TlsOptions,
    alpn: &[String],
) -> Result<Arc<ClientConfig>, TransportError> {
    let verifier = build_server_cert_verifier(proxy, tls)?;

    let mut config = if tls.skip_cert_verify {
        if tls.certificate.trim().is_empty() && tls.private_key.trim().is_empty() {
            ClientConfig::builder()
                .with_safe_defaults()
                .with_custom_certificate_verifier(verifier.clone())
                .with_no_client_auth()
        } else {
            let certs = parse_certificates(&tls.certificate)?;
            let key = parse_private_key(&tls.private_key)?;
            ClientConfig::builder()
                .with_safe_defaults()
                .with_custom_certificate_verifier(verifier.clone())
                .with_client_auth_cert(certs, key)
                .map_err(|err| TransportError::InvalidPlan(err.to_string()))?
        }
    } else if tls.certificate.trim().is_empty() && tls.private_key.trim().is_empty() {
        ClientConfig::builder()
            .with_safe_defaults()
            .with_custom_certificate_verifier(verifier.clone())
            .with_no_client_auth()
    } else {
        let certs = parse_certificates(&tls.certificate)?;
        let key = parse_private_key(&tls.private_key)?;
        ClientConfig::builder()
            .with_safe_defaults()
            .with_custom_certificate_verifier(verifier)
            .with_client_auth_cert(certs, key)
            .map_err(|err| TransportError::InvalidPlan(err.to_string()))?
    };

    config.alpn_protocols = alpn.iter().map(|value| value.as_bytes().to_vec()).collect();
    Ok(Arc::new(config))
}

fn build_server_cert_verifier(
    _proxy: &TransportTarget,
    tls: &TlsOptions,
) -> Result<Arc<dyn ServerCertVerifier>, TransportError> {
    let base: Arc<dyn ServerCertVerifier> = if tls.skip_cert_verify {
        Arc::new(NoCertificateVerification)
    } else {
        Arc::new(WebPkiVerifier::new(system_root_store()?, None))
    };
    if tls.fingerprint.trim().is_empty() {
        return Ok(base);
    }
    Ok(Arc::new(FingerprintVerifier::new(base, &tls.fingerprint)?))
}

pub(crate) fn system_root_store() -> Result<RootCertStore, TransportError> {
    let mut roots = RootCertStore::empty();
    if let Ok(native_certs) = rustls_native_certs::load_native_certs() {
        for cert in native_certs {
            roots
                .add(&Certificate(cert.0))
                .map_err(|err| TransportError::InvalidPlan(err.to_string()))?;
        }
    }
    if roots.is_empty() {
        roots.add_trust_anchors(
            webpki_roots::TLS_SERVER_ROOTS
                .iter()
                .map(|anchor| {
                    OwnedTrustAnchor::from_subject_spki_name_constraints(
                        anchor.subject,
                        anchor.spki,
                        anchor.name_constraints,
                    )
                }),
        );
    }
    for cert in extra_root_certificates()
        .lock()
        .expect("extra root certificate registry poisoned")
        .iter()
    {
        roots
            .add(cert)
            .map_err(|err| TransportError::InvalidPlan(err.to_string()))?;
    }
    Ok(roots)
}

fn extra_root_certificates() -> &'static Mutex<Vec<Certificate>> {
    static EXTRA_ROOT_CERTIFICATES: OnceLock<Mutex<Vec<Certificate>>> = OnceLock::new();
    EXTRA_ROOT_CERTIFICATES.get_or_init(|| Mutex::new(Vec::new()))
}

pub(crate) fn register_test_root_certificate(pem: &str) -> Result<(), TransportError> {
    let certs = parse_certificates(pem)?;
    extra_root_certificates()
        .lock()
        .expect("extra root certificate registry poisoned")
        .extend(certs);
    Ok(())
}

fn parse_certificates(pem: &str) -> Result<Vec<Certificate>, TransportError> {
    if pem.trim().is_empty() {
        return Err(TransportError::InvalidPlan(
            "tls certificate is required when private key is set".to_owned(),
        ));
    }
    let mut reader = io::Cursor::new(pem.as_bytes());
    let certs = rustls_pemfile::certs(&mut reader)
        .map_err(|err| TransportError::InvalidPlan(err.to_string()))?
        .into_iter()
        .map(Certificate)
        .collect::<Vec<_>>();
    if certs.is_empty() {
        return Err(TransportError::InvalidPlan(
            "failed to parse tls certificate chain".to_owned(),
        ));
    }
    Ok(certs)
}

fn parse_private_key(pem: &str) -> Result<rustls::PrivateKey, TransportError> {
    if pem.trim().is_empty() {
        return Err(TransportError::InvalidPlan(
            "tls private key is required when certificate is set".to_owned(),
        ));
    }
    let mut reader = io::Cursor::new(pem.as_bytes());
    if let Some(key) = rustls_pemfile::pkcs8_private_keys(&mut reader)
        .map_err(|err| TransportError::InvalidPlan(err.to_string()))?
        .into_iter()
        .next()
    {
        return Ok(rustls::PrivateKey(key));
    }

    let mut reader = io::Cursor::new(pem.as_bytes());
    if let Some(key) = rustls_pemfile::rsa_private_keys(&mut reader)
        .map_err(|err| TransportError::InvalidPlan(err.to_string()))?
        .into_iter()
        .next()
    {
        return Ok(rustls::PrivateKey(key));
    }

    Err(TransportError::InvalidPlan(
        "failed to parse tls private key".to_owned(),
    ))
}

fn server_name(proxy: &TransportTarget, tls: &TlsOptions) -> Result<ServerName, TransportError> {
    let name = if tls.sni.trim().is_empty() {
        proxy.host.as_str()
    } else {
        tls.sni.as_str()
    };
    ServerName::try_from(name)
        .map_err(|_| TransportError::InvalidPlan(format!("invalid tls server name: {name}")))
}

#[derive(Debug)]
struct NoCertificateVerification;

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &Certificate,
        _intermediates: &[Certificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
}

#[derive(Debug)]
struct FingerprintVerifier {
    inner: Arc<dyn ServerCertVerifier>,
    fingerprint: [u8; 32],
}

impl FingerprintVerifier {
    fn new(
        inner: Arc<dyn ServerCertVerifier>,
        fingerprint: &str,
    ) -> Result<Self, TransportError> {
        Ok(Self {
            inner,
            fingerprint: normalize_fingerprint(fingerprint)?,
        })
    }
}

impl ServerCertVerifier for FingerprintVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &Certificate,
        intermediates: &[Certificate],
        server_name: &ServerName,
        scts: &mut dyn Iterator<Item = &[u8]>,
        ocsp_response: &[u8],
        now: std::time::SystemTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        self.inner
            .verify_server_cert(end_entity, intermediates, server_name, scts, ocsp_response, now)?;

        let matches = std::iter::once(end_entity)
            .chain(intermediates.iter())
            .any(|cert| {
                let cert_hash = Sha256::digest(&cert.0);
                if cert_hash.as_slice() == self.fingerprint {
                    return true;
                }
                parse_x509_certificate(&cert.0)
                    .ok()
                    .map(|(_, parsed)| Sha256::digest(parsed.public_key().raw))
                    .is_some_and(|spki_hash| spki_hash.as_slice() == self.fingerprint)
            });
        if matches {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(RustlsError::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ))
        }
    }
}

fn normalize_fingerprint(fingerprint: &str) -> Result<[u8; 32], TransportError> {
    let normalized = fingerprint.trim().replace(':', "");
    match normalized.as_str() {
        "chrome" | "firefox" | "safari" | "ios" | "android" | "edge" | "360" | "qq"
        | "random" | "randomized" => {
            return Err(TransportError::InvalidPlan(
                "`fingerprint` is used for TLS certificate pinning. If you need to specify the browser fingerprint, use `client-fingerprint`".to_owned(),
            ));
        }
        _ => {}
    }
    let bytes = hex::decode(&normalized)
        .map_err(|err| TransportError::InvalidPlan(format!("fingerprint string decode error: {err}")))?;
    if bytes.len() != 32 {
        return Err(TransportError::InvalidPlan(
            "fingerprint string length error,need sha256 fingerprint".to_owned(),
        ));
    }
    let mut array = [0_u8; 32];
    array.copy_from_slice(&bytes);
    Ok(array)
}

struct TlsClientCore {
    conn: Mutex<ClientConnection>,
    write_direct: AtomicBool,
    vision: bool,
}

pub(crate) struct TlsClientStream {
    core: Arc<TlsClientCore>,
    socket: BoxedTcpStream,
    record: TlsRecordBuffer,
    read_direct: bool,
}

/// Keep raw Vision records following the final encrypted frame out of rustls.
/// The partial record survives socket timeouts and WouldBlock errors.
#[derive(Clone, Default)]
pub(crate) struct TlsRecordBuffer {
    bytes: Vec<u8>,
    needed: usize,
}

impl TlsRecordBuffer {
    pub(crate) fn is_empty(&self) -> bool { self.bytes.is_empty() }

    pub(crate) fn read_from(&mut self, socket: &mut dyn Read) -> io::Result<Option<Vec<u8>>> {
        if self.needed == 0 {
            self.needed = 5;
        }
        loop {
            while self.bytes.len() < self.needed {
                let mut part = [0_u8; 4096];
                let need = part.len().min(self.needed - self.bytes.len());
                match socket.read(&mut part[..need]) {
                    Ok(0) if self.bytes.is_empty() => return Ok(None),
                    Ok(0) => {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "truncated TLS record",
                        ))
                    }
                    Ok(n) => self.bytes.extend_from_slice(&part[..n]),
                    Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                    Err(err) => return Err(err),
                }
            }
            if self.needed == 5 {
                let length = u16::from_be_bytes([self.bytes[3], self.bytes[4]]) as usize;
                if length > 16 * 1024 + 256 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "oversized TLS record",
                    ));
                }
                self.needed += length;
                if length != 0 {
                    continue;
                }
            }
            self.needed = 0;
            return Ok(Some(std::mem::take(&mut self.bytes)));
        }
    }
}

struct TlsClientWriteClone {
    core: Arc<TlsClientCore>,
    socket: BoxedTcpStream,
}

impl TlsClientStream {
    fn complete_handshake(&mut self) -> io::Result<()> {
        let mut conn = self.core.conn.lock().unwrap();
        while conn.is_handshaking() {
            conn.complete_io(&mut self.socket)?;
        }
        Ok(())
    }

    fn write_pending_tls(conn: &mut ClientConnection, socket: &mut dyn Write) -> io::Result<()> {
        while conn.wants_write() {
            conn.write_tls(socket)?;
        }
        Ok(())
    }

    pub(crate) fn negotiated_tls13(&self) -> bool {
        self.core
            .conn
            .lock()
            .unwrap()
            .protocol_version()
            .is_some_and(|version| version == rustls::ProtocolVersion::TLSv1_3)
    }

    pub(crate) fn negotiated_cipher_suite(&self) -> Option<SupportedCipherSuite> {
        self.core.conn.lock().unwrap().negotiated_cipher_suite()
    }

}

impl Read for TlsClientStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.read_direct {
            let mut conn = self.core.conn.lock().unwrap();
            match conn.reader().read(buf) {
                Ok(n) if n > 0 => return Ok(n),
                Ok(_) => {}
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
                Err(err) => return Err(err),
            }
            drop(conn);
            return self.socket.read(buf);
        }
        let mut ciphertext = vec![0_u8; 16 * 1024];
        loop {
            {
                let mut conn = self.core.conn.lock().unwrap();
                match conn.reader().read(buf) {
                    Ok(read) if read != 0 => return Ok(read),
                    Ok(_) => {
                        if !self.core.write_direct.load(Ordering::Acquire) {
                            Self::write_pending_tls(&mut conn, &mut *self.socket)?;
                        }
                        // rustls returns EOF only after buffered plaintext has
                        // drained. A close_notify may share a read with data.
                        return Ok(0);
                    }
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                        if !self.core.write_direct.load(Ordering::Acquire) {
                            Self::write_pending_tls(&mut conn, &mut *self.socket)?;
                        }
                    }
                    Err(err) => return Err(err),
                }
            }

            let read = if self.core.vision {
                match self.record.read_from(&mut *self.socket)? {
                    Some(record) => {
                        ciphertext = record;
                        ciphertext.len()
                    }
                    None => 0,
                }
            } else {
                self.socket.read(&mut ciphertext)?
            };
            if read == 0 {
                let mut conn = self.core.conn.lock().unwrap();
                if !self.core.write_direct.load(Ordering::Acquire) {
                    Self::write_pending_tls(&mut conn, &mut *self.socket)?;
                }
                return match conn.reader().read(buf) {
                    Ok(read) => Ok(read),
                    Err(err)
                        if matches!(
                            err.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::UnexpectedEof
                        ) =>
                    {
                        Ok(0)
                    }
                    Err(err) => Err(err),
                };
            }

            let mut conn = self.core.conn.lock().unwrap();
            let mut cursor = Cursor::new(&ciphertext[..read]);
            while cursor.position() < read as u64 {
                if conn.read_tls(&mut cursor)? == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "TLS decoder made no progress",
                    ));
                }
                conn.process_new_packets()
                    .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
            }
            if !self.core.write_direct.load(Ordering::Acquire) {
                Self::write_pending_tls(&mut conn, &mut *self.socket)?;
            }
        }
    }
}

impl Write for TlsClientStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.core.write_direct.load(Ordering::Acquire) {
            return self.socket.write(buf);
        }
        let mut conn = self.core.conn.lock().unwrap();
        let written = conn.writer().write(buf)?;
        Self::write_pending_tls(&mut conn, &mut *self.socket)?;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.core.write_direct.load(Ordering::Acquire) {
            return self.socket.flush();
        }
        let mut conn = self.core.conn.lock().unwrap();
        Self::write_pending_tls(&mut conn, &mut *self.socket)?;
        self.socket.flush()
    }
}

impl TcpStream for TlsClientStream {
    fn tcp_stats(&self)->Option<mihomo_core::TcpStats>{self.socket.tcp_stats()}
    fn set_timeouts(&self,read:Option<std::time::Duration>,write:Option<std::time::Duration>)->io::Result<()>{self.socket.set_timeouts(read,write)}

    fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
        Ok(Box::new(TlsClientWriteClone {
            core: Arc::clone(&self.core),
            socket: self.socket.try_clone_box()?,
        }))
    }

    fn supports_tls_passthrough(&self) -> bool {
        self.core.vision
    }

    fn start_tls_passthrough_read(&mut self) -> io::Result<()> {
        if !self.core.vision || !self.record.bytes.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "TLS passthrough requires a record boundary",
            ));
        }
        self.read_direct = true;
        Ok(())
    }

    fn start_tls_passthrough_write(&mut self) -> io::Result<()> {
        if !self.core.vision {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "TLS passthrough was not enabled",
            ));
        }
        let mut conn = self.core.conn.lock().unwrap();
        TlsClientStream::write_pending_tls(&mut conn, &mut *self.socket)?;
        self.socket.flush()?;
        self.core.write_direct.store(true, Ordering::Release);
        Ok(())
    }

    fn shutdown_write(&mut self) -> io::Result<()> {
        if self.core.write_direct.load(Ordering::Acquire) {
            return self.socket.shutdown_write();
        }
        let mut conn = self.core.conn.lock().unwrap();
        conn.send_close_notify();
        Self::write_pending_tls(&mut conn, &mut *self.socket)?;
        self.socket.flush()
    }

    fn shutdown_all(&mut self) -> io::Result<()> {
        self.shutdown_write()?;
        self.socket.shutdown_all()
    }
}

impl Read for TlsClientWriteClone {
    fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "tls client write clone is write-only",
        ))
    }
}

impl Write for TlsClientWriteClone {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.core.write_direct.load(Ordering::Acquire) {
            return self.socket.write(buf);
        }
        let mut conn = self.core.conn.lock().unwrap();
        let written = conn.writer().write(buf)?;
        TlsClientStream::write_pending_tls(&mut conn, &mut *self.socket)?;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.core.write_direct.load(Ordering::Acquire) {
            return self.socket.flush();
        }
        let mut conn = self.core.conn.lock().unwrap();
        TlsClientStream::write_pending_tls(&mut conn, &mut *self.socket)?;
        self.socket.flush()
    }
}

impl TcpStream for TlsClientWriteClone {
    fn tcp_stats(&self)->Option<mihomo_core::TcpStats>{self.socket.tcp_stats()}
    fn set_timeouts(&self,read:Option<std::time::Duration>,write:Option<std::time::Duration>)->io::Result<()>{self.socket.set_timeouts(read,write)}

    fn supports_tls_passthrough(&self) -> bool {
        self.core.vision
    }

    fn start_tls_passthrough_write(&mut self) -> io::Result<()> {
        if !self.core.vision {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "TLS passthrough was not enabled",
            ));
        }
        let mut conn = self.core.conn.lock().unwrap();
        TlsClientStream::write_pending_tls(&mut conn, &mut *self.socket)?;
        self.socket.flush()?;
        self.core.write_direct.store(true, Ordering::Release);
        Ok(())
    }

    fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "tls client write clone does not support cloning",
        ))
    }

    fn shutdown_write(&mut self) -> io::Result<()> {
        if self.core.write_direct.load(Ordering::Acquire) {
            return self.socket.shutdown_write();
        }
        let mut conn = self.core.conn.lock().unwrap();
        conn.send_close_notify();
        TlsClientStream::write_pending_tls(&mut conn, &mut *self.socket)?;
        self.socket.flush()
    }

    fn shutdown_all(&mut self) -> io::Result<()> {
        self.shutdown_write()?;
        self.socket.shutdown_all()
    }
}

#[cfg(test)]
mod tests;
