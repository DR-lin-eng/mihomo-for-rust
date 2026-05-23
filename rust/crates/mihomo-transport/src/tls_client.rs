use std::io::{self, Read, Write};
use std::sync::Arc;
use std::sync::{Mutex, OnceLock};

use mihomo_core::{BoxedTcpStream, TcpStream};
use rustls::client::{ServerCertVerified, ServerCertVerifier, WebPkiVerifier};
use rustls::{Certificate, CertificateError, ClientConfig, ClientConnection, Error as RustlsError, OwnedTrustAnchor, RootCertStore, ServerName, StreamOwned};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::client::TlsStream as TokioTlsStream;
use tokio_rustls::TlsConnector;

use crate::{TlsOptions, TransportError, TransportTarget};

pub(crate) fn wrap_stream(
    stream: BoxedTcpStream,
    proxy: &TransportTarget,
    tls: &TlsOptions,
    alpn: &[String],
) -> Result<BoxedTcpStream, TransportError> {
    let config = build_client_config(proxy, tls, alpn)?;
    let server_name = server_name(proxy, tls)?;
    let connection =
        ClientConnection::new(config, server_name).map_err(|err| TransportError::InvalidPlan(err.to_string()))?;
    let mut stream = TlsClientStream {
        inner: StreamOwned::new(connection, stream),
    };
    stream
        .inner
        .flush()
        .map_err(TransportError::from)?;
    while stream.inner.conn.is_handshaking() {
        stream
            .inner
            .conn
            .complete_io(&mut stream.inner.sock)
            .map_err(TransportError::from)?;
    }
    Ok(Box::new(stream))
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

fn system_root_store() -> Result<RootCertStore, TransportError> {
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
                let hash = Sha256::digest(&cert.0);
                hash.as_slice() == self.fingerprint
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

struct TlsClientStream {
    inner: StreamOwned<ClientConnection, BoxedTcpStream>,
}

impl Read for TlsClientStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl Write for TlsClientStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl TcpStream for TlsClientStream {
    fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "tls client stream does not support cloning",
        ))
    }

    fn shutdown_write(&mut self) -> io::Result<()> {
        self.inner.conn.send_close_notify();
        self.inner.flush()
    }

    fn shutdown_all(&mut self) -> io::Result<()> {
        self.inner.conn.send_close_notify();
        self.inner.flush()?;
        self.inner.sock.shutdown_all()
    }
}
