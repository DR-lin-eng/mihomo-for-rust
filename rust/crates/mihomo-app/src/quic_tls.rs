use std::io;
use std::sync::Arc;

use quinn::rustls::ServerConfig;
use rustls023::crypto::{verify_tls12_signature, verify_tls13_signature};

use crate::listener_service_support::{normalize_client_auth_type, resolve_pem_source, ClientAuthMode};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct QuicServerTlsOptions {
    pub certificate: String,
    pub private_key: String,
    pub alpn: Vec<String>,
    pub client_auth_type: String,
    pub client_auth_cert: String,
}

pub(crate) fn build_quic_server_tls_config(
    options: &QuicServerTlsOptions,
) -> io::Result<ServerConfig> {
    let cert_pem = resolve_pem_source(&options.certificate)?;
    let key_pem = resolve_pem_source(&options.private_key)?;
    let certs = parse_certificates(&cert_pem)?;
    let key = parse_private_key(&key_pem)?;

    let client_auth_mode = normalize_client_auth_type(&options.client_auth_type).map_err(|other| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsupported quic listener client-auth-type: {other}"),
        )
    })?;
    let require_client_auth = client_auth_mode.is_some();
    if require_client_auth && options.client_auth_cert.trim().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "quic listener client-auth-cert is required when client-auth-type is set",
        ));
    }
    if !require_client_auth && !options.client_auth_cert.trim().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "quic listener client-auth-type is required when client-auth-cert is set",
        ));
    }

    let mut server_crypto = if require_client_auth {
        let client_auth_pem = resolve_pem_source(&options.client_auth_cert)?;
        let client_auth_certs = parse_certificates(&client_auth_pem)?;
        let mut roots = quinn::rustls::RootCertStore::empty();
        for cert in client_auth_certs {
            roots
                .add(cert.clone())
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;
        }
        match client_auth_mode.expect("checked above") {
            ClientAuthMode::RequireAny => {
                let supported_algs =
                    quinn::rustls::crypto::aws_lc_rs::default_provider()
                        .signature_verification_algorithms;
                let root_subjects = roots.subjects();
                #[derive(Debug)]
                struct RequireAnyClientCertVerifier {
                    root_subjects: Vec<rustls023::DistinguishedName>,
                    supported_algs: rustls023::crypto::WebPkiSupportedAlgorithms,
                }
                impl rustls023::server::danger::ClientCertVerifier for RequireAnyClientCertVerifier {
                    fn offer_client_auth(&self) -> bool {
                        true
                    }

                    fn client_auth_mandatory(&self) -> bool {
                        true
                    }

                    fn root_hint_subjects(&self) -> &[rustls023::DistinguishedName] {
                        &self.root_subjects
                    }

                    fn verify_client_cert(
                        &self,
                        _end_entity: &rustls023::pki_types::CertificateDer<'_>,
                        _intermediates: &[rustls023::pki_types::CertificateDer<'_>],
                        _now: rustls023::pki_types::UnixTime,
                    ) -> Result<rustls023::server::danger::ClientCertVerified, rustls023::Error> {
                        Ok(rustls023::server::danger::ClientCertVerified::assertion())
                    }

                    fn verify_tls12_signature(
                        &self,
                        message: &[u8],
                        cert: &rustls023::pki_types::CertificateDer<'_>,
                        dss: &rustls023::DigitallySignedStruct,
                    ) -> Result<rustls023::client::danger::HandshakeSignatureValid, rustls023::Error> {
                        verify_tls12_signature(message, cert, dss, &self.supported_algs)
                    }

                    fn verify_tls13_signature(
                        &self,
                        message: &[u8],
                        cert: &rustls023::pki_types::CertificateDer<'_>,
                        dss: &rustls023::DigitallySignedStruct,
                    ) -> Result<rustls023::client::danger::HandshakeSignatureValid, rustls023::Error> {
                        verify_tls13_signature(message, cert, dss, &self.supported_algs)
                    }

                    fn supported_verify_schemes(&self) -> Vec<rustls023::SignatureScheme> {
                        self.supported_algs.supported_schemes()
                    }
                }
                let verifier = Arc::new(RequireAnyClientCertVerifier {
                    root_subjects,
                    supported_algs,
                });
                quinn::rustls::ServerConfig::builder()
                    .with_client_cert_verifier(verifier)
                    .with_single_cert(certs, key)
                    .map_err(io::Error::other)?
            }
            ClientAuthMode::Request => {
                let supported_algs =
                    quinn::rustls::crypto::aws_lc_rs::default_provider()
                        .signature_verification_algorithms;
                let root_subjects = roots.subjects();
                #[derive(Debug)]
                struct RequestAnyClientCertVerifier {
                    root_subjects: Vec<rustls023::DistinguishedName>,
                    supported_algs: rustls023::crypto::WebPkiSupportedAlgorithms,
                }
                impl rustls023::server::danger::ClientCertVerifier for RequestAnyClientCertVerifier {
                    fn offer_client_auth(&self) -> bool {
                        true
                    }

                    fn client_auth_mandatory(&self) -> bool {
                        false
                    }

                    fn root_hint_subjects(&self) -> &[rustls023::DistinguishedName] {
                        &self.root_subjects
                    }

                    fn verify_client_cert(
                        &self,
                        _end_entity: &rustls023::pki_types::CertificateDer<'_>,
                        _intermediates: &[rustls023::pki_types::CertificateDer<'_>],
                        _now: rustls023::pki_types::UnixTime,
                    ) -> Result<rustls023::server::danger::ClientCertVerified, rustls023::Error> {
                        Ok(rustls023::server::danger::ClientCertVerified::assertion())
                    }

                    fn verify_tls12_signature(
                        &self,
                        message: &[u8],
                        cert: &rustls023::pki_types::CertificateDer<'_>,
                        dss: &rustls023::DigitallySignedStruct,
                    ) -> Result<rustls023::client::danger::HandshakeSignatureValid, rustls023::Error> {
                        verify_tls12_signature(message, cert, dss, &self.supported_algs)
                    }

                    fn verify_tls13_signature(
                        &self,
                        message: &[u8],
                        cert: &rustls023::pki_types::CertificateDer<'_>,
                        dss: &rustls023::DigitallySignedStruct,
                    ) -> Result<rustls023::client::danger::HandshakeSignatureValid, rustls023::Error> {
                        verify_tls13_signature(message, cert, dss, &self.supported_algs)
                    }

                    fn supported_verify_schemes(&self) -> Vec<rustls023::SignatureScheme> {
                        self.supported_algs.supported_schemes()
                    }
                }
                let verifier = Arc::new(RequestAnyClientCertVerifier {
                    root_subjects,
                    supported_algs,
                });
                quinn::rustls::ServerConfig::builder()
                    .with_client_cert_verifier(verifier)
                    .with_single_cert(certs, key)
                    .map_err(io::Error::other)?
            }
            ClientAuthMode::RequireAndVerify => {
                let verifier = quinn::rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
                    .build()
                    .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;
                quinn::rustls::ServerConfig::builder()
                    .with_client_cert_verifier(verifier)
                    .with_single_cert(certs, key)
                    .map_err(io::Error::other)?
            }
            ClientAuthMode::VerifyIfGiven => {
                #[derive(Debug)]
                struct VerifyIfGivenClientCertVerifier {
                    delegate: Arc<dyn rustls023::server::danger::ClientCertVerifier>,
                    root_subjects: Vec<rustls023::DistinguishedName>,
                }

                impl rustls023::server::danger::ClientCertVerifier
                    for VerifyIfGivenClientCertVerifier
                {
                    fn offer_client_auth(&self) -> bool {
                        true
                    }

                    fn client_auth_mandatory(&self) -> bool {
                        false
                    }

                    fn root_hint_subjects(&self) -> &[rustls023::DistinguishedName] {
                        &self.root_subjects
                    }

                    fn verify_client_cert(
                        &self,
                        end_entity: &rustls023::pki_types::CertificateDer<'_>,
                        intermediates: &[rustls023::pki_types::CertificateDer<'_>],
                        now: rustls023::pki_types::UnixTime,
                    ) -> Result<
                        rustls023::server::danger::ClientCertVerified,
                        rustls023::Error,
                    > {
                        self.delegate.verify_client_cert(end_entity, intermediates, now)
                    }

                    fn verify_tls12_signature(
                        &self,
                        message: &[u8],
                        cert: &rustls023::pki_types::CertificateDer<'_>,
                        dss: &rustls023::DigitallySignedStruct,
                    ) -> Result<
                        rustls023::client::danger::HandshakeSignatureValid,
                        rustls023::Error,
                    > {
                        self.delegate.verify_tls12_signature(message, cert, dss)
                    }

                    fn verify_tls13_signature(
                        &self,
                        message: &[u8],
                        cert: &rustls023::pki_types::CertificateDer<'_>,
                        dss: &rustls023::DigitallySignedStruct,
                    ) -> Result<
                        rustls023::client::danger::HandshakeSignatureValid,
                        rustls023::Error,
                    > {
                        self.delegate.verify_tls13_signature(message, cert, dss)
                    }

                    fn supported_verify_schemes(&self) -> Vec<rustls023::SignatureScheme> {
                        self.delegate.supported_verify_schemes()
                    }
                }

                let delegate =
                    quinn::rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
                        .build()
                        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;
                let verifier = Arc::new(VerifyIfGivenClientCertVerifier {
                    root_subjects: delegate.root_hint_subjects().to_vec(),
                    delegate,
                });
                quinn::rustls::ServerConfig::builder()
                    .with_client_cert_verifier(verifier)
                    .with_single_cert(certs, key)
                    .map_err(io::Error::other)?
            }
        }
    } else {
        quinn::rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(io::Error::other)?
    };
    server_crypto.alpn_protocols = options
        .alpn
        .iter()
        .map(|entry| entry.as_bytes().to_vec())
        .collect();
    Ok(server_crypto)
}

fn parse_certificates(
    cert_pem: &str,
) -> io::Result<Vec<quinn::rustls::pki_types::CertificateDer<'static>>> {
    let mut reader = io::Cursor::new(cert_pem.as_bytes());
    let certs = rustls_pemfile::certs(&mut reader)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;
    if certs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "failed to parse quic tls certificate",
        ));
    }
    Ok(certs
        .into_iter()
        .map(quinn::rustls::pki_types::CertificateDer::from)
        .collect())
}

fn parse_private_key(
    key_pem: &str,
) -> io::Result<quinn::rustls::pki_types::PrivateKeyDer<'static>> {
    let mut reader = io::Cursor::new(key_pem.as_bytes());
    if let Some(key) = rustls_pemfile::pkcs8_private_keys(&mut reader)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?
        .into_iter()
        .next()
    {
        return Ok(quinn::rustls::pki_types::PrivatePkcs8KeyDer::from(key).into());
    }
    let mut reader = io::Cursor::new(key_pem.as_bytes());
    let Some(key) = rustls_pemfile::rsa_private_keys(&mut reader)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?
        .into_iter()
        .next()
    else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "failed to parse quic tls private key",
        ));
    };
    Ok(quinn::rustls::pki_types::PrivatePkcs1KeyDer::from(key).into())
}
