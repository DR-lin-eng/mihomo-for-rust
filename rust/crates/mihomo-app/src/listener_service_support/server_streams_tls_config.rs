fn parse_certificates(pem: &str) -> io::Result<Vec<Certificate>> {
    if pem.trim().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "tls certificate is required when private key is set",
        ));
    }
    let mut reader = io::Cursor::new(pem.as_bytes());
    let certs = rustls_pemfile::certs(&mut reader)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;
    if certs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "failed to parse tls certificate",
        ));
    }
    Ok(certs.into_iter().map(Certificate).collect())
}

fn parse_private_key(pem: &str) -> io::Result<PrivateKey> {
    if pem.trim().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "tls private key is required when certificate is set",
        ));
    }
    let mut reader = io::Cursor::new(pem.as_bytes());
    if let Some(key) = rustls_pemfile::pkcs8_private_keys(&mut reader)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?
        .into_iter()
        .next()
    {
        return Ok(PrivateKey(key));
    }

    let mut reader = io::Cursor::new(pem.as_bytes());
    if let Some(key) = rustls_pemfile::rsa_private_keys(&mut reader)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?
        .into_iter()
        .next()
    {
        return Ok(PrivateKey(key));
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "failed to parse tls private key",
    ))
}

pub(crate) fn build_server_tls_config(
    certificate: &str,
    private_key: &str,
    network: &str,
    client_auth_type: &str,
    client_auth_cert: &str,
    ech_key: &str,
    has_reality_config: bool,
) -> Result<ServerConfig, crate::listener_service::ListenerServiceError> {
    let client_auth_mode = super::normalize_client_auth_type(client_auth_type)
        .map_err(|other| {
            crate::listener_service::ListenerServiceError::Rule(format!(
                "unsupported vmess listener client-auth-type: {other}"
            ))
        })?;
    let require_client_auth = client_auth_mode.is_some();
    if require_client_auth && client_auth_cert.trim().is_empty() {
        return Err(crate::listener_service::ListenerServiceError::Rule(
            "vmess listener client-auth-cert is required when client-auth-type is set".to_owned(),
        ));
    }
    if !require_client_auth && !client_auth_cert.trim().is_empty() {
        return Err(crate::listener_service::ListenerServiceError::Rule(
            "vmess listener client-auth-type is required when client-auth-cert is set".to_owned(),
        ));
    }
    if !ech_key.trim().is_empty() {
        return Err(crate::listener_service::ListenerServiceError::Rule(
            "vmess listener inbound ech is not implemented yet".to_owned(),
        ));
    }
    if has_reality_config {
        return Err(crate::listener_service::ListenerServiceError::Rule(
            "vmess listener inbound reality is not implemented yet".to_owned(),
        ));
    }

    let cert_pem = super::resolve_pem_source(certificate)?;
    let key_pem = super::resolve_pem_source(private_key)?;
    let certs = parse_certificates(&cert_pem)?;
    let key = parse_private_key(&key_pem)?;
    let mut config = if require_client_auth {
        let client_auth_pem = super::resolve_pem_source(client_auth_cert)?;
        let client_auth_certs = parse_certificates(&client_auth_pem)?;
        let mut roots = rustls::RootCertStore::empty();
        for cert in client_auth_certs {
            roots
                .add(&cert)
                .map_err(|err| crate::listener_service::ListenerServiceError::Rule(err.to_string()))?;
        }
        let builder = ServerConfig::builder().with_safe_defaults();
        match client_auth_mode.expect("checked above") {
            super::ClientAuthMode::RequireAny => {
                struct AllowAnyClientCert {
                    subjects: Vec<rustls::DistinguishedName>,
                }

                impl rustls::server::ClientCertVerifier for AllowAnyClientCert {
                    fn offer_client_auth(&self) -> bool {
                        true
                    }

                    fn client_auth_mandatory(&self) -> bool {
                        true
                    }

                    fn client_auth_root_subjects(&self) -> &[rustls::DistinguishedName] {
                        &self.subjects
                    }

                    fn verify_client_cert(
                        &self,
                        _end_entity: &rustls::Certificate,
                        _intermediates: &[rustls::Certificate],
                        _now: std::time::SystemTime,
                    ) -> Result<rustls::server::ClientCertVerified, rustls::Error> {
                        Ok(rustls::server::ClientCertVerified::assertion())
                    }
                }

                let verifier = AllowAnyClientCert {
                    subjects: roots.roots.iter().map(|r| r.subject().clone()).collect(),
                };
                builder
                    .with_client_cert_verifier(Arc::new(verifier))
                    .with_single_cert(certs, key)
                    .map_err(|err| crate::listener_service::ListenerServiceError::Rule(err.to_string()))?
            }
            super::ClientAuthMode::RequireAndVerify => {
                let verifier = rustls::server::AllowAnyAuthenticatedClient::new(roots);
                builder
                    .with_client_cert_verifier(Arc::new(verifier))
                    .with_single_cert(certs, key)
                    .map_err(|err| crate::listener_service::ListenerServiceError::Rule(err.to_string()))?
            }
            super::ClientAuthMode::Request => {
                struct RequestAnyClientCert {
                    subjects: Vec<rustls::DistinguishedName>,
                }

                impl rustls::server::ClientCertVerifier for RequestAnyClientCert {
                    fn offer_client_auth(&self) -> bool {
                        true
                    }

                    fn client_auth_mandatory(&self) -> bool {
                        false
                    }

                    fn client_auth_root_subjects(&self) -> &[rustls::DistinguishedName] {
                        &self.subjects
                    }

                    fn verify_client_cert(
                        &self,
                        _end_entity: &rustls::Certificate,
                        _intermediates: &[rustls::Certificate],
                        _now: std::time::SystemTime,
                    ) -> Result<rustls::server::ClientCertVerified, rustls::Error> {
                        Ok(rustls::server::ClientCertVerified::assertion())
                    }
                }

                let verifier = RequestAnyClientCert {
                    subjects: roots.roots.iter().map(|r| r.subject().clone()).collect(),
                };
                builder
                    .with_client_cert_verifier(Arc::new(verifier))
                    .with_single_cert(certs, key)
                    .map_err(|err| crate::listener_service::ListenerServiceError::Rule(err.to_string()))?
            }
            super::ClientAuthMode::VerifyIfGiven => {
                let verifier = rustls::server::AllowAnyAnonymousOrAuthenticatedClient::new(roots);
                builder
                    .with_client_cert_verifier(Arc::new(verifier))
                    .with_single_cert(certs, key)
                    .map_err(|err| crate::listener_service::ListenerServiceError::Rule(err.to_string()))?
            }
        }
    } else {
        ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|err| crate::listener_service::ListenerServiceError::Rule(err.to_string()))?
    };
    if network == "grpc" {
        config.alpn_protocols = vec![b"h2".to_vec()];
    }
    Ok(config)
}
