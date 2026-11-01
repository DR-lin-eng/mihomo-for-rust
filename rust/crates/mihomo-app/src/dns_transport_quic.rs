fn quic_root_store() -> Result<RootCertStore023, DnsError> {
    mihomo_dns::quic_root_store_for_tests_and_runtime()
}

fn build_quic_client_config() -> Result<Arc<RustlsClientConfig>, DnsError> {
    let mut crypto = RustlsClientConfig::builder()
        .with_root_certificates(quic_root_store()?)
        .with_no_client_auth();
    crypto.alpn_protocols = vec![b"doq".to_vec()];
    Ok(Arc::new(crypto))
}

fn ensure_quic_crypto_provider() {
    static PROVIDER: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    let _ = PROVIDER.get_or_init(|| {
        let _ = aws_lc_rs::default_provider().install_default();
    });
}

async fn connect_quic_endpoint(
    endpoint: &QuinnEndpoint,
    remote_addrs: &[SocketAddr],
    server_name: &str,
) -> io::Result<quinn::Connection> {
    let mut last_err = None;
    for remote_addr in remote_addrs {
        match endpoint.connect(*remote_addr, server_name) {
            Ok(connecting) => match tokio::time::timeout(Duration::from_secs(3), connecting).await {
                Ok(Ok(connection)) => return Ok(connection),
                Ok(Err(err)) => last_err = Some(io::Error::other(err.to_string())),
                Err(_) => {
                    last_err = Some(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("doq connect to {remote_addr} timed out"),
                    ))
                }
            },
            Err(err) => last_err = Some(io::Error::other(err.to_string())),
        }
    }
    Err(last_err.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "doq server connect failed for all resolved addresses",
        )
    }))
}
