use std::sync::Arc;

use tokio_rustls::TlsConnector;

pub fn connector() -> Result<TlsConnector, rustls::Error> {
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(rustls::RootCertStore::from_iter(
        webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
    ))
    .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(config)))
}
