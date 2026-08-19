// enclave/enclave_grpc/src/tls_config.rs
//
// Phase 11 (Prompt 206) — rustls mTLS server configuration.
//
// Loads the server identity (cert chain + private key) and a client CA
// bundle, then builds a rustls ServerConfig that REQUIRES a valid client
// certificate signed by that CA. Connections presenting no/invalid client
// certs are rejected during the handshake (tested in
// tests/test_mtls_handshake.rs, Prompt 215).
//
// NOTE: tonic 0.10's TLS support is client-side only, so the mTLS SERVER is
// built on tokio-rustls (0.24, the rustls 0.21 pairing) around the tonic
// service — see main_grpc.rs for the accept loop.
use rustls::{Certificate, PrivateKey, RootCertStore, ServerConfig};
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

/// Error type for TLS configuration failures.
#[derive(Debug)]
pub enum TlsConfigError {
    Io(std::io::Error),
    Rustls(rustls::Error),
    MissingCertChain,
    MissingPrivateKey,
    MissingClientCa,
}

impl std::fmt::Display for TlsConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TlsConfigError::Io(e) => write!(f, "io error: {e}"),
            TlsConfigError::Rustls(e) => write!(f, "rustls error: {e}"),
            TlsConfigError::MissingCertChain => write!(f, "no certificate found in cert file"),
            TlsConfigError::MissingPrivateKey => write!(f, "no private key found in key file"),
            TlsConfigError::MissingClientCa => write!(f, "no CA certificates found in client CA file"),
        }
    }
}

impl std::error::Error for TlsConfigError {}

impl From<std::io::Error> for TlsConfigError {
    fn from(e: std::io::Error) -> Self {
        TlsConfigError::Io(e)
    }
}

impl From<rustls::Error> for TlsConfigError {
    fn from(e: rustls::Error) -> Self {
        TlsConfigError::Rustls(e)
    }
}

fn read_pem_items<P: AsRef<Path>>(path: P) -> Result<Vec<rustls_pemfile::Item>, TlsConfigError> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    // rustls-pemfile 1.0: read_all returns Result<Vec<Item>, io::Error>.
    let items = rustls_pemfile::read_all(&mut reader)?;
    Ok(items)
}

/// Build the mTLS server configuration.
///
/// * `cert_path`    — PEM file with the server certificate chain
/// * `key_path`     — PEM file with the server private key
/// * `client_ca_path` — PEM file with the client CA bundle (client certs
///                      MUST chain to this CA)
pub fn load_server_config(
    cert_path: &Path,
    key_path: &Path,
    client_ca_path: &Path,
) -> Result<Arc<ServerConfig>, TlsConfigError> {
    // 1. Server identity.
    let cert_items = read_pem_items(cert_path)?;
    let certs: Vec<Certificate> = cert_items
        .into_iter()
        .filter_map(|i| match i {
            rustls_pemfile::Item::X509Certificate(der) => Some(Certificate(der)),
            _ => None,
        })
        .collect();
    if certs.is_empty() {
        return Err(TlsConfigError::MissingCertChain);
    }

    let key_items = read_pem_items(key_path)?;
    let key = key_items
        .into_iter()
        .find_map(|i| match i {
            rustls_pemfile::Item::PKCS8Key(der) => Some(PrivateKey(der)),
            rustls_pemfile::Item::RSAKey(der) => Some(PrivateKey(der)),
            rustls_pemfile::Item::ECKey(der) => Some(PrivateKey(der)),
            _ => None,
        })
        .ok_or(TlsConfigError::MissingPrivateKey)?;

    // 2. Client CA roots — used to verify presented client certificates.
    let ca_items = read_pem_items(client_ca_path)?;
    let mut roots = RootCertStore::empty();
    let mut added = 0usize;
    for item in ca_items {
        if let rustls_pemfile::Item::X509Certificate(der) = item {
            roots
                .add(&Certificate(der))
                .map_err(TlsConfigError::Rustls)?;
            added += 1;
        }
    }
    if added == 0 {
        return Err(TlsConfigError::MissingClientCa);
    }

    // 3. Enforce client certificate authentication during the handshake:
    //    handshake FAILS unless the client presents a cert trusted by `roots`.
    //    (rustls 0.21 API — AllowAnyAuthenticatedClient; the WebPkiClientVerifier
    //    builder arrived in 0.22.)
    let client_verifier = rustls::server::AllowAnyAuthenticatedClient::new(roots);

    let config = ServerConfig::builder()
        .with_safe_defaults()
        .with_client_cert_verifier(client_verifier.boxed())
        .with_single_cert(certs, key)?;

    Ok(Arc::new(config))
}

/// Build a TLS acceptor from the loaded config.
pub fn tls_acceptor(config: Arc<ServerConfig>) -> tokio_rustls::TlsAcceptor {
    tokio_rustls::TlsAcceptor::from(config)
}
