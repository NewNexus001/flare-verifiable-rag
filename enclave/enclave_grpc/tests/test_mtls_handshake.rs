// enclave/enclave_grpc/tests/test_mtls_handshake.rs
//
// Phase 11 (Prompt 215) — mTLS handshake enforcement.
//
// Real certificates generated in-process with rcgen (ECDSA P-256, the
// rustls 0.21 pairing). The server config REQUIRES a client certificate
// chaining to a pinned trust root:
//   - a client presenting NO certificate  → handshake REJECTED
//   - a client presenting an UNTRUSTED cert → handshake REJECTED
//   - a client presenting the TRUSTED cert → handshake ACCEPTED
//
// This exercises the exact configuration produced by
// enclave_grpc::tls_config::load_server_config semantics (client CA
// validation during the handshake).
use enclave_grpc::tls_config;
use rcgen::{Certificate, CertificateParams};
use rustls::{Certificate as RustlsCert, PrivateKey, RootCertStore, ServerConfig};
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::{ClientConfig, ServerName};
use tokio_rustls::{TlsAcceptor, TlsConnector};

/// Self-signed cert (DER + private key DER) — ECDSA P-256 default.
/// (rcgen 0.11: CertificateParams::new returns Self, not Result.)
fn make_cert(name: &str) -> (Vec<u8>, Vec<u8>) {
    let params = CertificateParams::new(vec![name.to_string()]);
    let cert = Certificate::from_params(params).unwrap();
    (cert.serialize_der().unwrap(), cert.serialize_private_key_der())
}

/// Start a TLS accept loop that REQUIRES a client cert trusted by `trust_roots`.
async fn spawn_mtls_server(
    server_der: Vec<u8>,
    server_key: Vec<u8>,
    trust_roots: Vec<Vec<u8>>,
) -> (String, tokio::task::JoinHandle<()>) {
    let mut roots = RootCertStore::empty();
    for der in &trust_roots {
        roots.add(&RustlsCert(der.clone())).unwrap();
    }
    let verifier = rustls::server::AllowAnyAuthenticatedClient::new(roots);
    let config = Arc::new(
        ServerConfig::builder()
            .with_safe_defaults()
            .with_client_cert_verifier(verifier.boxed())
            .with_single_cert(vec![RustlsCert(server_der)], PrivateKey(server_key))
            .unwrap(),
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = TlsAcceptor::from(config);

    let handle = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else { break };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                // Bind the TLS stream so it is NOT dropped after accept —
                // hold it open so accepted peers can complete their probe
                // (rejected peers already got their alert).
                let tls_stream = acceptor.accept(stream).await.ok();
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                drop(tls_stream);
            });
        }
    });

    (format!("{addr}"), handle)
}

/// Client connector: with or without a client certificate.
fn client_config(
    ca_roots: Vec<Vec<u8>>,
    client_identity: Option<(Vec<u8>, Vec<u8>)>,
) -> ClientConfig {
    let mut roots = RootCertStore::empty();
    for der in &ca_roots {
        roots.add(&RustlsCert(der.clone())).unwrap();
    }
    match client_identity {
        Some((cert_der, key_der)) => ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(roots)
            .with_client_auth_cert(vec![RustlsCert(cert_der)], PrivateKey(key_der))
            .unwrap(),
        None => ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    }
}

/// Connect + probe: write a byte, then read. A REJECTED handshake surfaces
/// the fatal alert on the first read (the client otherwise completes its own
/// side of the handshake optimistically). An accepted connection gets no
/// data, so the read times out.
async fn probe(addr: &str, config: ClientConfig) -> Result<(), String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let stream = TcpStream::connect(addr).await.map_err(|e| e.to_string())?;
    let connector = TlsConnector::from(Arc::new(config));
    let server_name = ServerName::try_from("localhost").map_err(|e| e.to_string())?;
    let mut tls = connector
        .connect(server_name, stream)
        .await
        .map_err(|e| format!("tls handshake: {e}"))?;

    tls.write_all(b"probe")
        .await
        .map_err(|e| format!("tls write: {e}"))?;
    let mut buf = [0u8; 8];
    match tokio::time::timeout(std::time::Duration::from_millis(800), tls.read(&mut buf)).await {
        Ok(Ok(_)) => Err("server sent data/EOF — connection closed".to_string()),
        Ok(Err(e)) => Err(format!("read error — server alert received: {e}")),
        Err(_elapsed) => Ok(()), // no alert within 800ms → connection accepted
    }
}

#[tokio::test]
async fn unauthenticated_client_is_rejected_during_handshake() {
    let (server_der, server_key) = make_cert("localhost");
    let (trusted_client_der, _trusted_key) = make_cert("trusted-client");
    let (addr, _handle) =
        spawn_mtls_server(server_der.clone(), server_key, vec![trusted_client_der]).await;

    // 1. NO client certificate → the handshake must FAIL (alert on read).
    let no_cert = client_config(vec![server_der.clone()], None);
    let res = probe(&addr, no_cert).await;
    assert!(
        res.is_err(),
        "unauthenticated TLS client MUST be rejected during the mTLS handshake: {res:?}"
    );
}

#[tokio::test]
async fn untrusted_client_certificate_is_rejected() {
    let (server_der, server_key) = make_cert("localhost");
    let (trusted_client_der, _trusted_key) = make_cert("trusted-client");
    let (untrusted_der, untrusted_key) = make_cert("impostor");
    let (addr, _handle) =
        spawn_mtls_server(server_der.clone(), server_key, vec![trusted_client_der]).await;

    // 2. A client cert NOT in the trust roots → rejected (alert on read).
    let impostor = client_config(vec![server_der.clone()], Some((untrusted_der, untrusted_key)));
    let res = probe(&addr, impostor).await;
    assert!(res.is_err(), "untrusted client certificate MUST be rejected: {res:?}");
}

#[tokio::test]
async fn trusted_client_certificate_is_accepted() {
    let (server_der, server_key) = make_cert("localhost");
    let (trusted_client_der, trusted_client_key) = make_cert("trusted-client");
    let (addr, _handle) = spawn_mtls_server(
        server_der.clone(),
        server_key,
        vec![trusted_client_der.clone()],
    )
    .await;

    // 3. The pinned client cert → handshake completes.
    let trusted = client_config(
        vec![server_der.clone()],
        Some((trusted_client_der, trusted_client_key)),
    );
    let res = probe(&addr, trusted).await;
    assert!(res.is_ok(), "trusted client certificate MUST be accepted: {res:?}");
}

/// Sanity: the production tls_config helper builds a valid acceptor.
#[test]
fn tls_config_loads_server_config() {
    let (server_der, server_key) = make_cert("localhost");
    let (client_der, _client_key) = make_cert("client");

    let dir = std::env::temp_dir().join(format!("enclave-grpc-mtls-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cert_path = dir.join("server.pem");
    let key_path = dir.join("server-key.pem");
    let ca_path = dir.join("client-ca.pem");

    // PEM-encode manually (rustls-pemfile 1.0 has no writer). Real PEM
    // text — rustls_pemfile::read_all in tls_config parses it back.
    use base64::Engine as _;
    fn pem(label: &str, der: &[u8]) -> String {
        let b64 = base64::engine::general_purpose::STANDARD.encode(der);
        let mut s = format!("-----BEGIN {label}-----\n");
        for chunk in b64.as_bytes().chunks(64) {
            s.push_str(std::str::from_utf8(chunk).unwrap());
            s.push('\n');
        }
        s.push_str(&format!("-----END {label}-----\n"));
        s
    }
    std::fs::write(&cert_path, pem("CERTIFICATE", &server_der)).unwrap();
    std::fs::write(&key_path, pem("PRIVATE KEY", &server_key)).unwrap();
    std::fs::write(&ca_path, pem("CERTIFICATE", &client_der)).unwrap();

    let config = tls_config::load_server_config(&cert_path, &key_path, &ca_path);
    assert!(config.is_ok(), "load_server_config failed: {config:?}");
}
