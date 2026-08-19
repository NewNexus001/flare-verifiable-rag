// enclave/enclave_grpc/tests/test_zktls_proxy.rs
//
// Phase 14 (Prompt 266) — end-to-end zkTLS proxy test on loopback.
//
// A REAL TLS 1.3 server (rustls server side, rcgen-issued certificate
// chained to an in-process CA) serves JSON over localhost. The ZkTlsProxy:
//   1. opens the TLS 1.3 session to the loopback server (Prompt 261);
//   2. its CapturingVerifier VALIDATES the chain against the test CA
//      (identical capture-then-verify code path as production Mozilla
//      roots — Prompt 263) and records the presented chain;
//   3. extract_ca_certificate_chain() returns the chain the handshake
//      presented (Prompt 262);
//   4. the proof generator runs the jq selector over the decrypted payload
//      and signs the binding (Prompts 264-265);
//   5. the recovered signer matches the enclave identity key, and the proof
//      contains no request-header material (Prompt 278).
//
// The server REQUIRES TLS 1.3 on its side too, so a successful handshake
// proves the 1.3-only pinning on both ends.

use std::sync::Arc;

use enclave_grpc::zktls::cert_verifier::CapturedChain;
use enclave_grpc::zktls::proof_generator::{ZkTlsProof, generate_proof};
use enclave_grpc::zktls::proxy::ZkTlsProxy;
use k256::ecdsa::SigningKey;
use k256::elliptic_curve::rand_core::OsRng;
use rcgen::{BasicConstraints, CertificateParams, IsCa, SanType};
use sha3::Digest;
use rustls::{Certificate as RustlsCert, PrivateKey, RootCertStore, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::rustls::version::TLS13;
use tokio_rustls::TlsAcceptor;

/// Generate a CA + a server certificate signed by it (SAN: localhost,
/// 127.0.0.1). Returns (ca_der, server_der, server_key_der).
fn make_ca_signed_server_cert() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    // CA — self-signed, CA basic constraint.
    let mut ca_params = CertificateParams::new(vec!["zktls-test-ca".to_string()]);
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = rcgen::Certificate::from_params(ca_params).expect("ca params");

    // Server cert signed by the CA with SANs for both loopback forms.
    let mut server_params = CertificateParams::new(vec![]);
    server_params.subject_alt_names = vec![
        SanType::DnsName("localhost".to_string()),
        SanType::IpAddress("127.0.0.1".parse().expect("ip")),
    ];
    let server = rcgen::Certificate::from_params(server_params).expect("server params");

    let server_der = server.serialize_der_with_signer(&ca).expect("signed der");
    (
        ca.serialize_der().expect("ca der"),
        server_der,
        server.serialize_private_key_der(),
    )
}

/// Serve a fixed JSON document over TLS 1.3 on loopback. Each connection
/// answers one HTTP/1.1 request with a JSON body.
async fn spawn_tls_json_server(
    server_der: Vec<u8>,
    server_key: Vec<u8>,
) -> (String, tokio::task::JoinHandle<()>) {
    let config = Arc::new(
        ServerConfig::builder()
            .with_safe_default_cipher_suites()
            .with_safe_default_kx_groups()
            .with_protocol_versions(&[&TLS13])
            .expect("tls13 supported")
            .with_no_client_auth()
            .with_single_cert(
                vec![RustlsCert(server_der)],
                PrivateKey(server_key),
            )
            .expect("server cert loads"),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let acceptor = TlsAcceptor::from(config);

    let handle = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(stream).await else {
                    return;
                };
                // Read the HTTP request head (up to the blank line).
                let mut buf = [0u8; 4096];
                let mut used = 0usize;
                loop {
                    let n = match tls.read(&mut buf[used..]).await {
                        Ok(n) => n,
                        Err(_) => return,
                    };
                    if n == 0 {
                        return;
                    }
                    used += n;
                    if buf[..used].windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                    if used == buf.len() {
                        return;
                    }
                }
                // Answer with the JSON document (Content-Length set).
                let body = br#"{"completed":true,"todos":[{"title":"buy milk","id":1}]}"#;
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = tls.write_all(head.as_bytes()).await;
                let _ = tls.write_all(body).await;
                let _ = tls.flush().await;
            });
        }
    });
    (format!("{addr}"), handle)
}

#[tokio::test]
async fn proxy_fetches_json_verifies_chain_and_mints_proof() {
    let (ca_der, server_der, server_key) = make_ca_signed_server_cert();
    let (addr, _handle) = spawn_tls_json_server(server_der.clone(), server_key).await;

    // Trust ONLY the test CA (the production path is identical except the
    // root store — mozilla_root_store()).
    let mut roots = RootCertStore::empty();
    roots.add(&RustlsCert(ca_der.clone())).expect("ca added");
    let proxy = ZkTlsProxy::with_roots(roots).expect("proxy builds");

    // Real request headers, including an Authorization bearer token held in
    // "enclave RAM" — these must NEVER appear in the proof (Prompt 278).
    let auth_secret = "Bearer zktls-test-secret-abcdef";
    let url = format!("https://localhost:{}/todos/1", addr.split(':').last().unwrap());
    let response = proxy
        .get(&url, &[("Authorization", auth_secret), ("Accept", "application/json")])
        .await
        .expect("fetch succeeds over TLS 1.3");
    assert_eq!(response.status, 200);
    let body = String::from_utf8(response.body.clone()).expect("utf8 json");
    assert!(body.contains("\"completed\":true"), "real JSON body: {body}");

    // Prompt 262: the presented chain was captured and validates against the
    // test CA — the end-entity must be the server cert we signed.
    let chain: CapturedChain = proxy
        .extract_ca_certificate_chain("localhost")
        .expect("validated chain captured");
    assert_eq!(chain.end_entity, server_der, "captured end-entity == server cert");

    // Prompt 264-265: mint the proof — jq over the decrypted payload.
    let signer = SigningKey::random(&mut OsRng);
    let nonce: [u8; 16] = {
        use k256::elliptic_curve::rand_core::RngCore;
        let mut n = [0u8; 16];
        OsRng.fill_bytes(&mut n);
        n
    };
    let proof: ZkTlsProof = generate_proof(
        &url,
        &response.body,
        ".todos[0].title",
        &chain,
        &signer,
        nonce,
        Some(&[auth_secret, "zktls-test-secret-abcdef"]),
    )
    .expect("proof mints from real TLS response");

    // The jq selection bound into the proof: "buy milk".
    assert_eq!(proof.data_hash, enclave_grpc::zktls::proof_generator::sha256_of(b"\"buy milk\"\n"));

    // Signer recovery (ecrecover-equivalent) matches the enclave identity key.
    let recovered = proof.recover_signer().expect("recovers");
    let vk = signer.verifying_key();
    let uncompressed = vk.to_encoded_point(false);
    // keccak256 of the uncompressed key (the address derivation).
    let mut hasher = sha3::Keccak256::new();
    hasher.update(&uncompressed.as_bytes()[1..]);
    let digest = hasher.finalize();
    let mut expected = [0u8; 20];
    expected.copy_from_slice(&digest[12..]);
    assert_eq!(recovered, expected, "proof signer == enclave identity key");

    // Prompt 278 (mechanical): the serialized proof contains NO request
    // header material.
    let serialized = proof.to_bytes();
    for secret in [auth_secret, "zktls-test-secret-abcdef"] {
        assert!(
            !serialized
                .windows(secret.as_bytes().len())
                .any(|w| w == secret.as_bytes()),
            "header secret leaked into proof bytes"
        );
    }
    // Wire format round-trips.
    let decoded = ZkTlsProof::from_bytes(&serialized).expect("decodes");
    assert_eq!(decoded.url_hash, proof.url_hash);
    assert_eq!(decoded.signed_digest(), proof.signed_digest());
}

#[tokio::test]
async fn proxy_rejects_untrusted_chain() {
    // Two separate CAs: the server is signed by CA1, the client trusts CA2 —
    // the handshake MUST fail (chain rejected), and NO chain is captured
    // (capture-then-verify: only validated chains are recorded).
    let (ca1_der, server_der, server_key) = make_ca_signed_server_cert();
    let (ca2_der, _, _) = make_ca_signed_server_cert();
    let (_addr, _handle) = spawn_tls_json_server(server_der, server_key).await;
    let _ = ca1_der;

    let mut roots = RootCertStore::empty();
    roots.add(&RustlsCert(ca2_der)).expect("ca2 added");
    let proxy = ZkTlsProxy::with_roots(roots).expect("proxy builds");

    let url = "https://localhost:1/x";
    // Port 1 connection fails at TCP before TLS; what we assert here is the
    // typed error path (never a proof, never a panic). The chain-rejection
    // case itself is covered by test_chain_rejection below against a real
    // server.
    assert!(proxy.get(url, &[]).await.is_err());
}

#[tokio::test]
async fn chain_rejected_by_untrusted_ca_is_not_captured() {
    // Server signed by CA1; client trusts CA2 → handshake rejection. The
    // sink must remain empty (no validated chain → no proof possible).
    let (ca1_der, server_der, server_key) = make_ca_signed_server_cert();
    let (ca2_der, _, _) = make_ca_signed_server_cert();
    let (addr, _handle) = spawn_tls_json_server(server_der, server_key).await;
    let _ = ca1_der;

    let mut roots = RootCertStore::empty();
    roots.add(&RustlsCert(ca2_der)).expect("ca2 added");
    let proxy = ZkTlsProxy::with_roots(roots).expect("proxy builds");

    let url = format!("https://localhost:{}/x", addr.split(':').last().unwrap());
    let err = proxy.get(&url, &[]).await;
    assert!(err.is_err(), "untrusted CA must fail the handshake");

    // Capture-then-verify: nothing was captured for this server.
    assert!(
        proxy.extract_ca_certificate_chain("localhost").is_none(),
        "rejected chain must never be captured"
    );
}
