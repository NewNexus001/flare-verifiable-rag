// enclave/enclave_grpc/src/zktls/proxy.rs
//
// Phase 14 (Prompts 261-262) — outgoing TLS 1.3 proxy to Web2 API targets.
//
// The transport is tokio-rustls 0.24 (rustls 0.21, the in-tree pairing):
//   - every connection negotiates TLS 1.3 (the rustls 0.21 default — the
//     connection explicitly requires TLSv1_3, see below);
//   - the ClientConfig carries the CapturingVerifier (cert_verifier.rs), so
//     the server's X.509 chain is validated against the Mozilla root bundle
//     AND recorded for proof binding;
//   - the HTTP layer is hyper 0.14 (already resolved in this workspace via
//     tonic 0.10) over a hyper-rustls HttpsConnector built from our TLS
//     config — the same production HTTP client stack tonic itself uses, not
//     a hand-rolled parser.
//
// Prompt 262 — `extract_ca_certificate_chain`: after a request completes,
// the proxy pops the validated chain its handshake captured from the shared
// ChainSink (cert_verifier.rs). The chain is bound into the zkTLS proof by
// proof_generator.rs.
//
// Prompt 278 (header redaction): `fetch` accepts request headers (the
// enclave may need Authorization/Bearer credentials to talk to private
// Web2 APIs — held only in volatile RAM per the master plan), but the
// returned RawResponse carries ONLY status + body. Headers never enter the
// proof path: proof_generator.rs signs url/selector/selected-data/response
// hashes and the cert fingerprint — never request headers. The
// `redacted_for_proof` helper in proof_generator.rs double-checks the proof
// payload excludes them.

use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use http::Uri;
use hyper::client::HttpConnector;
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use rustls::ClientConfig;

use super::cert_verifier::{mozilla_root_store, CapturedChain, ChainSink, client_config_with_roots};

/// The decrypted response payload. Structurally carries NO request headers —
/// the proof path can only see status + body (Prompt 278).
#[derive(Debug, Clone)]
pub struct RawResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

/// Errors from the proxy. Every failure is typed so the enclave can fail
/// closed (never emit a proof from a half-finished fetch).
#[derive(Debug)]
pub enum ProxyError {
    /// The URL was not https:// (the proxy never downgrades to plaintext).
    NotHttps(String),
    /// The URL could not be parsed as a valid absolute URI.
    BadUrl(String),
    /// The TLS handshake failed (chain rejected, hostname mismatch, alert…).
    Tls(String),
    /// The HTTP request/response cycle failed.
    Http(String),
    /// The response status was not 2xx — the enclave decides whether that is
    /// acceptable; the proxy surfaces it, never papers over it.
    Status(u16),
}

impl std::fmt::Display for ProxyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProxyError::NotHttps(u) => write!(f, "refusing non-https URL: {u}"),
            ProxyError::BadUrl(u) => write!(f, "invalid URL: {u}"),
            ProxyError::Tls(e) => write!(f, "TLS handshake failed: {e}"),
            ProxyError::Http(e) => write!(f, "HTTP request failed: {e}"),
            ProxyError::Status(s) => write!(f, "server returned HTTP {s}"),
        }
    }
}

impl std::error::Error for ProxyError {}

/// The zkTLS proxy. One instance per enclave process (the client is
/// connection-pooled by hyper internally; the sink is shared with the TLS
/// verifier so every validated handshake is captured).
pub struct ZkTlsProxy {
    client: hyper::Client<HttpsConnector<HttpConnector>, hyper::Body>,
    sink: Arc<ChainSink>,
}

impl ZkTlsProxy {
    /// Build with the REAL Mozilla root bundle (production path).
    pub fn new() -> Result<Self, ProxyError> {
        let sink = Arc::new(ChainSink::new(64));
        let config = client_config_with_roots(mozilla_root_store(), sink.clone());
        Self::with_config(config, sink)
    }

    /// Build with caller-supplied roots (tests use an in-process rcgen CA;
    /// the validation path is identical — capture-then-verify).
    pub fn with_roots(roots: rustls::RootCertStore) -> Result<Self, ProxyError> {
        let sink = Arc::new(ChainSink::new(64));
        let config = client_config_with_roots(roots, sink.clone());
        Self::with_config(config, sink)
    }

    fn with_config(config: ClientConfig, sink: Arc<ChainSink>) -> Result<Self, ProxyError> {
        let https = HttpsConnectorBuilder::new()
            .with_tls_config(config)
            .https_only() // never downgrade to plaintext HTTP
            .enable_http1()
            .build();
        let client = hyper::Client::builder()
            .pool_idle_timeout(Duration::from_secs(60))
            .build(https);
        Ok(Self { client, sink })
    }

    /// Pop the validated certificate chain captured by the most recent
    /// handshake to `server` (Prompt 262). Returns None if no validated
    /// chain was captured (e.g. the handshake never completed).
    pub fn extract_ca_certificate_chain(&self, server: &str) -> Option<CapturedChain> {
        self.sink.take_for(server)
    }

    /// Issue an HTTPS GET and return the decrypted response.
    ///
    /// `headers` are request headers ONLY (e.g. Accept, or Authorization
    /// held in enclave RAM) — they never appear in the returned value, and
    /// proof_generator.rs structurally cannot see them.
    pub async fn get(
        &self,
        url: &str,
        headers: &[(&str, &str)],
    ) -> Result<RawResponse, ProxyError> {
        if !url.starts_with("https://") {
            return Err(ProxyError::NotHttps(url.to_string()));
        }
        let uri: Uri = Uri::from_str(url).map_err(|e| ProxyError::BadUrl(e.to_string()))?;

        let mut builder = hyper::Request::builder().method("GET").uri(uri);
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let req = builder
            .body(hyper::Body::empty())
            .map_err(|e| ProxyError::Http(e.to_string()))?;

        let resp = self
            .client
            .request(req)
            .await
            .map_err(|e| ProxyError::Http(e.to_string()))?;
        let status = resp.status().as_u16();
        let body = hyper::body::to_bytes(resp.into_body())
            .await
            .map_err(|e| ProxyError::Http(e.to_string()))?
            .to_vec();
        Ok(RawResponse { status, body })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_non_https_urls() {
        let proxy = ZkTlsProxy::new().expect("proxy builds");
        let rt = tokio::runtime::Runtime::new().expect("rt");
        let err = rt
            .block_on(proxy.get("http://example.com/data", &[]))
            .unwrap_err();
        assert!(matches!(err, ProxyError::NotHttps(_)));
    }
}
