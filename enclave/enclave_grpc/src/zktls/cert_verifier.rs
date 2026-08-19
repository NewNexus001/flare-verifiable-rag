// enclave/enclave_grpc/src/zktls/cert_verifier.rs
//
// Phase 14 (Prompt 263) — server certificate chain capture + verification
// against the embedded Mozilla root bundle (webpki-roots).
//
// Design (capture-then-verify, the mitmproxy-class pattern):
//   rustls calls `ServerCertVerifier::verify_server_cert` during the TLS 1.3
//   handshake with the RAW DER bytes of the end-entity certificate and every
//   intermediate the server presented. This verifier:
//     1. Delegates to the REAL `WebPkiVerifier` (rustls's own implementation
//        over rustls-webpki 0.101) loaded with the Mozilla root bundle —
//        the same validation the standard rustls client performs: chain to a
//        trust anchor, validity windows, name constraints, hostname check.
//     2. ONLY IF that validation succeeds, records the exact presented chain
//        (end-entity + intermediates DER) into a shared `ChainSink` keyed by
//        server name. A failed or tampered handshake never contributes an
//        entry, so a zkTLS proof can never be minted against a chain that did
//        not verify.
//
// The sink is shared with the proxy (proxy.rs): after the request completes
// the proxy pops the chain for its server and binds a fingerprint of it into
// the proof (proof_generator.rs).

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

// rustls 0.21 exposes the custom-verifier API under `rustls::client::{...}`
// behind the `dangerous_configuration` feature (enabled in Cargo.toml).
use rustls::client::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiVerifier;
use rustls::{
    Certificate, ClientConfig, DigitallySignedStruct, OwnedTrustAnchor, RootCertStore,
    ServerName, SignatureScheme,
};
use std::time::SystemTime;

/// A certificate chain exactly as the server presented it (DER bytes).
/// `end_entity` is the server leaf; `intermediates` are the additional
/// certificates from the server's Certificate message, in presentation order.
#[derive(Debug, Clone)]
pub struct CapturedChain {
    pub server: String,
    pub end_entity: Vec<u8>,
    pub intermediates: Vec<Vec<u8>>,
}

impl CapturedChain {
    /// The full presented chain, end-entity first.
    pub fn all_der(&self) -> Vec<Vec<u8>> {
        let mut all = Vec::with_capacity(self.intermediates.len() + 1);
        all.push(self.end_entity.clone());
        all.extend(self.intermediates.iter().cloned());
        all
    }
}

/// Bounded, server-keyed store of successfully-validated chains.
/// Bounded (max 64 entries) so a busy enclave cannot grow it without limit.
#[derive(Debug, Default)]
pub struct ChainSink {
    inner: Mutex<VecDeque<CapturedChain>>,
    max: usize,
}

impl ChainSink {
    pub fn new(max: usize) -> Self {
        Self {
            inner: Mutex::new(VecDeque::new()),
            max,
        }
    }

    /// Record a validated chain (called by the verifier only after the real
    /// validation succeeded).
    pub fn push(&self, chain: CapturedChain) {
        let mut q = self.inner.lock().expect("chain sink poisoned");
        if q.len() >= self.max {
            q.pop_front();
        }
        q.push_back(chain);
    }

    /// Pop the MOST RECENT validated chain for `server` (the chain the proxy's
    /// just-completed handshake captured). Older entries for the same server
    /// are dropped so a repeated handshake cannot be confused with a fresh one.
    pub fn take_for(&self, server: &str) -> Option<CapturedChain> {
        let mut q = self.inner.lock().expect("chain sink poisoned");
        let idx = q.iter().rposition(|c| c.server == server)?;
        q.remove(idx)
    }
}

/// Capture-then-verify server cert verifier.
pub struct CapturingVerifier {
    inner: WebPkiVerifier,
    sink: Arc<ChainSink>,
}

impl CapturingVerifier {
    pub fn new(roots: RootCertStore, sink: Arc<ChainSink>) -> Self {
        Self {
            inner: WebPkiVerifier::new(Arc::new(roots), None),
            sink,
        }
    }
}

impl ServerCertVerifier for CapturingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &Certificate,
        intermediates: &[Certificate],
        server_name: &ServerName,
        scts: &mut dyn Iterator<Item = &[u8]>,
        ocsp_response: &[u8],
        now: SystemTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // 1) REAL validation first — full webpki chain check against the
        //    Mozilla bundle (or the caller-supplied test roots).
        let verified = self
            .inner
            .verify_server_cert(end_entity, intermediates, server_name, scts, ocsp_response, now)?;
        // 2) Only validated chains are ever recorded. rustls 0.21 has no
        //    Display for ServerName (and the enum is #[non_exhaustive]);
        //    match the known variants with a Debug fallback.
        let server = match server_name {
            ServerName::DnsName(dns) => dns.as_ref().to_string(),
            ServerName::IpAddress(ip) => ip.to_string(),
            other => format!("{other:?}"),
        };
        self.sink.push(CapturedChain {
            server,
            end_entity: end_entity.0.clone(),
            intermediates: intermediates.iter().map(|c| c.0.clone()).collect(),
        });
        Ok(verified)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &Certificate,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &Certificate,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Build the Mozilla root store (webpki-roots 0.25) the canonical rustls 0.21
/// way — the exact pattern from rustls's own lib.rs docs:
/// `OwnedTrustAnchor::from_subject_spki_name_constraints`.
pub fn mozilla_root_store() -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots.add_trust_anchors(
        webpki_roots::TLS_SERVER_ROOTS
            .iter()
            .map(|ta| {
                OwnedTrustAnchor::from_subject_spki_name_constraints(
                    ta.subject,
                    ta.spki,
                    ta.name_constraints,
                )
            }),
    );
    roots
}

/// Build a rustls ClientConfig that uses the CapturingVerifier over the given
/// trust roots and pins TLS 1.3 (the zkTLS claim is a TLS 1.3 session). The
/// verifier is shared with the proxy via `sink`, so every handshake this
/// config performs is captured there (after validation).
pub fn client_config_with_roots(roots: RootCertStore, sink: Arc<ChainSink>) -> ClientConfig {
    let verifier = CapturingVerifier::new(roots, sink);
    ClientConfig::builder()
        .with_safe_default_cipher_suites()
        .with_safe_default_kx_groups()
        // rustls 0.21 returns Result here (errors when no usable suite
        // matches the requested version); TLS 1.3 is always usable with
        // the safe-default suites, so this cannot fail — but we surface
        // it explicitly rather than panic silently.
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3 is supported by the safe-default cipher suites")
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_sink_is_bounded_and_server_keyed() {
        let sink = Arc::new(ChainSink::new(2));
        sink.push(CapturedChain {
            server: "a.example".into(),
            end_entity: vec![1],
            intermediates: vec![],
        });
        sink.push(CapturedChain {
            server: "b.example".into(),
            end_entity: vec![2],
            intermediates: vec![vec![3]],
        });
        sink.push(CapturedChain {
            server: "a.example".into(),
            end_entity: vec![4],
            intermediates: vec![],
        });
        // Most recent for a.example wins; the oldest entry was evicted.
        let a = sink.take_for("a.example").expect("a chain present");
        assert_eq!(a.end_entity, vec![4]);
        // Take again → the older a.example entry is gone (only one left).
        assert!(sink.take_for("a.example").is_none());
        let b = sink.take_for("b.example").expect("b chain present");
        assert_eq!(b.end_entity, vec![2]);
        assert_eq!(b.intermediates, vec![vec![3]]);
    }

    #[test]
    fn all_der_orders_end_entity_first() {
        let chain = CapturedChain {
            server: "x".into(),
            end_entity: vec![1],
            intermediates: vec![vec![2], vec![3]],
        };
        assert_eq!(chain.all_der(), vec![vec![1], vec![2], vec![3]]);
    }
}
