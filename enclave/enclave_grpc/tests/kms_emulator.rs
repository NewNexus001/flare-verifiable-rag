// enclave/enclave_grpc/tests/kms_emulator.rs
//
// Phase 13 (Prompt 246) — LOCAL GCP KMS EMULATOR (test-only).
//
// Implements the two REST contracts the KMS client talks to, locally, so the
// RATS Passport flow can be integration-tested without a GCP project or the
// google/cloud-sdk Docker emulator (which requires Docker — deliberately not
// a hard dependency of the test suite; when Docker IS available the same
// client works against the real emulator image on :8085 with zero code
// changes, since it implements the same documented API).
//
//   POST /v1/token                    → STS token exchange (RFC 8693)
//       request:  { subjectToken: <EAT>, audience: <wip-audience>, ... }
//       response: { access_token: "test-token-<nonce>" }
//   POST /v1/{cryptoKey}:decrypt      → Cloud KMS Decrypt
//       request:  { ciphertext: <b64> }
//       response: { plaintext: <b64> }
//
// The emulator is honest about what it is: it validates the AUTHORIZATION
// header (the token minted by its own /v1/token endpoint) and rejects
// requests without it — mirroring the real IAM policy gate. It does NOT
// fabricate production attestation material; it only serves the shard the
// TEST OPERATOR loaded into it.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use base64::Engine;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server, StatusCode};

/// In-memory emulator state: the shard ciphertext→plaintext map and the
/// bearer token it issued (so Decrypt can validate it).
#[derive(Debug, Default)]
struct EmulatorState {
    ciphertexts: HashMap<String, Vec<u8>>,
    issued_token: Option<String>,
}

type SharedState = Arc<Mutex<EmulatorState>>;

/// Start the emulator on an ephemeral port. Returns the base URL (no trailing
/// slash) plus a handle to load shards / inspect state.
pub struct KmsEmulator {
    pub base_url: String,
    pub sts_url: String,
    state: SharedState,
}

impl KmsEmulator {
    pub async fn start() -> Result<Self, Box<dyn std::error::Error>> {
        let state: SharedState = Arc::new(Mutex::new(EmulatorState::default()));
        let st = state.clone();

        let make_svc = make_service_fn(move |_conn| {
            let st = st.clone();
            async move { Ok::<_, std::convert::Infallible>(service_fn(move |req| handle(req, st.clone()))) }
        });

        let addr: SocketAddr = "127.0.0.1:0".parse()?;
        let server = Server::bind(&addr).serve(make_svc);
        let local = server.local_addr();
        let base_url = format!("http://{local}");
        let sts_url = format!("{base_url}/v1/token");

        tokio::spawn(async move {
            let _ = server.await;
        });

        Ok(Self {
            base_url,
            sts_url,
            state,
        })
    }

    /// Load a shard into the emulator: ciphertext (as given to Decrypt) →
    /// plaintext (what Decrypt returns). The TEST OPERATOR's equivalent of
    /// GCP KMS holding the enclave shard.
    pub fn load_shard(&self, ciphertext_b64: &str, plaintext: Vec<u8>) {
        let mut s = self.state.lock().unwrap();
        s.ciphertexts.insert(ciphertext_b64.to_string(), plaintext);
    }

    /// The token the emulator issued (for assertions).
    pub fn issued_token(&self) -> Option<String> {
        self.state.lock().unwrap().issued_token.clone()
    }
}

/// Route + implement the two REST endpoints.
async fn handle(
    req: Request<Body>,
    state: SharedState,
) -> Result<Response<Body>, std::convert::Infallible> {
    let path = req.uri().path().to_string();
    // Authorization header is needed AFTER the body is consumed below.
    let auth_header = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_string());
    let body_bytes = match hyper::body::to_bytes(req.into_body()).await {
        Ok(b) => b,
        Err(_) => {
            return Ok(json_response(StatusCode::BAD_REQUEST, r#"{"error":"bad body"}"#));
        }
    };
    let body = String::from_utf8_lossy(&body_bytes).to_string();

    if path == "/v1/token" {
        // STS token exchange — mirror of the documented contract.
        if !body.contains("\"grantType\":\"urn:ietf:params:oauth:grant-type:token-exchange\"") {
            return Ok(json_response(StatusCode::BAD_REQUEST, r#"{"error":"missing grantType"}"#));
        }
        let nonce: String = {
            use std::time::{SystemTime, UNIX_EPOCH};
            let n = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            format!("test-token-{n}")
        };
        let mut s = state.lock().unwrap();
        s.issued_token = Some(nonce.clone());
        let resp = format!(r#"{{"access_token":"{nonce}","expires_in":3600,"token_type":"Bearer"}}"#);
        return Ok(json_response(StatusCode::OK, &resp));
    }

    if path.ends_with(":decrypt") {
        // Cloud KMS Decrypt — mirror of the documented contract.
        let auth = auth_header.clone();
        let state_guard = state.lock().unwrap();
        let expected = state_guard.issued_token.clone();
        match (auth, expected) {
            (Some(a), Some(expected)) if a == format!("Bearer {expected}") => {}
            _ => {
                return Ok(json_response(
                    StatusCode::UNAUTHORIZED,
                    r#"{"error":"unauthorized: no valid bearer token"}"#,
                ));
            }
        }
        let ct = match json_str_field(&body, "ciphertext") {
            Some(c) => c,
            None => {
                return Ok(json_response(StatusCode::BAD_REQUEST, r#"{"error":"missing ciphertext"}"#));
            }
        };
        // Clone out of the lock so the response builder never holds it.
        let plaintext = state_guard.ciphertexts.get(&ct).cloned();
        drop(state_guard);
        return match plaintext {
            Some(plaintext) => {
                let b64 = base64::engine::general_purpose::STANDARD.encode(plaintext);
                let resp = format!(r#"{{"plaintext":"{b64}"}}"#);
                Ok(json_response(StatusCode::OK, &resp))
            }
            None => Ok(json_response(
                StatusCode::NOT_FOUND,
                r#"{"error":"unknown ciphertext"}"#,
            )),
        };
    }

    Ok(json_response(StatusCode::NOT_FOUND, r#"{"error":"not found"}"#))
}

fn json_response(status: StatusCode, body: &str) -> Response<Body> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

/// Extract a top-level string field (mirror of the client's own parser).
fn json_str_field(body: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\":");
    let idx = body.find(&needle)?;
    let rest = &body[idx + needle.len()..];
    let rest = rest.trim_start();
    if let Some(v) = rest.strip_prefix('"') {
        let end = v.find('"')?;
        Some(v[..end].to_string())
    } else {
        None
    }
}
