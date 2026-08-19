// enclave/enclave_grpc/src/kms/client.rs
//
// Phase 13 (Prompts 241, 242) — GCP Cloud KMS client with RATS Passport flow.
//
// The RATS Passport model (master plan §GCP KMS MPC Wallet):
//   1. The Intel TDX enclave mints an IETF RATS EAT (Phase 12) and submits it
//      to the GCP Workload Identity Federation STS token exchange endpoint.
//   2. STS evaluates the EAT claims against the WIP attribute condition
//      policy (swname == CONFIDENTIAL_SPACE ∧ image_digest == approved) and,
//      on success, issues a short-lived OAuth2 access token for the TEE
//      service account.
//   3. The enclave presents that token to Cloud KMS `Decrypt`, which releases
//      the enclave key shard (S_enclave) into enclave volatile RAM.
//   4. mpc_signer.rs combines S_enclave with the client shard and signs;
//      every secret is zeroized on drop (P248).
//
// HONEST DEVIATION NOTE (project no-lies rule): the master plan says "gRPC
// client". Google's own Rust client for KMS (google-cloud-kms-v1) is built on
// the gax/grpc-transport stack — a second tonic plus a ~200-crate tree that
// is impractical to compile on this project's constrained build hosts and
// would duplicate the tonic 0.10 already pinned here. Cloud KMS exposes its
// full API over REST (https://cloudkms.googleapis.com/v1/...) with IDENTICAL
// IAM auth — this is the same wire contract Google documents as first-class.
// This client implements the REAL REST protocol (token exchange + decrypt)
// against the REAL endpoint; swapping in the official gRPC client in CI is a
// drop-in change of this one file. Nothing here is simulated: if the
// endpoint is not reachable the client returns a typed error and the
// enclave fails closed.
//
// The local test suite exercises this same code against a local emulator that
// implements the documented STS + KMS REST contracts (tests/kms_emulator.rs).

use std::time::Duration;

use base64::Engine;

/// GCP STS token exchange endpoint (Workload Identity Federation).
pub const STS_TOKEN_URL: &str = "https://sts.googleapis.com/v1/token";
/// GCP Cloud KMS REST base URL.
pub const KMS_BASE_URL: &str = "https://cloudkms.googleapis.com";

/// A single error type for the whole KMS client — the enclave treats any
/// KMS failure as fail-closed (no shard, no signature).
#[derive(Debug)]
pub enum KmsError {
    /// The KMS/STS endpoint could not be reached (network/TLS).
    Transport(String),
    /// The HTTP response was not 2xx (auth rejected, policy denied, etc.).
    Http { status: u16, body: String },
    /// The response body could not be parsed.
    Parse(String),
    /// The exchange succeeded but returned no token.
    MissingToken,
    /// No KMS resource name was configured (ENCLAVE_KMS_CRYPTO_KEY unset).
    Unconfigured(&'static str),
    /// The EAT was not supplied — required by the RATS Passport flow.
    MissingEat,
}

impl std::fmt::Display for KmsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KmsError::Transport(e) => write!(f, "KMS transport error: {e}"),
            KmsError::Http { status, body } => {
                write!(f, "KMS HTTP {status}: {body}")
            }
            KmsError::Parse(e) => write!(f, "KMS response parse error: {e}"),
            KmsError::MissingToken => write!(f, "STS exchange returned no access token"),
            KmsError::Unconfigured(what) => write!(f, "KMS client unconfigured: {what}"),
            KmsError::MissingEat => write!(f, "EAT token required but not supplied"),
        }
    }
}

impl std::error::Error for KmsError {}

/// Configuration for the KMS client. All values come from the environment /
/// deployment config — never hardcoded (zero-mock policy).
#[derive(Debug, Clone)]
pub struct KmsConfig {
    /// Full resource name of the KMS CryptoKey holding the enclave shard:
    /// projects/{project}/locations/{location}/keyRings/{ring}/cryptoKeys/{key}
    pub crypto_key_name: String,
    /// The Workload Identity Pool provider audience
    /// (//iam.googleapis.com/projects/{p}/locations/global/workloadIdentityPools/{pool}/providers/{provider})
    pub wip_audience: String,
    /// Base URL override (tests point this at the local emulator).
    pub kms_base_url: String,
    /// STS token endpoint override (tests point this at the local emulator).
    pub sts_token_url: String,
    /// HTTP client timeout.
    pub timeout: Duration,
}

impl KmsConfig {
    /// Build from environment variables. Fails closed with a descriptive
    /// error when required values are missing — the enclave must never guess.
    pub fn from_env() -> Result<Self, KmsError> {
        let crypto_key_name = std::env::var("ENCLAVE_KMS_CRYPTO_KEY")
            .map_err(|_| KmsError::Unconfigured("ENCLAVE_KMS_CRYPTO_KEY is not set"))?;
        let wip_audience = std::env::var("ENCLAVE_WIP_AUDIENCE")
            .map_err(|_| KmsError::Unconfigured("ENCLAVE_WIP_AUDIENCE is not set"))?;
        Ok(Self {
            crypto_key_name,
            wip_audience,
            kms_base_url: std::env::var("ENCLAVE_KMS_BASE_URL")
                .unwrap_or_else(|_| KMS_BASE_URL.to_string()),
            sts_token_url: std::env::var("ENCLAVE_STS_TOKEN_URL")
                .unwrap_or_else(|_| STS_TOKEN_URL.to_string()),
            timeout: Duration::from_secs(10),
        })
    }
}

/// HTTP POST helper over hyper 0.14 (in-tree via tonic 0.10). Uses the
/// rustls-based connector so real TLS to googleapis.com works; plain HTTP is
/// allowed only for the local emulator override (explicit config).
async fn post_json(
    url: &str,
    bearer: Option<&str>,
    body: &str,
    timeout: Duration,
) -> Result<(u16, String), KmsError> {
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_native_roots()
        .https_or_http()
        .enable_http1()
        .build();
    let client: hyper::Client<_, hyper::Body> = hyper::Client::builder().build(https);

    let req = hyper::Request::builder()
        .method("POST")
        .uri(url)
        .header("content-type", "application/json");
    let req = match bearer {
        Some(tok) => req.header("authorization", format!("Bearer {tok}")),
        None => req,
    };
    let req = req
        .body(hyper::Body::from(body.to_string()))
        .map_err(|e| KmsError::Transport(e.to_string()))?;

    let resp = tokio::time::timeout(timeout, client.request(req))
        .await
        .map_err(|_| KmsError::Transport("request timed out".to_string()))?
        .map_err(|e| KmsError::Transport(e.to_string()))?;

    let status = resp.status().as_u16();
    let bytes = tokio::time::timeout(timeout, hyper::body::to_bytes(resp.into_body()))
        .await
        .map_err(|_| KmsError::Transport("response read timed out".to_string()))?
        .map_err(|e| KmsError::Transport(e.to_string()))?;
    let text = String::from_utf8_lossy(&bytes).to_string();
    Ok((status, text))
}

/// Minimal JSON field extraction (standard-library only — the KMS/STS REST
/// responses are flat JSON objects; no serde dependency needed for these two
/// fields, keeping the crate lean). Extracts the string value of `key`.
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

/// The KMS client. Stateless per call: a fresh HTTP connection per operation
/// is fine for the enclave's low-frequency signing path (and keeps zero
/// secrets in long-lived state).
#[derive(Debug, Clone)]
pub struct KmsClient {
    pub config: KmsConfig,
}

impl KmsClient {
    pub fn new(config: KmsConfig) -> Self {
        Self { config }
    }

    /// Step 1 of the RATS Passport flow: exchange the enclave's IETF RATS EAT
    /// (a JWT-style OIDC token) for a short-lived GCP OAuth2 access token via
    /// the Workload Identity Federation STS token exchange endpoint.
    ///
    /// This is the REAL documented protocol (RFC 8693-style token exchange):
    /// POST https://sts.googleapis.com/v1/token with the EAT as
    /// subject_token + the WIP provider audience.
    pub async fn exchange_eat_for_access_token(
        &self,
        eat_token: &str,
    ) -> Result<String, KmsError> {
        if eat_token.trim().is_empty() {
            return Err(KmsError::MissingEat);
        }
        let body = format!(
            "{{\"audience\":\"{aud}\",\"grantType\":\"urn:ietf:params:oauth:grant-type:token-exchange\",\
             \"requestedTokenType\":\"urn:ietf:params:oauth:token-type:access_token\",\
             \"scope\":\"https://www.googleapis.com/auth/cloudkms\",\
             \"subjectTokenType\":\"urn:ietf:params:oauth:token-type:jwt\",\
             \"subjectToken\":\"{tok}\"}}",
            aud = self.config.wip_audience,
            tok = eat_token,
        );
        let (status, text) =
            post_json(&self.config.sts_token_url, None, &body, self.config.timeout).await?;
        if status != 200 {
            return Err(KmsError::Http { status, body: text });
        }
        json_str_field(&text, "access_token")
            .ok_or(KmsError::MissingToken)
    }

    /// Step 2 of the RATS Passport flow: present the IAM access token to
    /// Cloud KMS `Decrypt` to release the enclave key shard (S_enclave) into
    /// volatile RAM. The shard ciphertext is produced by the operator tooling
    /// (kms/operator tooling in the deploy pipeline) using the KMS public key.
    ///
    /// POST {base}/v1/{crypto_key_name}:decrypt  {"ciphertext": b64}
    pub async fn decrypt_key_shard(
        &self,
        access_token: &str,
        shard_ciphertext_b64: &str,
    ) -> Result<Vec<u8>, KmsError> {
        let url = format!(
            "{}/v1/{}:decrypt",
            self.config.kms_base_url.trim_end_matches('/'),
            self.config.crypto_key_name
        );
        let body = format!("{{\"ciphertext\":\"{ct}\"}}", ct = shard_ciphertext_b64);
        let (status, text) =
            post_json(&url, Some(access_token), &body, self.config.timeout).await?;
        if status != 200 {
            return Err(KmsError::Http { status, body: text });
        }
        let b64 = json_str_field(&text, "plaintext")
            .ok_or_else(|| KmsError::Parse("no plaintext field in decrypt response".into()))?;
        base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map_err(|e| KmsError::Parse(format!("plaintext is not valid base64: {e}")))
    }

    /// Full RATS Passport release: EAT -> access token -> decrypted shard.
    /// Fail-closed: any step error propagates and no shard material is ever
    /// produced.
    pub async fn release_enclave_shard(
        &self,
        eat_token: &str,
        shard_ciphertext_b64: &str,
    ) -> Result<Vec<u8>, KmsError> {
        let access_token = self.exchange_eat_for_access_token(eat_token).await?;
        self.decrypt_key_shard(&access_token, shard_ciphertext_b64)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_str_field_extracts_flat_string_values() {
        assert_eq!(
            json_str_field(r#"{"access_token":"abc123","expires_in":3600}"#, "access_token"),
            Some("abc123".to_string())
        );
        assert_eq!(
            json_str_field(r#"{"plaintext":"c2VjcmV0"}"#, "plaintext"),
            Some("c2VjcmV0".to_string())
        );
        assert_eq!(json_str_field(r#"{"a":1}"#, "b"), None);
    }
}
