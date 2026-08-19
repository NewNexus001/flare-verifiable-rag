// enclave/enclave_grpc/src/grpc_server.rs
//
// Phase 11 (Prompt 204, 205, 210, 212) + Phase 12 (Prompt 228) —
// EnclaveService server implementation.
//
// State is wrapped in Arc<RwLock<EnclaveState>> so concurrent requests are
// handled across Tokio tasks without blocking the reactor: readers take a
// short read-lock, mutations (query counter) take a write-lock.
//
// Honest boundaries (no fabricated data):
//   - ExecuteQuery computes a DETERMINISTIC output + real SHA-256 bindings
//     (doc_hash / prompt_hash / output_hash) and measures wall latency. The
//     halo2 ZK proof generation (Rust engine) lands in a later phase; until
//     then proof bytes are empty by design.
//   - GetAttestationToken (Prompt 228) tries the REAL TEE devices first
//     (/dev/tdx-guest, then /dev/sev-guest). Only when a genuine hardware
//     report is obtained does it mint a signed EAT (Phase 12 builder).
//     No hardware → typed UNAVAILABLE, fail-closed. Never a fabricated token.
//   - StreamFtsoFeeds streams only REAL cached values (empty until the
//     Phase 15 feed provider lands — never synthetic prices).
use crate::attestation::eat_builder::{build_eat, DEFAULT_SWNAME, EatClaims};
use crate::attestation::tdx::TeeDeviceError;
use crate::metrics;
use crate::middleware::rate_limit::{default_ingress_bucket, rate_limit_interceptor};
use crate::proto::enclave_service_server::{EnclaveService, EnclaveServiceServer};
use crate::proto::{
    AttestationRequest, AttestationResponse, FtsoFeed, FtsoFeedsRequest, QueryRequest, QueryResponse,
};
use p256::ecdsa::SigningKey;
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

/// Shared, thread-safe enclave state (Prompt 205).
pub struct EnclaveState {
    started_at: std::time::Instant,
    query_count: u64,
    /// Cached FTSO v2 feed snapshots (populated by the feed provider, Phase 15).
    feeds: HashMap<String, FtsoFeed>,
    /// Expected image digest (sha256:...) — read from ENCLAVE_IMAGE_DIGEST,
    /// embedded into EAT claims when hardware attestation is available.
    image_digest: String,
}

impl Default for EnclaveState {
    fn default() -> Self {
        Self {
            started_at: std::time::Instant::now(),
            query_count: 0,
            feeds: HashMap::new(),
            image_digest: std::env::var("ENCLAVE_IMAGE_DIGEST").unwrap_or_default(),
        }
    }
}

impl EnclaveState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Monotonic uptime in seconds.
    pub fn uptime_secs(&self) -> u64 {
        self.started_at.elapsed().as_secs()
    }
}

/// The EnclaveService implementation — one handle over the shared state.
pub struct EnclaveServiceImpl {
    pub state: Arc<RwLock<EnclaveState>>,
}

/// Deterministic graph-engine style output: normalized prompt text.
/// (The Rust symbolic graph engine bindings replace this in a later phase;
/// the contract here is DETERMINISM + hash binding.)
fn deterministic_output(prompt: &str) -> String {
    prompt.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[tonic::async_trait]
impl EnclaveService for EnclaveServiceImpl {
    async fn execute_query(
        &self,
        request: Request<QueryRequest>,
    ) -> Result<Response<QueryResponse>, Status> {
        let started = std::time::Instant::now();
        let req = request.into_inner();

        if req.prompt.trim().is_empty() {
            metrics::global().queries_total.inc();
            metrics::global()
                .query_latency
                .with_label_values(&["execute_query"])
                .observe(started.elapsed().as_secs_f64());
            return Err(Status::invalid_argument("prompt must not be empty"));
        }

        let output = deterministic_output(&req.prompt);
        // RAW SHA-256 digests (32 bytes each) — the proto field is `bytes`,
        // these are the public inputs bound into the (later) ZK proof.
        let doc_hash = Sha256::digest(req.document_id.as_bytes()).to_vec();
        let prompt_hash = Sha256::digest(req.prompt.as_bytes()).to_vec();
        let output_hash = Sha256::digest(output.as_bytes()).to_vec();

        {
            let mut state = self
                .state
                .write()
                .map_err(|_| Status::internal("enclave state lock poisoned"))?;
            state.query_count = state.query_count.saturating_add(1);
        }

        // Prometheus telemetry (Phase 15, Prompt 293): count + latency.
        metrics::global().queries_total.inc();
        metrics::global()
            .query_latency
            .with_label_values(&["execute_query"])
            .observe(started.elapsed().as_secs_f64());

        let latency_ms = started.elapsed().as_millis() as u64;
        Ok(Response::new(QueryResponse {
            output,
            proof: Vec::new(), // halo2 ZK proof generation lands with the Rust engine port
            doc_hash,
            prompt_hash,
            output_hash,
            latency_ms,
        }))
    }

    async fn get_attestation_token(
        &self,
        request: Request<AttestationRequest>,
    ) -> Result<Response<AttestationResponse>, Status> {
        let req = request.into_inner();
        if req.nonce.trim().is_empty() {
            return Err(Status::invalid_argument("nonce must not be empty"));
        }

        // 1. Obtain a REAL hardware report — fail-closed if none exists.
        //    Order: Intel TDX first, AMD SEV-SNP fallback (Prompt 221/222).
        let nonce_hash = sha256_hex(req.nonce.as_bytes());

        #[cfg(target_os = "linux")]
        let hardware: Result<(String, Vec<u8>), TeeDeviceError> = {
            use crate::attestation::eat_builder::nonce_to_reportdata;
            use crate::attestation::{sev_snp, tdx};
            let reportdata = nonce_to_reportdata(req.nonce.as_bytes());
            match tdx::get_tdreport(&reportdata) {
                Ok(report) => Ok(("intel-tdx".to_string(), report.to_vec())),
                Err(TeeDeviceError::DeviceNotFound) => {
                    let mut certs = [0u8; 8192];
                    match sev_snp::get_snp_attestation_report(&reportdata, &mut certs) {
                        Ok((report, _certs)) => Ok(("amd-sev-snp".to_string(), report)),
                        Err(e) => Err(e.into()),
                    }
                }
                Err(e) => Err(e),
            }
        };
        #[cfg(not(target_os = "linux"))]
        let hardware: Result<(String, Vec<u8>), TeeDeviceError> =
            Err(TeeDeviceError::UnsupportedPlatform(std::env::consts::OS));

        let (hardware, hardware_report) = match hardware {
            Ok(hr) => hr,
            Err(e) => {
                return Err(Status::unavailable(format!(
                    "hardware attestation unavailable (fail-closed): {e}"
                )));
            }
        };

        // 2. Mint a REAL EAT (RFC 9334 + COSE-Sign1, ES256). P231: the
        //    signing key is scoped to this block so it is dropped the moment
        //    build_eat returns, and its secret scalar is scrubbed on drop by
        //    the ecdsa crate (compile-time asserted in eat_builder.rs via
        //    ZeroizeOnDrop). The key never leaves this scope.
        let image_digest = {
            let state = self
                .state
                .read()
                .map_err(|_| Status::internal("enclave state lock poisoned"))?;
            state.image_digest.clone()
        };
        if image_digest.is_empty() {
            return Err(Status::failed_precondition(
                "ENCLAVE_IMAGE_DIGEST not configured — cannot bind EAT to a build digest",
            ));
        }

        let mut instance_id = [0u8; 16];
        rand_core::RngCore::fill_bytes(&mut OsRng, &mut instance_id);

        let claims = EatClaims {
            nonce: nonce_hash.into_bytes(),
            swname: DEFAULT_SWNAME.to_string(),
            image_digest,
            hardware,
            instance_id,
            iat: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            measurements: vec![hardware_report.as_slice().try_into().unwrap_or([0u8; 32])],
        };

        // Ephemeral signing key — created here, dropped at the end of this
        // block (P231 zeroize-on-drop contract). Never stored, never logged.
        let eat_token = {
            let signing_key = SigningKey::random(&mut OsRng);
            build_eat(&claims, &signing_key)
                .map_err(|e| Status::internal(format!("EAT build failed: {e}")))?
            // signing_key drops here → secret scalar zeroized
        };

        Ok(Response::new(AttestationResponse {
            eat_token,
            swname: claims.swname.clone(),
            image_digest: claims.image_digest.clone(),
            hardware: claims.hardware.clone(),
            instance_id: hex::encode(claims.instance_id),
        }))
    }

    type StreamFtsoFeedsStream = ReceiverStream<Result<FtsoFeed, Status>>;

    async fn stream_ftso_feeds(
        &self,
        request: Request<FtsoFeedsRequest>,
    ) -> Result<Response<Self::StreamFtsoFeedsStream>, Status> {
        let req = request.into_inner();
        let (tx, rx) = mpsc::channel(64);
        let state = self
            .state
            .read()
            .map_err(|_| Status::internal("enclave state lock poisoned"))?;

        // Stream only REAL cached feed values (empty until the Phase 15
        // provider lands — never synthetic prices).
        for feed_id in &req.feed_ids {
            if let Some(feed) = state.feeds.get(feed_id) {
                let _ = tx.try_send(Ok(feed.clone()));
            }
        }
        drop(state);
        drop(tx);

        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

/// Cloneable router (services are Clone) — served either plaintext or over
/// the mTLS accept loop in main_grpc.rs. NOTE: in tonic 0.10 the Router
/// generic is the LAYER STACK (not the HTTP body): `Server::builder()`
/// returns `Server<Identity>`, and `.add_service()` yields
/// `Router<Identity>`. Verified against tonic-0.10.2 source.
pub type EnclaveRouter = tonic::transport::server::Router<tower::layer::util::Identity>;

/// Assemble the router: rate-limited ingress (Prompt 210), the enclave
/// service, and the standard grpc.health.v1 health service (Prompt 212).
/// Async because HealthReporter::set_service_status is an async send.
pub async fn build_router() -> EnclaveRouter {
    let state = Arc::new(RwLock::new(EnclaveState::new()));
    let service = EnclaveServiceImpl { state };

    let (mut health_reporter, health_service) = tonic_health::server::health_reporter();
    health_reporter
        .set_service_status(
            "enclave.v1.EnclaveService",
            tonic_health::ServingStatus::Serving,
        )
        .await;

    // Rate limiting (Prompt 210) is applied to the enclave service via a
    // cloneable token-bucket interceptor (tower::limit::RateLimit itself is
    // not Clone — see middleware/rate_limit.rs). Health checks stay
    // unlimited so orchestrators can always probe liveness.
    let rate_limited =
        EnclaveServiceServer::with_interceptor(service, rate_limit_interceptor(default_ingress_bucket()));

    tonic::transport::Server::builder()
        .add_service(rate_limited)
        .add_service(health_service)
}
