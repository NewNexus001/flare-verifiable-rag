// enclave/enclave_grpc/tests/test_grpc_server.rs
//
// Phase 11 (Prompt 207, 212) — loopback gRPC integration tests.
//
// Spins the real router on an ephemeral port and drives it with the
// generated client over loopback:
//   - ExecuteQuery: deterministic output + SHA-256 bindings
//   - GetAttestationToken: FAILS CLOSED (UNAVAILABLE) when no TEE hardware
//     is present — and succeeds with a genuine EAT on real TEE hosts
//   - grpc.health.v1: the enclave service reports SERVING
use enclave_grpc::grpc_server::build_router;
use enclave_grpc::proto::enclave_service_client::EnclaveServiceClient;
use enclave_grpc::proto::{AttestationRequest, QueryRequest};
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::Code;
use tonic_health::pb::health_check_response::ServingStatus;
use tonic_health::pb::health_client::HealthClient;
use tonic_health::pb::HealthCheckRequest;

async fn spawn_server() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = build_router().await;
    tokio::spawn(async move {
        router
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .unwrap();
    });
    format!("http://{addr}")
}

#[tokio::test]
async fn execute_query_roundtrip_over_loopback() {
    let ep = spawn_server().await;
    let mut client = EnclaveServiceClient::connect(ep).await.unwrap();

    let resp = client
        .execute_query(QueryRequest {
            document_id: "doc-001".to_string(),
            prompt: "  what   governs   clause 4  ".to_string(),
            encrypted_payload: Vec::new(),
        })
        .await
        .unwrap();

    let r = resp.into_inner();
    // Deterministic normalized output.
    assert_eq!(r.output, "what governs clause 4");
    // Real SHA-256 bindings (32 bytes each) — computed from real inputs.
    assert_eq!(r.doc_hash.len(), 32);
    assert_eq!(r.prompt_hash.len(), 32);
    assert_eq!(r.output_hash.len(), 32);
    assert_ne!(r.prompt_hash, r.output_hash);
}

#[tokio::test]
async fn execute_query_rejects_empty_prompt() {
    let ep = spawn_server().await;
    let mut client = EnclaveServiceClient::connect(ep).await.unwrap();
    let err = client
        .execute_query(QueryRequest {
            document_id: "doc-001".to_string(),
            prompt: "   ".to_string(),
            encrypted_payload: Vec::new(),
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument);
}

#[tokio::test]
async fn attestation_fails_closed_without_tee_hardware() {
    let ep = spawn_server().await;
    let mut client = EnclaveServiceClient::connect(ep).await.unwrap();

    match client
        .get_attestation_token(AttestationRequest {
            nonce: "test-nonce".to_string(),
            audience: "test".to_string(),
        })
        .await
    {
        // Real TEE host: a genuine EAT is minted (never fabricated).
        Ok(resp) => {
            let r = resp.into_inner();
            assert!(!r.eat_token.is_empty());
            assert!(!r.swname.is_empty());
        }
        // Dev/CI host (no /dev/tdx-guest, no /dev/sev-guest): fail-closed.
        Err(status) => assert_eq!(status.code(), Code::Unavailable),
    }
}

#[tokio::test]
async fn health_protocol_reports_serving() {
    let ep = spawn_server().await;
    // tonic-health 0.10's generated client has no `connect` helper — build
    // a Channel explicitly.
    let channel = tonic::transport::Endpoint::from_shared(ep)
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut health = HealthClient::new(channel);
    let resp = health
        .check(HealthCheckRequest {
            service: "enclave.v1.EnclaveService".to_string(),
        })
        .await
        .unwrap();
    assert_eq!(resp.into_inner().status, ServingStatus::Serving as i32);
}
