// enclave/enclave_grpc/tests/test_rate_limit.rs
//
// Phase 11 (Prompt 211) — tower::limit ingress rate limiting.
//
// The router is built with default_ingress_layer() (100 req / 1s window,
// Prompt 210). A burst of 150 sequential requests completes in well under a
// second, so requests beyond the quota MUST be answered with gRPC status
// RESOURCE_EXHAUSTED — never silently accepted.
use enclave_grpc::grpc_server::build_router;
use enclave_grpc::proto::enclave_service_client::EnclaveServiceClient;
use enclave_grpc::proto::QueryRequest;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::Code;

const BURST: usize = 150;
const QUOTA: usize = 100;

#[tokio::test]
async fn burst_exceeding_quota_yields_resource_exhausted() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = build_router().await;
    tokio::spawn(async move {
        router
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .unwrap();
    });

    let mut client = EnclaveServiceClient::connect(format!("http://{addr}"))
        .await
        .unwrap();

    let mut ok = 0usize;
    let mut exhausted = 0usize;
    for i in 0..BURST {
        match client
            .execute_query(QueryRequest {
                document_id: format!("burst-{i}"),
                prompt: "rate limit probe".to_string(),
                encrypted_payload: Vec::new(),
            })
            .await
        {
            Ok(_) => ok += 1,
            Err(status) if status.code() == Code::ResourceExhausted => exhausted += 1,
            Err(status) => panic!("unexpected status in burst: {status:?}"),
        }
    }

    assert!(
        ok >= QUOTA,
        "expected at least the {QUOTA}/s quota to pass, got {ok}"
    );
    assert!(
        exhausted >= 1,
        "expected RESOURCE_EXHAUSTED for over-quota requests, got {exhausted}"
    );
    assert_eq!(ok + exhausted, BURST);
}
