// enclave/enclave_grpc/src/bin/client_cli.rs
//
// Phase 11 (Prompt 216) — command-line gRPC client for local debugging.
//
// Usage:
//   client_cli --endpoint http://[::1]:50051 query <document_id> <prompt>
//   client_cli --endpoint http://[::1]:50051 attest <nonce>
//   client_cli --endpoint http://[::1]:50051 stream FXRP/USD,BTC/USD
//   client_cli --endpoint http://[::1]:50051 health
use enclave_grpc::proto::enclave_service_client::EnclaveServiceClient;
use enclave_grpc::proto::{AttestationRequest, FtsoFeedsRequest, QueryRequest};
use futures::StreamExt;

const DEFAULT_ENDPOINT: &str = "http://[::1]:50051";

fn usage() -> ! {
    eprintln!(
        "usage: client_cli [--endpoint <addr>] <query|attest|stream|health> [args...]\n  \
         query <document_id> <prompt>\n  \
         attest <nonce>\n  \
         stream <feed1,feed2,...>\n  \
         health"
    );
    std::process::exit(2);
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();

    let mut endpoint = DEFAULT_ENDPOINT.to_string();
    let mut rest: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--endpoint" => {
                i += 1;
                endpoint = args
                    .get(i)
                    .cloned()
                    .unwrap_or_else(|| usage());
            }
            other => rest.push(other.to_string()),
        }
        i += 1;
    }
    if rest.is_empty() {
        usage();
    }
    let cmd = rest[0].clone();
    let params = &rest[1..];

    let mut client = EnclaveServiceClient::connect(endpoint.clone()).await?;

    match cmd.as_str() {
        "query" => {
            let document_id = params.first().cloned().unwrap_or_else(|| usage());
            let prompt = params.get(1).cloned().unwrap_or_else(|| usage());
            let started = std::time::Instant::now();
            let resp = client
                .execute_query(QueryRequest {
                    document_id,
                    prompt,
                    encrypted_payload: Vec::new(),
                })
                .await?;
            let r = resp.into_inner();
            println!("--- ExecuteQuery ---");
            println!("output:      {}", r.output);
            println!("doc_hash:    0x{}", hex::encode(r.doc_hash));
            println!("prompt_hash: 0x{}", hex::encode(r.prompt_hash));
            println!("output_hash: 0x{}", hex::encode(r.output_hash));
            println!("proof bytes: {} (ZK engine lands in a later phase)", r.proof.len());
            println!("latency:     {} ms (wall, incl. ~{} ms RTT)", r.latency_ms, started.elapsed().as_millis());
        }
        "attest" => {
            let nonce = params.first().cloned().unwrap_or_else(|| usage());
            match client
                .get_attestation_token(AttestationRequest {
                    nonce,
                    audience: "cli".to_string(),
                })
                .await
            {
                Ok(resp) => {
                    let r = resp.into_inner();
                    println!("--- GetAttestationToken ---");
                    println!("swname:       {}", r.swname);
                    println!("hardware:     {}", r.hardware);
                    println!("image_digest: {}", r.image_digest);
                    println!("instance_id:  {}", r.instance_id);
                    println!("eat_token:    {} bytes (COSE-Sign1)", r.eat_token.len());
                }
                Err(status) => {
                    println!("--- GetAttestationToken: fail-closed ---");
                    println!("code:    {}", status.code());
                    println!("message: {}", status.message());
                }
            }
        }
        "stream" => {
            let feeds = params
                .first()
                .cloned()
                .unwrap_or_else(|| usage())
                .split(',')
                .map(|s| s.to_string())
                .collect::<Vec<_>>();
            println!("--- StreamFtsoFeeds (max 10) ---");
            let mut stream = client
                .stream_ftso_feeds(FtsoFeedsRequest {
                    feed_ids: feeds,
                    max_updates: 10,
                })
                .await?
                .into_inner();
            let mut count = 0usize;
            while let Some(item) = stream.next().await {
                let feed = item?;
                println!(
                    "  {} = {} @ ts={}",
                    feed.feed_id, feed.price, feed.timestamp
                );
                count += 1;
                if count >= 10 {
                    break;
                }
            }
            println!("stream ended ({} items — provider lands in Phase 15)", count);
        }
        "health" => {
            // tonic-health 0.10's generated client has no `connect` helper —
            // build a Channel explicitly.
            let channel = tonic::transport::Endpoint::from_shared(endpoint.clone())?
                .connect()
                .await?;
            let mut health = tonic_health::pb::health_client::HealthClient::new(channel);
            let resp = health
                .check(tonic_health::pb::HealthCheckRequest {
                    service: "".to_string(),
                })
                .await?;
            let status = resp.into_inner().status;
            println!("--- grpc.health.v1 ---");
            println!("status: {:?}", status);
        }
        _ => usage(),
    }

    Ok(())
}
