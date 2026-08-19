// enclave/enclave_grpc/tests/test_ftso_node.rs
//
// Phase 15 (Prompts 289-290, 292) — FTSO provider node integration tests
// against a LOOPBACK WebSocket server (test-only fixture, same pattern as
// the KMS emulator and the zkTLS loopback TLS server).
//
//   Prompt 289/290 — staleness monitoring + automatic reconnection: the
//     production connector machinery (connect, subscribe, parse, backoff,
//     reconnect) is driven against a local server that closes connections
//     and goes silent, and the node must recover and report stale feeds.
//   Prompt 292 — memory footprint gate: the running node must stay under
//     50 MB of physical RSS (measured with the memory-stats crate).
//
// The loopback server is a real WebSocket endpoint speaking the real
// Coinbase ticker JSON — the parsers under test are the production ones.

use std::time::Duration;

use enclave_grpc::ftso_provider::node::{ExchangeId, ProviderNode};
use futures::{SinkExt, StreamExt};
use tokio::net::TcpListener;
use tokio_tungstenite::accept_async;
use tokio_tungstenite::tungstenite::Message;

/// One ticker message in the real Coinbase wire format (the same JSON the
/// production parser consumes).
const TICKER_BTC: &str = r#"{"type":"ticker","product_id":"BTC-USD","price":"64001.23","volume_24h":"1234.5"}"#;

/// A loopback WebSocket server. Each accepted connection:
///   mode = SendOnce: sends one ticker then closes (drives reconnection).
///   mode = Silent:   sends nothing and stays open (drives staleness).
#[derive(Clone, Copy, PartialEq)]
enum ServerMode {
    SendOnce,
    Silent,
}

async fn spawn_ws_server(mode: ServerMode) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(_) => break,
            };
            tokio::spawn(async move {
                let mut ws = match accept_async(stream).await {
                    Ok(ws) => ws,
                    Err(_) => return,
                };
                match mode {
                    ServerMode::SendOnce => {
                        if ws.send(Message::Text(TICKER_BTC.into())).await.is_err() {
                            return;
                        }
                        // Let the message flush, then drop the connection.
                        let _ = ws.flush().await;
                    }
                    ServerMode::Silent => {
                        // Hold the connection open, never send anything.
                        let _ = ws.next().await;
                    }
                }
            });
        }
    });
    addr
}

/// Poll `f` until it returns true or the timeout elapses.
async fn wait_until<F>(f: F, timeout: Duration)
where
    F: Fn() -> bool,
{
    let deadline = tokio::time::Instant::now() + timeout;
    while !f() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "condition not met within {timeout:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn reconnects_after_connection_drop() {
    // Server closes every connection right after one ticker → the connector
    // must notice and reconnect, and the book must keep filling.
    let addr = spawn_ws_server(ServerMode::SendOnce).await;
    let url = format!("ws://{addr}");
    let node = ProviderNode::start_with_urls(
        Duration::from_secs(30), // staleness irrelevant here
        vec![(ExchangeId::Coinbase, url)],
    );

    // First connection delivers the ticker.
    wait_until(
        || !node.snapshot().prices.is_empty(),
        Duration::from_secs(10),
    )
    .await;
    let snap = node.snapshot();
    let (price, sources) = snap.prices.get("BTC/USD").expect("BTC/USD price");
    assert_eq!(*price, 64001.23);
    assert_eq!(*sources, 1);

    // The server drops the connection → automatic reconnection fires.
    wait_until(
        || node.reconnects_total() >= 1,
        Duration::from_secs(10),
    )
    .await;

    // And after the reconnect the book is still being fed fresh data.
    wait_until(
        || node.live_exchanges("BTC/USD") >= 1,
        Duration::from_secs(10),
    )
    .await;
}

#[tokio::test]
async fn staleness_monitor_flags_silent_feed() {
    // A connection that never sends anything → the feed has no fresh data →
    // the staleness monitor (1s threshold) must flag it and alert (Sentry
    // is a no-op without a DSN; the flag + trace are the observable state).
    let addr = spawn_ws_server(ServerMode::Silent).await;
    let url = format!("ws://{addr}");
    let node = ProviderNode::start_with_urls(
        Duration::from_millis(500),
        vec![(ExchangeId::Coinbase, url)],
    );

    wait_until(|| node.is_stale(), Duration::from_secs(10)).await;
    let stale = node.stale_feeds();
    assert!(stale.contains(&"BTC/USD"), "BTC/USD must be stale: {stale:?}");
}

#[tokio::test]
async fn memory_footprint_stays_under_50mb() {
    // Prompt 292 gate: the provider node (connectors + book + parsers)
    // running with live loopback tickers must stay under 50 MB physical RSS.
    let addr = spawn_ws_server(ServerMode::SendOnce).await;
    let url = format!("ws://{addr}");

    // Baseline after the runtime is warm.
    let before = memory_stats::memory_stats()
        .expect("memory_stats on this platform")
        .physical_mem;

    let node = ProviderNode::start_with_urls(
        Duration::from_secs(30),
        vec![(ExchangeId::Coinbase, url)],
    );

    // Let it run: connect, feed, reconnect, feed — several cycles.
    wait_until(
        || node.reconnects_total() >= 2,
        Duration::from_secs(15),
    )
    .await;

    let after = memory_stats::memory_stats()
        .expect("memory_stats on this platform")
        .physical_mem;

    let delta_mb = (after.saturating_sub(before)) as f64 / (1024.0 * 1024.0);
    let budget_mb = 50.0;
    assert!(
        delta_mb < budget_mb,
        "provider node RSS grew {delta_mb:.2} MB — over the {budget_mb} MB budget"
    );
    // Log the measured footprint for the PoW report.
    eprintln!("[P292] provider node + fixture RSS delta: {delta_mb:.2} MB");
}
