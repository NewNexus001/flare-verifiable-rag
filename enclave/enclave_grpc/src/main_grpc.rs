// enclave/enclave_grpc/src/main_grpc.rs
//
// Phase 11 (Prompt 208, 209, 218) — enclave gRPC entrypoint.
//
//   - tracing-subscriber JSON structured logging (Prompt 218)
//   - Sentry runtime panic capture (Prompt 209) — no-op when SENTRY_DSN unset
//   - graceful shutdown on SIGINT/SIGTERM, waiting for pending tasks to flush
//     (Prompt 208)
//   - mTLS mode: when ENCLAVE_TLS_CERT / ENCLAVE_TLS_KEY / ENCLAVE_CLIENT_CA
//     are all set, the router is served behind a rustls accept loop that
//     REQUIRES client certificates (Prompt 206). Otherwise plaintext on the
//     same port (local dev).
use enclave_grpc::ftso_provider::node::ProviderNode;
use enclave_grpc::grpc_server::build_router;
use enclave_grpc::metrics;
use enclave_grpc::tls_config;
use std::path::PathBuf;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

/// Newtype over the TLS stream so tonic 0.10's `Connected` bound (required
/// by serve_with_incoming*) is satisfied — tokio_rustls::TlsStream does not
/// implement it (verified against tonic-0.10.2 source).
#[derive(Debug)]
struct TlsStreamIo(tokio_rustls::server::TlsStream<TcpStream>);

impl AsyncRead for TlsStreamIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for TlsStreamIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

impl tonic::transport::server::Connected for TlsStreamIo {
    type ConnectInfo = std::net::SocketAddr;

    fn connect_info(&self) -> Self::ConnectInfo {
        // tokio-rustls 0.24: server TlsStream::get_ref() -> (&IO, &CommonState).
        self.0
            .get_ref()
            .0
            .peer_addr()
            .unwrap_or_else(|_| "0.0.0.0:0".parse().expect("valid socket addr"))
    }
}

/// Signal-driven graceful shutdown: SIGINT (Ctrl+C) and SIGTERM.
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install SIGINT handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => tracing::info!("SIGINT received — draining and shutting down"),
        _ = terminate => tracing::info!("SIGTERM received — draining and shutting down"),
    }
}

/// Serve the router over an mTLS accept loop: each connection must complete
/// a client-certificate-authenticated handshake before tonic serves it.
///
/// NOTE: tonic 0.10's Router is NOT Clone, so the correct pattern is ONE
/// router serving a STREAM of TLS connections (futures::stream::unfold),
/// not per-connection clones. Rejected handshakes (no/invalid client cert)
/// are logged and skipped — the connection is dropped (Prompt 215).
async fn serve_mtls(addr: std::net::SocketAddr, acceptor: TlsAcceptor) -> Result<(), Box<dyn std::error::Error>> {
    let router = build_router().await;
    let listener = TcpListener::bind(addr).await?;
    tracing::info!(%addr, "mTLS enclave gRPC listening");

    // ONE router, one incoming STREAM of TLS connections (Router is not
    // Clone in tonic 0.10). The acceptor is cheap to clone (Arc bump).
    let incoming = futures::stream::unfold(listener, move |listener| {
        let acceptor = acceptor.clone();
        async move {
            loop {
                let (stream, peer) = match listener.accept().await {
                    Ok(pair) => pair,
                    Err(e) => {
                        tracing::warn!(error = %e, "accept failed — stopping");
                        return None;
                    }
                };
                match acceptor.accept(stream).await {
                    Ok(tls_stream) => {
                        tracing::debug!(%peer, "mTLS handshake accepted");
                        return Some((Ok::<_, std::io::Error>(TlsStreamIo(tls_stream)), listener));
                    }
                    Err(e) => {
                        // Unauthenticated / invalid client certs land here —
                        // the handshake is REJECTED, connection closed.
                        tracing::warn!(%peer, error = %e, "mTLS handshake REJECTED");
                        continue;
                    }
                }
            }
        }
    });

    router
        .serve_with_incoming_shutdown(incoming, shutdown_signal())
        .await?;
    Ok(())
}

async fn serve_plaintext(addr: std::net::SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
    let router = build_router().await;
    tracing::info!(%addr, "enclave gRPC listening (plaintext dev mode)");
    router
        .serve_with_shutdown(addr, shutdown_signal())
        .await?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // JSON structured logging (Prompt 218) — first thing configured.
    tracing_subscriber::fmt()
        .with_max_level(
            std::env::var("RUST_LOG")
                .ok()
                .and_then(|l| l.parse().ok())
                .unwrap_or(tracing::Level::INFO),
        )
        .json()
        .init();

    // Sentry panic capture (Prompt 209). Without SENTRY_DSN this is a no-op
    // client — the app never fails because Sentry is absent.
    let _sentry_guard = sentry::init(sentry::ClientOptions {
        dsn: std::env::var("SENTRY_DSN")
            .ok()
            .map(|d| d.parse().expect("SENTRY_DSN must be a valid DSN")),
        release: Some(format!("enclave_grpc@{}", env!("CARGO_PKG_VERSION")).into()),
        ..Default::default()
    });
    // Panic capture (sentry 0.32: sentry::integrations::panic::panic_handler
    // is the handler; registration is NOT automatic — chain it on top of the
    // default hook so stderr output is preserved).
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        sentry::integrations::panic::panic_handler(info);
        default_hook(info);
    }));

    // Prometheus /metrics sidecar (Phase 15, Prompt 293) — separate HTTP
    // port so the gRPC surface is untouched.
    let metrics_addr: std::net::SocketAddr = std::env::var("ENCLAVE_METRICS_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8080".to_string())
        .parse()?;
    tokio::spawn(async move {
        if let Err(e) = metrics::start_metrics_server(metrics_addr).await {
            tracing::error!(error = %e, "metrics server failed");
        }
    });

    // Enclave-hosted FTSO v2 provider node (Phase 15) + telemetry sync:
    // the node daemon runs in its own Tokio tasks (exchange connectors +
    // staleness monitor); a small task mirrors its counters into Prometheus.
    let provider_node = ProviderNode::start();
    tokio::spawn(async move {
        let mut every = tokio::time::interval(std::time::Duration::from_secs(5));
        // Prometheus counters must receive deltas, not running totals.
        let mut last_reconnects: u64 = 0;
        loop {
            every.tick().await;
            let total = provider_node.reconnects_total();
            metrics::global()
                .ftso_reconnects_total
                .inc_by(total.saturating_sub(last_reconnects));
            last_reconnects = total;
            metrics::global().ftso_feed_stale.set(provider_node.is_stale() as i64);
            // Mirror the live aggregated prices (volume-trimmed median of the
            // exchanges currently streaming) into Prometheus gauges — the
            // /metrics endpoint therefore shows REAL live market prices.
            let snapshot = provider_node.snapshot();
            for (feed, (price, exchanges)) in &snapshot.prices {
                metrics::global()
                    .ftso_feed_price_usd
                    .with_label_values(&[feed])
                    .set(*price);
                metrics::global()
                    .ftso_feed_exchanges
                    .with_label_values(&[feed])
                    .set(*exchanges as f64);
            }
        }
    });

    let addr: std::net::SocketAddr = std::env::var("ENCLAVE_GRPC_ADDR")
        .unwrap_or_else(|_| "[::1]:50051".to_string())
        .parse()?;

    // mTLS mode when all three files are configured (Prompt 206).
    let cert = std::env::var("ENCLAVE_TLS_CERT").ok().map(PathBuf::from);
    let key = std::env::var("ENCLAVE_TLS_KEY").ok().map(PathBuf::from);
    let ca = std::env::var("ENCLAVE_CLIENT_CA").ok().map(PathBuf::from);

    match (cert, key, ca) {
        (Some(cert), Some(key), Some(ca)) => {
            let config = tls_config::load_server_config(&cert, &key, &ca)?;
            let acceptor = tls_config::tls_acceptor(config);
            serve_mtls(addr, acceptor).await?;
        }
        (None, None, None) => {
            serve_plaintext(addr).await?;
        }
        _ => {
            return Err("set ENCLAVE_TLS_CERT, ENCLAVE_TLS_KEY AND ENCLAVE_CLIENT_CA together".into());
        }
    }

    tracing::info!("enclave gRPC shutdown complete");
    Ok(())
}
