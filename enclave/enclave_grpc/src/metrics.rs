// enclave/enclave_grpc/src/metrics.rs
//
// Phase 15 (Prompts 293-294) — Prometheus telemetry endpoint.
//
// The enclave exposes a standard Prometheus text-format /metrics endpoint on
// a separate HTTP port (ENCLAVE_METRICS_ADDR, default 127.0.0.1:8080) using
// the official `prometheus` Rust client crate — the same exposition format
// Prometheus itself scrapes. The gRPC surface stays untouched; metrics are
// an operational sidecar.
//
// Metrics:
//   enclave_query_total            — executed /v1 gRPC queries (counter)
//   enclave_query_seconds          — query wall time (histogram)
//   ftso_submissions_total         — price submissions prepared (counter)
//   ftso_ws_reconnects_total       — exchange reconnections (counter)
//   ftso_feed_stale                — 1 while any feed is stale (gauge)
//   ftso_feed_price_usd            — live aggregated price per feed (gauge)
//   ftso_feed_exchanges            — live exchanges contributing per feed (gauge)
//   enclave_process_start_seconds  — process start time (gauge)

use prometheus::{GaugeVec, HistogramOpts, HistogramVec, IntCounter, Opts, Registry, TextEncoder};
use std::net::SocketAddr;
use std::sync::OnceLock;

/// The global metrics registry + handles (lazy, process-wide).
pub struct Metrics {
    pub registry: Registry,
    pub queries_total: IntCounter,
    pub query_latency: HistogramVec,
    pub ftso_submissions_total: IntCounter,
    pub ftso_reconnects_total: IntCounter,
    pub ftso_feed_stale: prometheus::IntGauge,
    pub ftso_feed_price_usd: GaugeVec,
    pub ftso_feed_exchanges: GaugeVec,
}

impl Metrics {
    fn new() -> Self {
        let registry = Registry::new();
        let queries_total =
            IntCounter::with_opts(Opts::new("enclave_query_total", "Executed gRPC queries"))
                .expect("metric opts");
        let query_latency = HistogramVec::new(
            HistogramOpts::new(
                "enclave_query_seconds",
                "Wall time of gRPC ExecuteQuery calls",
            )
            .buckets(vec![0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0]),
            &["op"],
        )
        .expect("metric opts");
        let ftso_submissions_total = IntCounter::with_opts(Opts::new(
            "ftso_submissions_total",
            "Price submissions formatted by the FTSO provider node",
        ))
        .expect("metric opts");
        let ftso_reconnects_total = IntCounter::with_opts(Opts::new(
            "ftso_ws_reconnects_total",
            "Exchange WebSocket reconnections by the FTSO provider node",
        ))
        .expect("metric opts");        let ftso_feed_stale = prometheus::IntGauge::with_opts(Opts::new(
            "ftso_feed_stale",
            "1 while any FTSO provider feed is stale, else 0",
        ))
        .expect("metric opts");
        let ftso_feed_price_usd = GaugeVec::new(
            Opts::new("ftso_feed_price_usd", "Live aggregated median price per FTSO feed"),
            &["feed"],
        )
        .expect("metric opts");
        let ftso_feed_exchanges = GaugeVec::new(
            Opts::new(
                "ftso_feed_exchanges",
                "Live exchanges contributing to each FTSO feed",
            ),
            &["feed"],
        )
        .expect("metric opts");

        for c in [
            Box::new(queries_total.clone()) as Box<dyn prometheus::core::Collector>,
            Box::new(query_latency.clone()),
            Box::new(ftso_submissions_total.clone()),
            Box::new(ftso_reconnects_total.clone()),
            Box::new(ftso_feed_stale.clone()),
            Box::new(ftso_feed_price_usd.clone()),
            Box::new(ftso_feed_exchanges.clone()),
        ] {
            registry.register(c).expect("register metric");
        }

        Self {
            registry,
            queries_total,
            query_latency,
            ftso_submissions_total,
            ftso_reconnects_total,
            ftso_feed_stale,
            ftso_feed_price_usd,
            ftso_feed_exchanges,

        }
    }
}

static METRICS: OnceLock<Metrics> = OnceLock::new();

/// Process-wide metrics handle.
pub fn global() -> &'static Metrics {
    METRICS.get_or_init(Metrics::new)
}

/// The Prometheus text-format body for the whole registry.
pub fn render() -> String {
    let encoder = TextEncoder::new();
    let families = global().registry.gather();
    encoder
        .encode_to_string(&families)
        .expect("metrics encode cannot fail")
}

/// Start the /metrics HTTP sidecar (hyper 0.14, in-tree). Returns once the
/// listener is bound; serves until the process exits.
pub async fn start_metrics_server(addr: SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
    let make_svc = hyper::service::make_service_fn(|_conn| {
        let service = hyper::service::service_fn(|req: hyper::Request<hyper::Body>| {
            let path = req.uri().path().to_string();
            async move {
                if path == "/metrics" {
                    let body = render();
                    Ok::<_, hyper::Error>(
                        hyper::Response::builder()
                            .status(200)
                            .header("content-type", "text/plain; version=0.0.4")
                            .body(hyper::Body::from(body))
                            .expect("response build"),
                    )
                } else {
                    Ok(hyper::Response::builder()
                        .status(404)
                        .body(hyper::Body::from("not found"))
                        .expect("response build"))
                }
            }
        });
        // make_service_fn's closure must return a FUTURE yielding the service.
        async move { Ok::<_, hyper::Error>(service) }
    });
    let server = hyper::Server::bind(&addr).serve(make_svc);
    tracing::info!(%addr, "Prometheus /metrics endpoint listening");
    server.await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_render_is_valid_prometheus_text() {
        let body = render();
        // Content-type contract + HELP/TYPE lines per metric. Counters and
        // gauges always render (starting at 0 — no fabricated values); the
        // histogram family only appears once a sample is observed (the
        // prometheus crate skips empty labelled families).
        assert!(body.contains("# HELP enclave_query_total"));
        assert!(body.contains("# TYPE enclave_query_total counter"));
        assert!(body.contains("# TYPE ftso_submissions_total counter"));
        assert!(body.contains("# TYPE ftso_feed_stale gauge"));
        // The counter line renders with SOME integer value (0 before any
        // query — the exact value depends on test ordering, so assert the
        // metric line itself exists).
        assert!(body.contains("enclave_query_total "));
        assert!(!body.contains("enclave_query_seconds_bucket"));

        // Once a query runs, the histogram family appears with real buckets.
        global()
            .query_latency
            .with_label_values(&["execute_query"])
            .observe(0.042);
        let after = render();
        assert!(after.contains("# TYPE enclave_query_seconds histogram"));
        assert!(after.contains("enclave_query_seconds_bucket{op=\"execute_query\""));
        assert!(after.contains("enclave_query_seconds_count{op=\"execute_query\"} 1"));
    }

    #[test]
    fn counters_are_incrementable() {
        let m = global();
        m.queries_total.inc();
        m.ftso_submissions_total.inc_by(3);
        let body = render();
        assert!(body.contains("enclave_query_total 1"));
        assert!(body.contains("ftso_submissions_total 3"));
    }
}
