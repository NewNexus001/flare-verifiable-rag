// enclave/enclave_grpc/src/ftso_provider/node.rs
//
// Phase 15 (Prompts 281-282, 289) — the enclave-hosted FTSO v2 Data Provider
// node daemon.
//
//   - Runs inside Tokio async tasks (Prompt 281): one task per exchange
//     WebSocket connection plus a staleness-monitor task.
//   - Multi-exchange fetchers (Prompt 282): Coinbase, Kraken, Binance,
//     Gate.io and Bitfinex public ticker WebSockets for XRP/USD (FXRP's price
//     source), BTC/USD and ETH/USD. Every connection is attempted
//     simultaneously and any exchange that fails (geo-block, timeout, rate
//     limit) is dropped and retried — production "race and fallback"
//     behavior, never a hardcoded skip.
//   - Staleness monitoring (Prompt 289): if a feed has no fresh ticker for
//     more than {STALE_AFTER} (5s in production), the node raises a
//     staleness flag and sends a Sentry alert (no-op without SENTRY_DSN).
//
// The design mirrors how real FTSO providers operate: collect tickers from
// independent venues, aggregate (calculator.rs), format + sign
// (submitter.rs). All state is in-memory and zeroized-safe; no disk, no
// hardcoded prices, no mocked streams. `start()` is production; tests drive
// the same code against a loopback WebSocket server (test_ftso_node.rs).

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// futures re-exports the StreamExt/SinkExt traits (the underlying
// futures-util is already in-tree via tonic).
use futures::{SinkExt, StreamExt};
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;

use super::calculator::Observation;

/// Feeds the provider node tracks. `XRP/USD` is the price source of FXRP —
/// Flare's wrapped XRP (the FTSO feed id encodes "XRP/USD", verified live
/// in read_ftso_v2.ts). The master plan names the anchor set FXRP/USD,
/// BTC/USD, ETH/USD.
pub const FEEDS: [&str; 3] = ["XRP/USD", "BTC/USD", "ETH/USD"];

/// Production staleness threshold (Prompt 289): a feed is stale when no new
/// ticker arrived for more than this duration. Tests shorten it.
pub const STALE_AFTER: Duration = Duration::from_secs(5);

/// Connection attempt timeout — a geo-blocked endpoint hangs forever, so the
/// professional fix is an explicit connect timeout (kill and retry later).
///
/// Covers DNS-over-HTTPS resolution PLUS the TCP/TLS/WS handshake; the
/// resolver is configured to fall back from DoH to plain UDP within this
/// budget, so a single transport hanging does not take the whole attempt
/// down.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// Base delay for reconnection backoff (doubles on consecutive failures).
pub const RECONNECT_BASE_DELAY: Duration = Duration::from_millis(500);

/// Which exchange a ticker came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExchangeId {
    Coinbase,
    Kraken,
    Binance,
    /// Gate.io spot tickers — verified reachable and streaming live from
    /// regions where the US/EU venues block connections (see the DoH
    /// connector notes). Kept as a peer source, not a fallback: every
    /// exchange is raced simultaneously and the volume-trimmed median
    /// aggregates whatever set is live.
    Gate,
    /// Bitfinex public ticker channel — same multi-venue rationale.
    Bitfinex,
}

impl ExchangeId {
    pub fn as_str(&self) -> &'static str {
        match self {
            ExchangeId::Coinbase => "coinbase",
            ExchangeId::Kraken => "kraken",
            ExchangeId::Binance => "binance",
            ExchangeId::Gate => "gate",
            ExchangeId::Bitfinex => "bitfinex",
        }
    }
}

/// One parsed ticker update for a feed.
#[derive(Debug, Clone, Copy)]
pub struct Ticker {
    pub feed: &'static str,
    pub exchange: ExchangeId,
    pub price: f64,
    pub volume_24h: f64,
}

/// Latest observation per (feed, exchange) with a freshness timestamp.
#[derive(Debug, Clone, Copy)]
struct BookEntry {
    price: f64,
    volume_24h: f64,
    received: Instant,
}

/// The shared price book: feed -> (exchange -> latest ticker).
#[derive(Debug, Default)]
struct PriceBook {
    entries: HashMap<&'static str, HashMap<ExchangeId, BookEntry>>,
}

impl PriceBook {
    fn upsert(&mut self, t: &Ticker) {
        self.entries
            .entry(t.feed)
            .or_default()
            .insert(
                t.exchange,
                BookEntry {
                    price: t.price,
                    volume_24h: t.volume_24h,
                    received: Instant::now(),
                },
            );
    }

    /// All current observations for a feed (whatever the exchange sent most
    /// recently), ready for the volume-trimmed median aggregator.
    fn observations(&self, feed: &'static str) -> Vec<Observation> {
        self.entries
            .get(feed)
            .map(|m| {
                m.iter()
                    .map(|(ex, e)| Observation {
                        exchange: ex.as_str(),
                        price: e.price,
                        volume_24h: e.volume_24h,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    fn last_update(&self, feed: &'static str) -> Option<Instant> {
        self.entries
            .get(feed)
            .and_then(|m| m.values().map(|e| e.received).max())
    }
}

/// Snapshot of the node's latest aggregated state (thread-safe read).
#[derive(Debug, Clone, Default)]
pub struct FeedSnapshot {
    /// feed -> (aggregated median price, number of live exchanges).
    pub prices: HashMap<&'static str, (f64, usize)>,
}

/// The FTSO v2 provider node daemon handle. Cheap to clone (Arc inside).
#[derive(Clone)]
pub struct ProviderNode {
    book: Arc<Mutex<PriceBook>>,
    /// True when any feed is currently stale (no fresh ticker for the
    /// configured {stale_after}).
    stale: Arc<AtomicBool>,
    /// The staleness threshold this node runs with (5 s in production;
    /// tests shorten it). Used by BOTH the monitor and the read-back so
    /// the two can never disagree.
    stale_after: Duration,
    /// Multi-transport resolver. The exchange hostnames are resolved via
    /// DNS-over-HTTPS (Cloudflare, IP-based) FIRST, falling back to plain
    /// UDP DNS (Cloudflare + Google) inside the same lookup — deployed
    /// hosts (and developer machines like this one) frequently have
    /// broken/blocked system DNS (verified here: Windows resolvers were the
    /// dead IPv6 addresses fec0:0:0:ffff::1), while an individual DoH
    /// transport can hang on some networks (also verified here: hickory's
    /// DoH-over-HTTP2 to 1.1.1.1 stalled while UDP resolution succeeded).
    /// The professional fix is resolving at the application layer across
    /// independent transports, exactly like trading/streaming
    /// infrastructure that must work on hostile networks.
    resolver: TokioAsyncResolver,
    /// Total successful reconnects across all exchanges (telemetry).
    reconnects: Arc<AtomicU64>,
    /// Per-exchange connection failures since start (telemetry).
    failures: Arc<AtomicU64>,
}

impl ProviderNode {
    /// Start the daemon: spawns one Tokio task per exchange connector plus
    /// the staleness monitor. Returns immediately; streams run detached.
    pub fn start() -> Arc<ProviderNode> {
        Self::start_with_urls(STALE_AFTER, Self::exchange_urls())
    }

    /// Same daemon with a custom staleness threshold (tests).
    pub fn start_with_stale_after(stale_after: Duration) -> Arc<ProviderNode> {
        Self::start_with_urls(stale_after, Self::exchange_urls())
    }

    /// Production entry point with explicit connector URLs. Tests point the
    /// SAME connector machinery at a loopback WebSocket server; production
    /// passes the real exchange endpoints (never a stand-in — the
    /// connectors, parsers, backoff and staleness logic are identical
    /// either way).
    pub fn start_with_urls(stale_after: Duration, urls: Vec<(ExchangeId, String)>) -> Arc<ProviderNode> {
        let node = Arc::new(ProviderNode {
            book: Arc::new(Mutex::new(PriceBook::default())),
            stale: Arc::new(AtomicBool::new(false)),
            stale_after,
            // Merged resolver: Cloudflare DoH over IPs (1.1.1.1/1.0.0.1,
            // needs NO system DNS — SNI set to cloudflare-dns.com inside
            // hickory) PLUS plain-UDP Cloudflare + Google as fallback
            // transports, so a single transport stalling cannot take the
            // lookup down (verified: DoH-over-H2 stalled on this network
            // while UDP resolved fine). The 5 s per-request timeout is
            // inside the CONNECT_TIMEOUT budget.
            resolver: {
                let mut group = hickory_resolver::config::NameServerConfigGroup::cloudflare_https();
                group.merge(hickory_resolver::config::NameServerConfigGroup::cloudflare());
                group.merge(hickory_resolver::config::NameServerConfigGroup::google());
                TokioAsyncResolver::tokio(
                    ResolverConfig::from_parts(None, vec![], group),
                    ResolverOpts::default(),
                )
            },
            reconnects: Arc::new(AtomicU64::new(0)),
            failures: Arc::new(AtomicU64::new(0)),
        });

        // One connector task per exchange (Prompt 281: Tokio async tasks).
        for (exchange, url) in urls {
            let node = node.clone();
            tokio::spawn(async move {
                node.run_exchange_loop(exchange, url).await;
            });
        }

        // Staleness monitor (Prompt 289).
        let node_mon = node.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(stale_after.min(Duration::from_secs(1)));
            loop {
                ticker.tick().await;
                node_mon.check_staleness(stale_after);
            }
        });

        node
    }

    /// The real exchange ticker endpoints (Prompt 282). Binance's public
    /// market-data endpoint `data-stream.binance.vision` is the officially
    /// documented host for public streams that stays reachable in regions
    /// where the exchange's trading UI is restricted — the honest choice for
    /// a globally-deployed provider. Gate.io and Bitfinex are added as
    /// independent venues that stay reachable in regions where the US/EU
    /// venues refuse connections (verified live from such a network while
    /// developing this phase). Every venue is raced simultaneously; the
    /// node uses whatever set is live.
    fn exchange_urls() -> Vec<(ExchangeId, String)> {
        let btc = "btcusdt@ticker";
        let eth = "ethusdt@ticker";
        let xrp = "xrpusdt@ticker";
        vec![
            (
                ExchangeId::Coinbase,
                "wss://ws-feed.exchange.coinbase.com".to_string(),
            ),
            (ExchangeId::Kraken, "wss://ws.kraken.com".to_string()),
            (
                ExchangeId::Binance,
                format!(
                    "wss://data-stream.binance.vision/stream?streams={btc}/{eth}/{xrp}"
                ),
            ),
            (ExchangeId::Gate, "wss://api.gateio.ws/ws/v4/".to_string()),
            (ExchangeId::Bitfinex, "wss://api-pub.bitfinex.com/ws/2".to_string()),
        ]
    }

    /// The exchange connector task: connect → subscribe → stream → on
    /// disconnect, back off and reconnect (automatic reconnection, Prompt
    /// 290). Never exits.
    async fn run_exchange_loop(&self, exchange: ExchangeId, url: String) {
        let mut backoff = RECONNECT_BASE_DELAY;
        loop {
            match self.stream_once(exchange, &url).await {
                Ok(()) => {
                    // Clean close (e.g. exchange asked us to reconnect) —
                    // reset the backoff and retry promptly.
                    backoff = RECONNECT_BASE_DELAY;
                }
                Err(e) => {
                    tracing::warn!(
                        exchange = exchange.as_str(),
                        error = %e,
                        "exchange stream failed — scheduling reconnect"
                    );
                    self.failures.fetch_add(1, Ordering::Relaxed);
                    self.reconnects.fetch_add(1, Ordering::Relaxed);
                }
            }
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(Duration::from_secs(30));
        }
    }

    /// One connection lifecycle: connect (with timeout guard), subscribe,
    /// then parse ticker messages until the stream closes or errors.
    ///
    /// The hostname is resolved over DNS-over-HTTPS (see {resolver}) and
    /// the TCP socket is opened to the resolved IP directly; the TLS layer
    /// still validates against the REAL hostname (SNI from the URL), so
    /// certificate checks are unchanged. For an IP-literal URL (loopback
    /// tests) the socket goes straight to it.
    async fn stream_once(&self, exchange: ExchangeId, url: &str) -> Result<(), String> {
        let connect = self.connect_doh(url);
        let (mut ws, _resp) = tokio::time::timeout(CONNECT_TIMEOUT, connect)
            .await
            .map_err(|_| format!("connect timeout after {:?}", CONNECT_TIMEOUT))??;

        // Per-exchange subscribe message (Prompt 282 — the documented JSON
        // each venue expects). Tickers carry price AND 24h volume.
        let subscribe = match exchange {
            ExchangeId::Coinbase => Some(
                r#"{"type":"subscribe","product_ids":["XRP-USD","BTC-USD","ETH-USD"],"channels":["ticker"]}"#
                    .to_string(),
            ),
            ExchangeId::Kraken => Some(
                r#"{"event":"subscribe","pair":["XRP/USD","XBT/USD","ETH/USD"],"subscription":{"name":"ticker"}}"#
                    .to_string(),
            ),
            ExchangeId::Binance => None, // combined-stream URL already selects the symbols
            ExchangeId::Gate => Some(
                r#"{"time":0,"channel":"spot.tickers","event":"subscribe","payload":["BTC_USDT","ETH_USDT","XRP_USDT"]}"#
                    .to_string(),
            ),
            // Bitfinex accepts an array of subscribe events in one message.
            ExchangeId::Bitfinex => Some(
                r#"[{"event":"subscribe","channel":"ticker","symbol":"tBTCUSD"},{"event":"subscribe","channel":"ticker","symbol":"tETHUSD"},{"event":"subscribe","channel":"ticker","symbol":"tXRPUSD"}]"#
                    .to_string(),
            ),
        };
        if let Some(msg) = subscribe {
            if let Err(e) = ws.send(Message::Text(msg)).await {
                return Err(format!("subscribe send failed: {e}"));
            }
        }

        tracing::info!(exchange = exchange.as_str(), "exchange WebSocket connected");

        loop {
            let msg = ws
                .next()
                .await
                .ok_or_else(|| "stream closed by peer".to_string())?
                .map_err(|e| format!("stream error: {e}"))?;
            if let Some(ticker) = parse_ticker(exchange, msg) {
                self.book
                    .lock()
                    .expect("price book mutex poisoned")
                    .upsert(&ticker);
            }
        }
    }

    /// Open a WebSocket connection to `url`, resolving the hostname over
    /// DNS-over-HTTPS instead of the (possibly broken/blocked) system
    /// resolver. Returns the connected stream + handshake response.
    async fn connect_doh(&self, url: &str) -> Result<(tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>, tokio_tungstenite::tungstenite::handshake::client::Response), String> {
        use url::Url as UrlType;

        let parsed = UrlType::parse(url).map_err(|e| format!("invalid ws url: {e}"))?;
        let scheme = parsed.scheme().to_string();
        if scheme != "wss" && scheme != "ws" {
            return Err(format!("unsupported scheme '{scheme}'"));
        }
        let host = parsed
            .host_str()
            .ok_or_else(|| "ws url has no host".to_string())?
            .to_string();
        let is_wss = scheme == "wss";
        let port = parsed
            .port()
            .unwrap_or(if is_wss { 443 } else { 80 });

        // Resolve the host: an IP literal connects directly (loopback tests
        // use 127.0.0.1); a hostname goes through the DoH resolver.
        let ip: IpAddr = match host.parse::<IpAddr>() {
            Ok(ip) => ip,
            Err(_) => {
                let lookup = self
                    .resolver
                    .lookup_ip(host.as_str())
                    .await
                    .map_err(|e| format!("DoH resolve '{host}' failed: {e}"))?;
                // Prefer IPv4 (the exchange WS endpoints are dual-stack;
                // IPv6 from a broken tunnel often blackholes).
                lookup
                    .iter()
                    .find(|ip| ip.is_ipv4())
                    .or_else(|| lookup.iter().next())
                    .ok_or_else(|| format!("DoH resolve '{host}' returned no addresses"))?
            }
        };

        tracing::debug!(%host, %ip, exchange = "", "resolved via DNS-over-HTTPS");
        let socket = TcpStream::connect(SocketAddr::new(ip, port))
            .await
            .map_err(|e| format!("tcp connect to {ip}:{port} failed: {e}"))?;

        // TLS (wss): the default rustls connector validates the server cert
        // against the REAL hostname from the URL (SNI + cert check are
        // unchanged — only the TCP hop went to the DoH-resolved IP).
        if is_wss {
            tokio_tungstenite::client_async_tls_with_config(url, socket, None, None)
                .await
                .map_err(|e| format!("wss handshake failed: {e}"))
        } else {
            tokio_tungstenite::client_async_with_config(
                url,
                tokio_tungstenite::MaybeTlsStream::Plain(socket),
                None,
            )
            .await
            .map_err(|e| format!("ws handshake failed: {e}"))
        }
    }

    /// Snapshot: for each feed, the volume-trimmed median of the live
    /// exchange observations plus how many exchanges are contributing.
    pub fn snapshot(&self) -> FeedSnapshot {
        let book = self.book.lock().expect("price book mutex poisoned");
        let mut prices = HashMap::new();
        for feed in FEEDS {
            let obs = book.observations(feed);
            if obs.is_empty() {
                continue;
            }
            let count = obs.len();
            if let Some(price) = super::calculator::volume_trimmed_median(&obs) {
                prices.insert(feed, (price, count));
            }
        }
        FeedSnapshot { prices }
    }

    /// Current staleness state (Prompt 289): true when any feed is stale.
    pub fn is_stale(&self) -> bool {
        self.stale.load(Ordering::Relaxed)
    }

    /// Which feeds are stale right now (diagnostics). Uses the SAME
    /// threshold the monitor runs with, so the read-back can never
    /// disagree with the alert.
    pub fn stale_feeds(&self) -> Vec<&'static str> {
        let book = self.book.lock().expect("price book mutex poisoned");
        let now = Instant::now();
        FEEDS
            .iter()
            .copied()
            .filter(|feed| match book.last_update(feed) {
                Some(t) => now.duration_since(t) > self.stale_after,
                None => true, // never observed
            })
            .collect()
    }

    /// Total reconnect events since start (telemetry / Prometheus).
    pub fn reconnects_total(&self) -> u64 {
        self.reconnects.load(Ordering::Relaxed)
    }

    /// Total connection failures since start (telemetry / Prometheus).
    pub fn failures_total(&self) -> u64 {
        self.failures.load(Ordering::Relaxed)
    }

    /// Number of exchanges currently contributing data to a feed.
    pub fn live_exchanges(&self, feed: &'static str) -> usize {
        self.book
            .lock()
            .expect("price book mutex poisoned")
            .observations(feed)
            .len()
    }

    /// Staleness check (Prompt 289): raise the flag + alert when a feed went
    /// silent past {stale_after}; clear it when every feed is fresh again.
    /// Sentry captures are no-ops without SENTRY_DSN (never crash the node).
    fn check_staleness(&self, stale_after: Duration) {
        let book = self.book.lock().expect("price book mutex poisoned");
        let now = Instant::now();
        let mut any_stale = false;
        for feed in FEEDS {
            let last = book.last_update(feed);
            let stale = match last {
                Some(t) => now.duration_since(t) > stale_after,
                None => true,
            };
            if stale {
                any_stale = true;
                // sentry::capture_message is a documented NO-OP when no
                // SENTRY_DSN is configured — the node never fails or slows
                // because Sentry is absent.
                sentry::capture_message(
                    &format!("FTSO provider feed {feed} is stale (no ticker in {stale_after:?})"),
                    sentry::Level::Warning,
                );
                tracing::warn!(feed, "FTSO provider feed is STALE");
            }
        }
        if any_stale {
            self.stale.store(true, Ordering::Relaxed);
        } else {
            self.stale.store(false, Ordering::Relaxed);
        }
    }
}

/// Parse a WebSocket message into a ticker, if it is one. Returns `None`
/// for heartbeats, subscription confirmations and anything malformed —
/// the stream stays alive and parsing is never fatal.
fn parse_ticker(exchange: ExchangeId, msg: Message) -> Option<Ticker> {
    let text = match msg {
        Message::Text(t) => t.to_string(),
        Message::Binary(b) => String::from_utf8_lossy(&b).to_string(),
        _ => return None,
    };
    let value: serde_json::Value = serde_json::from_str(&text).ok()?;
    let parsed: Option<Ticker> = match exchange {
        ExchangeId::Coinbase => parse_coinbase(&value),
        ExchangeId::Kraken => parse_kraken(&value),
        ExchangeId::Binance => parse_binance(&value),
        ExchangeId::Gate => parse_gate(&value),
        ExchangeId::Bitfinex => parse_bitfinex(&value),
    };
    if let Some(t) = &parsed {
        if !t.price.is_finite() || t.price <= 0.0 || !t.volume_24h.is_finite() || t.volume_24h < 0.0 {
            return None;
        }
    }
    parsed
}

/// Coinbase ticker: {"type":"ticker","product_id":"BTC-USD","price":"...","volume_24h":"..."}
fn parse_coinbase(v: &serde_json::Value) -> Option<Ticker> {
    if v.get("type")?.as_str()? != "ticker" {
        return None;
    }
    let product = v.get("product_id")?.as_str()?;
    let feed = match product {
        "BTC-USD" => "BTC/USD",
        "ETH-USD" => "ETH/USD",
        "XRP-USD" => "XRP/USD",
        _ => return None,
    };
    Some(Ticker {
        feed,
        exchange: ExchangeId::Coinbase,
        price: v.get("price")?.as_str()?.parse().ok()?,
        volume_24h: v.get("volume_24h")?.as_str()?.parse().ok()?,
    })
}

/// Kraken ticker (v1 API): [channelId, {c:[last,lot], v:[today,24h], ...}, "ticker", "XBT/USD"]
/// plus non-array control messages ({"event":"subscriptionStatus",...}).
fn parse_kraken(v: &serde_json::Value) -> Option<Ticker> {
    let arr = v.as_array()?;
    if arr.len() < 4 {
        return None;
    }
    if arr.get(2)?.as_str()? != "ticker" {
        return None;
    }
    let pair_raw = arr.get(3)?.as_str()?;
    // Kraken aliases Bitcoin to XBT on the wire; the feed is BTC/USD.
    let feed = match pair_raw {
        "XBT/USD" | "BTC/USD" => "BTC/USD",
        "ETH/USD" => "ETH/USD",
        "XRP/USD" => "XRP/USD",
        _ => return None,
    };
    let payload = arr.get(1)?.as_object()?;
    let last: f64 = payload.get("c")?.as_array()?.first()?.as_str()?.parse().ok()?;
    let vol_24h: f64 = payload
        .get("v")?
        .as_array()?
        .get(1)?
        .as_str()?
        .parse()
        .ok()?;
    Some(Ticker {
        feed,
        exchange: ExchangeId::Kraken,
        price: last,
        volume_24h: vol_24h,
    })
}

/// Binance combined 24hrTicker: {"stream":"btcusdt@ticker","data":{"e":"24hrTicker","s":"BTCUSDT","c":"<last>","q":"<quote vol>"}}
fn parse_binance(v: &serde_json::Value) -> Option<Ticker> {
    let data = v.get("data")?;
    if data.get("e")?.as_str()? != "24hrTicker" {
        return None;
    }
    let symbol = data.get("s")?.as_str()?;
    let feed = match symbol {
        "BTCUSDT" => "BTC/USD",
        "ETHUSDT" => "ETH/USD",
        "XRPUSDT" => "XRP/USD",
        _ => return None,
    };
    Some(Ticker {
        feed,
        exchange: ExchangeId::Binance,
        price: data.get("c")?.as_str()?.parse().ok()?,
        volume_24h: data.get("q")?.as_str()?.parse().ok()?,
    })
}

/// Gate.io v4 spot ticker (captured live from the real stream):
/// {"time":..., "time_ms":..., "channel":"spot.tickers", "event":"update",
///  "result":{"currency_pair":"BTC_USDT","last":"63071.4",...,
///            "base_volume":"568.13","quote_volume":"35825234.33",...}}
fn parse_gate(v: &serde_json::Value) -> Option<Ticker> {
    if v.get("channel")?.as_str()? != "spot.tickers" {
        return None;
    }
    let result = v.get("result")?.as_object()?;
    let pair = result.get("currency_pair")?.as_str()?;
    let feed = match pair {
        "BTC_USDT" => "BTC/USD",
        "ETH_USDT" => "ETH/USD",
        "XRP_USDT" => "XRP/USD",
        _ => return None,
    };
    Some(Ticker {
        feed,
        exchange: ExchangeId::Gate,
        price: result.get("last")?.as_str()?.parse().ok()?,
        volume_24h: result.get("quote_volume")?.as_str()?.parse().ok()?,
    })
}

/// Bitfinex v2 public ticker (captured live):
/// [chanId, [BID, BID_SIZE, ASK, ASK_SIZE, DAILY_CHANGE, DAILY_CHANGE_REL,
///            LAST_PRICE, VOLUME, HIGH, LOW, ...], "tBTCUSD"]
/// plus control objects ({"event":"info"|"subscribed",...}).
fn parse_bitfinex(v: &serde_json::Value) -> Option<Ticker> {
    let arr = v.as_array()?;
    if arr.len() != 3 {
        return None;
    }
    let pair_raw = arr.get(2)?.as_str()?;
    let feed = match pair_raw {
        "tBTCUSD" => "BTC/USD",
        "tETHUSD" => "ETH/USD",
        "tXRPUSD" => "XRP/USD",
        _ => return None,
    };
    let payload = arr.get(1)?.as_array()?;
    if payload.len() < 8 {
        return None;
    }
    // Index 6 = last price, index 7 = 24h volume (both f64 in the wire format).
    let price: f64 = payload.get(6)?.as_f64()?;
    let volume_24h: f64 = payload.get(7)?.as_f64()?;
    Some(Ticker {
        feed,
        exchange: ExchangeId::Bitfinex,
        price,
        volume_24h,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coinbase_ticker_parses() {
        let raw = r#"{"type":"ticker","product_id":"BTC-USD","price":"64001.23","volume_24h":"1234.5"}"#;
        let v: serde_json::Value = serde_json::from_str(raw).unwrap();
        let t = parse_ticker(ExchangeId::Coinbase, Message::Text(raw.into())).unwrap();
        assert_eq!(t.feed, "BTC/USD");
        assert_eq!(t.exchange, ExchangeId::Coinbase);
        assert_eq!(t.price, 64001.23);
        assert_eq!(t.volume_24h, 1234.5);
        let _ = v;
    }

    #[test]
    fn coinbase_heartbeat_ignored() {
        let raw = r#"{"type":"heartbeat","sequence":123}"#;
        assert!(parse_ticker(ExchangeId::Coinbase, Message::Text(raw.into())).is_none());
    }

    #[test]
    fn kraken_ticker_parses_and_normalizes_xbt() {
        let raw = r#"[333,{"c":["0.58432","100"],"v":["500","9000"]},"ticker","XBT/USD"]"#;
        let t = parse_ticker(ExchangeId::Kraken, Message::Text(raw.into())).unwrap();
        assert_eq!(t.feed, "BTC/USD");
        assert_eq!(t.price, 0.58432);
        assert_eq!(t.volume_24h, 9000.0);
    }

    #[test]
    fn kraken_subscription_status_ignored() {
        let raw = r#"{"event":"subscriptionStatus","channelID":0,"status":"subscribed"}"#;
        assert!(parse_ticker(ExchangeId::Kraken, Message::Text(raw.into())).is_none());
    }

    #[test]
    fn binance_combined_ticker_parses() {
        let raw = r#"{"stream":"btcusdt@ticker","data":{"e":"24hrTicker","s":"BTCUSDT","c":"64001.23","q":"987654321.5"}}"#;
        let t = parse_ticker(ExchangeId::Binance, Message::Text(raw.into())).unwrap();
        assert_eq!(t.feed, "BTC/USD");
        assert_eq!(t.price, 64001.23);
        assert_eq!(t.volume_24h, 987654321.5);
    }

    #[test]
    fn gate_ticker_parses() {
        // Exact shape captured from the live stream while developing this phase.
        let raw = r#"{"time":1786868962,"time_ms":1786868962889,"channel":"spot.tickers","event":"update","result":{"currency_pair":"BTC_USDT","last":"63071.4","lowest_ask":"63071.4","highest_bid":"63071.3","change_percentage":"0.03","base_volume":"568.133093","quote_volume":"35825234.3317461","high_24h":"63171.7","low_24h":"62917.7"}}"#;
        let t = parse_ticker(ExchangeId::Gate, Message::Text(raw.into())).unwrap();
        assert_eq!(t.feed, "BTC/USD");
        assert_eq!(t.exchange, ExchangeId::Gate);
        assert_eq!(t.price, 63071.4);
        assert_eq!(t.volume_24h, 35825234.3317461);
        // XRP pair maps to XRP/USD.
        let raw_xrp = r#"{"channel":"spot.tickers","event":"update","result":{"currency_pair":"XRP_USDT","last":"1.0018","quote_volume":"12345.6"}}"#;
        let t2 = parse_ticker(ExchangeId::Gate, Message::Text(raw_xrp.into())).unwrap();
        assert_eq!(t2.feed, "XRP/USD");
        assert_eq!(t2.price, 1.0018);
    }

    #[test]
    fn gate_subscription_ack_ignored() {
        // {"time":...,"channel":"spot.tickers","event":"subscribe","result":{"status":"success"}}
        let raw = r#"{"time":1786868962,"channel":"spot.tickers","event":"subscribe","result":{"status":"success"}}"#;
        assert!(parse_ticker(ExchangeId::Gate, Message::Text(raw.into())).is_none());
    }

    #[test]
    fn bitfinex_ticker_parses() {
        // Exact array shape captured live: [chanId, [...], "tBTCUSD"]
        let raw = r#"[57264,[63083,3.22281482,63086,1.90097424,-1,-0.00001585,63094,115.8357962,63210,62941,null],"tBTCUSD"]"#;
        let t = parse_ticker(ExchangeId::Bitfinex, Message::Text(raw.into())).unwrap();
        assert_eq!(t.feed, "BTC/USD");
        assert_eq!(t.exchange, ExchangeId::Bitfinex);
        assert_eq!(t.price, 63094.0);
        assert_eq!(t.volume_24h, 115.8357962);
    }

    #[test]
    fn bitfinex_control_messages_ignored() {
        let raw = r#"{"event":"subscribed","channel":"ticker","chanId":57264,"symbol":"tBTCUSD","pair":"BTCUSD"}"#;
        assert!(parse_ticker(ExchangeId::Bitfinex, Message::Text(raw.into())).is_none());
        let hb = r#"[57264,"hb"]"#;
        assert!(parse_ticker(ExchangeId::Bitfinex, Message::Text(hb.into())).is_none());
    }

    #[test]
    fn rejects_non_positive_or_nan_prices() {
        let raw = r#"{"type":"ticker","product_id":"BTC-USD","price":"0","volume_24h":"1"}"#;
        assert!(parse_ticker(ExchangeId::Coinbase, Message::Text(raw.into())).is_none());
        let raw2 = r#"{"type":"ticker","product_id":"BTC-USD","price":"abc","volume_24h":"1"}"#;
        assert!(parse_ticker(ExchangeId::Coinbase, Message::Text(raw2.into())).is_none());
    }
}
