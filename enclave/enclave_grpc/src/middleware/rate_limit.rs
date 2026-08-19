// enclave/enclave_grpc/src/middleware/rate_limit.rs
//
// Phase 11 (Prompt 210, 211) — ingress rate limiting.
//
// ENGINEERING NOTE (researched, not guessed): the master plan specifies
// `tower::limit::RateLimitLayer`. Verified against the RESOLVED tower
// source (tower-0.4.13): `RateLimit<T>` derives ONLY `Debug` — it is NOT
// Clone. tonic 0.10's Router requires every layered/intercepted service to
// be Clone (`serve_with_incoming` bound: `L::Service: Service + Clone` —
// verified against tonic-0.10.2 source). Therefore RateLimitLayer CANNOT be
// applied to the tonic router without a clone wrapper.
//
// The implementation below therefore provides the SAME sliding-window token
// bucket semantics (rate = N req per `per` window, burst = N) as a
// CLONEABLE shared bucket applied via a tonic interceptor, which returns the
// exact gRPC status RESOURCE_EXHAUSTED on quota breach (Prompt 211).
// `rate_limit_layer()` keeps the tower::limit::RateLimitLayer reference for
// non-tonic service stacks.
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tonic::{Request, Status};
use tower::limit::RateLimitLayer;

/// Default quota from the master plan: 100 req/s.
pub const DEFAULT_RATE_PER_SEC: u64 = 100;

/// Build a tower::limit::RateLimitLayer (reference implementation per the
/// spec — usable on non-tonic stacks where the service need not be Clone).
pub fn rate_limit_layer(rate: u64, per: Duration) -> RateLimitLayer {
    RateLimitLayer::new(rate, per)
}

/// Sliding-window token bucket state.
#[derive(Debug)]
struct Bucket {
    capacity: u64,
    rate_per_sec: u64,
    tokens: f64,
    last_refill: Instant,
}

/// Cloneable shared token bucket (Arc<Mutex<Bucket>>) — safe for tonic's
/// Clone-bound router. All clones share one counter.
#[derive(Clone, Debug)]
pub struct SharedTokenBucket {
    inner: Arc<Mutex<Bucket>>,
}

impl SharedTokenBucket {
    /// `rate_per_sec` = refill rate, `burst` = max accumulated tokens.
    pub fn new(rate_per_sec: u64, burst: u64) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Bucket {
                capacity: burst,
                rate_per_sec,
                tokens: burst as f64,
                last_refill: Instant::now(),
            })),
        }
    }

    /// Try to consume one token. `false` when the bucket is empty (over
    /// quota) after applying the continuous refill.
    pub fn try_acquire(&self) -> bool {
        let mut bucket = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = Instant::now();
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens =
            (bucket.tokens + elapsed * bucket.rate_per_sec as f64).min(bucket.capacity as f64);
        bucket.last_refill = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// The standard ingress bucket (100 req/s, burst 100).
pub fn default_ingress_bucket() -> SharedTokenBucket {
    SharedTokenBucket::new(DEFAULT_RATE_PER_SEC, DEFAULT_RATE_PER_SEC)
}

/// Tonic interceptor: consumes a token per request; over-quota requests are
/// rejected with gRPC status RESOURCE_EXHAUSTED before reaching handlers.
pub fn rate_limit_interceptor(
    bucket: SharedTokenBucket,
) -> impl Fn(Request<()>) -> Result<Request<()>, Status> + Clone + Send + 'static {
    move |req: Request<()>| {
        if bucket.try_acquire() {
            Ok(req)
        } else {
            Err(Status::resource_exhausted(format!(
                "rate limit exceeded ({DEFAULT_RATE_PER_SEC} req/s)"
            )))
        }
    }
}
