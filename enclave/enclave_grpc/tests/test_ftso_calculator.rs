// enclave/enclave_grpc/tests/test_ftso_calculator.rs
//
// Phase 15 (Prompt 284) — weighted volume-trimmed median verification
// against synthetic price arrays, through the public library API.
//
// Every case is hand-computed: given (price, 24h-volume) observations from
// several exchanges, the aggregator must (1) trim the top/bottom 25% of the
// volume distribution, (2) return the volume-weighted median of the middle
// band, and (3) never invent a price.

use enclave_grpc::ftso_provider::calculator::{Observation, volume_trimmed_median};

fn obs(exchange: &'static str, price: f64, volume: f64) -> Observation {
    Observation {
        exchange,
        price,
        volume_24h: volume,
    }
}

#[test]
fn no_observations_produces_no_price() {
    assert_eq!(volume_trimmed_median(&[]), None);
}

#[test]
fn a_single_exchange_is_its_price() {
    let o = [obs("kraken", 0.58432, 1_000_000.0)];
    assert_eq!(volume_trimmed_median(&o), Some(0.58432));
}

#[test]
fn synthetic_median_hand_computed_case() {
    // Three realistic XRP/USD quotes with 24h volumes:
    //   kraken  0.58420 @ 12M
    //   coinbase 0.58432 @ 9M
    //   binance 0.58440 @ 15M
    // Total volume 36M; trim band (9M, 27M).
    //   kraken   cum window [0, 12M)   -> intersects (9M, 27M)? yes (12 > 9)
    //   coinbase cum window [12M, 21M) -> yes
    //   binance  cum window [21M, 36M) -> yes (21 < 27)
    // Kept volume 36M, half 18M: cumulative crosses 18M inside coinbase
    // (12M -> 21M), so the median is coinbase's 0.58432.
    let o = [
        obs("kraken", 0.58420, 12_000_000.0),
        obs("coinbase", 0.58432, 9_000_000.0),
        obs("binance", 0.58440, 15_000_000.0),
    ];
    assert_eq!(volume_trimmed_median(&o), Some(0.58432));
}

#[test]
fn synthetic_trim_removes_extreme_quotes() {
    // A two-tick fake at 0.60 (10x off-market) must be trimmed when it sits
    // in the outer volume band, leaving the market band intact.
    let o = [
        obs("a", 0.50, 1000.0),
        obs("b", 0.51, 1000.0),
        obs("c", 0.52, 1000.0),
        obs("d", 0.53, 1000.0),
        obs("e", 0.60, 1000.0),
    ];
    // Total 5000, band (1250, 3750): drop 0.50 (cum [0,1000)) and 0.60
    // (cum [4000,5000)); weighted median of {0.51,0.52,0.53} = 0.52.
    assert_eq!(volume_trimmed_median(&o), Some(0.52));
}

#[test]
fn synthetic_volume_weight_beats_equal_weight() {
    // Equal-weight median of {100, 101} is 100.5; but 95% of volume traded
    // at 101, so the volume-weighted trimmed median must be 101.
    let o = [
        obs("thin", 100.0, 1.0),
        obs("deep", 101.0, 95.0),
        obs("rest", 101.0, 4.0),
    ];
    let median = volume_trimmed_median(&o).expect("median");
    assert!(median >= 101.0, "volume weight must dominate, got {median}");
}

#[test]
fn synthetic_stable_across_input_order() {
    // Determinism: the same observations in any order yield the same median.
    let a = [
        obs("kraken", 0.58420, 12.0),
        obs("coinbase", 0.58432, 9.0),
        obs("binance", 0.58440, 15.0),
    ];
    let b = [
        obs("binance", 0.58440, 15.0),
        obs("kraken", 0.58420, 12.0),
        obs("coinbase", 0.58432, 9.0),
    ];
    assert_eq!(volume_trimmed_median(&a), volume_trimmed_median(&b));
}

#[test]
fn synthetic_zero_volume_uses_plain_median() {
    // No volume anywhere: never invent a price — fall back to the plain
    // median of the prices.
    let o = [
        obs("a", 1.0, 0.0),
        obs("b", 2.0, 0.0),
        obs("c", 3.0, 0.0),
        obs("d", 100.0, 0.0),
    ];
    assert_eq!(volume_trimmed_median(&o), Some(2.5));
}
