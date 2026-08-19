// enclave/enclave_grpc/src/ftso_provider/calculator.rs
//
// Phase 15 (Prompt 283) — weighted volume-trimmed median price calculation.
//
// This is the aggregation algorithm the enclave-hosted FTSO v2 provider node
// runs over real exchange tickers. It mirrors how institutional FTSO data
// providers aggregate decentralized price signals:
//
//   1. Collect one (price, 24h-volume) observation per exchange per feed.
//   2. Sort observations by price.
//   3. TRIM outliers: drop the observations that fall in the highest and
//      lowest 25% of the total volume distribution, keeping only the band
//      that intersects the middle 50% of volume. A single extreme quote with
//      thin volume is cut; a large-volume quote that deviates from consensus
//      is retained only if its volume intersects the median band (it then
//      legitimately moves the median — that is the signal, not noise).
//   4. Compute the VOLUME-WEIGHTED MEDIAN of the trimmed set: the price at
//      which cumulative (trimmed) volume crosses half of the trimmed total.
//
// Everything is deterministic and unit-tested against synthetic arrays
// (Prompt 284, tests/test_ftso_calculator.rs). No randomness, no state, no
// hardcoded prices — pure function over the observed tickers.

/// One exchange observation for a feed: the last ticker price and its 24h
/// volume (in the quote currency, i.e. USD). Both come straight from the
/// exchange WebSocket ticker payloads (node.rs).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Observation {
    pub exchange: &'static str,
    pub price: f64,
    pub volume_24h: f64,
}

/// The band widths for outlier trimming, as fractions of total volume.
/// 0.25/0.75 means: keep observations intersecting the middle 50% of volume.
pub const TRIM_LOW: f64 = 0.25;
pub const TRIM_HIGH: f64 = 0.75;

/// Compute the weighted volume-trimmed median of exchange observations.
///
/// Returns `None` when there are no observations. With a single observation
/// the median is that observation's price (nothing to trim or weight).
pub fn volume_trimmed_median(obs: &[Observation]) -> Option<f64> {
    if obs.is_empty() {
        return None;
    }
    if obs.len() == 1 {
        return Some(obs[0].price);
    }

    // Sort ascending by price (stable, deterministic).
    let mut sorted: Vec<&Observation> = obs.iter().collect();
    sorted.sort_by(|a, b| a.price.partial_cmp(&b.price).expect("prices are finite"));

    let total_volume: f64 = sorted.iter().map(|o| o.volume_24h).sum();
    if total_volume <= 0.0 {
        // No volume data at all: fall back to the plain median of prices.
        // (An exchange that omits volume still contributes a price; the
        // volume weighting is a best-effort refinement, never a reason to
        // drop data.)
        let mid = sorted.len() / 2;
        return Some(if sorted.len() % 2 == 0 {
            (sorted[mid - 1].price + sorted[mid].price) / 2.0
        } else {
            sorted[mid].price
        });
    }

    let low_cut = TRIM_LOW * total_volume;
    let high_cut = TRIM_HIGH * total_volume;

    // Trim: keep observations whose volume window intersects (low_cut, high_cut).
    let mut kept: Vec<(f64, f64)> = Vec::new(); // (price, volume)
    let mut cum: f64 = 0.0;
    for o in &sorted {
        let cum_after = cum + o.volume_24h;
        if cum_after > low_cut && cum < high_cut {
            kept.push((o.price, o.volume_24h));
        }
        cum = cum_after;
    }

    // Defensive: if trimming dropped everything (pathological volumes), fall
    // back to the full set — never return None from a non-empty input.
    if kept.is_empty() {
        kept = sorted.iter().map(|o| (o.price, o.volume_24h)).collect();
    }

    // Weighted median: first price where cumulative kept volume >= half.
    let kept_volume: f64 = kept.iter().map(|(_, v)| v).sum();
    let half = kept_volume / 2.0;
    let mut acc: f64 = 0.0;
    for (price, volume) in &kept {
        acc += *volume;
        if acc >= half {
            return Some(*price);
        }
    }
    // Unreachable for a non-empty kept set, but a total must be returned.
    kept.last().map(|(price, _)| *price)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(exchange: &'static str, price: f64, volume: f64) -> Observation {
        Observation {
            exchange,
            price,
            volume_24h: volume,
        }
    }

    #[test]
    fn empty_input_is_none() {
        assert_eq!(volume_trimmed_median(&[]), None);
    }

    #[test]
    fn single_observation_is_that_price() {
        let o = [obs("coinbase", 0.58432, 1_000.0)];
        assert_eq!(volume_trimmed_median(&o), Some(0.58432));
    }

    #[test]
    fn extreme_high_outlier_is_trimmed() {
        // 5 equal-volume quotes; 500 is a thin fake print at the top end.
        let o = [
            obs("a", 100.0, 1.0),
            obs("b", 101.0, 1.0),
            obs("c", 102.0, 1.0),
            obs("d", 103.0, 1.0),
            obs("e", 500.0, 1.0),
        ];
        // Total volume 5, band (1.25, 3.75): drop the 100 and the 500,
        // weighted median of {101,102,103} = 102.
        assert_eq!(volume_trimmed_median(&o), Some(102.0));
    }

    #[test]
    fn thin_low_quote_does_not_distort_median() {
        // A tiny 1-unit quote at 100 must not drag the median down when the
        // market traded 10 units at 110.
        let o = [obs("thin", 100.0, 1.0), obs("deep", 110.0, 10.0)];
        // Total 11, band (2.75, 8.25): the thin quote (cum window [0,1]) is
        // cut; kept = {110(10)}, weighted median = 110.
        assert_eq!(volume_trimmed_median(&o), Some(110.0));
    }

    #[test]
    fn dominant_volume_drives_median() {
        // 3 units at 100 vs 1 unit at 110 vs 1 unit at 120: the heavy quote
        // sits in the trimmed band and its volume decides the median.
        let o = [
            obs("a", 100.0, 3.0),
            obs("b", 110.0, 1.0),
            obs("c", 120.0, 1.0),
        ];
        // Total 5, band (1.25, 3.75): keep {100(3), 110(1)}; kept volume 4,
        // half 2 → cumulative crosses at 100. The thin 120 is cut.
        assert_eq!(volume_trimmed_median(&o), Some(100.0));
    }

    #[test]
    fn volume_weighting_beats_plain_median() {
        // Plain median of {99, 100, 101} = 100; but 90% of volume traded at
        // 101, so the volume-weighted trimmed median must be 101.
        let o = [
            obs("a", 99.0, 1.0),
            obs("b", 101.0, 90.0),
            obs("c", 101.0, 1.0),
        ];
        let result = volume_trimmed_median(&o).expect("median");
        assert!(result >= 101.0, "volume weighting must dominate: got {result}");
    }

    #[test]
    fn zero_volume_falls_back_to_plain_median() {
        let o = [obs("a", 10.0, 0.0), obs("b", 20.0, 0.0), obs("c", 30.0, 0.0)];
        assert_eq!(volume_trimmed_median(&o), Some(20.0));
        // Even-length fallback takes the mean of the middle pair.
        let o2 = [obs("a", 10.0, 0.0), obs("b", 20.0, 0.0)];
        assert_eq!(volume_trimmed_median(&o2), Some(15.0));
    }

    #[test]
    fn unsorted_input_is_handled_deterministically() {
        // Same data, shuffled order → identical result (sorted internally).
        let a = [
            obs("x", 103.0, 1.0),
            obs("y", 101.0, 1.0),
            obs("z", 500.0, 1.0),
            obs("w", 100.0, 1.0),
            obs("v", 102.0, 1.0),
        ];
        let b = [
            obs("w", 100.0, 1.0),
            obs("z", 500.0, 1.0),
            obs("x", 103.0, 1.0),
            obs("v", 102.0, 1.0),
            obs("y", 101.0, 1.0),
        ];
        assert_eq!(volume_trimmed_median(&a), volume_trimmed_median(&b));
    }
}
