//! Criterion benchmark harness for `SymbolicTrie` — statistical proof of the
//! O(k) complexity guarantees.
//!
//! Run with: `cargo bench --bench trie_bench`
//!
//! Two scaling groups are measured:
//!
//! - `lookup_by_population`: fixed key length, corpus growing 1k → 64k.
//!   O(k) lookup must stay flat as n grows.
//! - `lookup_by_key_length`: fixed corpus, key length 4 → 128 chars.
//!   O(k) lookup must grow linearly.
//!
//! Critical harness detail: the trie is built **once, outside the timed
//! region** (`b.iter` times only the lookup closure). Putting construction
//! inside the timed path would measure setup cost, not lookup — an O(n)
//! construction would dominate and mask the O(k) signal entirely.

use criterion::{criterion_group, criterion_main, Criterion};
use indexer_rs::SymbolicTrie;

/// Deterministic LCG key generator (no external dep, reproducible seeds).
fn key_from(rng: &mut u64, len: usize) -> String {
    let mut key = String::with_capacity(len);
    for _ in 0..len {
        *rng = rng
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        key.push((b'a' + ((*rng >> 33) % 26) as u8) as char);
    }
    key
}

fn build_trie(n: usize, key_len: usize) -> SymbolicTrie<u8> {
    let mut rng: u64 = 99;
    let mut trie = SymbolicTrie::new();
    for _ in 0..n {
        trie.insert(&key_from(&mut rng, key_len), 1u8)
            .expect("insert");
    }
    trie
}

pub fn lookup_by_population(c: &mut Criterion) {
    let mut group = c.benchmark_group("lookup_by_population");
    for n in [1_000usize, 8_000, 64_000] {
        // Built once, outside the timed closure. The probe is a HITTING key
        // (inserted last) so the lookup walks the full key length - the true
        // O(k) worst case - rather than early-exiting on a miss.
        let mut rng: u64 = 5;
        let mut trie = build_trie(n, 16);
        let probe = key_from(&mut rng, 16);
        trie.insert(&probe, 2u8).expect("insert");
        group.bench_function(format!("n={n}"), |b| {
            b.iter(|| criterion::black_box(trie.contains(&probe)));
        });
    }
    group.finish();
}

pub fn lookup_by_key_length(c: &mut Criterion) {
    let mut group = c.benchmark_group("lookup_by_key_length");
    for len in [4usize, 16, 64, 128] {
        let mut rng: u64 = 5;
        let mut trie = build_trie(8_000, 32);
        let probe = key_from(&mut rng, len);
        trie.insert(&probe, 2u8).expect("insert"); // hitting probe: full k-char walk each lookup
        group.bench_function(format!("k={len}"), |b| {
            b.iter(|| criterion::black_box(trie.lookup(&probe)));
        });
    }
    group.finish();
}

criterion_group!(benches, lookup_by_population, lookup_by_key_length);
criterion_main!(benches);
