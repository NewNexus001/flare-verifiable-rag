//! Adversarial-input probe — the production ingress contract, proven live.
//!
//! 1. **INGRESS CLAMPING**: `insert()` rejects keys longer than
//!    [`MAX_KEY_LEN`] (512 bytes) with `TrieError::KeyTooLong` **before any
//!    mutation** — a 100k-char key must be refused and leave the trie
//!    untouched. This caps max trie depth and per-key node allocation,
//!    neutralizing memory-amplification and deep-key DoS at the API boundary.
//! 2. **WORST-CASE TRAVERSAL**: a trie at the clamp's own maximum depth
//!    (512 levels) is fully enumerable without crashing — the iterative
//!    traversal guarantee.
//!
//! (The clamp-bypass scenario — a deep trie crafted outside `insert`, e.g. a
//! tampered persisted artifact — is covered by the `trie.rs` unit test
//! `traversal_and_drop_survive_clamp_bypassing_deep_trie`, which builds a
//! 100k-deep trie directly and proves traversal AND drop are stack-safe. That
//! scenario cannot be reproduced here because the public API is exactly the
//! clamped ingress.)
//!
//! Run: `cargo run --example deep_probe -- 100000`

use indexer_rs::trie::MAX_KEY_LEN;
use indexer_rs::{SymbolicTrie, TrieError};

fn main() {
    let depth = std::env::args()
        .nth(1)
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(100_000);

    // 1. Ingress clamping: the oversized key is REJECTED, trie untouched.
    let deep = "a".repeat(depth);
    let mut trie = SymbolicTrie::new();
    match trie.insert(&deep, 1u8) {
        Err(TrieError::KeyTooLong { len, .. }) => {
            assert_eq!(
                len, depth,
                "error must report the rejected key's true length"
            );
            println!("clamp: rejected {depth}-byte key (KeyTooLong) ✓");
        }
        other => panic!("expected KeyTooLong for {depth}-byte key, got {other:?}"),
    }
    assert!(trie.is_empty(), "rejected insert must not mutate the trie");

    // 2. Worst-case traversal: a trie AT the clamp limit works end-to-end.
    let at_limit = "b".repeat(MAX_KEY_LEN);
    trie.insert(&at_limit, 7u8)
        .expect("key at the limit must be accepted");
    let results = trie.prefix_matches("b");
    assert_eq!(results.len(), 1, "must find the single key at max depth");
    assert_eq!(results[0], &7u8);
    println!("traversal: prefix_matches over a depth-{MAX_KEY_LEN} trie → 1 result ✓");
    println!("PROBE PASSED: ingress clamp + worst-case traversal, depth={depth}");
}
