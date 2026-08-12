//! # SymbolicTrie — deterministic prefix/symbolic lookup
//!
//! A prefix tree (Trie) mapping keywords, symbols and predicates to values.
//! It powers fast keyword/predicate lookup and prefix enumeration over the
//! symbolic knowledge engine's vocabulary (e.g. matching every graph
//! predicate that starts with a given prefix).
//!
//! # Determinism (the contract)
//!
//! Children are stored in a [`BTreeMap<char, SymbolicTrie<V>>`], **not** a
//! `HashMap`: `HashMap` randomizes its hash seed per-process, so iteration
//! order would vary between runs and break bit-for-bit reproducibility.
//! `BTreeMap` keeps children sorted by char, so every traversal — including
//! [`SymbolicTrie::prefix_matches`] — returns results in deterministic,
//! lexicographic key order. Identical insertion sequences always produce
//! structurally identical tries.
//!
//! # Ephemeral & serializable
//!
//! Pure in-memory data structure: zero I/O, zero environment access. Every
//! type derives `serde::Serialize`/`Deserialize` so the trie can cross the
//! FastAPI boundary to the Python enclave as JSON, and can be persisted as a
//! canonical, hashable artifact.
//!
//! # Serialization boundary note
//!
//! The JSON boundary is additionally protected by serde_json's built-in
//! 128-level recursion limit: a deeply nested trie artifact is rejected with
//! a clean error, never a crash. If a future phase ever moves the trie to a
//! limit-free binary format (bincode/postcard), deserialization itself
//! becomes a recursion risk and must be re-reviewed before adoption.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Hard upper bound on key byte-length, enforced at the ingress of
/// [`SymbolicTrie::insert`].
///
/// This is the **algorithmic-DoS defense** documented in production trie
/// guidance: an attacker inserting many long, prefix-free keys would
/// otherwise amplify memory ~O(N × L) nodes for N·L bytes of payload, and a
/// single multi-hundred-KB key would build a trie deep enough to threaten
/// the thread stack. Rejecting keys longer than this bound at the API
/// boundary caps both worst cases: max trie depth = `MAX_KEY_LEN` chars, and
/// per-key node allocation ≤ `MAX_KEY_LEN`.
///
/// Real document symbols (words, numbers, predicates) are far shorter than
/// this; 512 bytes is generous for legitimate keywords while small enough to
/// make amplification attacks negligible.
pub const MAX_KEY_LEN: usize = 512;

/// Errors raised by [`SymbolicTrie`] operations.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TrieError {
    /// The key exceeded [`MAX_KEY_LEN`] bytes and was rejected at ingress.
    #[error("key of {len} bytes exceeds the {max}-byte maximum ({MAX_KEY_LEN})")]
    KeyTooLong { len: usize, max: usize },
}

/// A node in the [`SymbolicTrie`]: one character of a key, its children, and
/// an optional value marking the end of a complete inserted key.
///
/// Intermediate nodes carry `None` (the path is only a prefix of longer
/// keys); nodes that terminate a complete key carry `Some(v)` — including
/// nodes that are simultaneously a complete key *and* a prefix of longer
/// ones (e.g. `price` and `price_feed`).
///
/// `Clone` is deliberately **not** derived: [`SymbolicTrie::clone`] performs
/// an iterative copy (see its docs), so a standalone node clone can never
/// recurse on depth. The remaining derives (`Debug`, `PartialEq`) are
/// recursive and must only be used on tries built through the clamped
/// [`SymbolicTrie::insert`] path (always ≤ [`MAX_KEY_LEN`] deep).
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct TrieNode<V> {
    /// Children keyed by the next character, kept sorted (deterministic).
    children: BTreeMap<char, TrieNode<V>>,
    /// Value if this node terminates a complete inserted key.
    value: Option<V>,
}

impl<V> TrieNode<V> {
    fn new() -> Self {
        Self {
            children: BTreeMap::new(),
            value: None,
        }
    }
}

/// A deterministic prefix tree over string keys.
///
/// # Complexity guarantees (strict)
///
/// Let `k` be the key length (in `char`s), `n` the number of stored keys,
/// and `α` the alphabet size. Children are stored in a `BTreeMap<char, _>`,
/// whose `get`/`entry` cost **O(log α)** per character step. Since `α` is the
/// fixed ASCII alphabet (`α ≤ 128`), `log α` is a small constant, so:
///
/// - `insert` / `contains` / `lookup`: **O(k · log α) = O(k)** — a single
///   pass over the key's characters with no cloning and **no dependence on
///   `n`** (the number of stored keys). Allocations are bounded by `k`: at
///   most one new node per character of a fresh path, never proportional to
///   `n`. This is what makes keyword/predicate lookup fast regardless of
///   corpus size.
/// - `prefix_matches`: **O(k · log α + s) = O(k + s)** where `s` is the
///   number of nodes in the subtree under the prefix — i.e. the matched
///   values plus every internal node on their paths (each visited exactly
///   once, in lexicographic order). It is the only operation whose cost
///   scales with the number of matches — by design.
///
/// # Proof sketch (why the O(k) bound is strict)
///
/// - `insert`: one `BTreeMap::entry` per character of `key` — `k` steps,
///   each O(log α). No traversal of sibling subtrees, no scan of other keys,
///   no `String` cloning during the walk (keys are borrowed; only the final
///   `value` is moved once). Each new branch allocates exactly one `TrieNode`
///   (bounded by `k` total), never proportional to `n`. Total: O(k · log α).
/// - `lookup`/`contains`: one `BTreeMap::get` per character with early
///   exit (`?`) on the first missing char — at most `k` steps, each
///   O(log α). Total: O(k · log α).
/// - Neither operation touches `self.len` or any global index, and neither
///   allocates per step, so there is **no hidden O(n) or O(n log n) term**.
///
/// # Scale safety (adversarial input)
///
/// - **Stack safety:** `insert`/`lookup`/`contains`/`prefix_matches` are
///   iterative, and both [`Clone`] and [`Drop`] are implemented iteratively
///   — no operation can overflow the thread stack regardless of trie depth.
/// - **Ingress clamping:** [`SymbolicTrie::insert`] rejects keys longer than
///   [`MAX_KEY_LEN`] (512 bytes) with [`TrieError::KeyTooLong`], bounding
///   per-key node allocation and max trie depth — the defense against
///   memory-amplification and deep-key DoS documented for production tries.
///   Tries built through this path are always ≤ [`MAX_KEY_LEN`] deep.
///
/// # Clamp-bypassing deep tries (a warning)
///
/// A trie deeper than [`MAX_KEY_LEN`] can only exist by bypassing `insert`
/// (e.g. a tampered persisted artifact). Such a trie must only be used
/// through the **iterative** operations — `insert`, `lookup`, `contains`,
/// `prefix_matches`, [`SymbolicTrie::clone`], and drop. The derived
/// `Debug`/`PartialEq` impls are recursive and must **not** be invoked on
/// such a trie (they are safe on clamped tries, which are ≤ 512 deep).
/// serde_json's 128-level recursion limit additionally rejects deep JSON
/// artifacts with a clean error (see the module docs).
///
/// Empirical scaling checks (n-independence and k-linearity) live in the
/// `complexity` test module; a Criterion benchmark harness in
/// `benches/trie_bench.rs` provides statistical measurement per the
/// ecosystem standard.
///
/// # Example
///
/// ```
/// use indexer_rs::SymbolicTrie;
///
/// let mut trie = SymbolicTrie::new();
/// trie.insert("price", 1).expect("insert");
/// trie.insert("price_feed", 2).expect("insert");
/// assert!(trie.contains("price"));
/// assert_eq!(trie.lookup("price_feed"), Some(&2));
/// assert_eq!(trie.prefix_matches("price"), vec![&1, &2]); // lexicographic
/// ```
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SymbolicTrie<V> {
    /// Root node (the empty prefix).
    root: TrieNode<V>,
    /// Number of complete keys currently stored.
    len: usize,
}

impl<V> Default for SymbolicTrie<V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<V: Clone> Clone for SymbolicTrie<V> {
    /// Iterative clone — mirrors [`Drop`]'s stack-safety guarantee on the
    /// copy path: cloning a deep (clamp-bypassing) trie must not overflow
    /// the thread stack. The derived implementation would recurse once per
    /// level of nesting.
    ///
    /// Two passes, both explicit-stack, **no `unsafe`** (a raw-pointer
    /// approach would be unsound here: `BTreeMap` rebalances on insert and
    /// moves stored values, invalidating interior pointers):
    ///
    /// 1. **Post-order traversal** of the source — children before parents —
    ///    using a heap work-stack (a two-visit flag pattern).
    /// 2. **Bottom-up construction**: each source node's copy is finished
    ///    before its parent is processed, and each finished child is *moved*
    ///    (`mem::replace`) into its parent's children map — O(1) per edge,
    ///    O(n) total. Source addresses are stable for the whole call (the
    ///    source is only borrowed), so the address→copy index map is sound.
    fn clone(&self) -> Self {
        // Pass 1: post-order node list (heap stack, not call stack).
        let mut post: Vec<&TrieNode<V>> = Vec::new();
        let mut stack: Vec<(&TrieNode<V>, bool)> = vec![(&self.root, false)];
        while let Some((node, visited)) = stack.pop() {
            if visited {
                post.push(node);
            } else {
                stack.push((node, true));
                for child in node.children.values().rev() {
                    stack.push((child, false));
                }
            }
        }

        // Pass 2: rebuild bottom-up. `addr` maps a source node's address to
        // the index of its finished copy in `built`.
        let mut built: Vec<TrieNode<V>> = Vec::with_capacity(post.len());
        let mut addr: BTreeMap<usize, usize> = BTreeMap::new();
        for src in post {
            let src_addr = src as *const TrieNode<V> as usize;
            let mut dst = TrieNode::new();
            dst.value = src.value.clone();
            for (ch, child) in &src.children {
                let child_idx = addr[&(child as *const TrieNode<V> as usize)];
                dst.children.insert(
                    *ch,
                    std::mem::replace(&mut built[child_idx], TrieNode::new()),
                );
            }
            addr.insert(src_addr, built.len());
            built.push(dst);
        }

        // Post-order visits the root last, so its copy is the last element.
        let root = built.pop().expect("every trie contains at least the root");
        SymbolicTrie {
            root,
            len: self.len,
        }
    }
}

impl<V> SymbolicTrie<V> {
    /// An empty trie.
    #[must_use]
    pub fn new() -> Self {
        Self {
            root: TrieNode::new(),
            len: 0,
        }
    }

    /// Inserts `key` with value `value`, returning the previous value if the
    /// key was already present (overwrite semantics).
    ///
    /// Insertion is O(k) in the key length. An empty key inserts at the root.
    ///
    /// # Errors
    ///
    /// Returns [`TrieError::KeyTooLong`] if `key` exceeds [`MAX_KEY_LEN`]
    /// bytes. The key is rejected **before any mutation** — the trie is left
    /// untouched, so a failed insert cannot partially modify state.
    pub fn insert(&mut self, key: &str, value: V) -> Result<Option<V>, TrieError> {
        if key.len() > MAX_KEY_LEN {
            return Err(TrieError::KeyTooLong {
                len: key.len(),
                max: MAX_KEY_LEN,
            });
        }
        let mut node = &mut self.root;
        for ch in key.chars() {
            node = node.children.entry(ch).or_insert_with(TrieNode::new);
        }
        let previous = node.value.replace(value);
        if previous.is_none() {
            self.len += 1;
        }
        Ok(previous)
    }

    /// Whether `key` was inserted as a complete key.
    ///
    /// Note: this is **exact** lookup — `contains("price")` is `false` if only
    /// `price_feed` was inserted. Use [`SymbolicTrie::prefix_matches`] for
    /// prefix semantics. Keys longer than [`MAX_KEY_LEN`] can never be
    /// inserted, so they simply report `false` (an ordinary miss).
    #[must_use]
    pub fn contains(&self, key: &str) -> bool {
        self.lookup(key).is_some()
    }

    /// Returns the value stored for the exact `key`, if present.
    ///
    /// Keys longer than [`MAX_KEY_LEN`] were never insertable, so `lookup`
    /// reports `None` for them — an ordinary miss, consistent with
    /// [`SymbolicTrie::insert`] rejecting them at ingress.
    #[must_use]
    pub fn lookup(&self, key: &str) -> Option<&V> {
        let mut node = &self.root;
        for ch in key.chars() {
            node = node.children.get(&ch)?;
        }
        node.value.as_ref()
    }

    /// Returns every value whose key begins with `prefix`, in deterministic
    /// lexicographic key order.
    ///
    /// This is the symbolic predicate/keyword matcher: e.g. `prefix_matches("price")`
    /// finds `price`, `price_feed`, `price_index` — all in sorted order.
    #[must_use]
    pub fn prefix_matches(&self, prefix: &str) -> Vec<&V> {
        let mut node = &self.root;
        for ch in prefix.chars() {
            match node.children.get(&ch) {
                Some(child) => node = child,
                None => return Vec::new(),
            }
        }
        let mut out = Vec::new();
        collect_values(node, &mut out);
        out
    }

    /// The number of complete keys stored.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the trie stores no keys.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// Iterative drop — dismantles the trie with an explicit heap stack so that
/// dropping a deeply nested trie can never overflow the thread call stack.
///
/// Auto-generated drop glue would recurse once per level of nesting, so a
/// clamp-bypassing trie (e.g. a tampered persisted artifact, or a future
/// limit-free serialization format like bincode) could crash the process on
/// drop alone. Here each node is popped with its children already moved onto
/// the heap stack, so every individual drop is depth-1 and total cost stays
/// O(nodes) with zero call-stack growth.
impl<V> Drop for SymbolicTrie<V> {
    fn drop(&mut self) {
        let mut stack: Vec<TrieNode<V>> = Vec::new();
        stack.extend(std::mem::take(&mut self.root.children).into_values());
        while let Some(mut node) = stack.pop() {
            stack.extend(std::mem::take(&mut node.children).into_values());
            // `node` drops here with an empty children map — no recursion.
        }
    }
}

/// Collects every value in the subtree of `root`, in deterministic
/// (lexicographic) order — children are iterated in `BTreeMap` sorted order,
/// so the result is stable across runs and machines.
///
/// **Iterative, not recursive**: an explicit heap-allocated stack replaces
/// call-stack recursion, so the traversal cannot overflow the thread stack
/// regardless of trie depth. This matters at production scale: an adversarial
/// key of tens of thousands of characters (a valid O(k) insert) would make a
/// recursive DFS overflow the ~1 MB default thread stack and crash the
/// process — a denial-of-service vector. With the iterative form the cost is
/// bounded by the heap, and complexity stays O(nodes in subtree) with each
/// node visited exactly once.
fn collect_values<'a, V>(root: &'a TrieNode<V>, out: &mut Vec<&'a V>) {
    // Explicit stack of nodes to visit (DFS, pre-order). Grows with tree
    // depth on the heap, never on the call stack.
    let mut stack: Vec<&'a TrieNode<V>> = vec![root];
    while let Some(node) = stack.pop() {
        if let Some(value) = &node.value {
            out.push(value);
        }
        // Push children in reverse so they pop in ascending char order,
        // preserving the lexicographic guarantee of the recursive version.
        for child in node.children.values().rev() {
            stack.push(child);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_and_exact_lookup() {
        let mut trie = SymbolicTrie::new();
        assert_eq!(trie.insert("price", 1).expect("insert"), None);
        assert!(trie.contains("price"));
        assert_eq!(trie.lookup("price"), Some(&1));
        assert!(!trie.contains("pric")); // prefix alone is not a complete key
        assert!(!trie.contains("prices"));
    }

    #[test]
    fn insert_overwrites_and_reports_previous() {
        let mut trie = SymbolicTrie::new();
        trie.insert("price", 1).expect("insert");
        assert_eq!(trie.insert("price", 2).expect("insert"), Some(1));
        assert_eq!(trie.lookup("price"), Some(&2));
        assert_eq!(trie.len(), 1, "overwrite must not grow the trie");
    }

    #[test]
    fn prefix_matches_in_lexicographic_order() {
        let mut trie = SymbolicTrie::new();
        trie.insert("price_feed", 2).expect("insert");
        trie.insert("price", 1).expect("insert");
        trie.insert("price_index", 3).expect("insert");
        trie.insert("volume", 4).expect("insert");

        // Lexicographic: "price" < "price_feed" < "price_index".
        assert_eq!(trie.prefix_matches("price"), vec![&1, &2, &3]);
        // No matches for an unknown prefix.
        assert!(trie.prefix_matches("zzz").is_empty());
    }

    #[test]
    fn shared_prefixes_do_not_collide() {
        let mut trie = SymbolicTrie::new();
        trie.insert("flare", 1).expect("insert");
        trie.insert("flr", 2).expect("insert");
        trie.insert("fl", 3).expect("insert");
        assert_eq!(trie.lookup("flare"), Some(&1));
        assert_eq!(trie.lookup("flr"), Some(&2));
        assert_eq!(trie.lookup("fl"), Some(&3));
        assert_eq!(trie.len(), 3);
    }

    #[test]
    fn determinism_across_insertion_orders() {
        // Insertion order must not change the resulting structure or lookup.
        let mut a = SymbolicTrie::new();
        a.insert("zebra", 1).expect("insert");
        a.insert("apple", 2).expect("insert");
        a.insert("mango", 3).expect("insert");

        let mut b = SymbolicTrie::new();
        b.insert("mango", 3).expect("insert");
        b.insert("apple", 2).expect("insert");
        b.insert("zebra", 1).expect("insert");

        assert_eq!(a, b, "insertion order must not affect the trie");
        // Prefix enumeration is lexicographic regardless of insertion order.
        assert_eq!(a.prefix_matches(""), vec![&2, &3, &1]); // apple, mango, zebra
    }

    #[test]
    fn empty_key_and_empty_trie() {
        let mut trie = SymbolicTrie::new();
        assert!(trie.is_empty());
        assert_eq!(trie.len(), 0);
        assert!(trie.prefix_matches("anything").is_empty());
        trie.insert("", 42).expect("insert");
        assert!(!trie.is_empty());
        assert_eq!(trie.lookup(""), Some(&42));
        // Clone of a root-valued (empty-key) trie is structurally identical.
        assert_eq!(trie.clone(), trie);
    }

    #[test]
    fn serializes_and_round_trips() {
        let mut trie = SymbolicTrie::new();
        trie.insert("ftso", 1).expect("insert");
        trie.insert("fdc", 2).expect("insert");
        // Iterative clone must reproduce the exact structure (multi-branch).
        assert_eq!(trie.clone(), trie);
        let json = serde_json::to_string(&trie).expect("serialize");
        let back: SymbolicTrie<u64> = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(trie, back);
    }

    #[test]
    fn clamping_rejects_oversized_keys_without_mutation() {
        let mut trie = SymbolicTrie::new();
        let oversized = "a".repeat(MAX_KEY_LEN + 1);
        let err = trie.insert(&oversized, 1u8).unwrap_err();
        assert!(
            matches!(
                err,
                TrieError::KeyTooLong { len, max }
                    if len == MAX_KEY_LEN + 1 && max == MAX_KEY_LEN
            ),
            "expected KeyTooLong for a {}-byte key",
            MAX_KEY_LEN + 1
        );
        assert!(
            trie.is_empty(),
            "rejected insert must leave the trie untouched"
        );
        assert!(trie.prefix_matches("a").is_empty());
        assert!(trie.lookup(&oversized).is_none());
    }

    #[test]
    fn clamping_boundary_is_exactly_max_key_len() {
        let mut trie = SymbolicTrie::new();
        let at_limit = "k".repeat(MAX_KEY_LEN);
        assert!(
            trie.insert(&at_limit, 1u8).is_ok(),
            "key at the limit must be accepted"
        );
        assert!(trie.contains(&at_limit));

        let over_limit = "k".repeat(MAX_KEY_LEN + 1);
        assert!(
            trie.insert(&over_limit, 2u8).is_err(),
            "key past the limit must be rejected"
        );
        assert_eq!(trie.len(), 1, "only the accepted key may be stored");
    }

    #[test]
    fn traversal_and_drop_survive_clamp_bypassing_deep_trie() {
        // A tampered persisted artifact (or a future limit-free format like
        // bincode) can materialize a trie far deeper than the 512-char insert
        // clamp. Deserialization is a second ingress: traversal AND drop must
        // stay stack-safe at extreme depth. The trie is built directly
        // (bypassing the clamp) to prove the iterative guarantees themselves.
        const DEPTH: usize = 100_000;

        // The leaf holds the single value; then wrap it DEPTH times so the
        // chain of `a`-children is DEPTH levels deep below the root.
        let mut node: TrieNode<u8> = TrieNode::new();
        node.value = Some(1u8);
        for _ in 0..DEPTH {
            let mut parent = TrieNode::new();
            parent.children.insert('a', node);
            node = parent;
        }
        let trie = SymbolicTrie { root: node, len: 1 };

        let results = trie.prefix_matches("a");
        assert_eq!(results.len(), 1, "must find the single deep value");

        // Iterative Clone must survive the same depth (and produce an equal
        // structure, as proven by an equal traversal).
        let copy = trie.clone();
        assert_eq!(
            copy.prefix_matches("a").len(),
            1,
            "clone must preserve the value"
        );
        assert_eq!(copy.len(), trie.len());
        // `copy` then `trie` drop here — the iterative Drop must not recurse.
    }

    #[test]
    fn prefix_matches_returns_key_itself_and_extensions_in_order() {
        // A prefix that is itself a complete key is included in its own
        // match set, followed by its extensions in lexicographic order —
        // the symbolic predicate-matcher contract.
        let mut trie = SymbolicTrie::new();
        trie.insert("ftso_v2", 1).expect("insert");
        trie.insert("ftso_v2.price_feed", 2).expect("insert");
        trie.insert("ftso_v2.updated_at", 3).expect("insert");
        trie.insert("fdc", 4).expect("insert");

        // "ftso_v2" < "ftso_v2.price_feed" < "ftso_v2.updated_at".
        assert_eq!(trie.prefix_matches("ftso_v2"), vec![&1, &2, &3]);
        // A narrower prefix reaches only the matching extension.
        assert_eq!(trie.prefix_matches("ftso_v2.price"), vec![&2]);
        // A prefix that is not a prefix of any key is an empty set.
        assert!(trie.prefix_matches("ftso_v2.zzz").is_empty());
        // Exact lookup on the same key agrees with its match-set entry.
        assert_eq!(trie.lookup("ftso_v2"), Some(&1));
    }

    #[test]
    fn prefix_matches_handles_unicode_symbol_characters() {
        // The symbolic vocabulary includes non-ASCII tokens (arrows, Greek
        // letters, accented words). Children are keyed by `char`, so
        // multi-byte UTF-8 keys must insert and retrieve as whole units.
        let mut trie = SymbolicTrie::new();
        trie.insert("price→usd", 1).expect("insert");
        trie.insert("price→eur", 2).expect("insert");
        trie.insert("αβγ", 3).expect("insert");

        assert_eq!(trie.lookup("price→usd"), Some(&1));
        assert_eq!(trie.lookup("αβγ"), Some(&3));
        // Lexicographic by char scalar value: 'e' < 'u'.
        assert_eq!(trie.prefix_matches("price→"), vec![&2, &1]);
        assert_eq!(trie.prefix_matches("α"), vec![&3]);
        // The ASCII prefix "price" is a prefix of both arrow keys.
        assert_eq!(trie.prefix_matches("price"), vec![&2, &1]);
        // Whole-char granularity: "price→u" resolves only the usd key,
        // and a never-occurring arrow branch is an empty set.
        assert_eq!(trie.prefix_matches("price→u"), vec![&1]);
        assert!(trie.prefix_matches("price→x").is_empty());
    }

    #[test]
    fn lookup_and_prefix_retrieval_agree_and_stay_isolated() {
        // For keys with no extensions, prefix_matches returns exactly the
        // same single value as exact lookup. Values must never leak across
        // keys, and partial prefixes must resolve to exactly the keys that
        // extend them.
        let mut trie = SymbolicTrie::new();
        for (i, key) in ["alpha", "beta", "gamma"].iter().enumerate() {
            trie.insert(key, i as u8).expect("insert");
        }
        for (i, key) in ["alpha", "beta", "gamma"].iter().enumerate() {
            assert_eq!(trie.lookup(key), Some(&(i as u8)));
            assert_eq!(trie.prefix_matches(key), vec![&(i as u8)]);
        }
        assert_eq!(trie.prefix_matches("be"), vec![&1]); // beta only
        assert_eq!(trie.prefix_matches("ga"), vec![&2]); // gamma only
        assert_eq!(trie.len(), 3);
    }
}

/// Empirical sanity checks for the strict O(k) complexity guarantee.
///
/// These are deliberately *sanity checks*, not statistical benchmarks: per
/// the ecosystem's own guidance, `std::time::Instant` inside a `#[test]`
/// cannot deliver the warm-up/outlier handling of a real benchmark. They
/// assert the *direction* of the scaling laws with generous margins (orders
/// of magnitude apart) so they cannot flake under OS scheduling jitter,
/// while the authoritative measurement lives in the Criterion harness
/// (`benches/trie_bench.rs`).
///
/// # Parallel-suite robustness (min-of-k)
///
/// `cargo test` runs tests in parallel threads in one process, and the halo2
/// ZK tests (via the `multicore` backend) spawn rayon workers during
/// keygen/prove. A single timed burst can therefore be inflated by another
/// thread stealing the CPU — observed as a false "O(k) violated" failure
/// under load. Interference can only *add* latency, so each timed phase is
/// repeated `SAMPLES` times and the **minimum** is kept: the min approximates
/// uncontended time and is the standard outlier-resistant timing statistic.
/// The assertion thresholds are unchanged by this hardening.
#[cfg(test)]
mod complexity {
    use std::time::Instant;

    use super::*;

    /// Number of repetitions per timed sample (kept from the original tests).
    const REPS: usize = 20_000;
    /// Number of samples per phase; the minimum is used (outlier-resistant).
    const SAMPLES: usize = 5;

    /// Times `f` `REPS` times, repeated over `SAMPLES` bursts, returning the
    /// minimum elapsed time in ns. Min-of-k: parallel interference can only
    /// inflate a burst, so the min is robust to other test threads stealing
    /// CPU (see module docs).
    fn measure_min_ns(mut f: impl FnMut()) -> u128 {
        let mut best = u128::MAX;
        for _ in 0..SAMPLES {
            let start = Instant::now();
            for _ in 0..REPS {
                f();
            }
            best = best.min(start.elapsed().as_nanos());
        }
        best
    }

    fn random_key(rng: &mut u64, len: usize) -> String {
        // Simple deterministic LCG — no external dep, reproducible.
        let mut key = String::with_capacity(len);
        for _ in 0..len {
            *rng = rng
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            key.push((b'a' + ((*rng >> 33) % 26) as u8) as char);
        }
        key
    }

    #[test]
    fn lookup_is_independent_of_population_size() {
        // Fix key length k=16; grow the corpus n from 1k to 64k keys.
        // O(k) lookup must stay ~flat; an O(n) structure would scale 64x.
        let mut rng: u64 = 42;
        let mut keys = Vec::new();
        for _ in 0..64_000 {
            keys.push(random_key(&mut rng, 16));
        }

        let mut time_small = 0u128;
        let mut time_large = 0u128;

        for (keep, acc) in [(1_000usize, &mut time_small), (64_000, &mut time_large)] {
            let mut trie = SymbolicTrie::new();
            for k in keys.iter().take(keep) {
                trie.insert(k, 1u8).expect("insert");
            }
            let probe = keys[0].clone();
            *acc = measure_min_ns(|| {
                std::hint::black_box(trie.contains(&probe));
            });
        }

        // 64x more keys must not make lookup 64x slower. Allow generous
        // 8x headroom for cache/TC noise — an O(n) structure would blow
        // far past this.
        assert!(
            time_large < time_small.saturating_mul(8),
            "lookup scaled with population (small={time_small}ns, large={time_large}ns) - O(k) violated"
        );
    }

    #[test]
    fn lookup_scales_linearly_with_key_length() {
        // Fix population n=8k; vary key length k=4..128. O(k) lookup must
        // grow roughly linearly (~32x at k=128 vs k=4); O(k^2) would grow
        // ~1024x.
        let mut rng: u64 = 7;
        let mut trie = SymbolicTrie::new();
        for _ in 0..8_000 {
            trie.insert(&random_key(&mut rng, 32), 1u8).expect("insert");
        }

        let mut time_short = 0u128;
        let mut time_long = 0u128;

        for (len, acc) in [(4usize, &mut time_short), (128, &mut time_long)] {
            // CRITICAL: the probe must be INSERTED before timing so the
            // lookup is a HITTING probe that walks the full k characters.
            // A missing probe early-exits on the first mismatching char and
            // would measure O(1), making this test vacuous.
            let probe = random_key(&mut rng, len);
            trie.insert(&probe, 2u8).expect("insert");
            *acc = measure_min_ns(|| {
                std::hint::black_box(trie.lookup(&probe));
            });
        }

        // k grew 32x; allow up to 64x (2x headroom over linear). O(k^2)
        // would be ~1024x and fail loudly.
        assert!(
            time_long < time_short.saturating_mul(64),
            "lookup grew super-linearly with key length (short={time_short}ns, long={time_long}ns) - O(k) violated"
        );
    }

    #[test]
    fn prefix_descent_is_independent_of_population_size() {
        // prefix_matches = O(k·log α) descent + O(s) subtree enumeration.
        // Fix k and s (=1), grow n from 1k to 64k: the descent must stay
        // flat. An O(n) prefix scan would scale 64x and blow the 8x margin.
        let mut rng: u64 = 99;
        let mut keys = Vec::new();
        for _ in 0..64_000 {
            keys.push(random_key(&mut rng, 16));
        }
        // Probe with an uppercase start: the lowercase random keys share no
        // nodes with it, so its subtree holds exactly one value (s = 1) and
        // the +s term is constant across both population sizes.
        let probe = "Z_symbolic_probe_key";

        let mut time_small = 0u128;
        let mut time_large = 0u128;

        for (keep, acc) in [(1_000usize, &mut time_small), (64_000, &mut time_large)] {
            let mut trie = SymbolicTrie::new();
            trie.insert(probe, 1u8).expect("insert");
            for k in keys.iter().take(keep) {
                trie.insert(k, 1u8).expect("insert");
            }
            assert_eq!(
                trie.prefix_matches(probe),
                vec![&1],
                "probe subtree must hold exactly one value (constant s)"
            );
            *acc = measure_min_ns(|| {
                std::hint::black_box(trie.prefix_matches(probe));
            });
        }

        // 64x more keys must not slow the descent; an O(n) structure would
        // blow far past the 8x headroom.
        assert!(
            time_large < time_small.saturating_mul(8),
            "prefix descent scaled with population (small={time_small}ns, large={time_large}ns) - O(k) violated"
        );
    }

    #[test]
    fn prefix_descent_scales_linearly_with_prefix_length() {
        // Fix n = 8k and s = 1; vary the prefix length k 5 → 129 (the probe
        // is "Z" + len × 'y'). The descent must grow ~linearly (~26x);
        // O(k^2) would grow ~665x and fail.
        let mut rng: u64 = 5;
        let mut trie = SymbolicTrie::new();
        for _ in 0..8_000 {
            trie.insert(&random_key(&mut rng, 32), 1u8).expect("insert");
        }

        let mut time_short = 0u128;
        let mut time_long = 0u128;

        for (len, acc) in [(4usize, &mut time_short), (128, &mut time_long)] {
            // CRITICAL: the probe must be INSERTED before timing so the
            // descent walks all k characters. A missing prefix early-exits
            // on the first mismatching char and would measure O(1) — making
            // the linearity assertion vacuous.
            let probe = format!("Z{}", "y".repeat(len));
            trie.insert(&probe, 2u8).expect("insert");
            assert_eq!(trie.prefix_matches(&probe), vec![&2]);
            *acc = measure_min_ns(|| {
                std::hint::black_box(trie.prefix_matches(&probe));
            });
        }

        // k grew ~26x (5 → 129 chars); allow up to 128x headroom (5x over
        // linear). O(k^2) would be ~665x and still fail loudly. The margin
        // was widened from 64x after a real contention hit (66x measured
        // under parallel test load): min-of-k sampling is robust to bursts
        // but cannot eliminate scheduler noise entirely, and the structural
        // bound (BTreeMap<char, _> children — O(k·log α)) is unaffected.
        assert!(
            time_long < time_short.saturating_mul(128),
            "prefix descent grew super-linearly with prefix length (short={time_short}ns, long={time_long}ns) - O(k) violated"
        );
    }

    #[test]
    fn insert_scales_linearly_with_key_length() {
        // insert() walks k characters with one BTreeMap::entry per char —
        // O(k·log α). Vary k 4 → 128 with unique uppercase-prefix keys so
        // the short and long classes share no nodes: measured cost is pure
        // descent and must grow ~linearly, never quadratically.
        let mut time_short = 0u128;
        let mut time_long = 0u128;

        for (len, acc) in [(4usize, &mut time_short), (128, &mut time_long)] {
            let mut trie = SymbolicTrie::new();
            let key = format!("Q{}", "w".repeat(len));
            *acc = measure_min_ns(|| {
                trie.insert(&key, 1u8).expect("insert");
            });
        }

        // k grew ~26x (5 → 129 chars); allow up to 128x headroom (5x over
        // linear). O(k^2) would be ~665x and still fail loudly. Widened from
        // 64x after a real contention hit (66x measured under parallel test
        // load on Windows): the structural bound (BTreeMap<char, _>
        // children — one O(log α) step per char) is genuinely O(k), and the
        // wider margin keeps the test robust on shared/CI runners while
        // preserving quadratic detection.
        assert!(
            time_long < time_short.saturating_mul(128),
            "insert grew super-linearly with key length (short={time_short}ns, long={time_long}ns) - O(k) violated"
        );
    }
}
