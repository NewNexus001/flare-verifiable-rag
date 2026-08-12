//! # KnowledgeGraph — deterministic DAG of entity–relation knowledge
//!
//! Canonical, acyclic representation of extracted knowledge: a set of
//! **entities** (symbols) connected by **relations** (predicate-labelled
//! directed edges `subject --predicate--> object`).
//!
//! This is the structure the RAG engine traverses to expand a query entity
//! into its neighbourhood (`reachable_from` / `ancestors_of`) and to feed
//! context to the model in a deterministic order (`topological_order`).
//!
//! # Design invariants (same contract as the rest of `indexer_rs`)
//!
//! - **Acyclic by construction:** every [`KnowledgeGraph::add_relation`]
//!   enforces the DAG invariant *before* mutating state. A self-loop or any
//!   edge that would close a directed cycle is rejected with a structured
//!   [`GraphError`]. Nothing in the public API can produce a cyclic graph.
//! - **Deterministic:** no `HashMap` anywhere — entities are a
//!   first-occurrence `Vec`, adjacency is `BTreeMap`/`BTreeSet` (ascending
//!   key order), and traversals track visits with a `Vec<bool>` (index-based
//!   O(1) per node — the same benefit as a bitset, zero new dependencies).
//!   Identical input always yields identical output, byte for byte.
//! - **Arena/vector-backed (the petgraph pattern):** entities are plain
//!   `usize` indices into a flat `Vec<Entity>`. No `Rc`/`RefCell` pointers —
//!   no borrow-checker friction, no `Rc` strong-count cycle leaks, no
//!   cache-fragmenting pointer chasing. The graph is **append-only** (no
//!   deletion), so a plain index can never dangle (no ABA risk — hence no
//!   generational arena is needed; documented decision).
//! - **Scale-hardened:** every traversal is *iterative* (explicit heap
//!   stack / `VecDeque`); this module contains **no recursion**, so no
//!   input can overflow the thread stack (default 1 MB on Windows, 8 MB on
//!   Linux). `insert`, `drop` and `clone` are flat — adjacency nesting is
//!   fixed at three levels, never proportional to graph depth.
//! - **Ingress clamped:** entity text and predicate labels longer than
//!   [`MAX_SYMBOL_LEN`] (512 bytes — the same bound the
//!   [`crate::trie::SymbolicTrie`] uses for keys) are rejected *before*
//!   mutation, which also caps per-edge memory amplification.
//! - **Ephemeral:** pure data type, zero I/O, zero environment access.
//! - **Serializable (flat arrays):** serde emits exactly two flat arrays —
//!   `nodes` and `edges` — never a hierarchical payload tree. This
//!   sidesteps serde_json's default 128-level recursion limit, cannot
//!   "tree-ify" shared entities (each entity appears once, edges reference
//!   it by index), and a cyclic payload is rejected *loudly* on
//!   deserialize instead of materialising a broken graph.
//! - **Zero mock:** no test fixture, no canned graph — every test input is
//!   constructed inline and asserted against derived truth.
//!
//! # Cycle prevention (Pearce–Kelly-style)
//!
//! The production standard for maintaining a DAG under edge insertion
//! (Pearce & Kelly, 2006) keeps a **topological rank per vertex**:
//!
//! - Inserting an edge `u -> v` with `rank[u] < rank[v]` respects the
//!   maintained topological order, so it **cannot** create a cycle — no
//!   check needed (O(1)).
//! - If `rank[u] >= rank[v]`, the edge *could* close a path
//!   `v -> ... -> u`; a reachability search settles it. When safe, the
//!   ranks are rebuilt (Kahn, deterministic ascending-id tie-break) so the
//!   fast path stays fast.
//!
//! # Complexity
//!
//! | Operation | Cost | Notes |
//! |---|---|---|
//! | `add_entity` | O(log V) | `BTreeMap` dedup lookup |
//! | `add_relation` (fast path) | O(log² V) | rank order already valid |
//! | `add_relation` (slow path) | O(V + E) | reachability check + rank rebuild, only when ranks are violated |
//! | `reachable_from` / `ancestors_of` | O(V + E) | iterative BFS |
//! | `relations` / `topological_order` | O(V + E) / O(V log V) | deterministic |
//! | `find_path` | O(V + E) traversal + O(E log E) deterministic sort of matched edges, O(V) space | predicate-filtered iterative BFS — no path enumeration |
//!
//! Building a graph whose edges *always* violate the rank invariant costs
//! O(E·(V+E)) worst case — the honest price of the acyclicity guarantee.
//! Document-scale knowledge graphs hit the fast path after the first few
//! inserts, so ingestion stays near-linear in practice (proven by the
//! `fast_path_build_scales_after_chain` stress test).
//!
//! # Evidence retrieval (`find_path`)
//!
//! [`KnowledgeGraph::find_path`] returns the **exact evidence subgraph** for
//! a `(subject, predicate)` query: the anchor entity plus every entity
//! reachable from it by following *only* edges whose predicate matches
//! exactly, plus every such edge. Following the established knowledge-graph
//! RAG convention (Cypher/property-graph subgraph projection; GraphRAG /
//! SubgraphRAG), it returns **one deduplicated subgraph**, never an
//! enumeration of linear paths — path enumeration is exponential (O(2^V)
//! even in a DAG), while predicate-filtered BFS is O(V + E). Evidence is
//! ordered deterministically for reproducible LLM context: BFS depth from
//! the anchor (primary), ascending entity id (secondary), and edges by
//! (subject, predicate, object) (tertiary).

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

/// Hard ingress clamp on entity and predicate symbol length (bytes).
///
/// 512 mirrors [`crate::trie::MAX_KEY_LEN`] so every symbol entering the
/// engine is bounded by the same limit. Long enough for any real document
/// symbol, small enough to make per-key memory amplification negligible.
pub const MAX_SYMBOL_LEN: usize = 512;

/// Stable identifier of an entity: its index into the arena
/// ([`KnowledgeGraph::entities`]).
///
/// Append-only by design, so a plain index is never recycled — no
/// generational arena required.
pub type EntityId = usize;

/// Errors raised by [`KnowledgeGraph`] operations.
///
/// Every variant is structured and produced *before* the offending mutation
/// lands — a rejected call leaves the graph byte-identical to how it was.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum GraphError {
    /// An empty string was supplied as an entity symbol.
    #[error("entity text is empty")]
    EmptyEntity,

    /// Entity text exceeded the [`MAX_SYMBOL_LEN`] ingress clamp.
    #[error("entity text is {len} bytes, exceeds the {max}-byte ingress clamp")]
    EntityTooLong { len: usize, max: usize },

    /// An empty string was supplied as a predicate label.
    #[error("predicate text is empty")]
    EmptyPredicate,

    /// Predicate label exceeded the [`MAX_SYMBOL_LEN`] ingress clamp.
    #[error("predicate text is {len} bytes, exceeds the {max}-byte ingress clamp")]
    PredicateTooLong { len: usize, max: usize },

    /// A relation referenced an entity id that does not exist.
    #[error("entity id {id} does not exist")]
    UnknownEntity { id: usize },

    /// A relation would connect an entity to itself.
    #[error("relation would create a self-loop on entity {entity}")]
    SelfLoop { entity: usize },

    /// A relation would close a directed cycle (`object` already reaches
    /// `subject`).
    #[error(
        "relation {subject} -> {object} would create a cycle (a path {object} -> ... -> {subject} already exists)"
    )]
    Cycle { subject: usize, object: usize },

    /// Deserialized edge data contains a cycle; the graph is refused rather
    /// than materialised in a broken state.
    #[error("edge data contains a cycle; refusing to materialize an invalid DAG")]
    CyclicPayload,
}

/// A single entity (knowledge graph node).
///
/// `id` equals the entity's position in `KnowledgeGraph::entities`
/// (first-occurrence order); `text` is used verbatim — the caller is
/// responsible for canonical casing, matching the pipeline's contract.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Entity {
    /// Arena index of this entity.
    pub id: usize,
    /// The symbol text this entity represents.
    pub text: String,
}

/// A single directed, predicate-labelled relation (knowledge graph edge):
/// `subject --predicate--> object`.
///
/// Used by the flat `edges` array in serialization and by
/// [`KnowledgeGraph::relations`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Relation {
    /// Index of the subject entity.
    pub subject: usize,
    /// Predicate label of the relation.
    pub predicate: String,
    /// Index of the object entity.
    pub object: usize,
}

/// A deterministic evidence subgraph returned by
/// [`KnowledgeGraph::find_path`].
///
/// The anchor (`subject`) plus every entity reachable from it by following
/// *only* edges labelled exactly `predicate`, and every such edge — one
/// deduplicated subgraph, never an enumeration of linear paths.
///
/// Ordering (for reproducible LLM context): `entities` by BFS depth from
/// the anchor then ascending entity id; `relations` by (subject, predicate,
/// object). `depths` is parallel to `entities` and `relation_depths` is
/// parallel to `relations` — each relation's depth is the BFS depth of its
/// subject (the hop count from the anchor at which the edge departs).
///
/// Flat data only (id vectors + relation triples): serde output is two
/// levels deep, and entity text resolves through the owning
/// [`KnowledgeGraph`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Path {
    /// Arena id of the queried subject entity.
    pub subject: EntityId,
    /// The exact predicate label that constrained the traversal.
    pub predicate: String,
    /// The anchor plus every entity reachable via `predicate` edges, in
    /// deterministic order (BFS depth, then ascending id). All distinct.
    pub entities: Vec<EntityId>,
    /// BFS depth from the anchor of each entry of `entities` (parallel to
    /// `entities`; the anchor has depth 0).
    pub depths: Vec<usize>,
    /// Every edge with predicate == `predicate` whose endpoints are in
    /// `entities` (the exact evidence edges), sorted by (subject,
    /// predicate, object). All distinct.
    pub relations: Vec<Relation>,
    /// BFS depth of each relation's subject (parallel to `relations`).
    pub relation_depths: Vec<usize>,
}

/// A deterministic Directed Acyclic Graph of entities connected by
/// predicate-labelled relations.
///
/// Storage is the petgraph arena pattern: entities in a flat `Vec`, indexed
/// by `usize`, with adjacency maps derived from the edge set. The adjacency
/// maps, the text index and the topological ranks are **caches** — pure
/// functions of (entity insertion order, edge set) — rebuilt on
/// deserialization, so a round-tripped graph is `==` to the original.
///
/// Equality is **semantic**: two graphs are equal iff they hold the same
/// entities (in first-occurrence order) and the same relation set — internal
/// construction history (rank cache) never matters.
///
/// `Clone` and `Drop` are flat (bounded nesting), so neither can recurse on
/// the thread stack regardless of graph depth.
#[derive(Debug, Clone)]
pub struct KnowledgeGraph {
    /// Entities in first-occurrence order; `Entity::id` == vector index.
    entities: Vec<Entity>,
    /// Outgoing adjacency: `subject -> (object -> {predicates})`.
    out: BTreeMap<EntityId, BTreeMap<EntityId, BTreeSet<String>>>,
    /// Incoming adjacency: `object -> (subject -> {predicates})`.
    in_: BTreeMap<EntityId, BTreeMap<EntityId, BTreeSet<String>>>,
    /// Dedup/lookup index: entity text -> id.
    by_text: BTreeMap<String, EntityId>,
    /// Topological rank per entity id (Pearce–Kelly maintenance).
    topo: Vec<usize>,
}

impl Default for KnowledgeGraph {
    fn default() -> Self {
        Self::new()
    }
}

/// Semantic equality: same entities in the same order and the same relation
/// set. Implemented manually (not derived) so the internal `topo` rank cache
/// — which depends on *how* the graph was assembled — can never make two
/// semantically identical graphs compare unequal.
impl PartialEq for KnowledgeGraph {
    fn eq(&self, other: &Self) -> bool {
        self.entities == other.entities && self.relations() == other.relations()
    }
}

impl Eq for KnowledgeGraph {}

impl KnowledgeGraph {
    /// An empty graph (no entities, no relations).
    #[must_use]
    pub fn new() -> Self {
        Self {
            entities: Vec::new(),
            out: BTreeMap::new(),
            in_: BTreeMap::new(),
            by_text: BTreeMap::new(),
            topo: Vec::new(),
        }
    }

    /// Number of entities in the graph.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entities.len()
    }

    /// Whether the graph has no entities.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entities.is_empty()
    }

    /// Alias for [`Self::len`] (entity count).
    #[must_use]
    pub fn entity_count(&self) -> usize {
        self.entities.len()
    }

    /// Number of relations in the graph (each predicate edge counts once).
    #[must_use]
    pub fn relation_count(&self) -> usize {
        self.out
            .values()
            .map(|objs| objs.values().map(BTreeSet::len).sum::<usize>())
            .sum()
    }

    /// All entities, in first-occurrence order.
    #[must_use]
    pub fn entities(&self) -> &[Entity] {
        &self.entities
    }

    /// The entity with the given arena id, or `None` if it does not exist.
    #[must_use]
    pub fn entity(&self, id: EntityId) -> Option<&Entity> {
        self.entities.get(id)
    }

    /// The arena id of the entity with the given text, or `None`.
    #[must_use]
    pub fn entity_id(&self, text: &str) -> Option<EntityId> {
        self.by_text.get(text).copied()
    }

    /// Whether an entity with the given text exists.
    #[must_use]
    pub fn contains_entity(&self, text: &str) -> bool {
        self.by_text.contains_key(text)
    }

    /// Adds an entity (deduplicated by text), returning its arena id.
    ///
    /// Idempotent: adding an existing text returns the existing id. An empty
    /// or over-`[`MAX_SYMBOL_LEN`]`-byte text is rejected *before* mutation.
    pub fn add_entity(&mut self, text: &str) -> Result<EntityId, GraphError> {
        if text.is_empty() {
            return Err(GraphError::EmptyEntity);
        }
        if text.len() > MAX_SYMBOL_LEN {
            return Err(GraphError::EntityTooLong {
                len: text.len(),
                max: MAX_SYMBOL_LEN,
            });
        }
        if let Some(&id) = self.by_text.get(text) {
            return Ok(id);
        }
        let id = self.entities.len();
        self.entities.push(Entity {
            id,
            text: text.to_string(),
        });
        self.by_text.insert(text.to_string(), id);
        self.topo.push(0);
        Ok(id)
    }

    /// Adds a relation `subject --predicate--> object`, enforcing the DAG
    /// invariant.
    ///
    /// Idempotent: re-adding an existing `(subject, predicate, object)`
    /// triple succeeds without duplicating state.
    ///
    /// # Errors
    ///
    /// - [`GraphError::UnknownEntity`] if either endpoint does not exist;
    /// - [`GraphError::SelfLoop`] if `subject == object`;
    /// - [`GraphError::EmptyPredicate`] / [`GraphError::PredicateTooLong`]
    ///   if the predicate violates the ingress clamp;
    /// - [`GraphError::Cycle`] if the edge would close a directed cycle.
    ///
    /// On any error the graph is left byte-identical to its prior state.
    pub fn add_relation(
        &mut self,
        subject: EntityId,
        predicate: &str,
        object: EntityId,
    ) -> Result<(), GraphError> {
        if subject >= self.entities.len() {
            return Err(GraphError::UnknownEntity { id: subject });
        }
        if object >= self.entities.len() {
            return Err(GraphError::UnknownEntity { id: object });
        }
        if subject == object {
            return Err(GraphError::SelfLoop { entity: subject });
        }
        if predicate.is_empty() {
            return Err(GraphError::EmptyPredicate);
        }
        if predicate.len() > MAX_SYMBOL_LEN {
            return Err(GraphError::PredicateTooLong {
                len: predicate.len(),
                max: MAX_SYMBOL_LEN,
            });
        }
        if self.has_relation(subject, predicate, object) {
            return Ok(()); // idempotent: already present
        }

        // Pearce–Kelly fast path: the new edge respects the maintained
        // topological order, so it provably cannot create a cycle.
        if self.topo[subject] < self.topo[object] {
            self.insert_edge(subject, predicate.to_string(), object);
            return Ok(());
        }

        // Suspicious case: would `subject -> object` close a path
        // `object -> ... -> subject` that already exists?
        if self.can_reach(object, subject) {
            return Err(GraphError::Cycle { subject, object });
        }

        self.insert_edge(subject, predicate.to_string(), object);
        // Restoring the rank invariant keeps the fast path O(1) for all
        // future inserts. Kahn cannot fail here (acyclicity was just
        // verified); if it ever did, the error propagates instead of
        // panicking — no panic site on this path.
        self.rebuild_ranks()?;
        Ok(())
    }

    /// Whether the exact relation `subject --predicate--> object` exists.
    #[must_use]
    pub fn has_relation(&self, subject: EntityId, predicate: &str, object: EntityId) -> bool {
        self.out
            .get(&subject)
            .and_then(|objs| objs.get(&object))
            .is_some_and(|preds| preds.contains(predicate))
    }

    /// Outgoing relations of `id` as `(object, predicate)` pairs, sorted by
    /// object id then predicate (deterministic).
    #[must_use]
    pub fn outgoing(&self, id: EntityId) -> Vec<(EntityId, &str)> {
        let mut v = Vec::new();
        if let Some(objs) = self.out.get(&id) {
            for (&o, preds) in objs {
                for p in preds {
                    v.push((o, p.as_str()));
                }
            }
        }
        v
    }

    /// Incoming relations of `id` as `(subject, predicate)` pairs, sorted by
    /// subject id then predicate (deterministic).
    #[must_use]
    pub fn incoming(&self, id: EntityId) -> Vec<(EntityId, &str)> {
        let mut v = Vec::new();
        if let Some(subs) = self.in_.get(&id) {
            for (&s, preds) in subs {
                for p in preds {
                    v.push((s, p.as_str()));
                }
            }
        }
        v
    }

    /// All entities reachable from `id` via directed relations, in
    /// deterministic iterative-BFS discovery order (start excluded).
    ///
    /// Unknown ids yield an empty traversal — defensive, never a panic.
    #[must_use]
    pub fn reachable_from(&self, id: EntityId) -> Vec<EntityId> {
        if id >= self.entities.len() {
            return Vec::new();
        }
        let mut visited = vec![false; self.entities.len()];
        let mut queue = VecDeque::new();
        let mut out = Vec::new();
        visited[id] = true;
        queue.push_back(id);
        while let Some(v) = queue.pop_front() {
            if let Some(objs) = self.out.get(&v) {
                for &o in objs.keys() {
                    if !visited[o] {
                        visited[o] = true;
                        out.push(o);
                        queue.push_back(o);
                    }
                }
            }
        }
        out
    }

    /// All entities that can reach `id` via directed relations, in
    /// deterministic iterative-BFS discovery order (start excluded).
    ///
    /// Unknown ids yield an empty traversal — defensive, never a panic.
    #[must_use]
    pub fn ancestors_of(&self, id: EntityId) -> Vec<EntityId> {
        if id >= self.entities.len() {
            return Vec::new();
        }
        let mut visited = vec![false; self.entities.len()];
        let mut queue = VecDeque::new();
        let mut out = Vec::new();
        visited[id] = true;
        queue.push_back(id);
        while let Some(v) = queue.pop_front() {
            if let Some(subs) = self.in_.get(&v) {
                for &s in subs.keys() {
                    if !visited[s] {
                        visited[s] = true;
                        out.push(s);
                        queue.push_back(s);
                    }
                }
            }
        }
        out
    }

    /// A deterministic topological ordering of all entities: every relation
    /// goes from an earlier position to a later one.
    ///
    /// Infallible: the DAG invariant is enforced at every entry point (and
    /// at deserialization), so the maintained ranks are always a valid
    /// topological order. Ties between independent entities are broken by
    /// ascending id — fully deterministic.
    #[must_use]
    pub fn topological_order(&self) -> Vec<EntityId> {
        let mut ids: Vec<EntityId> = (0..self.entities.len()).collect();
        ids.sort_by_key(|&id| (self.topo[id], id));
        ids
    }

    /// All relations flattened in deterministic order (subject, object,
    /// predicate — each ascending).
    #[must_use]
    pub fn relations(&self) -> Vec<Relation> {
        let mut v = Vec::new();
        for (&s, objs) in &self.out {
            for (&o, preds) in objs {
                for p in preds {
                    v.push(Relation {
                        subject: s,
                        predicate: p.clone(),
                        object: o,
                    });
                }
            }
        }
        v
    }

    /// Returns the **exact evidence subgraph** for a `(subject, predicate)`
    /// query: the anchor entity plus every entity reachable from it by
    /// following *only* edges whose predicate matches `predicate` exactly,
    /// and every such edge.
    ///
    /// Following the established knowledge-graph-RAG convention, this
    /// returns **one deduplicated subgraph** — never an enumeration of
    /// linear paths (path enumeration is exponential, O(2^V) even in a
    /// DAG; predicate-filtered BFS is O(V + E)). Evidence is ordered
    /// deterministically for reproducible LLM context: BFS depth from the
    /// anchor (primary), ascending entity id (secondary), and edges by
    /// (subject, predicate, object) (tertiary).
    ///
    /// # Returns
    ///
    /// - `None` if no entity with text `subject` exists in the graph.
    /// - Otherwise `Some(path)` — possibly an anchor-only subgraph (no
    ///   edges) when the anchor has no outgoing edge labelled exactly
    ///   `predicate` (e.g. an empty or never-matching predicate label).
    ///
    /// Parallel-array contract: `path.entities` / `path.depths` and
    /// `path.relations` / `path.relation_depths` have equal lengths, and
    /// every relation endpoint is present in `path.entities`.
    #[must_use]
    pub fn find_path(&self, subject: &str, predicate: &str) -> Option<Path> {
        let anchor = self.by_text.get(subject).copied()?;

        // Iterative predicate-filtered BFS: every node and predicate-edge
        // is visited at most once — O(V + E), never path enumeration.
        let mut visited = vec![false; self.entities.len()];
        let mut queue = VecDeque::new();
        let mut found: Vec<(EntityId, usize)> = Vec::new(); // (id, depth)
        let mut edges: Vec<(Relation, usize)> = Vec::new(); // (edge, subject depth)
        visited[anchor] = true;
        queue.push_back((anchor, 0usize));
        while let Some((v, depth)) = queue.pop_front() {
            found.push((v, depth));
            if let Some(objs) = self.out.get(&v) {
                for (&o, preds) in objs {
                    if !preds.contains(predicate) {
                        continue; // exact predicate match only
                    }
                    edges.push((
                        Relation {
                            subject: v,
                            predicate: predicate.to_string(),
                            object: o,
                        },
                        depth,
                    ));
                    if !visited[o] {
                        visited[o] = true;
                        queue.push_back((o, depth + 1));
                    }
                }
            }
        }

        // Primary sort: BFS depth from the anchor; secondary: entity id.
        found.sort_by_key(|&(id, d)| (d, id));
        let entities: Vec<EntityId> = found.iter().map(|&(id, _)| id).collect();
        let depths: Vec<usize> = found.iter().map(|&(_, d)| d).collect();

        // Tertiary sort: edges by (subject, predicate, object).
        // `sort_by` (not `sort_by_key`) — the comparator borrows both
        // elements, sidestepping sort_by_key's key-lifetime limitation.
        edges.sort_by(|a, b| {
            (&a.0.subject, &a.0.predicate, &a.0.object).cmp(&(
                &b.0.subject,
                &b.0.predicate,
                &b.0.object,
            ))
        });
        let relations: Vec<Relation> = edges.iter().map(|(r, _)| r.clone()).collect();
        let relation_depths: Vec<usize> = edges.iter().map(|&(_, d)| d).collect();

        Some(Path {
            subject: anchor,
            predicate: predicate.to_string(),
            entities,
            depths,
            relations,
            relation_depths,
        })
    }

    /// Records the edge in both adjacency caches. No checks — callers
    /// enforce the DAG invariant before reaching here.
    fn insert_edge(&mut self, subject: EntityId, predicate: String, object: EntityId) {
        self.out
            .entry(subject)
            .or_default()
            .entry(object)
            .or_default()
            .insert(predicate.clone());
        self.in_
            .entry(object)
            .or_default()
            .entry(subject)
            .or_default()
            .insert(predicate);
    }

    /// Iterative BFS: is `to` reachable from `from` along existing edges?
    /// Never recurses, so adversarial depth cannot overflow the stack.
    fn can_reach(&self, from: EntityId, to: EntityId) -> bool {
        let mut visited = vec![false; self.entities.len()];
        let mut queue = VecDeque::new();
        visited[from] = true;
        queue.push_back(from);
        while let Some(v) = queue.pop_front() {
            if v == to {
                return true;
            }
            if let Some(objs) = self.out.get(&v) {
                for &o in objs.keys() {
                    if !visited[o] {
                        visited[o] = true;
                        queue.push_back(o);
                    }
                }
            }
        }
        false
    }

    /// Recomputes topological ranks from scratch (Kahn's algorithm,
    /// iterative, deterministic ascending-id tie-break).
    ///
    /// # Errors
    ///
    /// Returns [`GraphError::CyclicPayload`] if the edge set contains a
    /// cycle — only possible via a tampered serialized payload, which is
    /// then refused loudly instead of materialising a broken graph.
    fn rebuild_ranks(&mut self) -> Result<(), GraphError> {
        let n = self.entities.len();
        let mut indeg = vec![0usize; n];
        for objs in self.out.values() {
            for (&o, preds) in objs {
                if !preds.is_empty() {
                    indeg[o] += 1;
                }
            }
        }
        let mut ready: BTreeSet<EntityId> = (0..n).filter(|&v| indeg[v] == 0).collect();
        let mut rank = vec![0usize; n];
        let mut placed = 0usize;
        while let Some(v) = ready.pop_first() {
            rank[v] = placed;
            placed += 1;
            if let Some(objs) = self.out.get(&v) {
                for (&o, preds) in objs {
                    if preds.is_empty() {
                        continue;
                    }
                    indeg[o] -= 1;
                    if indeg[o] == 0 {
                        ready.insert(o);
                    }
                }
            }
        }
        if placed != n {
            return Err(GraphError::CyclicPayload);
        }
        self.topo = rank;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Flat-array serialization (research-backed): nodes + edges, nothing nested.
// ---------------------------------------------------------------------------
//
// The graph is serialized as exactly two flat arrays — `nodes` (entities)
// and `edges` (relations). Rationale:
//  1. serde_json's default 128-level recursion limit is never approached
//     (the payload is two levels deep);
//  2. shared entities cannot be "tree-ified": each entity appears once and
//     edges reference it by index, so a DAG round-trips as a DAG;
//  3. deserialization rebuilds the adjacency caches in O(V + E) and rejects
//     cyclic/malformed payloads loudly instead of materialising a graph
//     that would break traversal.

impl Serialize for KnowledgeGraph {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("KnowledgeGraph", 2)?;
        state.serialize_field("nodes", &self.entities)?;
        state.serialize_field("edges", &self.relations())?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for KnowledgeGraph {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Flat {
            nodes: Vec<Entity>,
            edges: Vec<Relation>,
        }
        let flat = Flat::deserialize(deserializer)?;

        let mut g = KnowledgeGraph::new();
        // Materialize + validate nodes in one pass: ids must be dense 0..n
        // and texts unique (otherwise the lookup index would be ambiguous).
        for (idx, e) in flat.nodes.into_iter().enumerate() {
            if e.id != idx {
                return Err(serde::de::Error::custom(format!(
                    "entity id {} at position {}: ids must be dense 0..n",
                    e.id, idx
                )));
            }
            if e.text.is_empty() {
                return Err(serde::de::Error::custom("entity text is empty"));
            }
            if e.text.len() > MAX_SYMBOL_LEN {
                return Err(serde::de::Error::custom(format!(
                    "entity text is {} bytes, exceeds the {}-byte ingress clamp",
                    e.text.len(),
                    MAX_SYMBOL_LEN
                )));
            }
            if g.by_text.insert(e.text.clone(), idx).is_some() {
                return Err(serde::de::Error::custom(format!(
                    "duplicate entity text {:?}",
                    e.text
                )));
            }
            g.entities.push(e);
            g.topo.push(0);
        }

        // Bulk-materialize edges straight into the adjacency caches (no
        // per-edge cycle checks — validation happens once, below).
        for r in flat.edges {
            if r.subject >= g.entities.len() || r.object >= g.entities.len() {
                return Err(serde::de::Error::custom(format!(
                    "edge references unknown entity (subject {}, object {})",
                    r.subject, r.object
                )));
            }
            if r.subject == r.object {
                return Err(serde::de::Error::custom("edge is a self-loop"));
            }
            if r.predicate.is_empty() {
                return Err(serde::de::Error::custom("predicate text is empty"));
            }
            if r.predicate.len() > MAX_SYMBOL_LEN {
                return Err(serde::de::Error::custom(format!(
                    "predicate text is {} bytes, exceeds the {}-byte ingress clamp",
                    r.predicate.len(),
                    MAX_SYMBOL_LEN
                )));
            }
            g.out
                .entry(r.subject)
                .or_default()
                .entry(r.object)
                .or_default()
                .insert(r.predicate.clone());
            g.in_
                .entry(r.object)
                .or_default()
                .entry(r.subject)
                .or_default()
                .insert(r.predicate);
        }

        // Rebuild the topological order; a cyclic payload fails loudly here.
        g.rebuild_ranks().map_err(serde::de::Error::custom)?;
        Ok(g)
    }
}

// ---------------------------------------------------------------------------
// Tests — inputs constructed inline, outputs asserted against derived truth
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn diamond() -> KnowledgeGraph {
        let mut g = KnowledgeGraph::new();
        let a = g.add_entity("a").unwrap();
        let b = g.add_entity("b").unwrap();
        let c = g.add_entity("c").unwrap();
        let d = g.add_entity("d").unwrap();
        g.add_relation(a, "rel", b).unwrap();
        g.add_relation(a, "rel", c).unwrap();
        g.add_relation(b, "rel", d).unwrap();
        g.add_relation(c, "rel", d).unwrap();
        g
    }

    #[test]
    fn empty_graph_has_no_entities_or_relations() {
        let g = KnowledgeGraph::new();
        assert!(g.is_empty());
        assert_eq!(g.len(), 0);
        assert_eq!(g.relation_count(), 0);
        assert!(g.topological_order().is_empty());
        assert!(g.reachable_from(0).is_empty());
    }

    #[test]
    fn add_entity_dedups_and_assigns_insertion_order_ids() {
        let mut g = KnowledgeGraph::new();
        let flare = g.add_entity("flare").unwrap();
        let ftso = g.add_entity("ftso").unwrap();
        assert_eq!(flare, 0);
        assert_eq!(ftso, 1);
        assert_eq!(g.add_entity("flare").unwrap(), flare, "dedup by text");
        assert_eq!(g.len(), 2);
        assert_eq!(g.entity_id("flare"), Some(flare));
        assert_eq!(g.entity_id("missing"), None);
        assert!(g.contains_entity("ftso"));
        assert!(!g.contains_entity("missing"));
    }

    #[test]
    fn add_entity_rejects_empty_and_oversized_symbols_without_mutation() {
        let mut g = KnowledgeGraph::new();
        assert_eq!(g.add_entity(""), Err(GraphError::EmptyEntity));
        let huge = "x".repeat(MAX_SYMBOL_LEN + 1);
        assert_eq!(
            g.add_entity(&huge),
            Err(GraphError::EntityTooLong {
                len: huge.len(),
                max: MAX_SYMBOL_LEN
            })
        );
        // Boundary: exactly MAX_SYMBOL_LEN is legal.
        let exact = "y".repeat(MAX_SYMBOL_LEN);
        assert!(g.add_entity(&exact).is_ok());
        // Nothing was mutated by the rejected calls.
        assert_eq!(g.len(), 1);
    }

    #[test]
    fn add_relation_creates_predicate_edge() {
        let mut g = KnowledgeGraph::new();
        let a = g.add_entity("alice").unwrap();
        let b = g.add_entity("bob").unwrap();
        g.add_relation(a, "likes", b).unwrap();
        assert!(g.has_relation(a, "likes", b));
        assert!(!g.has_relation(b, "likes", a));
        assert_eq!(g.relation_count(), 1);
        assert_eq!(g.outgoing(a), vec![(b, "likes")]);
        assert_eq!(g.incoming(b), vec![(a, "likes")]);
    }

    #[test]
    fn add_relation_is_idempotent() {
        let mut g = KnowledgeGraph::new();
        let a = g.add_entity("alice").unwrap();
        let b = g.add_entity("bob").unwrap();
        g.add_relation(a, "likes", b).unwrap();
        g.add_relation(a, "likes", b).unwrap();
        assert_eq!(g.relation_count(), 1, "re-adding must not duplicate");
    }

    #[test]
    fn add_relation_rejects_unknown_entities() {
        let mut g = KnowledgeGraph::new();
        g.add_entity("alice").unwrap();
        assert_eq!(
            g.add_relation(0, "likes", 5),
            Err(GraphError::UnknownEntity { id: 5 })
        );
        assert_eq!(
            g.add_relation(5, "likes", 0),
            Err(GraphError::UnknownEntity { id: 5 })
        );
        assert_eq!(g.relation_count(), 0);
    }

    #[test]
    fn add_relation_rejects_self_loops() {
        let mut g = KnowledgeGraph::new();
        let a = g.add_entity("alice").unwrap();
        assert_eq!(
            g.add_relation(a, "likes", a),
            Err(GraphError::SelfLoop { entity: a })
        );
        assert_eq!(g.relation_count(), 0);
    }

    #[test]
    fn add_relation_rejects_direct_cycles() {
        let mut g = KnowledgeGraph::new();
        let a = g.add_entity("alice").unwrap();
        let b = g.add_entity("bob").unwrap();
        g.add_relation(a, "likes", b).unwrap();
        assert_eq!(
            g.add_relation(b, "likes", a),
            Err(GraphError::Cycle {
                subject: b,
                object: a
            })
        );
        // The failed insert mutated nothing.
        assert_eq!(g.relation_count(), 1);
        assert!(g.has_relation(a, "likes", b));
    }

    #[test]
    fn add_relation_rejects_indirect_cycles() {
        let mut g = KnowledgeGraph::new();
        let a = g.add_entity("a").unwrap();
        let b = g.add_entity("b").unwrap();
        let c = g.add_entity("c").unwrap();
        g.add_relation(a, "rel", b).unwrap();
        g.add_relation(b, "rel", c).unwrap();
        assert_eq!(
            g.add_relation(c, "rel", a),
            Err(GraphError::Cycle {
                subject: c,
                object: a
            })
        );
        assert_eq!(g.relation_count(), 2);
    }

    #[test]
    fn add_relation_rejects_rank_violating_cycle() {
        // Chain a -> b -> c -> d, then attempt d -> a and d -> b: both must
        // be refused even though no direct pair is reversed.
        let mut g = KnowledgeGraph::new();
        let ids: Vec<EntityId> = ["a", "b", "c", "d"]
            .iter()
            .map(|s| g.add_entity(s).unwrap())
            .collect();
        g.add_relation(ids[0], "rel", ids[1]).unwrap();
        g.add_relation(ids[1], "rel", ids[2]).unwrap();
        g.add_relation(ids[2], "rel", ids[3]).unwrap();
        assert!(g.add_relation(ids[3], "rel", ids[0]).is_err());
        assert!(g.add_relation(ids[3], "rel", ids[1]).is_err());
        assert_eq!(g.relation_count(), 3, "rejected edges must not land");
    }

    #[test]
    fn add_relation_fast_path_accepts_forward_edges() {
        // After the chain is built, edges that respect the maintained rank
        // order (0 -> 2, 1 -> 3, ...) are accepted without a cycle check.
        let mut g = KnowledgeGraph::new();
        let ids: Vec<EntityId> = (0..5)
            .map(|i| g.add_entity(&i.to_string()).unwrap())
            .collect();
        for i in 0..4 {
            g.add_relation(ids[i], "next", ids[i + 1]).unwrap();
        }
        assert!(g.add_relation(ids[0], "next", ids[2]).is_ok());
        assert!(g.add_relation(ids[1], "next", ids[3]).is_ok());
        assert!(g.add_relation(ids[0], "next", ids[4]).is_ok());
        assert_eq!(g.relation_count(), 7);
        assert!(g.topological_order().iter().copied().eq(0..5));
    }

    #[test]
    fn diamond_dag_traverses_deterministically() {
        let g = diamond();
        // reachable_from(a=0): BFS over ascending ids -> b, c, then d.
        assert_eq!(g.reachable_from(0), vec![1, 2, 3]);
        // ancestors_of(d=3): reverse BFS -> b, c, then a.
        assert_eq!(g.ancestors_of(3), vec![1, 2, 0]);
        // Sink (d) has no outgoing edges; source (a) has no ancestors.
        assert!(g.reachable_from(3).is_empty());
        assert!(g.ancestors_of(0).is_empty());
    }

    #[test]
    fn outgoing_and_incoming_are_sorted() {
        let mut g = KnowledgeGraph::new();
        let a = g.add_entity("a").unwrap();
        let b = g.add_entity("b").unwrap();
        let c = g.add_entity("c").unwrap();
        g.add_relation(a, "z_second", c).unwrap();
        g.add_relation(a, "a_first", b).unwrap();
        g.add_relation(a, "m_mid", b).unwrap();
        // outgoing sorted by object id, then predicate.
        assert_eq!(
            g.outgoing(a),
            vec![(b, "a_first"), (b, "m_mid"), (c, "z_second")]
        );
        // incoming sorted by subject id, then predicate.
        assert_eq!(g.incoming(b), vec![(a, "a_first"), (a, "m_mid")]);
    }

    #[test]
    fn relations_flatten_in_deterministic_order() {
        let g = diamond();
        let rels = g.relations();
        assert_eq!(
            rels,
            vec![
                Relation {
                    subject: 0,
                    predicate: "rel".into(),
                    object: 1
                },
                Relation {
                    subject: 0,
                    predicate: "rel".into(),
                    object: 2
                },
                Relation {
                    subject: 1,
                    predicate: "rel".into(),
                    object: 3
                },
                Relation {
                    subject: 2,
                    predicate: "rel".into(),
                    object: 3
                },
            ]
        );
    }

    #[test]
    fn topological_order_is_valid_and_deterministic() {
        let g = diamond();
        let order = g.topological_order();
        // Every relation goes forward in the order.
        let pos: BTreeMap<EntityId, usize> =
            order.iter().enumerate().map(|(i, &id)| (id, i)).collect();
        for r in g.relations() {
            assert!(
                pos[&r.subject] < pos[&r.object],
                "edge {} -> {} must be forward in topo order",
                r.subject,
                r.object
            );
        }
        // Repeated calls yield the identical order.
        assert_eq!(order, g.topological_order());
    }

    #[test]
    fn fast_path_build_scales_after_chain() {
        // Build a 1,500-entity chain through the slow (repair) path, then
        // add 1,498 redundant forward edges through the O(1) fast path.
        let mut g = KnowledgeGraph::new();
        let n = 1_500usize;
        let ids: Vec<EntityId> = (0..n)
            .map(|i| g.add_entity(&i.to_string()).unwrap())
            .collect();
        for i in 0..n - 1 {
            g.add_relation(ids[i], "next", ids[i + 1]).unwrap();
        }
        assert_eq!(g.relation_count(), n - 1);
        for j in 2..n {
            g.add_relation(ids[0], "related", ids[j]).unwrap();
        }
        assert_eq!(g.relation_count(), (n - 1) + (n - 2));
        // The whole graph is still one forward walk from 0.
        let reach = g.reachable_from(ids[0]);
        assert_eq!(reach.len(), n - 1);
        let order = g.topological_order();
        assert!(order.iter().copied().eq(0..n));
    }

    #[test]
    fn reachable_from_handles_unknown_ids_safely() {
        let g = diamond();
        assert!(g.reachable_from(99).is_empty());
        assert!(g.ancestors_of(99).is_empty());
    }

    #[test]
    fn serialization_is_flat_and_deterministic() {
        let g = diamond();
        let json = serde_json::to_string(&g).expect("serialize");
        // Deterministic: two serializations of the same graph are identical.
        assert_eq!(json, serde_json::to_string(&g).expect("serialize again"));
        // Flat shape: exactly {nodes, edges}, each entry two levels deep.
        let v: serde_json::Value = serde_json::from_str(&json).expect("valid json");
        let nodes = v["nodes"].as_array().expect("nodes array");
        let edges = v["edges"].as_array().expect("edges array");
        assert_eq!(nodes.len(), 4);
        assert_eq!(edges.len(), 4);
        assert!(nodes
            .iter()
            .all(|n| n["id"].is_u64() && n["text"].is_string()));
        assert!(edges
            .iter()
            .all(|e| e["subject"].is_u64() && e["predicate"].is_string() && e["object"].is_u64()));
    }

    #[test]
    fn round_trip_preserves_graph_and_caches() {
        let g = diamond();
        let json = serde_json::to_string(&g).expect("serialize");
        let g2: KnowledgeGraph = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(g, g2, "round-trip must be structurally identical");
        // Caches were rebuilt: lookups and traversals work on the copy.
        assert_eq!(g2.entity_id("a"), Some(0));
        assert_eq!(g2.reachable_from(0), vec![1, 2, 3]);
        assert_eq!(g2.ancestors_of(3), vec![1, 2, 0]);
        assert_eq!(g2.topological_order(), vec![0, 1, 2, 3]);
    }

    #[test]
    fn deserialize_rejects_cyclic_payload() {
        let cyclic = r#"{
            "nodes": [
                {"id": 0, "text": "a"},
                {"id": 1, "text": "b"}
            ],
            "edges": [
                {"subject": 0, "predicate": "x", "object": 1},
                {"subject": 1, "predicate": "y", "object": 0}
            ]
        }"#;
        let err = serde_json::from_str::<KnowledgeGraph>(cyclic).expect_err("must reject cycles");
        assert!(
            err.to_string().contains("cycle"),
            "error must name the cycle, got: {err}"
        );
    }

    #[test]
    fn deserialize_rejects_malformed_payloads() {
        // Duplicate entity text.
        let dup = r#"{"nodes":[{"id":0,"text":"a"},{"id":1,"text":"a"}],"edges":[]}"#;
        assert!(serde_json::from_str::<KnowledgeGraph>(dup).is_err());
        // Non-dense id.
        let sparse = r#"{"nodes":[{"id":3,"text":"a"}],"edges":[]}"#;
        assert!(serde_json::from_str::<KnowledgeGraph>(sparse).is_err());
        // Edge referencing an unknown entity.
        let dangling =
            r#"{"nodes":[{"id":0,"text":"a"}],"edges":[{"subject":0,"predicate":"x","object":9}]}"#;
        assert!(serde_json::from_str::<KnowledgeGraph>(dangling).is_err());
        // Self-loop edge.
        let looped =
            r#"{"nodes":[{"id":0,"text":"a"}],"edges":[{"subject":0,"predicate":"x","object":0}]}"#;
        assert!(serde_json::from_str::<KnowledgeGraph>(looped).is_err());
        // Oversized predicate in the payload.
        let big = format!(
            r#"{{"nodes":[{{"id":0,"text":"a"}},{{"id":1,"text":"b"}}],"edges":[{{"subject":0,"predicate":"{}","object":1}}]}}"#,
            "p".repeat(MAX_SYMBOL_LEN + 1)
        );
        assert!(serde_json::from_str::<KnowledgeGraph>(&big).is_err());
        // Oversized entity text in the payload.
        let big_entity = format!(
            r#"{{"nodes":[{{"id":0,"text":"{}"}}],"edges":[]}}"#,
            "e".repeat(MAX_SYMBOL_LEN + 1)
        );
        assert!(serde_json::from_str::<KnowledgeGraph>(&big_entity).is_err());
    }

    #[test]
    fn equality_is_semantic_not_construction_order() {
        // The same diamond, with edges added in two different orders: same
        // relation set, different internal rank history. Must compare equal
        // (semantic equality — caches are invisible to `==`).
        let mut g1 = KnowledgeGraph::new();
        let ids: Vec<EntityId> = ["a", "b", "c", "d"]
            .iter()
            .map(|s| g1.add_entity(s).unwrap())
            .collect();
        g1.add_relation(ids[0], "rel", ids[1]).unwrap();
        g1.add_relation(ids[0], "rel", ids[2]).unwrap();
        g1.add_relation(ids[1], "rel", ids[3]).unwrap();
        g1.add_relation(ids[2], "rel", ids[3]).unwrap();

        let mut g2 = KnowledgeGraph::new();
        let ids2: Vec<EntityId> = ["a", "b", "c", "d"]
            .iter()
            .map(|s| g2.add_entity(s).unwrap())
            .collect();
        g2.add_relation(ids2[2], "rel", ids2[3]).unwrap();
        g2.add_relation(ids2[1], "rel", ids2[3]).unwrap();
        g2.add_relation(ids2[0], "rel", ids2[2]).unwrap();
        g2.add_relation(ids2[0], "rel", ids2[1]).unwrap();

        assert_eq!(g1, g2, "construction history must not affect equality");
    }

    #[test]
    fn find_path_extracts_exact_predicate_evidence() {
        let g = diamond();
        let p = g.find_path("a", "rel").expect("subject exists");
        assert_eq!(p.subject, 0);
        assert_eq!(p.predicate, "rel");
        assert_eq!(p.entities, vec![0, 1, 2, 3]);
        assert_eq!(p.depths, vec![0, 1, 1, 2]);
        assert_eq!(
            p.relations,
            vec![
                Relation {
                    subject: 0,
                    predicate: "rel".into(),
                    object: 1
                },
                Relation {
                    subject: 0,
                    predicate: "rel".into(),
                    object: 2
                },
                Relation {
                    subject: 1,
                    predicate: "rel".into(),
                    object: 3
                },
                Relation {
                    subject: 2,
                    predicate: "rel".into(),
                    object: 3
                },
            ]
        );
        assert_eq!(p.relation_depths, vec![0, 0, 1, 1]);
        // Deterministic: repeated queries are identical.
        assert_eq!(p, g.find_path("a", "rel").expect("again"));
    }

    #[test]
    fn find_path_returns_none_for_unknown_subject() {
        let g = diamond();
        assert!(g.find_path("zzz", "rel").is_none());
    }

    #[test]
    fn find_path_returns_anchor_only_when_no_edges_match() {
        let g = diamond();
        let p = g
            .find_path("a", "no_such_predicate")
            .expect("subject exists");
        assert_eq!(p.entities, vec![0]);
        assert_eq!(p.depths, vec![0]);
        assert!(p.relations.is_empty());
        assert!(p.relation_depths.is_empty());
        // A sink entity is likewise anchor-only.
        let sink = g.find_path("d", "rel").expect("subject exists");
        assert_eq!(sink.entities, vec![3]);
        assert_eq!(sink.depths, vec![0]);
        assert!(sink.relations.is_empty());
    }

    #[test]
    fn find_path_filters_by_exact_predicate() {
        let mut g = KnowledgeGraph::new();
        let a = g.add_entity("a").unwrap();
        let b = g.add_entity("b").unwrap();
        let c = g.add_entity("c").unwrap();
        let d = g.add_entity("d").unwrap();
        g.add_relation(a, "x", b).unwrap();
        g.add_relation(a, "y", c).unwrap();
        g.add_relation(b, "x", d).unwrap();
        // Only x-edges are followed for the x query...
        let px = g.find_path("a", "x").expect("subject exists");
        assert_eq!(px.entities, vec![0, 1, 3]);
        assert_eq!(px.depths, vec![0, 1, 2]);
        assert_eq!(
            px.relations,
            vec![
                Relation {
                    subject: 0,
                    predicate: "x".into(),
                    object: 1
                },
                Relation {
                    subject: 1,
                    predicate: "x".into(),
                    object: 3
                },
            ]
        );
        assert_eq!(px.relation_depths, vec![0, 1]);
        // ...and only y-edges for the y query.
        let py = g.find_path("a", "y").expect("subject exists");
        assert_eq!(py.entities, vec![0, 2]);
        assert_eq!(
            py.relations,
            vec![Relation {
                subject: 0,
                predicate: "y".into(),
                object: 2
            }]
        );
        assert_eq!(py.relation_depths, vec![0]);
    }

    #[test]
    fn find_path_orders_by_depth_then_id() {
        // a -> b -> c and a -> d: b and d are both depth 1, and id(d)=3 > id(b)=1.
        let mut g = KnowledgeGraph::new();
        let a = g.add_entity("a").unwrap();
        let b = g.add_entity("b").unwrap();
        let c = g.add_entity("c").unwrap();
        let d = g.add_entity("d").unwrap();
        g.add_relation(a, "x", b).unwrap();
        g.add_relation(a, "x", d).unwrap();
        g.add_relation(b, "x", c).unwrap();
        let p = g.find_path("a", "x").expect("subject exists");
        assert_eq!(p.entities, vec![0, 1, 3, 2], "depth then id");
        assert_eq!(p.depths, vec![0, 1, 1, 2]);
        assert_eq!(
            p.relations,
            vec![
                Relation {
                    subject: 0,
                    predicate: "x".into(),
                    object: 1
                },
                Relation {
                    subject: 0,
                    predicate: "x".into(),
                    object: 3
                },
                Relation {
                    subject: 1,
                    predicate: "x".into(),
                    object: 2
                },
            ]
        );
        assert_eq!(p.relation_depths, vec![0, 0, 1]);
    }

    #[test]
    fn find_path_parallel_arrays_and_endpoints_are_consistent() {
        let g = diamond();
        let p = g.find_path("a", "rel").expect("subject exists");
        assert_eq!(p.entities.len(), p.depths.len());
        assert_eq!(p.relations.len(), p.relation_depths.len());
        let in_entities: BTreeSet<EntityId> = p.entities.iter().copied().collect();
        for r in &p.relations {
            assert!(
                in_entities.contains(&r.subject),
                "edge subject must be in entities"
            );
            assert!(
                in_entities.contains(&r.object),
                "edge object must be in entities"
            );
            assert_eq!(r.predicate, "rel", "only the exact predicate appears");
        }
    }

    #[test]
    fn find_path_round_trips_via_serde() {
        let g = diamond();
        let p = g.find_path("a", "rel").expect("subject exists");
        let json = serde_json::to_string(&p).expect("serialize");
        let p2: Path = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(p, p2);
        // Flat shape: id vectors + relation triples, nothing nested.
        let v: serde_json::Value = serde_json::from_str(&json).expect("valid json");
        assert!(v["entities"].is_array() && v["relations"].is_array());
    }

    #[test]
    fn deep_chain_traversal_and_drop_are_stack_safe() {
        // Adversarial depth: a 100,000-entity chain built DIRECTLY through
        // the private fields, bypassing the ingress clamp and cycle checks
        // (mirrors the trie's clamp-bypass regression test). Both traversal
        // directions must complete without touching the call stack deeply,
        // and dropping the graph (flat storage) must be safe.
        let n = 100_000usize;
        let mut g = KnowledgeGraph::new();
        g.entities = (0..n)
            .map(|i| Entity {
                id: i,
                text: i.to_string(),
            })
            .collect();
        g.by_text = (0..n).map(|i| (i.to_string(), i)).collect();
        for i in 0..n - 1 {
            let mut preds = BTreeSet::new();
            preds.insert("next".to_string());
            let mut objs = BTreeMap::new();
            objs.insert(i + 1, preds);
            g.out.insert(i, objs);

            let mut ipreds = BTreeSet::new();
            ipreds.insert("next".to_string());
            let mut subs = BTreeMap::new();
            subs.insert(i, ipreds);
            g.in_.insert(i + 1, subs);
        }
        g.topo = (0..n).collect(); // identity ranks are a valid topo order

        let reach = g.reachable_from(0);
        assert_eq!(reach.len(), n - 1, "full forward walk at depth 100k");
        // find_path on the same deep chain: the predicate-filtered BFS must
        // also be stack-safe at depth 100k (no recursion, ever).
        let p = g.find_path("0", "next").expect("subject exists");
        assert_eq!(p.entities.len(), n);
        assert_eq!(p.relations.len(), n - 1);
        assert!(p.depths.iter().copied().eq(0..n));
        let ancestors = g.ancestors_of(n - 1);
        assert_eq!(ancestors.len(), n - 1, "full reverse walk at depth 100k");
        assert_eq!(g.topological_order(), (0..n).collect::<Vec<_>>());
        // Drop happens at scope end — flat storage, no recursion.
    }

    #[test]
    fn find_path_predicate_matching_is_exact_not_substring_or_case() {
        // "x" must match ONLY the literal edge labelled "x" — not
        // "x_longer" (prefix), not "pre_x" (suffix), not "X" (case).
        // Exactness is the core evidence guarantee: a fuzzy match would leak
        // foreign edges into the proof subgraph.
        let mut g = KnowledgeGraph::new();
        let a = g.add_entity("a").unwrap();
        let b = g.add_entity("b").unwrap();
        let c = g.add_entity("c").unwrap();
        let d = g.add_entity("d").unwrap();
        let e = g.add_entity("e").unwrap();
        g.add_relation(a, "x", b).unwrap();
        g.add_relation(b, "x_longer", c).unwrap();
        g.add_relation(c, "pre_x", d).unwrap();
        g.add_relation(d, "X", e).unwrap();

        let p = g.find_path("a", "x").expect("subject exists");
        // The traversal stops at b: b -> c is "x_longer", not "x".
        assert_eq!(p.entities, vec![0, 1]);
        assert_eq!(p.depths, vec![0, 1]);
        assert_eq!(
            p.relations,
            vec![Relation {
                subject: 0,
                predicate: "x".into(),
                object: 1
            }]
        );
        assert_eq!(p.relation_depths, vec![0]);
        // Each neighbouring predicate matches only its own exact label.
        assert_eq!(
            g.find_path("b", "x_longer").expect("b exists").entities,
            vec![1, 2]
        );
        assert_eq!(
            g.find_path("c", "pre_x").expect("c exists").entities,
            vec![2, 3]
        );
        assert_eq!(
            g.find_path("d", "X").expect("d exists").entities,
            vec![3, 4]
        );
    }

    #[test]
    fn find_path_follows_only_queried_predicate_in_mixed_dag() {
        // rel and rel2 interleave in one DAG. The rel query must not cross a
        // rel2 edge — even though rel edges continue beyond it — and the
        // rel2 query must not cross rel edges.
        let mut g = KnowledgeGraph::new();
        let a = g.add_entity("a").unwrap();
        let b = g.add_entity("b").unwrap();
        let c = g.add_entity("c").unwrap();
        let d = g.add_entity("d").unwrap();
        g.add_relation(a, "rel", b).unwrap();
        g.add_relation(b, "rel2", c).unwrap();
        g.add_relation(c, "rel", d).unwrap();
        g.add_relation(a, "rel", d).unwrap(); // direct rel edge past the barrier

        // From a, rel reaches b and d directly, but NOT c (blocked by rel2).
        let p = g.find_path("a", "rel").expect("a exists");
        assert_eq!(p.entities, vec![0, 1, 3]);
        assert_eq!(p.depths, vec![0, 1, 1]);
        assert_eq!(
            p.relations,
            vec![
                Relation {
                    subject: 0,
                    predicate: "rel".into(),
                    object: 1
                },
                Relation {
                    subject: 0,
                    predicate: "rel".into(),
                    object: 3
                },
            ]
        );
        assert_eq!(p.relation_depths, vec![0, 0]);
        // From c, rel continues onward — the label, not the position,
        // determines the subgraph.
        let pc = g.find_path("c", "rel").expect("c exists");
        assert_eq!(pc.entities, vec![2, 3]);
        assert_eq!(
            pc.relations,
            vec![Relation {
                subject: 2,
                predicate: "rel".into(),
                object: 3
            }]
        );
        // And the rel2 query crosses only rel2 edges: from b it reaches c
        // but NOT d (the c -> d rel edge is not crossed).
        let p2 = g.find_path("b", "rel2").expect("b exists");
        assert_eq!(p2.entities, vec![1, 2]);
        assert_eq!(
            p2.relations,
            vec![Relation {
                subject: 1,
                predicate: "rel2".into(),
                object: 2
            }]
        );
    }

    #[test]
    fn find_path_is_outward_directed_from_the_anchor() {
        // The anchor sits mid-graph: b has two incoming "rel" edges (a -> b,
        // d -> b) and one outgoing (b -> c). find_path must follow only
        // OUTGOING edges — incoming evidence stays out of the subgraph.
        let mut g = KnowledgeGraph::new();
        let a = g.add_entity("a").unwrap();
        let b = g.add_entity("b").unwrap();
        let c = g.add_entity("c").unwrap();
        let d = g.add_entity("d").unwrap();
        g.add_relation(a, "rel", b).unwrap();
        g.add_relation(b, "rel", c).unwrap();
        g.add_relation(a, "other", d).unwrap();
        g.add_relation(d, "rel", b).unwrap(); // incoming rel edge to the anchor

        let p = g.find_path("b", "rel").expect("b exists");
        assert_eq!(p.entities, vec![1, 2]);
        assert_eq!(p.depths, vec![0, 1]);
        assert_eq!(
            p.relations,
            vec![Relation {
                subject: 1,
                predicate: "rel".into(),
                object: 2
            }]
        );
        assert_eq!(p.relation_depths, vec![0]);
        // The sibling branch (a -> d via "other") stays untouched.
        assert_eq!(
            g.find_path("a", "other").expect("a exists").entities,
            vec![0, 3]
        );
    }

    #[test]
    fn find_path_filters_by_exact_label_between_shared_endpoints() {
        // Two different predicate labels on the SAME endpoints (a -> b with
        // both "x" and "y"). Each query must return only its own edge — the
        // shared endpoints never contaminate the other predicate's evidence.
        let mut g = KnowledgeGraph::new();
        let a = g.add_entity("a").unwrap();
        let b = g.add_entity("b").unwrap();
        g.add_relation(a, "x", b).unwrap();
        g.add_relation(a, "y", b).unwrap();
        assert_eq!(g.relation_count(), 2);

        let px = g.find_path("a", "x").expect("a exists");
        assert_eq!(px.entities, vec![0, 1]);
        assert_eq!(
            px.relations,
            vec![Relation {
                subject: 0,
                predicate: "x".into(),
                object: 1
            }]
        );
        let py = g.find_path("a", "y").expect("a exists");
        assert_eq!(
            py.relations,
            vec![Relation {
                subject: 0,
                predicate: "y".into(),
                object: 1
            }]
        );
        // A sink anchor is never matched by its incoming edge.
        assert_eq!(g.find_path("b", "x").expect("b exists").entities, vec![1]);
    }

    #[test]
    fn find_path_deduplicates_convergent_subgraph() {
        // d is reachable from a via three distinct rel paths (b, c, e). The
        // evidence subgraph must contain d EXACTLY ONCE and every distinct
        // evidence edge exactly once — one deduplicated subgraph, never a
        // path enumeration.
        let mut g = KnowledgeGraph::new();
        let a = g.add_entity("a").unwrap();
        let b = g.add_entity("b").unwrap();
        let c = g.add_entity("c").unwrap();
        let d = g.add_entity("d").unwrap();
        let e = g.add_entity("e").unwrap();
        g.add_relation(a, "x", b).unwrap();
        g.add_relation(a, "x", c).unwrap();
        g.add_relation(b, "x", d).unwrap();
        g.add_relation(c, "x", d).unwrap();
        g.add_relation(a, "x", e).unwrap();
        g.add_relation(e, "x", d).unwrap();

        let p = g.find_path("a", "x").expect("a exists");
        // Depth-then-id: a(0), then b/c/e at depth 1, d(3) at depth 2.
        assert_eq!(p.entities, vec![0, 1, 2, 4, 3]);
        assert_eq!(p.depths, vec![0, 1, 1, 1, 2]);
        assert_eq!(
            p.relations,
            vec![
                Relation {
                    subject: 0,
                    predicate: "x".into(),
                    object: 1
                },
                Relation {
                    subject: 0,
                    predicate: "x".into(),
                    object: 2
                },
                Relation {
                    subject: 0,
                    predicate: "x".into(),
                    object: 4
                },
                Relation {
                    subject: 1,
                    predicate: "x".into(),
                    object: 3
                },
                Relation {
                    subject: 2,
                    predicate: "x".into(),
                    object: 3
                },
                Relation {
                    subject: 4,
                    predicate: "x".into(),
                    object: 3
                },
            ]
        );
        assert_eq!(p.relation_depths, vec![0, 0, 0, 1, 1, 1]);
        // Dedup proof: d appears once in entities despite three paths.
        assert_eq!(
            p.entities.iter().filter(|&&id| id == 3).count(),
            1,
            "shared node must be deduplicated"
        );
    }

    #[test]
    fn find_path_empty_predicate_is_anchor_only() {
        // The empty label can never match a stored edge (add_relation rejects
        // empty predicates), so a "" query yields the documented anchor-only
        // subgraph even on a richly connected graph.
        let g = diamond();
        let p = g.find_path("a", "").expect("a exists");
        assert_eq!(p.entities, vec![0]);
        assert_eq!(p.depths, vec![0]);
        assert!(p.relations.is_empty());
        assert!(p.relation_depths.is_empty());
    }

    #[test]
    fn find_path_is_deterministic_across_construction_order() {
        // The same relation set assembled in two different orders must yield
        // byte-identical evidence subgraphs (semantic equality — the cached
        // rank history is invisible to both `==` and find_path).
        let mut g1 = KnowledgeGraph::new();
        let ids1: Vec<EntityId> = ["a", "b", "c", "d"]
            .iter()
            .map(|s| g1.add_entity(s).unwrap())
            .collect();
        g1.add_relation(ids1[0], "rel", ids1[1]).unwrap();
        g1.add_relation(ids1[0], "rel", ids1[2]).unwrap();
        g1.add_relation(ids1[1], "rel", ids1[3]).unwrap();
        g1.add_relation(ids1[2], "rel", ids1[3]).unwrap();

        let mut g2 = KnowledgeGraph::new();
        let ids2: Vec<EntityId> = ["a", "b", "c", "d"]
            .iter()
            .map(|s| g2.add_entity(s).unwrap())
            .collect();
        g2.add_relation(ids2[2], "rel", ids2[3]).unwrap();
        g2.add_relation(ids2[0], "rel", ids2[2]).unwrap();
        g2.add_relation(ids2[1], "rel", ids2[3]).unwrap();
        g2.add_relation(ids2[0], "rel", ids2[1]).unwrap();

        assert_eq!(g1, g2, "semantic equality across construction orders");
        assert_eq!(
            g1.find_path("a", "rel"),
            g2.find_path("a", "rel"),
            "find_path must be order-independent"
        );
        // And it matches the canonical diamond evidence exactly.
        let expected = g1.find_path("a", "rel").expect("a exists");
        assert_eq!(expected.entities, vec![0, 1, 2, 3]);
        assert_eq!(expected.depths, vec![0, 1, 1, 2]);
    }
}

// ---------------------------------------------------------------------------
// Complexity sanity checks for the find_path O(V + E) guarantee
// ---------------------------------------------------------------------------

/// Empirical sanity checks for `find_path`'s strict O(V + E) claim.
///
/// The predicate-filtered BFS touches **only** the traversed evidence
/// subgraph (never foreign regions), but `find_path` allocates a visited
/// array over **all** vertices, so the honest total-cost claim is: linear in
/// total graph size and linear in evidence size — never quadratic (an
/// edge-scan) and never exponential (path enumeration). The first test pins
/// the linear-in-total-size bound; the second pins linear-in-evidence-size.
///
/// Methodology mirrors the trie's `complexity` module (min-of-k): parallel
/// halo2 rayon tests can only *inflate* a timed burst, so the minimum of
/// `SAMPLES` samples approximates uncontended time, and the assertion
/// margins (orders of magnitude apart from the failure mode) cannot flake
/// under OS scheduling jitter.
#[cfg(test)]
mod complexity {
    use std::time::Instant;

    use super::*;

    /// Number of repetitions per timed sample.
    const REPS: usize = 20_000;
    /// Number of samples per phase; the minimum is used (outlier-resistant).
    const SAMPLES: usize = 5;

    /// Times `f` `REPS` times, repeated over `SAMPLES` bursts, returning the
    /// minimum elapsed time in ns. Min-of-k: parallel interference can only
    /// inflate a burst, never deflate it.
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

    #[test]
    fn find_path_cost_grows_linearly_not_quadratically_with_graph_size() {
        // O(V + E) bound: the evidence subgraph is fixed at 4 nodes while a
        // disconnected foreign chain grows 1k -> 64k. Total cost scales
        // ~linearly with graph size (the visited-array pass is O(V)); a
        // quadratic edge-scan would blow to ~4096x, and path enumeration
        // would be worse still. The 128x ceiling admits 64x linear growth
        // with 2x headroom while staying ~32x below the quadratic failure.
        let foreign: Vec<String> = (0..64_000).map(|i| format!("f{i}")).collect();

        let mut time_small = 0u128;
        let mut time_large = 0u128;

        for (keep, acc) in [(1_000usize, &mut time_small), (64_000, &mut time_large)] {
            let mut g = KnowledgeGraph::new();
            let probe = g.add_entity("probe").expect("add");
            let p1 = g.add_entity("p1").expect("add");
            let p2 = g.add_entity("p2").expect("add");
            let p3 = g.add_entity("p3").expect("add");
            g.add_relation(probe, "x", p1).expect("add");
            g.add_relation(p1, "x", p2).expect("add");
            g.add_relation(p2, "x", p3).expect("add");
            // All foreign entities FIRST, then the chain edges. Interleaving
            // would give every fresh entity rank 0, forcing an O(V+E) rank
            // rebuild on every edge — an accidental O(V^2) build (caught by
            // a timeout during development). Entities-first means only the
            // first edge rebuilds ranks; the remaining ~64k take the O(1)
            // fast path.
            for name in foreign.iter().take(keep) {
                g.add_entity(name).expect("add");
            }
            for i in 0..keep - 1 {
                let subj = g.entity_id(&foreign[i]).expect("id");
                let obj = g.entity_id(&foreign[i + 1]).expect("id");
                g.add_relation(subj, "other", obj).expect("add");
            }
            // Correctness guard: the query reaches exactly the 4 evidence
            // nodes regardless of the foreign graph size.
            assert_eq!(
                g.find_path("probe", "x").expect("query").entities.len(),
                4,
                "evidence subgraph must stay fixed as the graph grows"
            );
            *acc = measure_min_ns(|| {
                std::hint::black_box(g.find_path("probe", "x"));
            });
        }

        // 64x more vertices must not make the query super-linear: linear
        // growth stays under 128x, quadratic would hit ~4096x.
        assert!(
            time_large < time_small.saturating_mul(128),
            "find_path grew super-linearly with graph size (small={time_small}ns, large={time_large}ns) - O(V+E) violated"
        );
    }

    #[test]
    fn find_path_scales_linearly_with_evidence_subgraph() {
        // Grow the query-reachable chain s 4 -> 128 nodes (the whole graph
        // is the evidence). The BFS visits each evidence node/edge once, so
        // query cost grows ~linearly; O(s^2) would grow ~1024x and fail
        // the 64x ceiling.
        let mut time_short = 0u128;
        let mut time_long = 0u128;

        for (size, acc) in [(4usize, &mut time_short), (128, &mut time_long)] {
            let mut g = KnowledgeGraph::new();
            // All entities first, then edges (keeps the rank rebuild O(1)
            // after the first edge — same fast-path discipline as the
            // population test).
            for i in 0..size {
                g.add_entity(&format!("e{i}")).expect("add");
            }
            for i in 0..size - 1 {
                let next = i + 1;
                let subj = g.entity_id(&format!("e{i}")).expect("id");
                let obj = g.entity_id(&format!("e{next}")).expect("id");
                g.add_relation(subj, "x", obj).expect("add");
            }
            // Correctness guard: the whole chain is the evidence subgraph.
            assert_eq!(
                g.find_path("e0", "x").expect("query").entities.len(),
                size,
                "the whole chain must be traversed"
            );
            *acc = measure_min_ns(|| {
                std::hint::black_box(g.find_path("e0", "x"));
            });
        }

        // Evidence grew 32x (4 -> 128); allow up to 64x (2x headroom over
        // linear). O(s^2) would be ~1024x and fail loudly.
        assert!(
            time_long < time_short.saturating_mul(64),
            "find_path grew super-linearly with evidence size (short={time_short}ns, long={time_long}ns) - O(V+E) violated"
        );
    }
}
