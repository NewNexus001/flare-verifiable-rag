//! # indexer_rs
//!
//! Deterministic symbolic knowledge engine — the Rust grounding core of the
//! Flare Verifiable RAG pipeline.
//!
//! The engine turns raw document text into a *provable, machine-checkable*
//! symbolic structure in three deterministic stages:
//!
//! 1. **Tokenization** — `tokenize()` splits text into typed `Token`s
//!    (word, number, symbol, whitespace, punctuation). Pure function of
//!    its input: identical input always yields identical tokens.
//! 2. **AST generation** — `parse()` folds the token stream into a
//!    `Document` AST (`Section`s of `Sentence`s of `Term`s). The AST is the
//!    canonical, lossless intermediate representation.
//! 3. **Symbolic graph matching** — `match_graph()` evaluates symbolic
//!    `Pattern`s against the extracted `DocumentAST` token graph
//!    (subject–predicate–object edges), returning every `GraphMatch` with
//!    its provenance (source term, byte span) so every answer the RAG agent
//!    produces can be traced back to a concrete document location.
//!
//! # Design invariants (enforced by construction)
//!
//! - **Determinism:** no `HashMap` (unordered) anywhere — `BTreeMap` /
//!   `Vec` ordering only. `tokenize` → `parse` → `match_graph` is a pure
//!   function chain, so the same document always produces the same graph.
//!   This is what makes the pipeline *verifiable*: the enclave can hash the
//!   AST and re-derive it inside the halo2 circuit later.
//! - **Ephemeral:** zero I/O, zero network, zero `std::env` reads. The
//!   engine works entirely in RAM — it never touches disk, matching the
//!   enclave's "memory-only sandbox" requirement.
//! - **Serializable:** every public data type derives `serde::Serialize` /
//!   `Deserialize` so the Python enclave can exchange ASTs/graphs over the
//!   FastAPI boundary as JSON.
//! - **Zero mock:** there is no test fixture, no hardcoded document, no
//!   canned graph in the library. All test inputs are constructed inline
//!   and asserted against expected *derived* output.
//!
//! The heavy zero-knowledge machinery (`halo2_proofs`, `sha2`) is declared
//! in `Cargo.toml` and consumed by the proof layer in later prompts; this
//! file defines only the stable public contract the rest of the pipeline
//! builds on.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod ast;
pub use ast::{DocumentAST, Edge, Node, SymbolType};

pub mod trie;
pub use trie::{SymbolicTrie, TrieError};

pub mod graph;
pub use graph::{Entity, EntityId, GraphError, KnowledgeGraph, Path, Relation};

#[cfg(feature = "python")]
pub mod ffi;

pub mod zkp;
pub use zkp::{
    digest_to_field, generate_params, generate_proof, graph_output_to_field, keygen, prove,
    prover_verifying_key, verify, verify_proof, RAGConfig, RAGVerificationCircuit, ZkpError,
    DEFAULT_K,
};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Unified error type for the indexer pipeline.
///
/// Every fallible stage reports a structured error carrying the byte offset
/// (and where meaningful, the offending span) so failures are traceable
/// back to the exact input position — no silent truncation, no fallback.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum IndexerError {
    /// Tokenization hit an input position it could not classify.
    #[error("tokenization failed at byte offset {offset}: {message}")]
    Tokenize { offset: usize, message: String },

    /// The token stream was not a valid document structure.
    #[error("parse failed at token index {index}: {message}")]
    Parse { index: usize, message: String },

    /// A pattern was malformed or referenced an unknown symbol.
    #[error("invalid pattern: {0}")]
    InvalidPattern(String),

    /// The requested graph operation was applied to an empty graph.
    #[error("graph is empty: {0}")]
    EmptyGraph(String),
}

/// Convenience alias for pipeline results.
pub type IndexerResult<T> = Result<T, IndexerError>;

// ---------------------------------------------------------------------------
// Stage 1 — Document tokenization
// ---------------------------------------------------------------------------

/// The lexical class of a [`Token`].
///
/// Classification is purely rule-based and locale-independent: a run of
/// ASCII alphanumerics (or `_`) is a word; a run of ASCII digits (optionally
/// with a single `.` separator) is a number; everything else falls into the
/// structural classes. No dictionaries, no heuristics, no ML — the same
/// bytes always yield the same class.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenKind {
    /// Alphanumeric run (ASCII letters, digits, `_`), e.g. `RAG`, `price`.
    Word,
    /// Numeric run, optionally decimal, e.g. `123`, `4.56`.
    Number,
    /// Punctuation (`.`, `,`, `;`, `:`, `!`, `?`, quotes, brackets).
    Punctuation,
    /// Symbolic operator (`.`, `=`, `+`, `-`, `*`, `/`, `>`, `<`, `&`, `|`).
    Symbol,
    /// Whitespace run (spaces, tabs, newlines, CRLF).
    Whitespace,
}

impl TokenKind {
    /// Whether this kind carries meaning for the symbolic graph (i.e. is not
    /// whitespace). Punctuation is retained — it is significant for sentence
    /// boundaries and decimal points.
    #[must_use]
    pub fn is_significant(&self) -> bool {
        !matches!(self, TokenKind::Whitespace)
    }
}

/// A single lexical unit produced by [`tokenize`].
///
/// `start`/`end` are **byte offsets** into the source document (not char
/// indices), so a token can always be sliced back out of the original
/// string for provenance reporting.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Token {
    /// The lexical class of this token.
    pub kind: TokenKind,
    /// Exact source text of the token (a subslice of the input).
    pub lexeme: String,
    /// Byte offset of the first byte of the token in the source document.
    pub start: usize,
    /// Byte offset one past the last byte of the token.
    pub end: usize,
}

impl Token {
    #[must_use]
    pub fn new(kind: TokenKind, lexeme: impl Into<String>, start: usize, end: usize) -> Self {
        Self {
            kind,
            lexeme: lexeme.into(),
            start,
            end,
        }
    }
}

/// Tokenizes a document into a typed, ordered token stream.
///
/// This is a **pure function**: `tokenize(a) == tokenize(a)` for any `a`,
/// and `tokenize(a) == tokenize(b)` iff `a == b` (byte-for-byte). No state,
/// no randomness, no environment access.
///
/// # Errors
///
/// Returns [`IndexerError::Tokenize`] if the input contains a byte sequence
/// that cannot be classified (e.g. a lone surrogate in a UTF-8 stream is
/// rejected before classification begins).
pub fn tokenize(input: &str) -> IndexerResult<Vec<Token>> {
    // Reject malformed UTF-8 up front: `&str` is always valid UTF-8, but
    // this guards the invariant that byte offsets always land on char
    // boundaries for the slicing done in `parse`.
    let bytes = input.as_bytes();
    let mut tokens = Vec::with_capacity(bytes.len() / 4 + 1);
    let mut i = 0usize;

    while i < bytes.len() {
        let b = bytes[i];
        let start = i;

        let kind = if b.is_ascii_alphabetic() || b == b'_' {
            while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                i += 1;
            }
            TokenKind::Word
        } else if b.is_ascii_digit() {
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i += 1;
            }
            // Optional single decimal point, followed by at least one digit.
            if i + 1 < bytes.len() && bytes[i] == b'.' && bytes[i + 1].is_ascii_digit() {
                i += 1;
                while i < bytes.len() && bytes[i].is_ascii_digit() {
                    i += 1;
                }
            }
            TokenKind::Number
        } else if b.is_ascii_whitespace() {
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            TokenKind::Whitespace
        } else if matches!(
            b,
            b'.' | b','
                | b';'
                | b':'
                | b'!'
                | b'?'
                | b'"'
                | b'\''
                | b'('
                | b')'
                | b'['
                | b']'
                | b'{'
                | b'}'
        ) {
            i += 1;
            TokenKind::Punctuation
        } else if matches!(
            b,
            b'=' | b'+'
                | b'-'
                | b'*'
                | b'/'
                | b'>'
                | b'<'
                | b'&'
                | b'|'
                | b'%'
                | b'^'
                | b'~'
                | b'#'
        ) {
            i += 1;
            TokenKind::Symbol
        } else {
            // Unclassifiable byte (non-ASCII punctuation, control chars).
            return Err(IndexerError::Tokenize {
                offset: i,
                message: format!("byte 0x{b:02x} is not classifiable"),
            });
        };

        // `input` is a valid `&str`, so a byte offset that walked a full
        // ASCII run always lies on a char boundary; slicing is safe.
        let lexeme = &input[start..i];
        tokens.push(Token::new(kind, lexeme, start, i));
    }

    Ok(tokens)
}

// ---------------------------------------------------------------------------
// Stage 2 — AST generation
// ---------------------------------------------------------------------------

/// A node in the document AST.
///
/// The AST is the canonical intermediate representation: `Document` contains
/// `Section`s, sections contain `Sentence`s, and sentences contain `Term`s.
/// Every node carries the byte span it was derived from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AstNode {
    /// Root node: a whole document made of sections.
    Document {
        /// Child sections in source order.
        sections: Vec<AstNode>,
    },
    /// A logical block of the document (e.g. a paragraph or heading).
    Section {
        /// Byte span of the section in the source document.
        span: Span,
        /// Sentences within the section, in source order.
        sentences: Vec<AstNode>,
    },
    /// A single sentence (terminated by `.`, `!`, `?` or end of input).
    Sentence {
        /// Byte span of the sentence.
        span: Span,
        /// Terms within the sentence, in source order.
        terms: Vec<AstNode>,
    },
    /// A single significant token (word or number).
    Term {
        /// The underlying token.
        token: Token,
    },
}

/// Half-open byte range `[start, end)` into the source document.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Span {
    /// First byte offset (inclusive).
    pub start: usize,
    /// Last byte offset (exclusive).
    pub end: usize,
}

impl Span {
    #[must_use]
    pub fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }

    /// The length of the span in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.end - self.start
    }

    /// Whether the span is empty (`start == end`).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.start == self.end
    }

    /// Union of two adjacent/overlapping spans.
    #[must_use]
    pub fn union(&self, other: &Span) -> Span {
        Span::new(self.start.min(other.start), self.end.max(other.end))
    }
}

/// Parses a token stream into a `Document` AST.
///
/// Structure rules (deterministic):
/// - Whitespace tokens are processed only to detect blank-line section
///   boundaries; punctuation is used for sentence boundaries (`.`, `!`, `?`)
///   and is not emitted as a term.
/// - A `Section` boundary is introduced at every run of ≥ 2 newlines.
/// - A `Sentence` boundary is introduced at `.`/`!`/`?`.
/// - The AST is a pure function of the token stream: re-parsing the same
///   tokens always yields the identical tree.
///
/// # Errors
///
/// Returns [`IndexerError::Parse`] if the token stream is empty.
pub fn parse(tokens: &[Token]) -> IndexerResult<AstNode> {
    if tokens.is_empty() {
        return Err(IndexerError::Parse {
            index: 0,
            message: "document contains no significant tokens".to_string(),
        });
    }

    let mut sections: Vec<AstNode> = Vec::new();
    let mut current_sentence: Vec<AstNode> = Vec::new(); // terms
    let mut current_sentences: Vec<AstNode> = Vec::new(); // sentences of the section

    // Flush the pending sentence into the pending section.
    let flush_sentence = |current_sentence: &mut Vec<AstNode>,
                          current_sentences: &mut Vec<AstNode>| {
        if current_sentence.is_empty() {
            return;
        }
        let start = match &current_sentence[0] {
            AstNode::Term { token } => token.start,
            _ => unreachable!("sentence members are always terms"),
        };
        let end = match current_sentence.last() {
            Some(AstNode::Term { token }) => token.end,
            _ => start,
        };
        current_sentences.push(AstNode::Sentence {
            span: Span::new(start, end),
            terms: std::mem::take(current_sentence),
        });
    };

    // Flush the pending section (if it has sentences) into the document.
    let flush_section = |current_sentences: &mut Vec<AstNode>, sections: &mut Vec<AstNode>| {
        if current_sentences.is_empty() {
            return;
        }
        let span_start = match &current_sentences[0] {
            AstNode::Sentence { span, .. } => span.start,
            _ => unreachable!(),
        };
        let span_end = match current_sentences.last() {
            Some(AstNode::Sentence { span, .. }) => span.end,
            _ => span_start,
        };
        sections.push(AstNode::Section {
            span: Span::new(span_start, span_end),
            sentences: std::mem::take(current_sentences),
        });
    };

    // Tracks consecutive newlines between significant tokens. Whitespace is
    // NOT filtered here: a whitespace token containing >= 2 newline chars (or
    // an accumulated run across tokens) marks a section boundary, matching
    // the documented contract.
    let mut newline_run: usize = 0;

    for tok in tokens {
        match tok.kind {
            TokenKind::Word | TokenKind::Number => {
                newline_run = 0;
                current_sentence.push(AstNode::Term { token: tok.clone() });
            }
            TokenKind::Punctuation if matches!(tok.lexeme.as_str(), "." | "!" | "?") => {
                // Sentence boundary: flush the current sentence (if non-empty).
                flush_sentence(&mut current_sentence, &mut current_sentences);
                newline_run = 0;
            }
            TokenKind::Punctuation | TokenKind::Symbol => {
                // Structural punctuation (commas, brackets, operators) does
                // not open or close sentence boundaries.
                newline_run = 0;
            }
            TokenKind::Whitespace => {
                // Count newline chars in this whitespace run. A run of >= 2
                // newlines ends the current section.
                newline_run += tok.lexeme.chars().filter(|&c| c == '\n').count();
                if newline_run >= 2 {
                    flush_sentence(&mut current_sentence, &mut current_sentences);
                    flush_section(&mut current_sentences, &mut sections);
                    newline_run = 0;
                }
            }
        }
    }

    // Flush any trailing sentence/section not terminated by punctuation.
    flush_sentence(&mut current_sentence, &mut current_sentences);
    flush_section(&mut current_sentences, &mut sections);

    if sections.is_empty() {
        return Err(IndexerError::Parse {
            index: 0,
            message: "no sentences could be derived from the token stream".to_string(),
        });
    }

    Ok(AstNode::Document { sections })
}

// ---------------------------------------------------------------------------
// Stage 3 — Symbolic graph extraction & matching
// ---------------------------------------------------------------------------
//
// The token-graph data model (DocumentAST / Node / Edge / SymbolType) lives
// in the `ast` module (src/ast.rs) and is re-exported at the crate root via
// `pub use ast::{...}`. This section only implements the extraction and
// matching logic on top of that model.

impl DocumentAST {
    /// Builds a token graph from a parsed document.
    ///
    /// Every `Term` becomes a node; within each sentence, every pair of
    /// distinct terms (in source order) yields an edge whose predicate is the
    /// lexeme of the intermediate word when exactly one word sits between
    /// them, otherwise `"related_to"`. This is a purely structural heuristic
    /// — deterministic and dependency-free — designed so the graph is fully
    /// re-derivable from the AST (which is what makes matching verifiable).
    #[must_use]
    pub fn from_ast(ast: &AstNode) -> DocumentAST {
        let mut nodes: Vec<Node> = Vec::new();
        let mut index: BTreeMap<String, usize> = BTreeMap::new();
        let mut edges: Vec<Edge> = Vec::new();
        let ensure_node = |text: &str,
                           kind: &TokenKind,
                           span: Span,
                           nodes: &mut Vec<Node>,
                           index: &mut BTreeMap<String, usize>| {
            let key = text.to_lowercase();
            if let Some(&idx) = index.get(&key) {
                idx
            } else {
                let idx = nodes.len();
                nodes.push(Node {
                    id: idx,
                    text: key.clone(),
                    // parse() emits only Word|Number terms, so this is always
                    // Some; the fallback keeps the type total for hand-built ASTs.
                    symbol_type: SymbolType::from_token_kind(kind).unwrap_or(SymbolType::Word),
                    span,
                });
                index.insert(key, idx);
                idx
            }
        };

        for sentence in ast.sentences() {
            let terms: Vec<&Token> = sentence.terms();
            for (i, term) in terms.iter().enumerate() {
                let subj = ensure_node(
                    &term.lexeme,
                    &term.kind,
                    Span::new(term.start, term.end),
                    &mut nodes,
                    &mut index,
                );
                for j in (i + 1)..terms.len() {
                    let obj_term = terms[j];
                    let obj = ensure_node(
                        &obj_term.lexeme,
                        &obj_term.kind,
                        Span::new(obj_term.start, obj_term.end),
                        &mut nodes,
                        &mut index,
                    );
                    if subj == obj {
                        continue;
                    }
                    let predicate = if j == i + 2 {
                        // Exactly one term between subject and object.
                        terms[i + 1].lexeme.to_lowercase()
                    } else {
                        "related_to".to_string()
                    };
                    edges.push(Edge {
                        predicate,
                        subject: subj,
                        object: obj,
                        span: nodes[subj].span,
                    });
                }
            }
        }

        DocumentAST { nodes, edges }
    }
}

impl AstNode {
    /// Returns the sentences contained in this node (recursively), in order.
    #[must_use]
    pub fn sentences(&self) -> Vec<&AstNode> {
        match self {
            AstNode::Document { sections } => sections.iter().flat_map(|s| s.sentences()).collect(),
            AstNode::Section { sentences, .. } => sentences.iter().collect(),
            AstNode::Sentence { .. } | AstNode::Term { .. } => Vec::new(),
        }
    }

    /// Returns the term tokens contained in this sentence node.
    #[must_use]
    pub fn terms(&self) -> Vec<&Token> {
        match self {
            AstNode::Sentence { terms, .. } => terms
                .iter()
                .filter_map(|t| match t {
                    AstNode::Term { token } => Some(token),
                    _ => None,
                })
                .collect(),
            _ => Vec::new(),
        }
    }
}

/// A symbolic pattern to match against a [`DocumentAST`].
///
/// Patterns are expressed as a list of `(subject, predicate, object)` triples
/// where each element is either an exact symbol text or a wildcard (`*`).
/// Each triple is evaluated **independently** — `match_graph` returns every
/// edge that satisfies any listed triple (OR semantics across triples).
/// Constrain a single query with one triple and wildcards.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pattern {
    /// The triples to evaluate; each is matched independently.
    pub triples: Vec<(String, String, String)>,
}

impl Pattern {
    /// Builds a pattern from a list of triples.
    #[must_use]
    pub fn new(triples: Vec<(String, String, String)>) -> Self {
        Self { triples }
    }

    /// Builds a single-triple pattern with wildcard support:
    /// `("*", predicate, object)` matches any subject.
    #[must_use]
    pub fn single(subject: &str, predicate: &str, object: &str) -> Self {
        Self::new(vec![(
            subject.to_string(),
            predicate.to_string(),
            object.to_string(),
        )])
    }
}

/// A successful match of a [`Pattern`] against a [`DocumentAST`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphMatch {
    /// The index of the matched subject node in the graph.
    pub subject: usize,
    /// The index of the matched object node in the graph.
    pub object: usize,
    /// The predicate text that was matched.
    pub predicate: String,
    /// The provenance span of the matched edge's subject in the source.
    pub span: Span,
}

/// Matches every triple of `pattern` against `graph`, returning all
/// successful matches in deterministic (graph-edge) order.
///
/// Wildcards (`*`) match any symbol text. A triple with an exact subject or
/// object that does not exist in the graph simply never matches — no error,
/// no fallback, no mock.
///
/// # Errors
///
/// Returns [`IndexerError::EmptyGraph`] if the graph has no symbols.
pub fn match_graph(graph: &DocumentAST, pattern: &Pattern) -> IndexerResult<Vec<GraphMatch>> {
    if graph.is_empty() {
        return Err(IndexerError::EmptyGraph(
            "cannot match a pattern against an empty graph".to_string(),
        ));
    }

    let mut matches = Vec::new();

    for (subj_text, pred_text, obj_text) in &pattern.triples {
        for edge in &graph.edges {
            // Defensive: skip edges whose indices do not resolve rather than
            // panic on a hand-constructed graph.
            let (Some(subj), Some(obj)) = (graph.node(edge.subject), graph.node(edge.object))
            else {
                continue;
            };
            let subj_ok = subj_text == "*" || subj.text == *subj_text;
            let pred_ok = pred_text == "*" || edge.predicate == *pred_text;
            let obj_ok = obj_text == "*" || obj.text == *obj_text;

            if subj_ok && pred_ok && obj_ok {
                matches.push(GraphMatch {
                    subject: edge.subject,
                    object: edge.object,
                    predicate: edge.predicate.clone(),
                    span: subj.span,
                });
            }
        }
    }

    Ok(matches)
}

// ---------------------------------------------------------------------------
// Deterministic content fingerprint (sha2)
// ---------------------------------------------------------------------------

/// Computes the SHA-256 digest of a canonical serialization of the document
/// AST.
///
/// Because the AST is deterministic and serde's `Serialize` for these exact
/// type definitions yields a stable byte layout, this digest is reproducible
/// across processes on the same code version — it is the value the enclave
/// records to prove *which* document grounding was used, and the value a
/// later halo2 circuit can verify in zero knowledge. (The layout is stable
/// per struct definition, not a cross-version canonical form.)
#[must_use]
pub fn content_digest(ast: &AstNode) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let canonical = serde_json::to_vec(ast).expect("AST serialization cannot fail");
    let mut hasher = Sha256::new();
    hasher.update(canonical);
    let out = hasher.finalize();
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&out);
    digest
}

// ---------------------------------------------------------------------------
// Tests — inputs constructed inline, outputs asserted against derived truth
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokenize_words_numbers_and_whitespace() {
        let tokens = tokenize("RAG price is 4.56").expect("tokenize must succeed");
        let kinds: Vec<&TokenKind> = tokens.iter().map(|t| &t.kind).collect();
        assert_eq!(
            kinds,
            vec![
                &TokenKind::Word,
                &TokenKind::Whitespace,
                &TokenKind::Word,
                &TokenKind::Whitespace,
                &TokenKind::Word,
                &TokenKind::Whitespace,
                &TokenKind::Number,
            ]
        );
        assert_eq!(tokens[0].lexeme, "RAG");
        assert_eq!(tokens[6].lexeme, "4.56");
        assert_eq!(tokens[6].start, 13);
        assert_eq!(tokens[6].end, 17);
    }

    #[test]
    fn tokenize_is_deterministic() {
        let a = tokenize("Flare FTSO v2 price feed").unwrap();
        let b = tokenize("Flare FTSO v2 price feed").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn parse_builds_document_with_sentences() {
        let tokens =
            tokenize("The price is 2.50. It rose yesterday.").expect("tokenize must succeed");
        let ast = parse(&tokens).expect("parse must succeed");
        let sentences = ast.sentences();
        assert_eq!(sentences.len(), 2);
        // First sentence: "The price is 2.50." → 4 terms (2.50 is one number).
        assert_eq!(sentences[0].terms().len(), 4);
        // Second sentence: "It rose yesterday." → 3 terms.
        assert_eq!(sentences[1].terms().len(), 3);
    }

    #[test]
    fn empty_document_errors() {
        let err = parse(&[]).unwrap_err();
        assert!(matches!(err, IndexerError::Parse { .. }));
    }

    #[test]
    fn parse_splits_sections_on_double_newline() {
        // Two sentences, separated by a blank line => two sections.
        let tokens = tokenize("Alpha one.\n\nBeta two.").expect("tokenize");
        let ast = parse(&tokens).expect("parse");
        let AstNode::Document { sections } = &ast else {
            panic!("expected document root");
        };
        assert_eq!(sections.len(), 2, "blank line must split sections");
        // Each section holds exactly one sentence.
        for section in sections {
            let AstNode::Section { sentences, .. } = section else {
                panic!("expected section node");
            };
            assert_eq!(sentences.len(), 1);
        }
        // A single newline must NOT split sections.
        let tokens2 = tokenize("Alpha one.\nBeta two.").expect("tokenize");
        let ast2 = parse(&tokens2).expect("parse");
        let AstNode::Document { sections: s2 } = &ast2 else {
            panic!("expected document root");
        };
        assert_eq!(s2.len(), 1, "single newline must not split sections");
    }

    #[test]
    fn graph_extraction_is_deterministic_and_has_edges() {
        let tokens = tokenize("Flare uses FTSO").unwrap();
        let ast = parse(&tokens).unwrap();
        let graph = DocumentAST::from_ast(&ast);
        assert!(!graph.is_empty());
        assert!(!graph.edges.is_empty());
        // Flare -uses-> FTSO must exist as a predicate edge.
        assert!(graph.edges.iter().any(|e| e.predicate == "uses"));
    }

    #[test]
    fn graph_nodes_classify_numbers_correctly() {
        let tokens = tokenize("The price is 4.56").unwrap();
        let ast = parse(&tokens).unwrap();
        let graph = DocumentAST::from_ast(&ast);
        let number_node = graph.nodes.iter().find(|n| n.text == "4.56");
        assert!(number_node.is_some(), "4.56 must become a node");
        assert_eq!(number_node.unwrap().symbol_type, SymbolType::Number);
        // Word nodes keep the Word class.
        let word_node = graph.nodes.iter().find(|n| n.text == "price").unwrap();
        assert_eq!(word_node.symbol_type, SymbolType::Word);
    }

    #[test]
    fn match_graph_finds_wildcard_matches() {
        let tokens = tokenize("Flare uses FTSO v2").unwrap();
        let ast = parse(&tokens).unwrap();
        let graph = DocumentAST::from_ast(&ast);

        let pattern = Pattern::single("*", "uses", "ftso");
        let matches = match_graph(&graph, &pattern).expect("match must not error");
        assert!(!matches.is_empty());
        assert_eq!(graph.nodes[matches[0].subject].text, "flare");
    }

    #[test]
    fn content_digest_is_stable() {
        let tokens = tokenize("deterministic grounding").unwrap();
        let ast = parse(&tokens).unwrap();
        let d1 = content_digest(&ast);
        let d2 = content_digest(&ast);
        assert_eq!(d1, d2);
        assert_ne!(d1, [0u8; 32]);
    }

    #[test]
    fn matching_against_empty_graph_errors() {
        let empty = DocumentAST::empty();
        let pattern = Pattern::single("a", "b", "c");
        let err = match_graph(&empty, &pattern).unwrap_err();
        assert!(matches!(err, IndexerError::EmptyGraph(_)));
    }
}
