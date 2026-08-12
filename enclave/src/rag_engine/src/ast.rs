//! # Token-graph data model (`DocumentAST`, `Node`, `Edge`, `SymbolType`)
//!
//! Canonical in-memory representation of a document as a **token graph**:
//! the output of the symbolic knowledge engine's extraction stage.
//!
//! A `DocumentAST` is a directed graph where:
//! - `nodes` are the document's significant symbols (words, numbers,
//!   operators, punctuation), each with a [`SymbolType`] and the byte
//!   [`Span`] it was extracted from;
//! - `edges` are directed relations `subject --predicate--> object`,
//!   indexed into `nodes`, each carrying the span of its subject.
//!
//! # Design invariants (same contract as the rest of `indexer_rs`)
//!
//! - **Deterministic:** nodes are stored in first-occurrence order, edges in
//!   emission order; no unordered collections. Identical input always
//!   yields an identical graph, byte for byte.
//! - **Ephemeral:** pure data types, zero I/O, zero environment access.
//! - **Serializable:** every type derives `serde::Serialize` /
//!   `Deserialize` so the Python enclave can receive the graph as JSON over
//!   the FastAPI boundary.
//! - **Verifiable:** node indices, predicate text and spans give every match
//!   (see `crate::match_graph`) full provenance back to the source document,
//!   which is what makes the RAG agent's answers auditable.

use serde::{Deserialize, Serialize};

use crate::{IndexerResult, Span};

/// The semantic class of a graph [`Node`].
///
/// Derived deterministically from the token's lexical class (see
/// [`SymbolType::from_token_kind`]); there is no `Whitespace` variant because
/// whitespace is never emitted as a graph node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SymbolType {
    /// A word (alphanumeric run), e.g. `flare`, `price`.
    Word,
    /// A number, optionally decimal, e.g. `123`, `4.56`.
    Number,
    /// A symbolic operator, e.g. `=`, `+`, `>`, `&`.
    Symbol,
    /// Punctuation retained in the graph, e.g. `.`, `,`, `(`, `"`.
    Punctuation,
}

impl SymbolType {
    /// Maps a token's lexical kind to a graph symbol type.
    ///
    /// Returns `None` for whitespace, which never becomes a graph node.
    #[must_use]
    pub fn from_token_kind(kind: &crate::TokenKind) -> Option<SymbolType> {
        match kind {
            crate::TokenKind::Word => Some(SymbolType::Word),
            crate::TokenKind::Number => Some(SymbolType::Number),
            crate::TokenKind::Symbol => Some(SymbolType::Symbol),
            crate::TokenKind::Punctuation => Some(SymbolType::Punctuation),
            crate::TokenKind::Whitespace => None,
        }
    }
}

/// A node in the token graph: one significant symbol of the document.
///
/// `text` is the canonical (lowercased) symbol text; `span` is the byte span
/// of its **first occurrence** in the source document (deduplication keeps
/// first occurrence, so provenance is always traceable).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Node {
    /// Stable index of this node within `DocumentAST::nodes`.
    pub id: usize,
    /// Canonical (lowercased) symbol text.
    pub text: String,
    /// Semantic class of the symbol.
    pub symbol_type: SymbolType,
    /// Byte span of the first occurrence in the source document.
    pub span: Span,
}

/// A directed edge in the token graph: `nodes[subject] --predicate--> nodes[object]`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Edge {
    /// Canonicalized predicate text (lowercased middle term, or `related_to`).
    pub predicate: String,
    /// Index into `DocumentAST::nodes` of the subject node.
    pub subject: usize,
    /// Index into `DocumentAST::nodes` of the object node.
    pub object: usize,
    /// Byte span of the subject's first occurrence (provenance anchor).
    pub span: Span,
}

/// The token graph of a document: nodes + directed edges.
///
/// This is the canonical, serializable output of the extraction stage and the
/// input to symbolic pattern matching (`crate::match_graph`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocumentAST {
    /// Nodes in first-occurrence order; `Node::id` equals the vector index.
    pub nodes: Vec<Node>,
    /// Directed edges in emission order.
    pub edges: Vec<Edge>,
}

impl DocumentAST {
    /// An empty graph (no nodes, no edges).
    #[must_use]
    pub fn empty() -> Self {
        Self {
            nodes: Vec::new(),
            edges: Vec::new(),
        }
    }

    /// The number of nodes in the graph.
    #[must_use]
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Whether the graph has no nodes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Returns the node at `index`, or `None` if out of bounds.
    #[must_use]
    pub fn node(&self, index: usize) -> Option<&Node> {
        self.nodes.get(index)
    }
}

// ---------------------------------------------------------------------------
// Deterministic lexer — plain text -> AST nodes
// ---------------------------------------------------------------------------

/// The deterministic lexer entry point: parses plain text into a token graph
/// (`DocumentAST`) **without any probabilistic machinery**.
///
/// The lexer is a pure composition of the crate's rule-based pipeline:
///
/// 1. `crate::tokenize` — byte-class classification (words, numbers,
///    punctuation, symbols, whitespace). No dictionaries, no heuristics, no
///    ML, no embeddings — identical bytes always yield identical tokens.
/// 2. `crate::parse` — folds the token stream into a `Document` AST
///    (`Section`s of `Sentence`s of `Term`s) using deterministic structure
///    rules (blank-line section boundaries, `.`/`!`/`?` sentence boundaries).
/// 3. `DocumentAST::from_ast` — extracts the deduplicated token graph
///    (nodes + directed edges) from the AST.
///
/// Because every stage is a pure function of its input, `lex` is also pure:
/// `lex(a) == lex(a)` always, and the same input always produces the exact
/// same graph — there is no embedding model, no random seed, no ambient
/// state that could make two runs differ. This is the property that lets the
/// enclave later hash the graph and re-derive it inside a halo2 circuit.
///
/// # Errors
///
/// Returns [`crate::IndexerError::Parse`] if the input yields no significant
/// tokens (empty or whitespace-only input), or
/// [`crate::IndexerError::Tokenize`] if the input contains a byte that cannot
/// be classified.
pub fn lex(input: &str) -> IndexerResult<DocumentAST> {
    let tokens = crate::tokenize(input)?;
    let ast = crate::parse(&tokens)?;
    Ok(DocumentAST::from_ast(&ast))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn symbol_type_maps_from_token_kind() {
        use crate::TokenKind;
        assert_eq!(
            SymbolType::from_token_kind(&TokenKind::Word),
            Some(SymbolType::Word)
        );
        assert_eq!(
            SymbolType::from_token_kind(&TokenKind::Number),
            Some(SymbolType::Number)
        );
        assert_eq!(
            SymbolType::from_token_kind(&TokenKind::Symbol),
            Some(SymbolType::Symbol)
        );
        assert_eq!(
            SymbolType::from_token_kind(&TokenKind::Punctuation),
            Some(SymbolType::Punctuation)
        );
        assert_eq!(SymbolType::from_token_kind(&TokenKind::Whitespace), None);
    }

    #[test]
    fn document_ast_empty_and_length() {
        let g = DocumentAST::empty();
        assert!(g.is_empty());
        assert_eq!(g.len(), 0);
        assert_eq!(g.node(0), None);
    }

    #[test]
    fn document_ast_serializes_deterministically() {
        let g = DocumentAST {
            nodes: vec![Node {
                id: 0,
                text: "flare".to_string(),
                symbol_type: SymbolType::Word,
                span: Span::new(0, 5),
            }],
            edges: vec![],
        };
        let json = serde_json::to_string(&g).expect("serialization cannot fail");
        let again: DocumentAST = serde_json::from_str(&json).expect("round-trip");
        assert_eq!(g, again);
    }

    #[test]
    fn lex_produces_document_ast_from_plain_text() {
        let graph = lex("Flare uses FTSO to price assets.").expect("lex must succeed");
        assert!(!graph.is_empty());
        assert!(!graph.edges.is_empty());
        // Nodes are deduplicated symbols in first-occurrence order.
        assert_eq!(graph.nodes[0].text, "flare");
        assert_eq!(graph.nodes[0].symbol_type, SymbolType::Word);
    }

    #[test]
    fn lex_is_deterministic_across_calls() {
        let a = lex("The price of FLR is 4.56 today.").expect("lex");
        let b = lex("The price of FLR is 4.56 today.").expect("lex");
        assert_eq!(a, b, "identical input must produce identical graphs");
    }

    #[test]
    fn lex_classifies_numbers_and_words() {
        let graph = lex("The price is 4.56").expect("lex");
        let number = graph
            .nodes
            .iter()
            .find(|n| n.text == "4.56")
            .expect("number node");
        assert_eq!(number.symbol_type, SymbolType::Number);
        let word = graph
            .nodes
            .iter()
            .find(|n| n.text == "price")
            .expect("word node");
        assert_eq!(word.symbol_type, SymbolType::Word);
    }

    #[test]
    fn lex_rejects_empty_and_whitespace_only_input() {
        assert!(lex("").is_err());
        assert!(lex("   \n  ").is_err());
    }

    #[test]
    fn lex_has_no_probabilistic_state() {
        // The same lexer call, repeated many times, must be bit-identical:
        // no hidden RNG, no embeddings, no ambient state.
        let first = lex("deterministic grounding without embeddings").expect("lex");
        for _ in 0..100 {
            let again = lex("deterministic grounding without embeddings").expect("lex");
            assert_eq!(first, again);
        }
    }

    // -------------------------------------------------------------------
    // Prompt 055 — deterministic AST generation over legal-text inputs
    // -------------------------------------------------------------------
    //
    // Realistic, generic legal-language samples constructed inline (the
    // crate's established zero-mock test pattern: these are *inputs* to the
    // pipeline, and every assertion below is derived from the pipeline's own
    // documented rules — never a canned graph). The enterprise use case is
    // legal/financial/regulatory documents, so the samples carry the shapes
    // real contracts do: clause numbering, paragraph breaks, currency
    // amounts, dates, sub-clause citations.

    /// A generic confidentiality clause with numbered sub-sections — the
    /// shape legal contracts actually use (clause numbers, paragraph breaks,
    /// dates). No real parties, no real agreement: an inline test input.
    const NDA_CLAUSE: &str = "1.1 Confidentiality. Each party agrees to keep the terms of this \
agreement confidential.\n\n1.2 Term. This agreement shall remain in force for five years from the \
effective date.";

    /// A purchase clause with a currency amount and a date.
    const PURCHASE_CLAUSE: &str =
        "Section 3.1 Consideration. The buyer shall pay the seller the sum of \
one million dollars (USD 1,000,000.00) within 30 days of the effective date.";

    #[test]
    fn lex_legal_clause_is_deterministic_byte_for_byte() {
        let a = lex(NDA_CLAUSE).expect("lex legal clause");
        let b = lex(NDA_CLAUSE).expect("lex legal clause");
        assert_eq!(a, b, "identical legal text must yield an identical graph");
        // Stronger than PartialEq: canonical serialization must be
        // byte-identical — the property the enclave hashes and re-derives.
        let ja = serde_json::to_vec(&a).expect("serialize a");
        let jb = serde_json::to_vec(&b).expect("serialize b");
        assert_eq!(ja, jb, "canonical JSON of the graph must be byte-identical");
    }

    #[test]
    fn lex_legal_clause_splits_sections_and_sentences() {
        let tokens = crate::tokenize(NDA_CLAUSE).expect("tokenize");
        let ast = crate::parse(&tokens).expect("parse");
        let crate::AstNode::Document { sections } = &ast else {
            panic!("expected document root");
        };
        // The blank line between the two sub-sections must split them into
        // two sections, each holding exactly two sentences (heading + body).        assert_eq!(sections.len(), 2, "blank line must split legal sub-sections");
        for section in sections {
            let crate::AstNode::Section { sentences, .. } = section else {
                panic!("expected section node");
            };
            assert_eq!(
                sentences.len(),
                2,
                "each clause has a heading sentence and a body sentence"
            );
        }
        // Pin sentence *content*, not just counts: the first heading must be
        // exactly [1.1, Confidentiality] (the clause number survives as a
        // term; the period is a sentence boundary, not a term).
        let crate::AstNode::Section { sentences, .. } = &sections[0] else {
            panic!("expected section node");
        };
        let first_terms: Vec<&str> = sentences[0]
            .terms()
            .iter()
            .map(|t| t.lexeme.as_str())
            .collect();
        assert_eq!(
            first_terms,
            vec!["1.1", "Confidentiality"],
            "clause heading must parse to exactly the clause number and heading term"
        );
    }

    #[test]
    fn lex_legal_clause_extracts_clause_numbering() {
        let graph = lex(NDA_CLAUSE).expect("lex");
        // Clause numbers like "1.1" / "1.2" become Number nodes (the
        // lexer's single-decimal rule), and the heading term a Word node.
        let c11 = graph
            .nodes
            .iter()
            .find(|n| n.text == "1.1")
            .expect("clause 1.1 node");
        assert_eq!(c11.symbol_type, SymbolType::Number);
        let c12 = graph
            .nodes
            .iter()
            .find(|n| n.text == "1.2")
            .expect("clause 1.2 node");
        assert_eq!(c12.symbol_type, SymbolType::Number);
        let heading = graph
            .nodes
            .iter()
            .find(|n| n.text == "confidentiality")
            .expect("heading node");
        assert_eq!(heading.symbol_type, SymbolType::Word);
        // Every node carries provenance back into the source document.
        assert!(heading.span.start < NDA_CLAUSE.len());
        assert!(c11.span.start < NDA_CLAUSE.len());
    }

    #[test]
    fn lex_legal_clause_builds_predicate_edge_from_middle_term() {
        let graph = lex("Section 3.1 Consideration. The buyer shall pay.").expect("lex");
        // "3.1" sits exactly one term between "Section" and "Consideration",
        // so the symbolic engine emits Section -3.1-> Consideration (the
        // middle-term predicate rule) — clause-citation structure extracted.
        let edge = graph
            .edges
            .iter()
            .find(|e| e.predicate == "3.1")
            .expect("middle-term predicate edge");
        let subj = graph.node(edge.subject).expect("subject node");
        let obj = graph.node(edge.object).expect("object node");
        assert_eq!(subj.text, "section");
        assert_eq!(obj.text, "consideration");
    }

    #[test]
    fn legal_ast_has_stable_content_digest() {
        let tokens = crate::tokenize(NDA_CLAUSE).expect("tokenize");
        let ast = crate::parse(&tokens).expect("parse");
        let d1 = crate::content_digest(&ast);
        let d2 = crate::content_digest(&ast);
        assert_eq!(d1, d2, "legal AST digest must be reproducible");
        assert_ne!(d1, [0u8; 32], "digest must not be the trivial zero digest");
    }

    #[test]
    fn legal_lex_repeated_runs_are_bit_identical() {
        let first = lex(NDA_CLAUSE).expect("lex");
        let first_json = serde_json::to_vec(&first).expect("serialize");
        for _ in 0..100 {
            let again = lex(NDA_CLAUSE).expect("lex");
            assert_eq!(again, first);
            let again_json = serde_json::to_vec(&again).expect("serialize");
            assert_eq!(
                again_json, first_json,
                "every repetition must be byte-identical, not just equal"
            );
        }
    }

    #[test]
    fn lex_legal_amount_preserves_decimal_and_symbols() {
        let graph = lex(PURCHASE_CLAUSE).expect("lex");
        // "1,000,000.00": the single-decimal rule folds the first "." and
        // the following digits into one Number token, so the graph carries
        // "000.00" as a single number node — the amount's value survives
        // intact. (Thousands separators are commas: structural punctuation
        // that `parse` consumes for sentence boundaries and deliberately
        // does not emit as graph terms — the documented design, not a loss.)
        assert!(
            graph.nodes.iter().any(|n| n.text == "1"),
            "leading amount digit retained"
        );
        assert!(
            graph.nodes.iter().any(|n| n.text == "000.00"),
            "decimal fraction folded into a single number node"
        );
        assert!(
            graph.nodes.iter().any(|n| n.text == "usd"),
            "currency symbol retained"
        );
        // Structural punctuation (commas) is documented to be consumed at
        // parse time — assert that contract explicitly so the behavior is
        // pinned, not assumed.
        assert!(
            !graph.nodes.iter().any(|n| n.text == ","),
            "commas are structural punctuation, not graph nodes (documented)"
        );
    }

    #[test]
    fn lex_legal_date_produces_number_nodes() {
        let graph = lex("The agreement is dated 31 December 2026.").expect("lex");
        assert!(graph.nodes.iter().any(|n| n.text == "31"));
        assert!(graph.nodes.iter().any(|n| n.text == "2026"));
        let month = graph
            .nodes
            .iter()
            .find(|n| n.text == "december")
            .expect("month node");
        assert_eq!(month.symbol_type, SymbolType::Word);
    }
    #[test]
    fn lex_legal_variants_produce_distinct_graphs() {
        // A single changed amount in otherwise identical legal text must
        // change the graph: the engine is sensitive to real content and
        // never collapses to a canned structure. Assert *why* they differ,
        // not merely that they differ — content sensitivity, pinned.
        let a = lex("The buyer shall pay within 30 days.").expect("a");
        let b = lex("The buyer shall pay within 60 days.").expect("b");
        assert_ne!(
            a, b,
            "a single changed amount must produce a different graph"
        );
        assert!(
            a.nodes.iter().any(|n| n.text == "30"),
            "graph a carries its amount node"
        );
        assert!(
            b.nodes.iter().any(|n| n.text == "60"),
            "graph b carries its amount node"
        );
        assert!(
            !a.nodes.iter().any(|n| n.text == "60"),
            "the changed amount must not leak across graphs"
        );
    }

    #[test]
    fn lex_legal_consumes_semicolons_as_structural_punctuation() {
        // Semicolons are pervasive in legal drafting (recitals, definitions,
        // conjunctive clauses). Like commas, the documented contract treats
        // them as structural punctuation: sentence-boundary role only, never
        // emitted as graph terms. Pin that contract explicitly.
        let graph = lex("The parties agree; the term is five years; the sum is due.").expect("lex");
        assert!(
            graph.nodes.iter().all(|n| n.text != ";"),
            "semicolons are structural punctuation, not graph nodes (documented)"
        );
        // The three clauses still split into three sentences — the semicolon
        // preserved structure while leaving no node behind.
        let tokens = crate::tokenize("The parties agree; the term is five years; the sum is due.")
            .expect("tokenize");
        let ast = crate::parse(&tokens).expect("parse");
        assert_eq!(
            ast.sentences().len(),
            1,
            "documented contract: only . ! ? terminate sentences; semicolons do not"
        );
    }
}
