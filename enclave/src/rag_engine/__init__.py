"""Enclave rag_engine package.

Python-side processing layer (Phase 4): the in-memory ephemeral context
processor (`processor.py`) that wraps the deterministic symbolic engine
compiled from `indexer_rs` (the Rust crate living in this same directory).

The Rust crate (Cargo.toml, src/, tests/, benches/, target/) shares this
directory by design — the Python gateway imports the compiled `indexer_rs`
wheel; the package marker makes `src.rag_engine.processor` importable from
the FastAPI app.
"""
