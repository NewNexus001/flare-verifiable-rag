// enclave/enclave_grpc/src/ftso_provider/mod.rs
//
// Phase 15 — Enclave-Hosted FTSO v2 Provider Node & Anchor Feed Relayer
// (Prompts 281-300).
//
//   calculator.rs — weighted volume-trimmed median aggregation (P283)
//   node.rs       — Tokio daemon + multi-exchange WebSocket fetchers (P281-282)
//   submitter.rs  — price formatting + commit/reveal + KMS MPC signing (P285-286)

pub mod calculator;
pub mod node;
pub mod submitter;

pub use node::{FeedSnapshot, ProviderNode, Ticker};
