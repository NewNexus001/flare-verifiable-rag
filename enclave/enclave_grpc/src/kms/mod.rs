// enclave/enclave_grpc/src/kms/mod.rs
//
// Phase 13 — GCP Cloud KMS FIPS 140-2 L3 MPC wallet (Prompts 241-260).
//
//   client.rs     — KMS client: presents the IETF RATS EAT to GCP Workload
//                   Identity Federation, exchanges it for a short-lived IAM
//                   access token, and calls Cloud KMS Decrypt to release the
//                   enclave key shard into volatile RAM (P241-242).
//   mpc_signer.rs — 2-of-2 threshold ECDSA over secp256k1: combines the
//                   enclave shard (from KMS) with the client shard to sign
//                   EIP-1559 Flare transactions, zeroizing all key material
//                   the moment signing completes (P243-244, P248).
//
// Design honesty (project no-lies rule): this module performs REAL key
// management against the REAL GCP Cloud KMS API (or a local emulator in
// tests). There is no fake HSM, no hardcoded private key, no static shard.

pub mod client;
pub mod mpc_signer;
