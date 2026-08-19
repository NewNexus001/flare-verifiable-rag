// enclave/enclave_grpc/build.rs
//
// Phase 11 (Prompt 203) — compiles proto/enclave_service.proto into Rust
// code during `cargo build`. Uses protoc-bin-vendored so the build is
// hermetic on hosts without protoc installed (verified absent on this
// Windows host). The generated sources land in OUT_DIR and are pulled in
// via tonic::include_proto! in src/lib.rs.
use std::env;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto/enclave_service.proto");

    // Point tonic-build at the vendored protoc binary (official release).
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    env::set_var("PROTOC", protoc);

    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile(&["proto/enclave_service.proto"], &["proto"])?;

    println!(
        "cargo:info=proto compiled to OUT_DIR: {}",
        PathBuf::from(env::var("OUT_DIR")?).display()
    );
    Ok(())
}
