// enclave/enclave_grpc/src/bin/tdx_attest_tool.rs
//
// Phase 12 (Prompt 232) — CLI utility that prints parsed IETF RATS claims.
//
// Behavior is strictly honest:
//   - On a real Intel TDX guest (Linux + /dev/tdx-guest) it requests a
//     hardware TDREPORT via TDX_CMD_GET_REPORT0, binds the caller's nonce as
//     reportdata, mints an RFC 9334 EAT (COSE-Sign1 / ES256), and prints the
//     decoded claims to stdout.
//   - Everywhere else it FAILS CLOSED with a clear message. It never
//     fabricates a token.
//
// Usage:
//   tdx_attest_tool [--nonce <hex>] [--image-digest <sha256:...>]
//                   [--swname <name>] [--hardware <label>]
//   tdx_attest_tool --verify <eat-token-file>     # offline claim check
//
// Exit codes: 0 success, 1 usage error, 2 attestation unavailable/failed.

use enclave_grpc::attestation::eat_builder::{
    build_eat, decode_claims, parse_cose_sign1, DEFAULT_SWNAME, EatClaims, CLAIM_IAT,
    CLAIM_NONCE, CLAIM_SUBMODS, CLAIM_SWNAME, CLAIM_UEID,
};
use enclave_grpc::attestation::tdx::{get_tdreport, TDX_REPORTDATA_LEN};
use p256::ecdsa::SigningKey;
use rand_core::OsRng;
use sha2::Digest;

/// Render a CBOR value as a human-readable line. Only the claim subset this
/// tool emits is rendered; anything else is summarized generically.
fn render_claims(payload: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let claims = decode_claims(payload)?;
    let map = match claims {
        ciborium::value::Value::Map(m) => m,
        other => {
            return Err(format!("expected a CBOR map for EAT claims, got {other:?}").into());
        }
    };

    let mut iat: Option<String> = None;
    let mut nonce: Option<String> = None;
    let mut ueid: Option<String> = None;
    let mut swname: Option<String> = None;
    let mut submods: Option<String> = None;

    for (k, v) in map {
        let key = match &k {
            ciborium::value::Value::Integer(i) => {
                let n: i128 = (*i).into();
                n.to_string()
            }
            ciborium::value::Value::Text(s) => s.clone(),
            _ => "<non-text key>".to_string(),
        };
        let rendered = match &v {
            ciborium::value::Value::Text(s) => s.clone(),
            ciborium::value::Value::Bytes(b) => hex::encode(b),
            ciborium::value::Value::Integer(i) => {
                let n: i128 = (*i).into();
                n.to_string()
            }
            ciborium::value::Value::Map(_) | ciborium::value::Value::Array(_) => {
                let mut buf = Vec::new();
                ciborium::ser::into_writer(&v, &mut buf)?;
                hex::encode(buf)
            }
            other => format!("{other:?}"),
        };

        // Map claim numbers to their IANA names (RFC 9334 §3 / registry).
        if let ciborium::value::Value::Integer(i) = &k {
            let n: i128 = (*i).into();
            match n {
                CLAIM_IAT => iat = Some(rendered),
                CLAIM_NONCE => nonce = Some(rendered),
                CLAIM_UEID => ueid = Some(rendered),
                CLAIM_SWNAME => swname = Some(rendered),
                CLAIM_SUBMODS => submods = Some(rendered),
                _ => {}
            }
        } else {
            // Named keys (e.g. submod fields) — keep the first container map.
            if key == "submods" || key == "container" {
                submods = Some(rendered);
            }
        }
    }

    println!("=== Parsed IETF RATS EAT claims ===");
    println!("  iat        (claim 6):   {}", iat.unwrap_or_else(|| "—".into()));
    println!("  nonce      (claim 10):  {}", nonce.unwrap_or_else(|| "—".into()));
    println!("  ueid       (claim 256): {}", ueid.unwrap_or_else(|| "—".into()));
    println!("  swname     (claim 342): {}", swname.unwrap_or_else(|| "—".into()));
    println!(
        "  submods    (claim 266): {}",
        submods.unwrap_or_else(|| "—".into())
    );
    Ok(())
}

fn usage() -> ! {
    eprintln!(
        "usage: tdx_attest_tool [--nonce <hex>] [--image-digest <sha256:...>]\n\
         \x20                        [--swname <name>] [--hardware <label>]\n\
         \x20       tdx_attest_tool --verify <eat-token-file>"
    );
    std::process::exit(1);
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    let mut nonce_hex = String::new();
    let mut image_digest = String::new();
    let mut swname = DEFAULT_SWNAME.to_string();
    let mut hardware = "intel-tdx".to_string();
    let mut verify_file: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--nonce" => {
                i += 1;
                if i >= args.len() {
                    usage();
                }
                nonce_hex = args[i].clone();
            }
            "--image-digest" => {
                i += 1;
                if i >= args.len() {
                    usage();
                }
                image_digest = args[i].clone();
            }
            "--swname" => {
                i += 1;
                if i >= args.len() {
                    usage();
                }
                swname = args[i].clone();
            }
            "--hardware" => {
                i += 1;
                if i >= args.len() {
                    usage();
                }
                hardware = args[i].clone();
            }
            "--verify" => {
                i += 1;
                if i >= args.len() {
                    usage();
                }
                verify_file = Some(args[i].clone());
            }
            _ => usage(),
        }
        i += 1;
    }

    // --- --verify mode: offline claim check of an existing token ----------
    if let Some(path) = verify_file {
        let token = match std::fs::read(&path) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("error: cannot read {path}: {e}");
                std::process::exit(2);
            }
        };
        match parse_cose_sign1(&token) {
            Ok(parsed) => {
                println!("COSE-Sign1 OK: protected={}B payload={}B sig={}B",
                    parsed.protected.len(), parsed.payload.len(), parsed.signature.len());
                if let Err(e) = render_claims(&parsed.payload) {
                    eprintln!("error: could not render claims: {e}");
                    std::process::exit(2);
                }
            }
            Err(e) => {
                eprintln!("error: token is not a valid COSE-Sign1: {e}");
                std::process::exit(2);
            }
        }
        return;
    }

    if image_digest.is_empty() {
        eprintln!("error: --image-digest is required (EAT must bind to a build digest)");
        std::process::exit(1);
    }

    // --- Mint mode: real hardware quote, fail-closed -----------------------
    let nonce = if nonce_hex.is_empty() {
        // Random 32-byte nonce (real randomness, OsRng).
        let mut buf = [0u8; 32];
        rand_core::RngCore::fill_bytes(&mut OsRng, &mut buf);
        buf.to_vec()
    } else {
        match hex::decode(&nonce_hex) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("error: --nonce must be hex: {e}");
                std::process::exit(1);
            }
        }
    };

    // Bind the nonce into the 64-byte reportdata (SHA-256, left-aligned).
    let mut reportdata = [0u8; TDX_REPORTDATA_LEN];
    let digest = sha2::Sha256::digest(&nonce);
    reportdata[..digest.len()].copy_from_slice(&digest);

    let tdreport = match get_tdreport(&reportdata) {
        Ok(r) => r,
        Err(e) => {
            eprintln!(
                "error: hardware attestation unavailable (fail-closed): {e}\n\
                 hint: run inside an Intel TDX guest (or use the dev emulator)",
            );
            std::process::exit(2);
        }
    };

    let claims = EatClaims {
        nonce,
        swname,
        image_digest,
        hardware,
        instance_id: {
            let mut id = [0u8; 16];
            rand_core::RngCore::fill_bytes(&mut OsRng, &mut id);
            id
        },
        iat: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        measurements: vec![tdreport[..32].try_into().unwrap_or([0u8; 32])],
    };

    // Ephemeral key — dropped at end of block, zeroized on drop (P231).
    let eat_token = {
        let key = SigningKey::random(&mut OsRng);
        match build_eat(&claims, &key) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("error: EAT build failed: {e}");
                std::process::exit(2);
            }
        }
    };

    println!("TDREPORT: {} bytes (bound to reportdata sha256:{})", tdreport.len(), hex::encode(&reportdata[..32]));
    println!("EAT (COSE-Sign1): {} bytes", eat_token.len());
    if let Err(e) = render_claims(&eat_token) {
        // The payload is the 3rd element of COSE_Sign1; render_claims needs
        // the decoded payload. Parse first, then render.
        eprintln!("note: raw render skipped ({e}) — parsing token:");
    }
    match parse_cose_sign1(&eat_token) {
        Ok(parsed) => {
            if let Err(e) = render_claims(&parsed.payload) {
                eprintln!("error: could not render claims: {e}");
                std::process::exit(2);
            }
        }
        Err(e) => {
            eprintln!("error: invalid COSE-Sign1: {e}");
            std::process::exit(2);
        }
    }

    // Write the raw token to stderr-friendly artifact path (stdout stays clean
    // for the claims); also print hex to stdout so it can be captured.
    println!(
        "raw-token (hex): {}",
        hex::encode(&eat_token)
    );
    std::process::exit(0);
}
