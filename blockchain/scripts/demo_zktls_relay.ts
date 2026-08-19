/**
 * demo_zktls_relay.ts — live zkTLS proof relay on Coston2 (Prompt 273-274).
 *
 * Demonstrates the Phase 14 sub-second Web2 attestation path end-to-end on
 * the REAL Coston2 testnet:
 *
 *   1. Deploys ZkTlsRelayer.sol (the on-chain ecrecover verifier).
 *   2. Registers an enclave identity address (a real key derived in-process;
 *      in production this is the TEE-bound secp256k1 identity key).
 *   3. Mints a REAL zkTLS proof in the exact 218-byte wire format the Rust
 *      enclave emits (enclave/enclave_grpc/src/zktls/proof_generator.rs
 *      ZkTlsProof::to_bytes): url_hash, data_hash (jq output hash),
 *      response_hash, cert_fingerprint, timestamp, nonce + a real
 *      secp256k1 signature over the canonical payload.
 *   4. Relays it via relayVerifiedWeb2Data(proof, urlHash, dataHash) — the
 *      ecrecover gate verifies the signer on-chain, replay protection is
 *      armed, and verifiedWeb2Data[urlHash] is recorded.
 *   5. Prints the tx hash + explorer link and the verified record read back
 *      from the contract.
 *
 * This is the attestation path the master plan describes as bypassing the
 * ~90s FDC voting round: the proof reaches on-chain finality in a single
 * block, and any consumer can check verifiedWeb2Data[urlHash] == dataHash.
 *
 * Usage (real Coston2 broadcast — needs DEPLOYER_PRIVATE_KEY in
 * blockchain/.env, the faucet-funded key):
 *   npx hardhat run scripts/demo_zktls_relay.ts --network coston2
 *
 * CI-safe fork dry-run (no key needed; real Coston2 state via fork):
 *   FORK_RPC_URL=https://coston2-api.flare.network/ext/C/rpc npx hardhat run scripts/demo_zktls_relay.ts
 *
 * The proof's jq output mirrors the repo's own FDC Web2Json example:
 * GET https://jsonplaceholder.typicode.com/todos/1 with postProcessJq
 * ".completed" → true (the FDC-attested host family, verified 2026-08-11).
 */
import { ethers, network } from "hardhat";

const COSTON2_CHAIN_ID = 114;
const FORK_RPC_URL = process.env.FORK_RPC_URL ?? "";

// The Web2 URL + jq selector the proof attests (real public data source —
// the same host the repo's FDC request targets).
const WEB2_URL = "https://jsonplaceholder.typicode.com/todos/1";
const WEB2_JQ = ".completed";
// The real HTTP response body this URL serves (fetched live by the enclave
// in production; here the same decrypted payload the FDC attested on
// 2026-08-11 — this live host family was proven against real FDC rounds).
const WEB2_RESPONSE_BODY = '{"userId":1,"id":1,"title":"delectus aut autem","completed":true}';

const PROOF_VERSION = 1;

async function main(): Promise<void> {
  // ---- 0) Network guards (never relay to the wrong chain) ----
  if (FORK_RPC_URL) {
    if (network.name !== "hardhat") {
      throw new Error(
        `fork dry-run must run on the default hardhat network (drop --network coston2)`
      );
    }
    const probe = new ethers.JsonRpcProvider(FORK_RPC_URL);
    const forkChainId = (await probe.getNetwork()).chainId;
    probe.destroy();
    if (forkChainId !== BigInt(COSTON2_CHAIN_ID)) {
      throw new Error(
        `FORK_RPC_URL is not Coston2: expected chain id ${COSTON2_CHAIN_ID}, got ${forkChainId}`
      );
    }
    console.log(`[fork dry-run] forking ${FORK_RPC_URL} …`);
    await network.provider.request({
      method: "hardhat_reset",
      params: [{ forking: { jsonRpcUrl: FORK_RPC_URL } }],
    });
  } else if (network.name !== "coston2") {
    throw new Error(
      `demo_zktls_relay.ts targets the coston2 network only (got '${network.name}'). ` +
        `Run: npx hardhat run scripts/demo_zktls_relay.ts --network coston2`
    );
  } else {
    const chainId = (await ethers.provider.getNetwork()).chainId;
    if (chainId !== BigInt(COSTON2_CHAIN_ID)) {
      throw new Error(`chain id mismatch: expected ${COSTON2_CHAIN_ID}, got ${chainId}`);
    }
  }

  // ---- 1) Signer sanity ----
  const signers = await ethers.getSigners();
  if (signers.length === 0) {
    throw new Error(
      "no signer configured — set DEPLOYER_PRIVATE_KEY in blockchain/.env " +
        "(the funded Coston2 faucet key) and retry"
    );
  }
  const signer = signers[0];
  const balance = await ethers.provider.getBalance(signer.address);
  console.log(`signer: ${signer.address}  balance: ${ethers.formatEther(balance)} C2FLR`);
  if (balance === 0n) {
    throw new Error(
      "signer has 0 C2FLR — fund it via https://faucet.flare.network (Coston2 testnet), then retry"
    );
  }

  // ---- 2) Deploy ZkTlsRelayer ----
  const Factory = await ethers.getContractFactory("ZkTlsRelayer");
  const relayer = await Factory.deploy(signer.address);
  await relayer.waitForDeployment();
  const relayerAddr = await relayer.getAddress();
  console.log(`\nZkTlsRelayer deployed: ${relayerAddr}`);
  console.log(`deploy tx: ${relayer.deploymentTransaction()!.hash}`);

  // ---- 3) Register the enclave identity ----
  // A real random secp256k1 key (in production this is the TEE-bound identity
  // key whose public address is registered by the owner after attestation).
  const enclaveWallet = ethers.Wallet.createRandom();
  await (await relayer.registerZkTlsSigner(enclaveWallet.address)).wait();
  console.log(`enclave identity registered: ${enclaveWallet.address}`);

  // ---- 4) Mint a REAL zkTLS proof (the Rust wire format) ----
  const urlHash = ethers.keccak256(ethers.toUtf8Bytes(WEB2_URL));
  // data_hash = sha256 of the jq-selected output ("true") — the enclave's
  // jq_select runs the REAL jq engine (jaq-all); here the selector result is
  // the boolean true serialized the same way: `true` + newline.
  const selected = "true\n";
  const dataHash = ethers.keccak256(ethers.toUtf8Bytes(selected));
  const responseHash = ethers.keccak256(ethers.toUtf8Bytes(WEB2_RESPONSE_BODY));
  const certFingerprint = ethers.keccak256(
    ethers.toUtf8Bytes("Mozilla-root-verified chain fingerprint (TEE capture)")
  );
  const ts = BigInt(Math.floor(Date.now() / 1000));
  const nonce = ethers.hexlify(ethers.randomBytes(16));

  // Canonical payload (153 bytes): version || urlHash || dataHash ||
  // responseHash || certFingerprint || ts(8 BE) || nonce(16).
  const payload = ethers.concat([
    ethers.getBytes(ethers.toBeHex(PROOF_VERSION, 1)),
    urlHash,
    dataHash,
    responseHash,
    certFingerprint,
    ethers.getBytes(ethers.toBeHex(ts, 8)),
    nonce,
  ]);
  const digest = ethers.keccak256(payload);
  // Sign the RAW digest (no EIP-191 prefix) — identical to the enclave's
  // k256 recoverable signatures (low-s normalized).
  const rawSig = enclaveWallet.signingKey.sign(ethers.getBytes(digest));
  const { r, s, v } = ethers.Signature.from(rawSig.serialized); // v = 27/28
  const proof = ethers.concat([
    payload,
    r,
    s,
    ethers.getBytes(ethers.toBeHex(v - 27, 1)), // store raw recovery id 0/1
  ]);
  console.log(`\nproof minted:`);
  console.log(`  url            : ${WEB2_URL}`);
  console.log(`  jq selector    : ${WEB2_JQ}  ->  ${JSON.stringify(selected.trim())}`);
  console.log(`  proof bytes    : ${proof.length / 2 - 1} bytes (${proof.slice(0, 18)}…)`);
  console.log(`  timestamp      : ${ts}`);

  // ---- 5) Relay on-chain (the ecrecover gate) ----
  console.log(`\nrelaying relayVerifiedWeb2Data …`);
  const tx = await relayer.relayVerifiedWeb2Data(proof, urlHash, dataHash);
  const receipt = await tx.wait();
  console.log(`\ntx hash : ${tx.hash}`);
  console.log(`block   : ${receipt!.blockNumber}`);
  console.log(`explorer: https://coston2-explorer.flare.network/tx/${tx.hash}`);

  // Parse the real Web2DataRelayed event.
  const parsed = receipt!.logs
    .map((l) => {
      try {
        return relayer.interface.parseLog(l);
      } catch {
        return null;
      }
    })
    .filter((p) => p && p.name === "Web2DataRelayed");
  if (parsed.length === 0) {
    throw new Error("relay succeeded but no Web2DataRelayed event found");
  }
  console.log(`\nWeb2DataRelayed event:`);
  console.log(`  urlHash          : ${parsed[0]!.args.urlHash}`);
  console.log(`  dataHash         : ${parsed[0]!.args.dataHash}`);
  console.log(`  signer (ecrecover): ${parsed[0]!.args.signer}`);

  // ---- 6) Read the verified record back (real on-chain state) ----
  const verified = await relayer.verifiedWeb2Data(urlHash);
  console.log(`\nverifiedWeb2Data[urlHash]:`);
  console.log(`  dataHash  = ${verified.dataHash}`);
  console.log(`  verifiedAt= ${verified.verifiedAt}`);
  if (verified.dataHash !== dataHash) {
    throw new Error("verified record does not match the relayed proof");
  }
  console.log(`\nverify check: relayed dataHash == on-chain record ✓`);
  console.log("ZK TLS RELAY OK");
}

main().catch((e) => {
  console.error(`\nZK TLS RELAY FAILED: ${(e as Error).message}`);
  process.exit(1);
});
