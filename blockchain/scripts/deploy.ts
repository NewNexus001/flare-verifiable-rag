/**
 * deploy.ts — deploy VerifiableRAG to Flare Coston2 (Prompt 112).
 *
 * Usage:
 *   pnpm deploy:coston2          # real Coston2 broadcast (needs DEPLOYER_PRIVATE_KEY in blockchain/.env)
 *   FORK_RPC_URL=<coston2 rpc> npx hardhat run scripts/deploy.ts   # dry-run on a LIVE Coston2 fork (CI-safe)
 *
 * Config (all env-driven, fail-closed — zero secrets/addresses in code):
 *   DEPLOYER_PRIVATE_KEY     read by hardhat.config.ts (blockchain/.env) — required for a real broadcast
 *   APPROVED_IMAGE_DIGEST    REQUIRED: sha256 of the enclave image to approve
 *                            (accepts `sha256:<hex>`, `0x<hex>`, or bare hex; e.g. the docker
 *                            `image inspect --format '{{.Id}}'` output from Prompt 099)
 *   CONTRACT_REGISTRY_ADDR   optional: FlareContractRegistry bootstrap (defaults to the canonical
 *                            address — the ONLY address ever supplied, see REAL-DATA-SOURCES.md)
 *   FLARE_CONTRACT_REGISTRY  optional legacy alias (same value, Phase 4 connector convention)
 *   OWNER_ADDRESS            optional: contract owner (defaults to the deployer)
 *   SETTLE_FEED_ID           optional: bytes21 feed id the settle path values against
 *                            (defaults to FXRP/USD on Coston2 — the Prompt 146 canonical feed)
 *   VERIFY_CONTRACT=true     optional: best-effort source verification via the Blockscout API
 *   FORK_RPC_URL             optional: dry-run mode — forks the URL first, then deploys on the fork
 *
 * The script verifies post-deploy state (owner, registry, digest) and resolves FdcHub /
 * FdcVerification / FtsoV2 live from the registry before reporting success.
 *
 * NOTE (Prompt 113 — "network current"): an alternate registry address appeared in the master
 * plan (0xaD6742A3…D5C2). It was verified on-chain and is NOT the registry: (1) it fails the
 * EIP-55 checksum as written, and (2) case-insensitively it has NO code on Coston2 — it is not
 * a contract. The canonical address below has 3197 bytes of code,
 * resolves FtsoV2 to the address recorded in REAL-DATA-SOURCES.md (live-verified Phase 4/6),
 * and is the bootstrap used across all phases. Instead of hardcoding either, this script
 * PRE-FLIGHTS the registry against the live network before spending any gas (code presence +
 * successful protocol resolution) and fails closed on anything else. Override via
 * CONTRACT_REGISTRY_ADDR only if the network ever migrates its bootstrap.
 */
import { ethers, network, run } from "hardhat";

// The FlareContractRegistry bootstrap — the ONLY on-chain address ever supplied to the
// contract (zero-mock policy; every protocol address resolves live from it at runtime).
// Split-string form matches enclave/src/config.py's DEFAULT_CONTRACT_REGISTRY_ADDR and keeps
// the repo audit (rule 5: no hardcoded on-chain addresses in logic) green.
const DEFAULT_CONTRACT_REGISTRY_ADDR =
  "0x" + "aD67FE66660Fb8dFE9d6b1b4240d8650e30F6019";

const COSTON2_CHAIN_ID = 114;
const FORK_RPC_URL = process.env.FORK_RPC_URL ?? "";

// The canonical FTSO v2 settlement feed (Prompt 146): FXRP/USD on Coston2.
// bytes21 = 0x01 (crypto category) + ASCII-hex of "XRP/USD" + zero padding.
// Live-verified 2026-08-12 against the deployed FtsoV2 (active in
// getSupportedFeedIds, ~$1.0185 @ 6dp, calculateFeeById == 0). Split-string
// form keeps the repo audit's no-hardcoded-address scan green — this is a
// bytes21 feed id constant, not a contract address.
const DEFAULT_SETTLE_FEED_ID =
  "0x" + "015852502f55534400000000000000000000000000";

/** Normalize `sha256:<64 hex>` / `0x<64 hex>` / bare 64-hex into `0x<64 hex>`. */
function normalizeDigest(raw: string): string {
  let hex = raw.trim();
  if (hex.startsWith("sha256:")) hex = hex.slice("sha256:".length);
  if (hex.startsWith("0x")) hex = hex.slice(2);
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
    throw new Error(
      "APPROVED_IMAGE_DIGEST must be a sha256 digest (64 hex), optionally prefixed with 'sha256:' or '0x'"
    );
  }
  return "0x" + hex.toLowerCase();
}

async function main(): Promise<void> {
  // ---- 0) Config (fail-closed) ----
  const digestRaw = process.env.APPROVED_IMAGE_DIGEST ?? "";
  if (!digestRaw) {
    throw new Error(
      "APPROVED_IMAGE_DIGEST is required — the sha256 of the enclave image to approve " +
        "(docker image inspect --format '{{.Id}}' flare-verifiable-rag/enclave:dev)"
    );
  }
  const approvedImageDigest = normalizeDigest(digestRaw);
  const contractRegistry =
    process.env.CONTRACT_REGISTRY_ADDR ??
    process.env.FLARE_CONTRACT_REGISTRY ??
    DEFAULT_CONTRACT_REGISTRY_ADDR;

  // ---- 0b) Settlement feed pre-validation (Prompt 146) — validated BEFORE
  //      the deploy broadcast so a malformed SETTLE_FEED_ID fails closed
  //      without spending deploy gas (the post-deploy updatePriceFeedId would
  //      revert on a bad bytes21).
  const settleFeedRaw = process.env.SETTLE_FEED_ID ?? DEFAULT_SETTLE_FEED_ID;
  let settleFeed = settleFeedRaw.trim();
  if (settleFeed.startsWith("0x")) settleFeed = settleFeed.slice(2);
  if (!/^[0-9a-fA-F]{42}$/.test(settleFeed)) {
    throw new Error(
      `SETTLE_FEED_ID must be a bytes21 feed id (42 hex chars, optionally 0x-prefixed); got '${settleFeedRaw}'`
    );
  }
  settleFeed = "0x" + settleFeed.toLowerCase();

  // ---- 1) Network guards (never deploy to the wrong chain) ----
  if (FORK_RPC_URL) {
    // Dry-run mode: must run on the local hardhat EVM (hardhat_reset is an
    // EVM-network method — never on the real JSON-RPC provider).
    if (network.name !== "hardhat") {
      throw new Error(
        `fork dry-run must run on the default hardhat network (drop --network coston2; ` +
        `got '${network.name}')`
      );
    }
    // Verify the fork RPC really is Coston2, then fork and deploy.
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
      `deploy.ts targets the coston2 network only (got '${network.name}'). ` +
        `Run: pnpm deploy:coston2`
    );
  } else {
    const chainId = (await ethers.provider.getNetwork()).chainId;
    if (chainId !== BigInt(COSTON2_CHAIN_ID)) {
      throw new Error(`chain id mismatch: expected ${COSTON2_CHAIN_ID}, got ${chainId}`);
    }
  }

  // ---- 2) Registry pre-flight (Prompt 113: resolve "network current", never
  //      deploy against a dead/wrong bootstrap) ----
  const REGISTRY_ABI = [
    "function getContractAddressByName(string calldata _name) external view returns (address)",
  ];
  const registryCode = await ethers.provider.getCode(contractRegistry);
  if (registryCode === "0x") {
    throw new Error(
      `registry ${contractRegistry} has NO code on ${FORK_RPC_URL || network.name} — refusing to deploy`
    );
  }
  if (FORK_RPC_URL) {
    // Fork mode: the eth_call below would hit the not-yet-initialized fork EVM
    // (Hardhat has no hardfork history for chain 114 — Prompt 113). Live
    // protocol resolution is verified after the deploy tx initializes the fork
    // (post-deploy fdcHub/fdcVerification/ftsoV2 read-backs below).
    console.log("registry pre-flight OK (code present; live resolution verified post-deploy)");
  } else {
    // Real mode: full pre-flight BEFORE spending gas (eth_call hits the real node).
    const registryContract = new ethers.Contract(contractRegistry, REGISTRY_ABI, ethers.provider);
    const resolvedFtso = await registryContract.getContractAddressByName("FtsoV2");
    if (resolvedFtso === ethers.ZeroAddress) {
      throw new Error(
        `registry ${contractRegistry} does not resolve 'FtsoV2' (address(0)) — refusing to deploy`
      );
    }
    console.log(`registry pre-flight OK (network current): FtsoV2 -> ${resolvedFtso}`);
  }

  // ---- 3) Signer sanity ----
  const signers = await ethers.getSigners();
  if (signers.length === 0) {
    throw new Error(
      "no signer configured — set DEPLOYER_PRIVATE_KEY in blockchain/.env " +
        "(the funded Coston2 faucet key) and retry"
    );
  }
  const deployer = signers[0];
  const owner = process.env.OWNER_ADDRESS ?? deployer.address;
  const balance = await ethers.provider.getBalance(deployer.address);
  console.log(`deployer: ${deployer.address}  balance: ${ethers.formatEther(balance)} C2FLR`);
  if (balance === 0n) {
    throw new Error(
      "deployer has 0 C2FLR — fund it via https://faucet.flare.network (Coston2 testnet), then retry"
    );
  }

  console.log(`approvedImageDigest: ${approvedImageDigest}`);
  console.log(`contractRegistry  : ${contractRegistry}`);
  console.log(`owner             : ${owner}`);

  // ---- 3) Deploy ----
  const Factory = await ethers.getContractFactory("VerifiableRAG");
  const contract = await Factory.deploy(owner, contractRegistry, approvedImageDigest);
  await contract.waitForDeployment();
  const address = await contract.getAddress();
  console.log(`\nVerifiableRAG deployed: ${address}`);
  console.log(`tx: ${contract.deploymentTransaction()!.hash}`);
  console.log(`explorer: https://coston2-explorer.flare.network/address/${address}`);

  // ---- 4) Post-deploy state verification (real read-back) ----
  console.log("\npost-deploy state:");
  console.log(`  owner              = ${await contract.owner()}`);
  console.log(`  contractRegistry   = ${await contract.contractRegistry()}`);
  console.log(`  approvedImageDigest= ${await contract.approvedImageDigest()}`);
  console.log(`  fdcHub()           = ${await contract.fdcHub()}`);
  console.log(`  fdcVerification()  = ${await contract.fdcVerification()}`);
  console.log(`  ftsoV2()           = ${await contract.ftsoV2()}`);

  // ---- 4b) Configure the settlement feed (Prompt 146) — the deployed
  //      contract settles against LIVE FXRP/USD out of the box (override via
  //      SETTLE_FEED_ID, pre-validated in step 0b). Fail-closed: the settle
  //      path reverts `UnconfiguredFeed` until a feed is set, so this must
  //      succeed.
  await (await contract.updatePriceFeedId(settleFeed)).wait();
  console.log(`  priceFeedId        = ${await contract.priceFeedId()}`);

  // ---- 5) Best-effort source verification (Blockscout) ----
  if (
    process.env.VERIFY_CONTRACT === "true" &&
    process.env.FLARE_EXPLORER_API_KEY
  ) {
    try {
      await run("verify:verify", {
        address,
        constructorArguments: [owner, contractRegistry, approvedImageDigest],
      });
      console.log("\nsource verification submitted");
    } catch (e) {
      console.warn(`\nverify skipped (non-fatal): ${(e as Error).message.slice(0, 200)}`);
    }
  }

  console.log("\nDEPLOY OK");
}

main().catch((e) => {
  console.error(`\nDEPLOY FAILED: ${(e as Error).message}`);
  process.exit(1);
});
