/**
 * VerifiableRAG.fork.test.ts — fork-based integration tests (Prompt 116/117
 * followup, extended for Prompts 130/131).
 *
 * Forks LIVE Coston2 (chain 114) and exercises `verifyAndSettleRAG` END-TO-END
 * against the REAL FXRP/USD block-latency feed: happy-path settlement with the
 * actual on-chain consensus value (Prompt 146: the contract fetches the price
 * itself and computes the USD valuation on-chain), plus the full negative matrix
 * (StaleFeed, UnauthorizedImage, DuplicateProof, QueryConflict,
 * UnconfiguredFeed). The suite skips itself when the Coston2 RPC is
 * unreachable, so the deterministic main suite stays offline-friendly.
 *
 * Prompt 130/131 additions — the REAL-FDC-PROOF suite: the fixture
 * test/fixtures/fdc-web2json-proof.json is a REAL attestation proof fetched
 * from the Coston2 DA Layer for a REAL Web2Json request submitted by
 * scripts/request_fdc_attestation.ts (round 1422772, protocol 200). The
 * response_hex is decoded into the canonical IWeb2Json.Response struct and
 * re-encoded (byte-identical round-trip asserted), the Proof struct is built
 * with the exact nested tuple shape, and the LIVE FdcVerification is asked to
 * verify it — proving the P131 gate end-to-end against real FDC state:
 *   - verifyWeb2Data(realProof) returns true (FDC consensus reached),
 *   - verifyAndSettleRAG records latestVerifiedWeb2Hash == the round's REAL
 *     merkle root read from the enshrined Relay (P130).
 */
import { expect } from "chai";
import { ethers, network } from "hardhat";
import fs from "fs";
import path from "path";
import type { VerifiableRAG } from "../typechain-types/contracts/VerifiableRAG";

const RPC = "https://coston2-api.flare.network/ext/C/rpc";
const REGISTRY = "0x" + "aD67FE66660Fb8dFE9d6b1b4240d8650e30F6019";
const DIGEST = "0x" + "25f55814e809632f5af58eaa2b1d48cec1c49aa6a451c82b6af9fe9de934f421";
const FXRP_USD_FEED = "0x" + "015852502f55534400000000000000000000000000"; // bytes21 FXRP/USD (P143, live-verified)
// Settlement quantity for the Prompt 146 on-chain valuation (replaces the old
// caller-supplied price argument of verifyAndSettleRAG).
const SETTLE_QTY = 10_000n;
const FTSO_ABI = ["function getFeedById(bytes21) external payable returns (uint256, int8, uint64)"];
const RELAY_ABI = [
  "function merkleRoots(uint256, uint256) view returns (bytes32)",
  "function relay() view returns (address)",
];

function b64url(buf: Buffer): string {
  return buf.toString("base64").replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
}
function makeToken(digestHex: string, swname: string | null = "CONFIDENTIAL_SPACE"): Uint8Array {
  const claims: Record<string, unknown> = {
    sub: "projects/000000000000/serviceAccounts/sa@developer.gserviceaccount.com",
    aud: "//iam.googleapis.com/projects/000000000000/locations/global/workloadIdentityPools/p/p",
    submods: { container: { image_digest: "sha256:" + digestHex }, gce: { instance_id: "1" } },
  };
  if (swname !== null) claims.swname = swname;
  const header = b64url(Buffer.from(JSON.stringify({ alg: "ES256", typ: "JWT" })));
  const payload = b64url(Buffer.from(JSON.stringify(claims)));
  const sig = b64url(Buffer.from("offchain-verified"));
  return ethers.toUtf8Bytes(`${header}.${payload}.${sig}`);
}

/** The REAL FDC Web2Json proof fixture (fetched from the Coston2 DA Layer by
 *  scripts/request_fdc_attestation.ts). Throws when absent so a broken
 *  checkout fails loudly instead of silently skipping the P130/131 gates. */
function loadRealProofFixture(): { responseHex: string; merkleProof: string[] } {
  const p = path.join(__dirname, "fixtures", "fdc-web2json-proof.json");
  if (!fs.existsSync(p)) {
    throw new Error(
      `missing real FDC proof fixture at ${p} — run scripts/request_fdc_attestation.ts first`
    );
  }
  const fix = JSON.parse(fs.readFileSync(p, "utf8")) as {
    response_hex: string;
    proof: string[];
  };
  return { responseHex: fix.response_hex, merkleProof: fix.proof };
}

/** Build the canonical ABI-encoded IWeb2Json.Proof from the fixture. The DA
 *  Layer's response_hex IS abi.encode(Response) verbatim (1024 bytes, leading
 *  offset word included) — decoded into the struct and re-encoded byte-identical
 *  (asserted), then nested inside the Proof tuple the way Solidity's ABI
 *  encoder does. Returns { proofHex, votingRound, responseHex } so tests can
 *  also read the attested round and re-derive the leaf. */
function buildRealProof(): { proofHex: string; votingRound: bigint; responseHex: string; merkleProof: string[] } {
  const { responseHex, merkleProof } = loadRealProofFixture();
  const coder = ethers.AbiCoder.defaultAbiCoder();

  const RESPONSE_TUPLE =
    "tuple(bytes32 attestationType, bytes32 sourceId, uint64 votingRound, uint64 lowestUsedTimestamp, " +
    "tuple(string url, string httpMethod, string headers, string queryParams, string body, string postProcessJq, string abiSignature) requestBody, " +
    "tuple(bytes abiEncodedData) responseBody)";
  const data = coder.decode([RESPONSE_TUPLE], responseHex)[0];
  // Guard: the re-encoded struct must reproduce the DA layer bytes exactly.
  // If this ever fails, the fixture is not abi.encode(Response) and the
  // leaf/round derivation below would be silently wrong.
  const re = coder.encode([RESPONSE_TUPLE], [data]);
  expect(re).to.equal(responseHex.toLowerCase(), "fixture response_hex must be abi.encode(Response)");

  // CANONICAL Proof shape: Proof = (bytes32[] merkleProof, Response data) —
  // the Response is NESTED under `data`, exactly as IWeb2Json.Proof declares.
  // (Empirically proven 2026-08-11: the FLAT form — fields spread into the
  // outer tuple — fails abi.decode on-chain, so every P131 gate reverts;
  // the NESTED form returns TRUE from the deployed FdcVerification.)
  const PROOF_TUPLE = "tuple(bytes32[] merkleProof, " + RESPONSE_TUPLE + " data)";
  const proofHex = coder.encode([PROOF_TUPLE], [{ merkleProof, data }]);
  return { proofHex, votingRound: data.votingRound, responseHex, merkleProof };
}

describe("VerifiableRAG (live Coston2 fork)", function () {
  this.timeout(120_000);

  before(async function () {
    try {
      await network.provider.request({
        method: "hardhat_reset",
        params: [{ forking: { jsonRpcUrl: RPC } }],
      });
    } catch (e) {
      console.warn("fork unavailable, skipping live-settle suite:", (e as Error).message.slice(0, 120));
      this.skip();
    }
  });

  let contract: VerifiableRAG;
  let liveValue: bigint;
  let liveDecimals: bigint;
  let realProof: { proofHex: string; votingRound: bigint; responseHex: string; merkleProof: string[] };

  before(async function () {
    const [owner] = await ethers.getSigners();
    contract = await (await ethers.getContractFactory("VerifiableRAG")).deploy(owner.address, REGISTRY, DIGEST);
    await contract.waitForDeployment();
    await (await contract.updatePriceFeedId(FXRP_USD_FEED)).wait();

    // Read the REAL live FXRP/USD value through the registry-resolved FtsoV2.
    const ftso = new ethers.Contract(await contract.ftsoV2(), FTSO_ABI, ethers.provider);
    [liveValue, liveDecimals] = await ftso.getFeedById.staticCall(FXRP_USD_FEED);

    realProof = buildRealProof();
  });

  it("settles a query against the REAL live FXRP/USD feed value (returns true)", async function () {
    const token = makeToken(DIGEST.slice(2));
    const query = ethers.id("fork-settle#1");
    const returned = await contract.verifyAndSettleRAG.staticCall(token, Buffer.from("proof-1"), query, SETTLE_QTY, realProof.proofHex);
    expect(returned).to.equal(true);

    const rcpt = await (await contract.verifyAndSettleRAG(token, Buffer.from("proof-1"), query, SETTLE_QTY, realProof.proofHex)).wait();
    const ev = rcpt.logs
      .map((l) => { try { return contract.interface.parseLog(l); } catch { return null; } })
      .find((p) => p && p.name === "ProofVerified");
    expect(ev).to.not.equal(undefined);
    expect(ev!.args.queryHash).to.equal(query);
    const rec = await contract.verifiedQueries(query);
    expect(rec.verified).to.equal(true);
    // Prompt 146: the contract fetched the price itself and valued on-chain.
    expect(await contract.lastSettlementPrice()).to.equal(liveValue);
  });

  it("verifyWeb2Data returns true for the REAL FDC proof (P131 gate end-to-end)", async function () {
    expect(await contract.verifyWeb2Data(realProof.proofHex)).to.equal(true);
  });

  it("records latestVerifiedWeb2Hash = the REAL relay merkle root for the attested round (P130)", async function () {
    const query = ethers.id("fork-settle#root");
    await contract.verifyAndSettleRAG(
      makeToken(DIGEST.slice(2)), Buffer.from("proof-root"), query, SETTLE_QTY, realProof.proofHex
    );
    // Read the SAME root the live FdcVerification verified against: relay
    // resolved through the verifier (protocolId 200, the proof's votingRound).
    const fdcVerification = new ethers.Contract(await contract.fdcVerification(), RELAY_ABI, ethers.provider);
    const relayAddr = await fdcVerification.relay();
    const relay = new ethers.Contract(relayAddr, RELAY_ABI, ethers.provider);
    const expectedRoot = await relay.merkleRoots(200, realProof.votingRound);
    expect(expectedRoot).to.not.equal(ethers.ZeroHash);
    expect(await contract.latestVerifiedWeb2Hash()).to.equal(expectedRoot);
  });

  it("rejects a TAMPERED proof (flipped merkle element) with UnverifiedWeb2Data (P131 gate)", async function () {
    const tampered = {
      ...realProof,
      proofHex: realProof.proofHex.replace(
        realProof.merkleProof[0].slice(2),
        (BigInt("0x" + realProof.merkleProof[0].slice(2)) ^ 1n).toString(16).padStart(64, "0")
      ),
    };
    // The on-chain abi.decode still succeeds (well-formed struct), but the
    // live FdcVerification rejects the flipped merkle path.
    expect(await contract.verifyWeb2Data(tampered.proofHex)).to.equal(false);
    await expect(
      contract.verifyAndSettleRAG(
        makeToken(DIGEST.slice(2)), Buffer.from("proof-tampered"), ethers.id("fork-settle#tampered"), SETTLE_QTY, tampered.proofHex
      )
    ).to.be.revertedWithCustomError(contract, "UnverifiedWeb2Data");
    // NOTE: must await the getter into a variable BEFORE reading .verified —
    // `await contract.verifiedQueries(h).verified` parses as
    // `await (promise.verified)` (undefined), a classic ethers/chai pitfall.
    const rec = await contract.verifiedQueries(ethers.id("fork-settle#tampered"));
    expect(rec.verified).to.equal(false);
  });

  it("records the LIVE FXRP/USD price and the on-chain valuation (Prompt 146)", async function () {
    const token = makeToken(DIGEST.slice(2));
    const query = ethers.id("fork-settle#2");
    const returned = await contract.verifyAndSettleRAG.staticCall(token, Buffer.from("proof-2"), query, SETTLE_QTY, realProof.proofHex);
    expect(returned).to.equal(true);
    await contract.verifyAndSettleRAG(token, Buffer.from("proof-2"), query, SETTLE_QTY, realProof.proofHex);
    expect(await contract.lastSettlementPrice()).to.equal(liveValue);
    // Recompute the on-chain fixed-point math over the SAME live value.
    const dec = Number(liveDecimals);
    const expected = dec >= 0
      ? (SETTLE_QTY * liveValue) / 10n ** BigInt(dec)
      : (SETTLE_QTY * liveValue) * 10n ** BigInt(-dec);
    expect(await contract.lastSettlementValuation()).to.equal(expected);
  });

  it("reverts StaleFeed when the feed is older than REALTIME_MAX_AGE", async function () {
    // Isolate the time-advance with evm_snapshot/evm_revert: on a fork the feed
    // state is FROZEN at the fork block (anchors only update on the real chain),
    // so a permanent +601s would make EVERY later settle revert StaleFeed too
    // (this actually broke DuplicateProof/QueryConflict on the first run —
    // diagnosed via a live-chain probe: real feed age was -1s, fork delta 2s).
    const snap = await network.provider.send("evm_snapshot", []);
    try {
      // Advance the chain 601s (> REALTIME_MAX_AGE=300) so block.timestamp - feedTs > 300.
      await network.provider.send("evm_increaseTime", [601]);
      await network.provider.send("evm_mine", []);
      await expect(
        contract.verifyAndSettleRAG(makeToken(DIGEST.slice(2)), Buffer.from("proof-3"), ethers.id("fork-settle#3"), SETTLE_QTY, realProof.proofHex)
      ).to.be.revertedWithCustomError(contract, "StaleFeed");
    } finally {
      await network.provider.send("evm_revert", [snap]);
    }
  });

  it("reverts UnauthorizedImage for an unapproved container digest", async function () {
    const bad = "0x" + "ef".repeat(32);
    await expect(
      contract.verifyAndSettleRAG(makeToken(bad.slice(2)), Buffer.from("proof-4"), ethers.id("fork-settle#4"), SETTLE_QTY, realProof.proofHex)
    ).to.be.revertedWithCustomError(contract, "UnauthorizedImage").withArgs(bad);
  });

  it("reverts DuplicateProof when the same (token, proof, query) is replayed", async function () {
    const token = makeToken(DIGEST.slice(2));
    const proof = Buffer.from("proof-5");
    const query = ethers.id("fork-settle#5");
    await contract.verifyAndSettleRAG(token, proof, query, SETTLE_QTY, realProof.proofHex);
    await expect(contract.verifyAndSettleRAG(token, proof, query, SETTLE_QTY, realProof.proofHex)).to.be.revertedWithCustomError(
      contract,
      "DuplicateProof"
    );
  });

  it("reverts QueryConflict when the same query is verified with a different proof", async function () {
    const token = makeToken(DIGEST.slice(2));
    const query = ethers.id("fork-settle#6");
    await contract.verifyAndSettleRAG(token, Buffer.from("proof-6a"), query, SETTLE_QTY, realProof.proofHex);
    await expect(
      contract.verifyAndSettleRAG(token, Buffer.from("proof-6b"), query, SETTLE_QTY, realProof.proofHex)
    ).to.be.revertedWithCustomError(contract, "QueryConflict");
  });

  it("reverts UnconfiguredFeed when no feed id is set (fresh deploy)", async function () {
    const [owner] = await ethers.getSigners();
    const fresh = await (await ethers.getContractFactory("VerifiableRAG")).deploy(owner.address, REGISTRY, DIGEST);
    await fresh.waitForDeployment();
    await expect(
      fresh.verifyAndSettleRAG(makeToken(DIGEST.slice(2)), Buffer.from("proof-7"), ethers.id("fork-settle#7"), SETTLE_QTY, realProof.proofHex)
    ).to.be.revertedWithCustomError(fresh, "UnconfiguredFeed");
  });
});
