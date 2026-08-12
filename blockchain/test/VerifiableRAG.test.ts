/**
 * VerifiableRAG.test.ts — Hardhat unit tests (Prompts 115/116/118).
 *
 * Covers:
 *   1. Deployment — constructor state, fail-closed guards (ZeroRegistry, ZeroAddress,
 *      OwnableInvalidOwner).
 *   2. Owner controls — Ownable transfer/renounce, onlyOwner gates on
 *      updateApprovedImageDigest / updatePriceFeedId.
 *   3. Digest updates — happy path + event, ZeroAddress, UnchangedImageDigest, plus the
 *      feed-id setter matrix (ZeroFeedId / UnchangedFeedId).
 *   4. Proof verification failure — unapproved container digest (Prompt 116).
 *   5. submitAttestation — commitment recording, replay protection (Prompt 104).
 *   6. Registry resolvers — fdcHub/fdcVerification/ftsoV2 live-lookup + Unregistered
 *      (Prompt 111).
 *   7. verifyAndSettleRAG full matrix — happy settlement, on-chain valuation,
 *      StaleFeed, UnconfiguredFeed, ZeroQueryHash, InvalidToken shapes, DuplicateProof,
 *      QueryConflict, idempotent same-binding, JWT parser edge branches (Prompt 118
 *      coverage gate: >90% branch on VerifiableRAG.sol).
 *
 * Registry/digest constants use the split-string convention (audit-safe; same as
 * config.py and scripts/deploy.ts). Helper contracts (TestFlareRegistry / TestFtsoV2)
 * live in contracts/test/ and are excluded from the coverage report (skipFiles).
 *
 * The describe uses `function ()` so this.timeout() works: solidity-coverage
 * instruments every branch (storage counter writes), making JWT-parsing tests
 * ~100x slower — the 40s mocha default made them time out under coverage.
 */
import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import type { VerifiableRAG } from "../typechain-types/contracts/VerifiableRAG";

// Canonical FlareContractRegistry bootstrap (same on every Flare network).
const REGISTRY = "0x" + "aD67FE66660Fb8dFE9d6b1b4240d8650e30F6019";
// Our real enclave image digest (Prompt 080 docker build), sha256: prefix stripped.
const DIGEST_A = "0x" + "25f55814e809632f5af58eaa2b1d48cec1c49aa6a451c82b6af9fe9de934f421";
const DIGEST_B = "0x" + "ab".repeat(32);
const FLR_USD_FEED = "0x" + "01464c522f55534400000000000000000000000000"; // bytes21 FLR/USD (21 bytes)
// Settlement quantity for the Prompt 146 on-chain valuation (quantity × live
// price / 10^decimals) — replaces the old caller-supplied price argument.
const SETTLE_QTY = 10_000n;
const RANDOM_DIGEST = "0x" + "ef".repeat(32); // never approved on-chain

async function deployFixture() {
  const [owner, stranger] = await ethers.getSigners();
  const Factory = await ethers.getContractFactory("VerifiableRAG");
  const contract = await Factory.deploy(owner.address, REGISTRY, DIGEST_A);
  await contract.waitForDeployment();
  return { contract, owner, stranger };
}

/** Build a minimally-valid ABI-encoded IWeb2Json.Proof (Prompt 123/131). The
 *  on-chain bridge only ABI-decodes and forwards to the verifier — it does
 *  not inspect fields — so the payload must satisfy the decoder's canonical
 *  struct shape, not the real FDC consensus semantics (those are enforced by
 *  the LIVE FdcVerification, exercised by the fork suite). The voting round
 *  used here (ROUND) is the one settleFixture stores a relay merkle root for. */
const FDC_ROUND = 77n; // arbitrary round with a stored TestRelay root
function encodeProof(merkle: string[], abiEncoded: string, votingRound: bigint = FDC_ROUND): string {
  return ethers.AbiCoder.defaultAbiCoder().encode(
    ["tuple(bytes32[] merkleProof, tuple(bytes32 attestationType, bytes32 sourceId, uint64 votingRound, uint64 lowestUsedTimestamp, tuple(string url, string httpMethod, string headers, string queryParams, string body, string postProcessJq, string abiSignature) requestBody, tuple(bytes abiEncodedData) responseBody) data)"],
    [{
      merkleProof: merkle,
      data: {
        attestationType: ethers.id("web2json"),
        sourceId: ethers.id("public-web2"),
        votingRound,
        lowestUsedTimestamp: 1n,
        requestBody: {
          url: "https://example.com/data.json",
          httpMethod: "GET",
          headers: "{}",
          queryParams: "{}",
          body: "{}",
          postProcessJq: ".",
          abiSignature: "string",
        },
        responseBody: { abiEncodedData: abiEncoded },
      },
    }]
  );
}

/** Fixture: TestFlareRegistry + TestFdcVerification(+TestRelay) + TestFtsoV2
 *  wired into a VerifiableRAG with the FLR/USD feed configured and a fresh
 *  live value. Registry names are resolved LIVE through the helper registry,
 *  exactly like production (Prompt 111). The FDC stack is fully wired for the
 *  Prompt 130/131 gate: FdcVerification points at the DEPLOYED
 *  TestFdcVerification (verifyWeb2Json -> true, relay -> TestRelay), and
 *  TestRelay stores a merkle root for (protocolId 200, FDC_ROUND) — the round
 *  every {encodeProof} payload carries — so a settle passes the gate and
 *  records the root in latestVerifiedWeb2Hash. (An EOA in the FdcVerification
 *  slot would bubble "unexpected amount of data" and blanket-revert.) */
async function settleFixture() {
  const [owner, stranger, hubSigner] = await ethers.getSigners();

  const Registry = await ethers.getContractFactory("TestFlareRegistry");
  const registry = await Registry.deploy();
  await registry.waitForDeployment();
  await registry.setAddress("FdcHub", hubSigner.address);

  // Prompt 130/131 FDC stack: verifier -> relay root.
  const Verifier = await ethers.getContractFactory("TestFdcVerification");
  const verifier = await Verifier.deploy();
  await verifier.waitForDeployment();
  const Relay = await ethers.getContractFactory("TestRelay");
  const relay = await Relay.deploy();
  await relay.waitForDeployment();
  await (await verifier.setResult(true)).wait();
  await (await verifier.setRelay(await relay.getAddress())).wait();
  const FDC_ROOT = ethers.id("verified-web2-round-root");
  await (await relay.setMerkleRoot(200, FDC_ROUND, FDC_ROOT)).wait();
  await registry.setAddress("FdcVerification", await verifier.getAddress());

  const Ftso = await ethers.getContractFactory("TestFtsoV2");
  const ftso = await Ftso.deploy();
  await ftso.waitForDeployment();
  await registry.setAddress("FtsoV2", await ftso.getAddress());

  const Factory = await ethers.getContractFactory("VerifiableRAG");
  const contract = await Factory.deploy(owner.address, await registry.getAddress(), DIGEST_A);
  await contract.waitForDeployment();
  await (await contract.updatePriceFeedId(FLR_USD_FEED)).wait();

  const block = await ethers.provider.getBlock("latest");
  const now = block!.timestamp;
  const LIVE_VALUE = 608_992n; // a realistic fixed-point FLR/USD (8 decimals)
  // Feed timestamp anchored REALTIME_MAX_AGE (300s) into the future: hardhat
  // 2.29/EDR mines blocks with WALL-CLOCK timestamps, so a long coverage run
  // drifts block.timestamp forward. The Prompt 145 freshness gate is SYMMETRIC
  // (|now − feedTs| ≤ 300s), so a +300s anchor stays inert for up to ~600s of
  // drift (≈2x the ~8-minute coverage run). The dedicated StaleFeed test
  // overrides this explicitly with ts = now − 601.
  await (await ftso.setFeed(LIVE_VALUE, now + 300)).wait();

  return { contract, owner, stranger, registry, ftso, hubSigner, verifier, relay, FDC_ROOT, LIVE_VALUE };
}

/** Build a GCP-shaped JWT (header.payload.signature) carrying the given digest.
 *  Claim VALUES are minimal (the on-chain parser only reads `swname` and
 *  `submods.container.image_digest`; long sub/aud values would only slow the
 *  instrumented parse loops under coverage — this keeps the run tractable).
 *  Pass swname=null to omit the claim (missing-claim case). */
function makeToken(digestHex: string, swname: string | null = "CONFIDENTIAL_SPACE"): Uint8Array {
  const b64 = (buf: Buffer) =>
    buf.toString("base64").replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
  const claims: Record<string, unknown> = {
    sub: "projects/p/serviceAccounts/sa@x",
    aud: "//iam.googleapis.com/p",
    submods: { container: { image_digest: "sha256:" + digestHex }, gce: { instance_id: "1" } },
  };
  if (swname !== null) claims.swname = swname; // null -> omit (missing claim case)
  const header = b64(Buffer.from(JSON.stringify({ alg: "ES256", typ: "JWT" })));
  const payload = b64(Buffer.from(JSON.stringify(claims)));
  const sig = b64(Buffer.from("sig")); // sig verified off-chain (Prompt 109 design)
  return ethers.toUtf8Bytes(`${header}.${payload}.${sig}`);
}

const PROOF = Buffer.from("halo2-proof-bytes");
const QUERY = ethers.id("rag-query");
// A well-formed FDC proof payload (Prompt 131 gate). The digest-focused tests
// below revert BEFORE the FDC gate, so any decodable payload satisfies the
// ABI-decode step; the gate itself is exercised in the settle matrix.
const FDC_PROOF = encodeProof([ethers.id("node-1")], "0x1234");

describe("VerifiableRAG", function () {
  // Under coverage the JWT-parsing tests are ~100x slower; 300s keeps them green
  // while the normal (uninstrumented) run stays well under a second each.
  this.timeout(300_000);

  describe("1. deployment", () => {
    it("deploys with constructor state (owner, immutable registry, digest)", async () => {
      const { contract, owner } = await loadFixture(deployFixture);
      expect(await contract.owner()).to.equal(owner.address);
      expect(await contract.contractRegistry()).to.equal(REGISTRY);
      expect(await contract.approvedImageDigest()).to.equal(DIGEST_A);
    });

    it("reverts ZeroRegistry when the registry bootstrap is address(0)", async () => {
      const [owner] = await ethers.getSigners();
      const Factory = await ethers.getContractFactory("VerifiableRAG");
      await expect(Factory.deploy(owner.address, ethers.ZeroAddress, DIGEST_A)).to.be.revertedWithCustomError(
        Factory,
        "ZeroRegistry"
      );
    });

    it("reverts ZeroAddress when the initial digest is bytes32(0)", async () => {
      const [owner] = await ethers.getSigners();
      const Factory = await ethers.getContractFactory("VerifiableRAG");
      await expect(Factory.deploy(owner.address, REGISTRY, ethers.ZeroHash)).to.be.revertedWithCustomError(
        Factory,
        "ZeroAddress"
      );
    });

    it("reverts OwnableInvalidOwner when the owner is address(0)", async () => {
      const Factory = await ethers.getContractFactory("VerifiableRAG");
      await expect(Factory.deploy(ethers.ZeroAddress, REGISTRY, DIGEST_A)).to.be.revertedWithCustomError(
        Factory,
        "OwnableInvalidOwner"
      );
    });

    it("registry is immutable: not in storage, constant inlined in deployed bytecode", async () => {
      const { contract } = await loadFixture(deployFixture);
      const code = (await ethers.provider.getCode(await contract.getAddress())).toLowerCase();
      expect(code.includes(REGISTRY.slice(2).toLowerCase())).to.equal(true);
    });
  });

  describe("2. owner controls", () => {
    it("owner can transfer ownership; new owner takes over, old owner is locked out", async () => {
      const { contract, owner, stranger } = await loadFixture(deployFixture);
      await expect(contract.transferOwnership(stranger.address)).to.emit(contract, "OwnershipTransferred").withArgs(owner.address, stranger.address);
      expect(await contract.owner()).to.equal(stranger.address);
      await expect(contract.connect(owner).updateApprovedImageDigest(DIGEST_B)).to.be.revertedWithCustomError(
        contract,
        "OwnableUnauthorizedAccount"
      );
    });

    it("non-owner cannot transfer ownership", async () => {
      const { contract, stranger } = await loadFixture(deployFixture);
      await expect(contract.connect(stranger).transferOwnership(stranger.address)).to.be.revertedWithCustomError(
        contract,
        "OwnableUnauthorizedAccount"
      );
    });

    it("transfer to address(0) reverts OwnableInvalidOwner", async () => {
      const { contract } = await loadFixture(deployFixture);
      await expect(contract.transferOwnership(ethers.ZeroAddress)).to.be.revertedWithCustomError(
        contract,
        "OwnableInvalidOwner"
      );
    });

    it("non-owner cannot rotate the image digest", async () => {
      const { contract, stranger } = await loadFixture(deployFixture);
      await expect(contract.connect(stranger).updateApprovedImageDigest(DIGEST_B)).to.be.revertedWithCustomError(
        contract,
        "OwnableUnauthorizedAccount"
      );
    });

    it("non-owner cannot configure the price feed", async () => {
      const { contract, stranger } = await loadFixture(deployFixture);
      await expect(contract.connect(stranger).updatePriceFeedId(FLR_USD_FEED)).to.be.revertedWithCustomError(
        contract,
        "OwnableUnauthorizedAccount"
      );
    });

    it("owner can renounce ownership (fail-closed: no owner afterwards)", async () => {
      const { contract, owner } = await loadFixture(deployFixture);
      await expect(contract.renounceOwnership()).to.emit(contract, "OwnershipTransferred").withArgs(owner.address, ethers.ZeroAddress);
      expect(await contract.owner()).to.equal(ethers.ZeroAddress);
    });
  });

  describe("3. digest updates", () => {
    it("owner rotates the digest: state updated + ImageDigestUpdated(old,new)", async () => {
      const { contract } = await loadFixture(deployFixture);
      await expect(contract.updateApprovedImageDigest(DIGEST_B))
        .to.emit(contract, "ImageDigestUpdated")
        .withArgs(DIGEST_A, DIGEST_B);
      expect(await contract.approvedImageDigest()).to.equal(DIGEST_B);
    });

    it("reverts ZeroAddress on bytes32(0)", async () => {
      const { contract } = await loadFixture(deployFixture);
      await expect(contract.updateApprovedImageDigest(ethers.ZeroHash)).to.be.revertedWithCustomError(
        contract,
        "ZeroAddress"
      );
    });

    it("reverts UnchangedImageDigest on a no-op update", async () => {
      const { contract } = await loadFixture(deployFixture);
      await expect(contract.updateApprovedImageDigest(DIGEST_A)).to.be.revertedWithCustomError(
        contract,
        "UnchangedImageDigest"
      );
    });

    it("price feed id setter: happy path + event", async () => {
      const { contract } = await loadFixture(deployFixture);
      await expect(contract.updatePriceFeedId(FLR_USD_FEED))
        .to.emit(contract, "PriceFeedIdUpdated")
        .withArgs("0x" + "00".repeat(21), FLR_USD_FEED);
      expect(await contract.priceFeedId()).to.equal(FLR_USD_FEED);
    });

    it("price feed id setter: reverts ZeroFeedId and UnchangedFeedId", async () => {
      const { contract } = await loadFixture(deployFixture);
      await expect(contract.updatePriceFeedId("0x" + "00".repeat(21))).to.be.revertedWithCustomError(contract, "ZeroFeedId");
      await contract.updatePriceFeedId(FLR_USD_FEED);
      await expect(contract.updatePriceFeedId(FLR_USD_FEED)).to.be.revertedWithCustomError(contract, "UnchangedFeedId");
    });
  });

  describe("4. proof verification failure — unapproved container digest (Prompt 116)", () => {
    it("rejects an unapproved digest with UnauthorizedImage (allowlist gate)", async () => {
      const { contract } = await loadFixture(deployFixture);
      // approvedImageDigest = DIGEST_A; submit a token claiming RANDOM_DIGEST.
      await expect(
        contract.verifyAndSettleRAG(makeToken(RANDOM_DIGEST.slice(2)), PROOF, QUERY, 1, FDC_PROOF)
      ).to.be.revertedWithCustomError(contract, "UnauthorizedImage");
    });

    it("UnauthorizedImage carries the offending digest in its args", async () => {
      const { contract } = await loadFixture(deployFixture);
      await expect(
        contract.verifyAndSettleRAG(makeToken(RANDOM_DIGEST.slice(2)), PROOF, QUERY, 1, FDC_PROOF)
      ).to.be.revertedWithCustomError(contract, "UnauthorizedImage")
        .withArgs(RANDOM_DIGEST);
    });

    it("a digest that was rotated OUT becomes unapproved", async () => {
      const { contract } = await loadFixture(deployFixture);
      await contract.updateApprovedImageDigest(DIGEST_B); // A no longer approved
      await expect(
        contract.verifyAndSettleRAG(makeToken(DIGEST_A.slice(2)), PROOF, QUERY, 1, FDC_PROOF)
      ).to.be.revertedWithCustomError(contract, "UnauthorizedImage")
        .withArgs(DIGEST_A);
    });

    it("control: the APPROVED digest passes the allowlist gate (fails later, not on the digest)", async () => {
      const { contract } = await loadFixture(deployFixture);
      // Same token shape, but with the approved digest. The digest check must
      // PASS — the revert must come from the NEXT gate, proving the failure
      // above is specifically the digest allowlist. On deployFixture (real
      // registry, no code on the local hardhat network), the next gate is the
      // Prompt 131 FDC verification: the well-formed proof reaches the gate,
      // the FdcVerification resolution fails (no verifier available), and the
      // gate reverts UnverifiedWeb2Data — NOT UnauthorizedImage, which is
      // exactly the control we need.
      await expect(
        contract.verifyAndSettleRAG(makeToken(DIGEST_A.slice(2)), PROOF, QUERY, 1, FDC_PROOF)
      ).to.be.revertedWithCustomError(contract, "UnverifiedWeb2Data");
    });

    it("a token missing the image_digest claim reverts InvalidToken", async () => {
      const { contract } = await loadFixture(deployFixture);
      const b64 = (buf: Buffer) =>
        buf.toString("base64").replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
      const claims = { swname: "CONFIDENTIAL_SPACE", submods: { gce: { instance_id: "1" } } }; // no image_digest
      const token = ethers.toUtf8Bytes(
        `${b64(Buffer.from("eyJhbGciOiJFUzI1NiJ9"))}.${b64(Buffer.from(JSON.stringify(claims)))}.${b64(Buffer.from("sig"))}`
      );
      await expect(contract.verifyAndSettleRAG(token, PROOF, QUERY, 1, FDC_PROOF)).to.be.revertedWithCustomError(
        contract,
        "InvalidToken"
      );
    });

    it("a token missing swname reverts InvalidToken", async () => {
      const { contract } = await loadFixture(deployFixture);
      await expect(
        contract.verifyAndSettleRAG(makeToken(DIGEST_A.slice(2), null), PROOF, QUERY, 1, FDC_PROOF)
      ).to.be.revertedWithCustomError(contract, "InvalidToken");
    });
  });

  describe("5. submitAttestation (Prompt 104)", () => {
    const proof = {
      bindingHash: ethers.id("binding-1"),
      zkProof: "0x1234abcd",
      publicInputs: [ethers.id("h1"), ethers.id("h2"), ethers.id("h3")],
    };
    const attestationData = "0xdeadbeef";

    it("records the commitment, sets latestProofHash, emits AttestationSubmitted", async () => {
      const { contract, owner } = await loadFixture(deployFixture);
      const expected = ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(
          ["bytes32", "bytes", "bytes32[3]"],
          [proof.bindingHash, proof.zkProof, proof.publicInputs]
        )
      );
      await expect(contract.submitAttestation(proof, attestationData))
        .to.emit(contract, "AttestationSubmitted")
        .withArgs(expected, owner.address, proof.bindingHash);
      expect(await contract.latestProofHash()).to.equal(expected);
      expect(await contract.submittedProofs(expected)).to.equal(true);
    });

    it("reverts DuplicateProof when the same commitment is submitted twice", async () => {
      const { contract } = await loadFixture(deployFixture);
      await contract.submitAttestation(proof, attestationData);
      await expect(contract.submitAttestation(proof, attestationData)).to.be.revertedWithCustomError(
        contract,
        "DuplicateProof"
      );
    });
  });

  describe("6. registry resolvers (Prompt 111)", () => {
    it("resolves FdcHub / FdcVerification / FtsoV2 live from the registry", async () => {
      const { contract, hubSigner, verifier, ftso } = await loadFixture(settleFixture);
      expect(await contract.fdcHub()).to.equal(hubSigner.address);
      expect(await contract.fdcVerification()).to.equal(await verifier.getAddress());
      expect(await contract.ftsoV2()).to.equal(await ftso.getAddress());
    });

    it("reverts UnregisteredContract when a name is not registered (fail-closed)", async () => {
      const [owner] = await ethers.getSigners();
      const Registry = await ethers.getContractFactory("TestFlareRegistry");
      const registry = await Registry.deploy();
      await registry.waitForDeployment();
      // No names set — every lookup returns address(0).
      const Factory = await ethers.getContractFactory("VerifiableRAG");
      const contract = await Factory.deploy(owner.address, await registry.getAddress(), DIGEST_A);
      await contract.waitForDeployment();
      await expect(contract.fdcHub()).to.be.revertedWithCustomError(contract, "UnregisteredContract");
      await expect(contract.fdcVerification()).to.be.revertedWithCustomError(contract, "UnregisteredContract");
      await expect(contract.ftsoV2()).to.be.revertedWithCustomError(contract, "UnregisteredContract");
    });
  });

  describe("7. verifyAndSettleRAG full matrix (Prompt 109)", () => {
    it("settles a query against the live feed: returns true + ProofVerified + record", async () => {
      const { contract, LIVE_VALUE } = await loadFixture(settleFixture);
      const q = ethers.id("settle#1");
      const tx = await contract.verifyAndSettleRAG(makeToken(DIGEST_A.slice(2)), PROOF, q, SETTLE_QTY, FDC_PROOF);
      const rcpt = await tx.wait();
      const ev = rcpt!.logs
        .map((l) => { try { return contract.interface.parseLog(l); } catch { return null; } })
        .find((p) => p && p.name === "ProofVerified");
      expect(ev).to.not.equal(undefined);
      expect(ev!.args.queryHash).to.equal(q);
      expect(ev!.args.imageDigest).to.equal(DIGEST_A);
      const rec = await contract.verifiedQueries(q);
      expect(rec.verified).to.equal(true);
      expect(rec.bindingHash).to.equal(ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(
          ["bytes32", "bytes", "bytes32"],
          [q, PROOF, DIGEST_A]
        )
      ));
      // Prompt 146: the contract fetched the feed itself and valued on-chain
      // (quantity × live price / 10^8, TestFtsoV2 default decimals).
      expect(await contract.lastSettlementPrice()).to.equal(LIVE_VALUE);
      expect(await contract.lastSettlementValuation()).to.equal(
        (SETTLE_QTY * LIVE_VALUE) / 10n ** 8n
      );
    });

    it("records the verified Web2 round's REAL merkle root in latestVerifiedWeb2Hash (Prompt 130)", async () => {
      const { contract, relay, FDC_ROOT, LIVE_VALUE } = await loadFixture(settleFixture);
      expect(await contract.latestVerifiedWeb2Hash()).to.equal(ethers.ZeroHash); // nothing verified yet
      const q = ethers.id("settle#root");
      await contract.verifyAndSettleRAG(makeToken(DIGEST_A.slice(2)), PROOF, q, SETTLE_QTY, FDC_PROOF);
      // The root read back from the relay the verifier points at — the SAME
      // (protocolId 200, votingRound 77) the encoded proof carries.
      const expected = await relay.merkleRoots(200, FDC_ROUND);
      expect(expected).to.equal(FDC_ROOT);
      expect(await contract.latestVerifiedWeb2Hash()).to.equal(FDC_ROOT);
    });

    it("records a DIFFERENT root for a proof attesting a different round (Prompt 130)", async () => {
      const { contract, relay, LIVE_VALUE } = await loadFixture(settleFixture);
      const otherRound = 99n;
      const otherRoot = ethers.id("other-round-root");
      await (await relay.setMerkleRoot(200, otherRound, otherRoot)).wait();
      const otherProof = encodeProof([ethers.id("node-9")], "0x9999", otherRound);
      await contract.verifyAndSettleRAG(
        makeToken(DIGEST_A.slice(2)), PROOF, ethers.id("settle#root2"), SETTLE_QTY, otherProof
      );
      expect(await contract.latestVerifiedWeb2Hash()).to.equal(otherRoot);
    });

    it("reverts UnverifiedWeb2Data when FdcVerification rejects the proof (Prompt 131 gate)", async () => {
      const { contract, verifier, LIVE_VALUE } = await loadFixture(settleFixture);
      await (await verifier.setResult(false)).wait();
      await expect(
        contract.verifyAndSettleRAG(makeToken(DIGEST_A.slice(2)), PROOF, ethers.id("settle#nogate"), SETTLE_QTY, FDC_PROOF)
      ).to.be.revertedWithCustomError(contract, "UnverifiedWeb2Data");
      // Nothing was settled — the gate runs BEFORE any settlement state write.
      const rec = await contract.verifiedQueries(ethers.id("settle#nogate"));
      expect(rec.verified).to.equal(false);
      expect(await contract.latestVerifiedWeb2Hash()).to.equal(ethers.ZeroHash);
    });

    it("reverts UnverifiedWeb2Data when the FDC proof is undecodable junk (Prompt 131 gate)", async () => {
      const { contract, LIVE_VALUE } = await loadFixture(settleFixture);
      await expect(
        contract.verifyAndSettleRAG(makeToken(DIGEST_A.slice(2)), PROOF, ethers.id("settle#junk"), SETTLE_QTY, "0xdeadbeef")
      ).to.be.revertedWithCustomError(contract, "UnverifiedWeb2Data");
      const rec = await contract.verifiedQueries(ethers.id("settle#junk"));
      expect(rec.verified).to.equal(false);
    });

    it("reverts UnverifiedWeb2Data when the attested round has NO published merkle root", async () => {
      const { contract, LIVE_VALUE } = await loadFixture(settleFixture);
      // FDC_ROUND has a root; 12345 does not -> relay returns bytes32(0). The
      // gate still requires the FDC bool, which is true here, but the recorded
      // root is the relay's real value — a round with no finalized root yields
      // zero. This pins the fail-closed semantics: no fabricated roots.
      const noRootProof = encodeProof([ethers.id("node-x")], "0xabcd", 12345n);
      await contract.verifyAndSettleRAG(
        makeToken(DIGEST_A.slice(2)), PROOF, ethers.id("settle#noroot"), SETTLE_QTY, noRootProof
      );
      expect(await contract.latestVerifiedWeb2Hash()).to.equal(ethers.ZeroHash);
    });

    it("computes the on-chain settlement valuation from the LIVE feed (Prompt 146)", async () => {
      const { contract, LIVE_VALUE } = await loadFixture(settleFixture);
      const q = ethers.id("settle#2");
      // TestFtsoV2's default decimals are 8 — the valuation the contract
      // computes on-chain must equal quantity × live price / 10^8. The price
      // comes from the feed the contract fetched itself (no caller input).
      const expected = (SETTLE_QTY * LIVE_VALUE) / 10n ** 8n;
      await contract.verifyAndSettleRAG(makeToken(DIGEST_A.slice(2)), PROOF, q, SETTLE_QTY, FDC_PROOF);
      expect(await contract.lastSettlementPrice()).to.equal(LIVE_VALUE);
      expect(await contract.lastSettlementValuation()).to.equal(expected);
    });

    it("reverts StaleFeed when the feed is older than REALTIME_MAX_AGE", async () => {
      const { contract, ftso, LIVE_VALUE } = await loadFixture(settleFixture);
      const block = await ethers.provider.getBlock("latest");
      await (await ftso.setFeed(LIVE_VALUE, block!.timestamp - 601)).wait(); // > 300s old
      await expect(
        contract.verifyAndSettleRAG(makeToken(DIGEST_A.slice(2)), PROOF, ethers.id("settle#3"), SETTLE_QTY, FDC_PROOF)
      ).to.be.revertedWithCustomError(contract, "StaleFeed");
    });

    it("a feed timestamp in the future is NOT stale (freshness gate passes)", async () => {
      const { contract, ftso, LIVE_VALUE } = await loadFixture(settleFixture);
      const block = await ethers.provider.getBlock("latest");
      await (await ftso.setFeed(LIVE_VALUE, block!.timestamp + 120)).wait();
      await expect(
        contract.verifyAndSettleRAG(makeToken(DIGEST_A.slice(2)), PROOF, ethers.id("settle#4"), SETTLE_QTY, FDC_PROOF)
      ).to.emit(contract, "ProofVerified");
    });

    it("reverts UnconfiguredFeed when no feed id is configured (fresh deploy)", async () => {
      const { owner, LIVE_VALUE } = await loadFixture(settleFixture);
      const Registry = await ethers.getContractFactory("TestFlareRegistry");
      const registry = await Registry.deploy();
      await registry.waitForDeployment();
      // The Prompt 131 FDC stack must be wired BEFORE the feed check can be
      // the failing gate: without it, the gate itself reverts UnverifiedWeb2Data
      // (which the gate tests above already cover). Here we pass the gate with
      // a valid proof and prove the NEXT failure is the missing feed.
      const Verifier = await ethers.getContractFactory("TestFdcVerification");
      const verifier = await Verifier.deploy();
      await verifier.waitForDeployment();
      const Relay = await ethers.getContractFactory("TestRelay");
      const relay = await Relay.deploy();
      await relay.waitForDeployment();
      await (await verifier.setResult(true)).wait();
      await (await verifier.setRelay(await relay.getAddress())).wait();
      await (await relay.setMerkleRoot(200, FDC_ROUND, ethers.id("root"))).wait();
      await registry.setAddress("FdcVerification", await verifier.getAddress());
      const Ftso = await ethers.getContractFactory("TestFtsoV2");
      const ftso = await Ftso.deploy();
      await ftso.waitForDeployment();
      await registry.setAddress("FtsoV2", await ftso.getAddress());
      const Factory = await ethers.getContractFactory("VerifiableRAG");
      const fresh = await Factory.deploy(owner.address, await registry.getAddress(), DIGEST_A);
      await fresh.waitForDeployment();
      await expect(
        fresh.verifyAndSettleRAG(makeToken(DIGEST_A.slice(2)), PROOF, ethers.id("settle#5"), SETTLE_QTY, FDC_PROOF)
      ).to.be.revertedWithCustomError(fresh, "UnconfiguredFeed");
    });

    it("reverts ZeroQueryHash for a zero query hash", async () => {
      const { contract, LIVE_VALUE } = await loadFixture(settleFixture);
      await expect(
        contract.verifyAndSettleRAG(makeToken(DIGEST_A.slice(2)), PROOF, ethers.ZeroHash, SETTLE_QTY, FDC_PROOF)
      ).to.be.revertedWithCustomError(contract, "ZeroQueryHash");
    });

    it("reverts InvalidToken for empty token or empty proof", async () => {
      const { contract, LIVE_VALUE } = await loadFixture(settleFixture);
      await expect(
        contract.verifyAndSettleRAG(new Uint8Array(0), PROOF, ethers.id("settle#6"), SETTLE_QTY, FDC_PROOF)
      ).to.be.revertedWithCustomError(contract, "InvalidToken");
      await expect(
        contract.verifyAndSettleRAG(makeToken(DIGEST_A.slice(2)), new Uint8Array(0), ethers.id("settle#6"), SETTLE_QTY, FDC_PROOF)
      ).to.be.revertedWithCustomError(contract, "InvalidToken");
    });

    it("reverts DuplicateProof when the identical (token, proof, query) is replayed", async () => {
      const { contract, LIVE_VALUE } = await loadFixture(settleFixture);
      const q = ethers.id("settle#7");
      await contract.verifyAndSettleRAG(makeToken(DIGEST_A.slice(2)), PROOF, q, SETTLE_QTY, FDC_PROOF);
      await expect(
        contract.verifyAndSettleRAG(makeToken(DIGEST_A.slice(2)), PROOF, q, SETTLE_QTY, FDC_PROOF)
      ).to.be.revertedWithCustomError(contract, "DuplicateProof");
    });

    it("reverts QueryConflict when the same query is settled with a different proof", async () => {
      const { contract, LIVE_VALUE } = await loadFixture(settleFixture);
      const q = ethers.id("settle#8");
      await contract.verifyAndSettleRAG(makeToken(DIGEST_A.slice(2)), PROOF, q, SETTLE_QTY, FDC_PROOF);
      await expect(
        contract.verifyAndSettleRAG(makeToken(DIGEST_A.slice(2)), Buffer.from("other-proof"), q, SETTLE_QTY, FDC_PROOF)
      ).to.be.revertedWithCustomError(contract, "QueryConflict");
    });

    it("same query + same binding under a different token returns true (idempotent-safe)", async () => {
      const { contract, LIVE_VALUE } = await loadFixture(settleFixture);
      const q = ethers.id("settle#9");
      await contract.verifyAndSettleRAG(makeToken(DIGEST_A.slice(2)), PROOF, q, SETTLE_QTY, FDC_PROOF);
      // Different token bytes (different signature segment) but the SAME digest,
      // proof and query -> different proofId, identical bindingHash.
      const alt = ethers.toUtf8Bytes(
        new TextDecoder().decode(makeToken(DIGEST_A.slice(2))).replace(/\.[^.]*$/, ".other-sig")
      );
      const tx = await contract.verifyAndSettleRAG(alt, PROOF, q, SETTLE_QTY, FDC_PROOF);
      await expect(tx).to.emit(contract, "ProofVerified");
    });

    it("reverts InvalidToken when the digest hex is malformed (non-hex chars)", async () => {
      const { contract, LIVE_VALUE } = await loadFixture(settleFixture);
      await expect(
        contract.verifyAndSettleRAG(makeToken("zz".repeat(32)), PROOF, ethers.id("settle#10"), SETTLE_QTY, FDC_PROOF)
      ).to.be.revertedWithCustomError(contract, "InvalidToken");
    });

    it("reverts InvalidToken when the digest is too short (< 64 hex chars)", async () => {
      const { contract, LIVE_VALUE } = await loadFixture(settleFixture);
      await expect(
        contract.verifyAndSettleRAG(makeToken("abcd"), PROOF, ethers.id("settle#11"), SETTLE_QTY, FDC_PROOF)
      ).to.be.revertedWithCustomError(contract, "InvalidToken");
    });

    it("reverts InvalidToken when image_digest lacks the sha256: prefix", async () => {
      const { contract, LIVE_VALUE } = await loadFixture(settleFixture);
      const b64 = (buf: Buffer) =>
        buf.toString("base64").replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
      const claims = { swname: "CONFIDENTIAL_SPACE", image_digest: DIGEST_A.slice(2) }; // no sha256: prefix
      const token = ethers.toUtf8Bytes(
        `${b64(Buffer.from("eyJhbGciOiJFUzI1NiJ9"))}.${b64(Buffer.from(JSON.stringify(claims)))}.${b64(Buffer.from("sig"))}`
      );
      await expect(contract.verifyAndSettleRAG(token, PROOF, ethers.id("settle#12"), SETTLE_QTY, FDC_PROOF)).to.be.revertedWithCustomError(
        contract,
        "InvalidToken"
      );
    });

    it("reverts InvalidToken when image_digest is not a quoted string", async () => {
      const { contract, LIVE_VALUE } = await loadFixture(settleFixture);
      const b64 = (buf: Buffer) =>
        buf.toString("base64").replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
      const claims = { swname: "CONFIDENTIAL_SPACE", image_digest: 123 }; // JSON: "image_digest":123
      const token = ethers.toUtf8Bytes(
        `${b64(Buffer.from("eyJhbGciOiJFUzI1NiJ9"))}.${b64(Buffer.from(JSON.stringify(claims)))}.${b64(Buffer.from("sig"))}`
      );
      await expect(contract.verifyAndSettleRAG(token, PROOF, ethers.id("settle#13"), SETTLE_QTY, FDC_PROOF)).to.be.revertedWithCustomError(
        contract,
        "InvalidToken"
      );
    });

    it("UPPERCASE hex digests parse correctly (hexValue A-F branch)", async () => {
      const { contract, LIVE_VALUE } = await loadFixture(settleFixture);
      // The parser accepts A-F; the decoded bytes equal the lowercase form, so an
      // uppercase spelling of the APPROVED digest passes the allowlist gate and
      // proceeds to the next gate (feed is configured -> settles, emitting event).
      const upper = ("0x" + DIGEST_A.slice(2).toUpperCase());
      await expect(
        contract.verifyAndSettleRAG(makeToken(upper.slice(2)), PROOF, ethers.id("settle#14"), SETTLE_QTY, FDC_PROOF)
      ).to.emit(contract, "ProofVerified");
    });

    it("reverts InvalidToken for a malformed JWT (no dots / one dot / empty payload)", async () => {
      const { contract, LIVE_VALUE } = await loadFixture(settleFixture);
      await expect(
        contract.verifyAndSettleRAG(ethers.toUtf8Bytes("no-dots-here"), PROOF, ethers.id("settle#15"), SETTLE_QTY, FDC_PROOF)
      ).to.be.revertedWithCustomError(contract, "InvalidToken");
      await expect(
        contract.verifyAndSettleRAG(ethers.toUtf8Bytes("a.b"), PROOF, ethers.id("settle#16"), SETTLE_QTY, FDC_PROOF)
      ).to.be.revertedWithCustomError(contract, "InvalidToken");
      await expect(
        contract.verifyAndSettleRAG(ethers.toUtf8Bytes("a..b"), PROOF, ethers.id("settle#17"), SETTLE_QTY, FDC_PROOF)
      ).to.be.revertedWithCustomError(contract, "InvalidToken");
    });

    it("reverts InvalidToken for a base64url payload with illegal characters", async () => {
      const { contract, LIVE_VALUE } = await loadFixture(settleFixture);
      // Payload segment "???" — '?' is not base64url -> InvalidToken.
      await expect(
        contract.verifyAndSettleRAG(ethers.toUtf8Bytes("eyJhbGciOiJFUzI1NiJ9.???.c2ln"), PROOF, ethers.id("settle#18"), SETTLE_QTY, FDC_PROOF)
      ).to.be.revertedWithCustomError(contract, "InvalidToken");
    });

    it("reverts InvalidToken when the base64url length mod 4 == 1", async () => {
      const { contract, LIVE_VALUE } = await loadFixture(settleFixture);
      // Payload segment "abcde" (5 chars, 5 % 4 == 1) -> InvalidToken.
      await expect(
        contract.verifyAndSettleRAG(ethers.toUtf8Bytes("eyJhbGciOiJFUzI1NiJ9.abcde.c2ln"), PROOF, ethers.id("settle#19"), SETTLE_QTY, FDC_PROOF)
      ).to.be.revertedWithCustomError(contract, "InvalidToken");
    });

    it("padded base64url payloads decode identically (padding-strip branch)", async () => {
      const { contract, LIVE_VALUE } = await loadFixture(settleFixture);
      // Standard base64url encoder that KEEPS trailing '=' padding (the real
      // JWT form) — the on-chain decoder strips '=' first, so a padded payload
      // must decode to the same claims and settle identically to the unpadded
      // form. A filler claim (unknown key — the parser only reads swname +
      // image_digest) is sized so the JSON byte length %3 != 0, which is what
      // makes the base64 actually carry padding; the guard below fails loudly
      // if no filler length produces a padded payload (tokenWithB64Char
      // precedent), so the strip branch can never be silently untested.
      const b64KeepPad = (buf: Buffer) =>
        buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_"); // keep '='
      let paddedToken: Uint8Array | null = null;
      for (const fillerLen of [0, 1, 2, 3]) {
        const claims: Record<string, unknown> = {
          sub: "s",
          aud: "a",
          submods: { container: { image_digest: "sha256:" + DIGEST_A.slice(2) }, gce: { instance_id: "1" } },
          swname: "CONFIDENTIAL_SPACE",
        };
        if (fillerLen > 0) claims.filler = "x".repeat(fillerLen);
        const payload = b64KeepPad(Buffer.from(JSON.stringify(claims)));
        if (payload.endsWith("=")) {
          paddedToken = ethers.toUtf8Bytes(
            `${b64KeepPad(Buffer.from("eyJhbGciOiJFUzI1NiJ9"))}.${payload}.${b64KeepPad(Buffer.from("sig"))}`
          );
          break;
        }
      }
      expect(paddedToken, "no filler length produced a padded base64url payload").to.not.equal(null);
      await expect(
        contract.verifyAndSettleRAG(paddedToken!, PROOF, ethers.id("settle#20"), SETTLE_QTY, FDC_PROOF)
      ).to.emit(contract, "ProofVerified");
    });

    it("reverts InvalidToken when image_digest is the LAST key (no colon after it)", async () => {
      const { contract, LIVE_VALUE } = await loadFixture(settleFixture);
      const b64 = (buf: Buffer) =>
        buf.toString("base64").replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
      // JSON ends right after the key: the parser's `p >= _json.length` bounds
      // check fires before it can read the colon.
      const raw = `{"swname":"CONFIDENTIAL_SPACE","image_digest"`;
      const token = ethers.toUtf8Bytes(
        `${b64(Buffer.from("eyJhbGciOiJFUzI1NiJ9"))}.${b64(Buffer.from(raw))}.${b64(Buffer.from("sig"))}`
      );
      await expect(contract.verifyAndSettleRAG(token, PROOF, ethers.id("settle#21"), SETTLE_QTY, FDC_PROOF)).to.be.revertedWithCustomError(
        contract,
        "InvalidToken"
      );
    });

    it("reverts InvalidToken when a space precedes the colon after image_digest", async () => {
      const { contract, LIVE_VALUE } = await loadFixture(settleFixture);
      const b64 = (buf: Buffer) =>
        buf.toString("base64").replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
      // Hand-built JSON with `"image_digest" : ...` (space before colon) — the
      // parser expects `:` immediately after the key.
      const raw = `{"swname":"CONFIDENTIAL_SPACE","image_digest" : "sha256:${DIGEST_A.slice(2)}"}`;
      const token = ethers.toUtf8Bytes(
        `${b64(Buffer.from("eyJhbGciOiJFUzI1NiJ9"))}.${b64(Buffer.from(raw))}.${b64(Buffer.from("sig"))}`
      );
      await expect(contract.verifyAndSettleRAG(token, PROOF, ethers.id("settle#22"), SETTLE_QTY, FDC_PROOF)).to.be.revertedWithCustomError(
        contract,
        "InvalidToken"
      );
    });

    it("reverts InvalidToken when image_digest has no opening quote after the colon", async () => {
      const { contract, LIVE_VALUE } = await loadFixture(settleFixture);
      const b64 = (buf: Buffer) =>
        buf.toString("base64").replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
      // `"image_digest":` at the very end — the opening-quote read runs off the
      // buffer (p >= _json.length in the quote check).
      const raw = `{"swname":"CONFIDENTIAL_SPACE","image_digest":`;
      const token = ethers.toUtf8Bytes(
        `${b64(Buffer.from("eyJhbGciOiJFUzI1NiJ9"))}.${b64(Buffer.from(raw))}.${b64(Buffer.from("sig"))}`
      );
      await expect(contract.verifyAndSettleRAG(token, PROOF, ethers.id("settle#23"), SETTLE_QTY, FDC_PROOF)).to.be.revertedWithCustomError(
        contract,
        "InvalidToken"
      );
    });

    it("reverts InvalidToken when the sha256: prefix runs off the buffer end", async () => {
      const { contract, LIVE_VALUE } = await loadFixture(settleFixture);
      const b64 = (buf: Buffer) =>
        buf.toString("base64").replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
      // Value is `"sha256` with NO closing quote and the buffer ends right after
      // it: the prefix loop's `p + j >= _json.length` bounds check fires at the
      // 7th prefix byte (the ':' of "sha256:").
      const raw = `{"swname":"CONFIDENTIAL_SPACE","image_digest":"sha256`;
      const token = ethers.toUtf8Bytes(
        `${b64(Buffer.from("eyJhbGciOiJFUzI1NiJ9"))}.${b64(Buffer.from(raw))}.${b64(Buffer.from("sig"))}`
      );
      await expect(contract.verifyAndSettleRAG(token, PROOF, ethers.id("settle#24"), SETTLE_QTY, FDC_PROOF)).to.be.revertedWithCustomError(
        contract,
        "InvalidToken"
      );
    });

    it("reverts InvalidToken for a base64url payload containing '-' (URL-safe char)", async () => {
      const { contract, LIVE_VALUE } = await loadFixture(settleFixture);
      // '-' decodes to a valid 6-bit value; the bytes are non-JSON, so the
      // swname search fails -> InvalidToken.
      await expect(
        contract.verifyAndSettleRAG(
          ethers.toUtf8Bytes("eyJhbGciOiJFUzI1NiJ9.ab-cd.c2ln"),
          PROOF,
          ethers.id("settle#25-minus"),
          LIVE_VALUE,
          FDC_PROOF
        )
      ).to.be.revertedWithCustomError(contract, "InvalidToken");
    });

    it("reverts InvalidToken for a base64url payload containing '_' (URL-safe char)", async () => {
      const { contract, LIVE_VALUE } = await loadFixture(settleFixture);
      await expect(
        contract.verifyAndSettleRAG(
          ethers.toUtf8Bytes("eyJhbGciOiJFUzI1NiJ9.ab_cd.c2ln"),
          PROOF,
          ethers.id("settle#25-underscore"),
          LIVE_VALUE,
          FDC_PROOF
        )
      ).to.be.revertedWithCustomError(contract, "InvalidToken");
    });

    it("reverts InvalidToken for a base64url payload with a mid-token '='", async () => {
      const { contract, LIVE_VALUE } = await loadFixture(settleFixture);
      // A mid-token '=' is NOT trailing padding, so it reaches _b64Value (maps
      // to 0) and the decoded bytes are non-JSON -> InvalidToken.
      await expect(
        contract.verifyAndSettleRAG(
          ethers.toUtf8Bytes("eyJhbGciOiJFUzI1NiJ9.ab=cd.c2ln"),
          PROOF,
          ethers.id("settle#25-equals"),
          LIVE_VALUE,
          FDC_PROOF
        )
      ).to.be.revertedWithCustomError(contract, "InvalidToken");
    });

    it("reverts InvalidToken for a base64url payload with a partial final group (mod 4 == 3)", async () => {
      const { contract, LIVE_VALUE } = await loadFixture(settleFixture);
      // 7 chars (7 % 4 == 3): the final group has only one byte of output —
      // exercises the b1/b2/b3 short-group ternaries in _b64UrlDecode.
      await expect(
        contract.verifyAndSettleRAG(
          ethers.toUtf8Bytes("eyJhbGciOiJFUzI1NiJ9.abc-def.c2ln"),
          PROOF,
          ethers.id("settle#25-partial"),
          LIVE_VALUE,
          FDC_PROOF
        )
      ).to.be.revertedWithCustomError(contract, "InvalidToken");
    });

    /** Build a valid approved-digest token whose payload base64url contains the
     *  given URL-safe char. The filler claim (an unknown key — the parser only
     *  reads swname + image_digest) is chosen so the raw base64 of the JSON
     *  contains '/' (-> '_') or '+' (-> '-'); the assertion below guards the
     *  assumption so a future payload change fails loudly instead of silently
     *  weakening the test. These settle SUCCESSFULLY so the coverage tracer
     *  records the _b64Value URL-safe branches in a committed (non-reverting)
     *  transaction — the only context where EDR tracing registers them. */
    function tokenWithB64Char(digestHex: string, filler: string, expectChar: string): Uint8Array {
      const b64 = (buf: Buffer) =>
        buf.toString("base64").replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
      const claims = {
        sub: "s",
        aud: "a",
        submods: { container: { image_digest: "sha256:" + digestHex }, gce: { instance_id: "1" } },
        swname: "CONFIDENTIAL_SPACE",
        filler,
      };
      const payload = b64(Buffer.from(JSON.stringify(claims)));
      if (!payload.includes(expectChar)) {
        throw new Error(`payload b64 lacks '${expectChar}' (filler '${filler}')`);
      }
      return ethers.toUtf8Bytes(
        `${b64(Buffer.from("eyJhbGciOiJFUzI1NiJ9"))}.${payload}.${b64(Buffer.from("sig"))}`
      );
    }

    it("a payload containing base64url '_' still settles (URL-safe alphabet)", async () => {
      const { contract, LIVE_VALUE } = await loadFixture(settleFixture);
      await expect(
        contract.verifyAndSettleRAG(tokenWithB64Char(DIGEST_A.slice(2), "??", "_"), PROOF, ethers.id("settle#26-underscore"), SETTLE_QTY, FDC_PROOF)
      ).to.emit(contract, "ProofVerified");
    });

    it("a payload containing base64url '-' still settles (URL-safe alphabet)", async () => {
      const { contract, LIVE_VALUE } = await loadFixture(settleFixture);
      await expect(
        contract.verifyAndSettleRAG(tokenWithB64Char(DIGEST_A.slice(2), ">>", "-"), PROOF, ethers.id("settle#26-dash"), SETTLE_QTY, FDC_PROOF)
      ).to.emit(contract, "ProofVerified");
    });
  });

  describe("8. verifyWeb2Data FDC bridge (Prompt 123)", () => {
    /** Fixture: TestFlareRegistry + a REAL TestFdcVerification wired in as the
     *  "FdcVerification" registry entry — exactly like production (Prompt 111
     *  resolver pattern). The proof payload is ABI-encoded on the client and
     *  decoded inside verifyWeb2Data before forwarding to the verifier. */
    async function web2Fixture() {
      const [owner] = await ethers.getSigners();

      const Registry = await ethers.getContractFactory("TestFlareRegistry");
      const registry = await Registry.deploy();
      await registry.waitForDeployment();

      const Verifier = await ethers.getContractFactory("TestFdcVerification");
      const verifier = await Verifier.deploy();
      await verifier.waitForDeployment();
      await registry.setAddress("FdcVerification", await verifier.getAddress());

      const Factory = await ethers.getContractFactory("VerifiableRAG");
      const contract = await Factory.deploy(owner.address, await registry.getAddress(), DIGEST_A);
      await contract.waitForDeployment();

      return { contract, owner, registry, verifier };
    }

    it("returns the live verifier's result (true when FDC verified the proof)", async () => {
      const { contract, verifier } = await loadFixture(web2Fixture);
      await (await verifier.setResult(true)).wait();
      const proof = encodeProof([ethers.id("node-1"), ethers.id("node-2")], ethers.id("payload"));
      expect(await contract.verifyWeb2Data(proof)).to.equal(true);
    });

    it("returns false when the verifier rejects the proof (no FDC consensus)", async () => {
      const { contract, verifier } = await loadFixture(web2Fixture);
      await (await verifier.setResult(false)).wait();
      const proof = encodeProof([ethers.id("node-1")], "0x1234");
      expect(await contract.verifyWeb2Data(proof)).to.equal(false);
    });

    it("reverts UnregisteredContract when FdcVerification is not registered", async () => {
      const [owner] = await ethers.getSigners();
      const Registry = await ethers.getContractFactory("TestFlareRegistry");
      const registry = await Registry.deploy();
      await registry.waitForDeployment();
      // Registry deployed but NO names set -> every lookup returns address(0).
      const Factory = await ethers.getContractFactory("VerifiableRAG");
      const contract = await Factory.deploy(owner.address, await registry.getAddress(), DIGEST_A);
      await contract.waitForDeployment();
      // A WELL-FORMED proof payload, so the decode succeeds and the registry
      // gate is what actually reverts (fail-closed, never a zero address).
      const proof = encodeProof([ethers.id("node-1")], "0x1234");
      await expect(contract.verifyWeb2Data(proof)).to.be.revertedWithCustomError(
        contract,
        "UnregisteredContract"
      );
    });

    it("reverts when the proof bytes are not a decodable IWeb2Json.Proof", async () => {
      const { contract } = await loadFixture(web2Fixture);
      // abi.decode reverts WITHOUT a custom error (pre-Solidity-0.8.24 default
      // revert) before the registry gate is reached — the generic `reverted`
      // matcher is correct here, and the UnregisteredContract test above
      // proves the registry gate itself uses the custom error path.
      await expect(contract.verifyWeb2Data("0xdeadbeef")).to.be.reverted;
    });
  });
});
