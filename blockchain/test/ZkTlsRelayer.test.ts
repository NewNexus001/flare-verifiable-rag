/**
 * ZkTlsRelayer.test.ts — Phase 14 zkTLS proof on-chain tests (Prompt 270).
 *
 * Covers the ZkTlsRelayer.sol surface:
 *   1. registerZkTlsSigner / deregisterZkTlsSigner — owner-only registry with
 *      ZeroAddress / ZkTlsSignerAlreadyRegistered / ZkTlsSignerNotRegistered
 *      fail-closed guards.
 *   2. relayVerifiedWeb2Data — the ecrecover gate: the test constructs a
 *      proof in the EXACT 218-byte wire format the Rust enclave emits
 *      (enclave/enclave_grpc/src/zktls/proof_generator.rs
 *      ZkTlsProof::to_bytes), signs the same 153-byte canonical payload with
 *      a real secp256k1 key (ethers low-level signingKey.sign — the same
 *      math as the enclave's k256 recoverable signatures), and asserts:
 *      - a valid proof from a REGISTERED signer records verifiedWeb2Data;
 *      - replay of the same proof reverts ProofAlreadyUsed;
 *      - a stale timestamp reverts StaleProof;
 *      - a proof from an UNREGISTERED signer reverts UnauthorizedZkTlsSigner;
 *      - mismatched urlHash/dataHash arguments revert ProofHashMismatch;
 *      - malformed bytes revert MalformedProof; wrong version reverts
 *        UnsupportedProofVersion.
 *
 * The wire layout (byte positions, matching the Rust side):
 *   version(1) @0 | url_hash(32) @1 | data_hash(32) @33 |
 *   response_hash(32) @65 | cert_fingerprint(32) @97 | ts(8 BE) @129 |
 *   nonce(16) @137 | r(32) @153 | s(32) @185 | v(1) @217        = 218 bytes
 * Signed digest = keccak256(payload[0..153]) — the SAME canonical payload
 * (version || urlHash || dataHash || responseHash || certFingerprint ||
 * ts || nonce) the contract recomputes with abi.encodePacked.
 */
import { expect } from "chai";
import { ethers } from "hardhat";
import {
  loadFixture,
  time,
  mine,
} from "@nomicfoundation/hardhat-network-helpers";
import type { ZkTlsRelayer } from "../typechain-types/contracts/ZkTlsRelayer";
import type { VerifiableRAG } from "../typechain-types/contracts/VerifiableRAG";

// Canonical FlareContractRegistry bootstrap (same on every Flare network).
const REGISTRY = "0x" + "aD67FE66660Fb8dFE9d6b1b4240d8650e30F6019";
// Real enclave image digest (sha256: prefix stripped), as in VerifiableRAG.test.ts.
const DIGEST_A = "0x" + "25f55814e809632f5af58eaa2b1d48cec1c49aa6a451c82b6af9fe9de934f421";

const VERSION = 1;

async function deployFixture() {
  const [owner, stranger] = await ethers.getSigners();
  const Factory = await ethers.getContractFactory("ZkTlsRelayer");
  const contract = (await Factory.deploy(owner.address)) as ZkTlsRelayer;
  await contract.waitForDeployment();
  // An enclave identity key: a real random secp256k1 key (stands in for the
  // hardware-bound enclave key; in production the address is registered by
  // the owner after the TEE key is derived inside the enclave).
  const enclaveWallet = ethers.Wallet.createRandom();
  return { contract, owner, stranger, enclaveWallet };
}

/** Build a proof in the exact 218-byte wire format the Rust enclave emits.
 *  `signer` must be an ethers.Wallet; `ts` and `nonce` are caller-chosen so
 *  tests can control freshness/replay. */
function buildProof(opts: {
  signer: ethers.Wallet;
  urlHash: string;
  dataHash: string;
  responseHash: string;
  certFingerprint: string;
  ts: bigint;
  nonce: string;
  version?: number;
}): string {
  const version = opts.version ?? VERSION;
  // 1 + 32*4 + 8 + 16 = 153 bytes of canonical payload.
  const payload = ethers.concat([
    ethers.getBytes(ethers.toBeHex(version, 1)),
    opts.urlHash,
    opts.dataHash,
    opts.responseHash,
    opts.certFingerprint,
    ethers.getBytes(ethers.toBeHex(opts.ts, 8)),
    opts.nonce,
  ]);
  const digest = ethers.keccak256(payload);
  // Sign the RAW digest (no EIP-191 prefix) — identical to the enclave's
  // k256 signer over keccak256(canonical payload).
  const rawSig = opts.signer.signingKey.sign(ethers.getBytes(digest));
  const { r, s, v } = ethers.Signature.from(rawSig.serialized); // v = 27/28
  const proof = ethers.concat([
    payload,
    r,
    s,
    ethers.getBytes(ethers.toBeHex(v - 27, 1)), // store raw recovery id 0/1
  ]);
  return proof;
}

describe("ZkTlsRelayer (Phase 14)", function () {
  this.timeout(300_000);

  describe("1. signer registry", () => {
    it("registers an enclave identity (owner) and reports membership", async () => {
      const { contract, owner } = await loadFixture(deployFixture);
      await expect(contract.registerZkTlsSigner(owner.address))
        .to.emit(contract, "ZkTlsSignerRegistered")
        .withArgs(owner.address);
      expect(await contract.isZkTlsSigner(owner.address)).to.equal(true);
    });

    it("reverts ZeroAddress when registering address(0)", async () => {
      const { contract } = await loadFixture(deployFixture);
      await expect(contract.registerZkTlsSigner(ethers.ZeroAddress)).to.be.revertedWithCustomError(
        contract,
        "ZeroAddress"
      );
    });

    it("reverts ZkTlsSignerAlreadyRegistered on a no-op re-register", async () => {
      const { contract, owner } = await loadFixture(deployFixture);
      await contract.registerZkTlsSigner(owner.address);
      await expect(contract.registerZkTlsSigner(owner.address)).to.be.revertedWithCustomError(
        contract,
        "ZkTlsSignerAlreadyRegistered"
      );
    });

    it("deregisters and reverts ZkTlsSignerNotRegistered on no-op", async () => {
      const { contract, owner } = await loadFixture(deployFixture);
      await contract.registerZkTlsSigner(owner.address);
      await expect(contract.deregisterZkTlsSigner(owner.address))
        .to.emit(contract, "ZkTlsSignerDeregistered")
        .withArgs(owner.address);
      expect(await contract.isZkTlsSigner(owner.address)).to.equal(false);
      await expect(contract.deregisterZkTlsSigner(owner.address)).to.be.revertedWithCustomError(
        contract,
        "ZkTlsSignerNotRegistered"
      );
    });

    it("non-owner cannot register or deregister", async () => {
      const { contract, stranger, owner } = await loadFixture(deployFixture);
      await expect(
        contract.connect(stranger).registerZkTlsSigner(stranger.address)
      ).to.be.revertedWithCustomError(contract, "OwnableUnauthorizedAccount");
      await contract.registerZkTlsSigner(owner.address);
      await expect(
        contract.connect(stranger).deregisterZkTlsSigner(owner.address)
      ).to.be.revertedWithCustomError(contract, "OwnableUnauthorizedAccount");
    });
  });

  describe("2. relayVerifiedWeb2Data (ecrecover gate)", () => {
    it("relays a valid proof from a registered enclave signer", async () => {
      const { contract, enclaveWallet } = await loadFixture(deployFixture);
      await contract.registerZkTlsSigner(enclaveWallet.address);

      const urlHash = ethers.keccak256(ethers.toUtf8Bytes("https://jsonplaceholder.typicode.com/todos/1"));
      const dataHash = ethers.keccak256(ethers.toUtf8Bytes("true"));
      const responseHash = ethers.keccak256(ethers.toUtf8Bytes('{"completed":true}'));
      const certFingerprint = ethers.keccak256(ethers.toUtf8Bytes("chain-fingerprint"));
      // Use block.timestamp (not Date.now) so the proof is fresh relative
      // to Hardhat's EVM clock, avoiding StaleProof reverts on slow machines.
      const blockTs = BigInt(await time.latest());
      const nonce = ethers.hexlify(ethers.randomBytes(16));

      const proof = buildProof({
        signer: enclaveWallet,
        urlHash,
        dataHash,
        responseHash,
        certFingerprint,
        ts: blockTs,
        nonce,
      });

      // Mine one block so block.timestamp advances past the proof ts.
      await mine(1);
      const tx = await contract.relayVerifiedWeb2Data(proof, urlHash, dataHash);
      // The event's timestamp is the RELAY block's timestamp (block.timestamp
      // at execution), not the proof's mint time — allow the standard block
      // latency between the two.
      await expect(tx).to.emit(contract, "Web2DataRelayed");
      const receipt = await tx.wait();
      const block = await ethers.provider.getBlock(receipt!.blockNumber);
      const event = receipt!.logs
        .map((l) => {
          try {
            return contract.interface.parseLog(l);
          } catch {
            return null;
          }
        })
        .find((p) => p?.name === "Web2DataRelayed");
      expect(event).to.not.equal(undefined);
      expect(event!.args.urlHash).to.equal(urlHash);
      expect(event!.args.dataHash).to.equal(dataHash);
      expect(event!.args.signer).to.equal(enclaveWallet.address);
      expect(event!.args.responseHash).to.equal(responseHash);
      expect(event!.args.certFingerprint).to.equal(certFingerprint);
      expect(event!.args.timestamp).to.equal(block!.timestamp);

      const verified = await contract.verifiedWeb2Data(urlHash);
      expect(verified.dataHash).to.equal(dataHash);
      expect(verified.verifiedAt).to.be.a("bigint");
    });

    it("reverts ProofAlreadyUsed on replay of the same proof", async () => {
      const { contract, enclaveWallet } = await loadFixture(deployFixture);
      await contract.registerZkTlsSigner(enclaveWallet.address);

      const urlHash = ethers.keccak256(ethers.toUtf8Bytes("https://example.com/a"));
      const dataHash = ethers.keccak256(ethers.toUtf8Bytes("42"));
      const responseHash = ethers.ZeroHash;
      const certFingerprint = ethers.ZeroHash;
      const blockTs = BigInt(await time.latest());
      const nonce = ethers.hexlify(ethers.randomBytes(16));
      const proof = buildProof({ signer: enclaveWallet, urlHash, dataHash, responseHash, certFingerprint, ts: blockTs, nonce });

      await mine(1);
      await contract.relayVerifiedWeb2Data(proof, urlHash, dataHash);
      await expect(contract.relayVerifiedWeb2Data(proof, urlHash, dataHash)).to.be.revertedWithCustomError(
        contract,
        "ProofAlreadyUsed"
      );
    });

    it("reverts StaleProof when the timestamp is older than the window", async () => {
      const { contract, enclaveWallet } = await loadFixture(deployFixture);
      await contract.registerZkTlsSigner(enclaveWallet.address);

      const urlHash = ethers.keccak256(ethers.toUtf8Bytes("https://example.com/stale"));
      const dataHash = ethers.keccak256(ethers.toUtf8Bytes("1"));
      // Build a proof whose timestamp is 401 seconds BEHIND the current
      // block timestamp — well outside the 300s PROOF_MAX_AGE window.
      const currentTs = BigInt(await time.latest());
      const staleTs = currentTs - 401n;
      const proof = buildProof({
        signer: enclaveWallet,
        urlHash,
        dataHash,
        responseHash: ethers.ZeroHash,
        certFingerprint: ethers.ZeroHash,
        ts: staleTs,
        nonce: ethers.hexlify(ethers.randomBytes(16)),
      });

      // Advance block.timestamp 400s past the proof so the freshness
      // check fails: block.timestamp > f.ts + PROOF_MAX_AGE.
      await time.increase(400);

      await expect(contract.relayVerifiedWeb2Data(proof, urlHash, dataHash)).to.be.revertedWithCustomError(
        contract,
        "StaleProof"
      );
    });

    it("reverts UnauthorizedZkTlsSigner for a proof from an unregistered key", async () => {
      const { contract, enclaveWallet } = await loadFixture(deployFixture);
      await contract.registerZkTlsSigner(enclaveWallet.address);
      const rogue = ethers.Wallet.createRandom();

      const urlHash = ethers.keccak256(ethers.toUtf8Bytes("https://example.com/rogue"));
      const dataHash = ethers.keccak256(ethers.toUtf8Bytes("x"));
      const proof = buildProof({
        signer: rogue,
        urlHash,
        dataHash,
        responseHash: ethers.ZeroHash,
        certFingerprint: ethers.ZeroHash,
        ts: BigInt(await time.latest()),
        nonce: ethers.hexlify(ethers.randomBytes(16)),
      });

      await mine(1);
      await expect(contract.relayVerifiedWeb2Data(proof, urlHash, dataHash))
        .to.be.revertedWithCustomError(contract, "UnauthorizedZkTlsSigner")
        .withArgs(rogue.address);
    });

    it("reverts ProofHashMismatch when arguments differ from the signed claims", async () => {
      const { contract, enclaveWallet } = await loadFixture(deployFixture);
      await contract.registerZkTlsSigner(enclaveWallet.address);

      const urlHash = ethers.keccak256(ethers.toUtf8Bytes("https://example.com/signed"));
      const dataHash = ethers.keccak256(ethers.toUtf8Bytes("true"));
      const proof = buildProof({
        signer: enclaveWallet,
        urlHash,
        dataHash,
        responseHash: ethers.ZeroHash,
        certFingerprint: ethers.ZeroHash,
        ts: BigInt(await time.latest()),
        nonce: ethers.hexlify(ethers.randomBytes(16)),
      });

      await mine(1);
      // Relay the same proof with a DIFFERENT dataHash argument — the
      // embedded data_hash in the proof no longer matches the argument.
      const otherDataHash = ethers.keccak256(ethers.toUtf8Bytes("false"));
      await expect(contract.relayVerifiedWeb2Data(proof, urlHash, otherDataHash))
        .to.be.revertedWithCustomError(contract, "ProofHashMismatch");
    });

    it("reverts MalformedProof for wrong-length bytes", async () => {
      const { contract, enclaveWallet } = await loadFixture(deployFixture);
      await contract.registerZkTlsSigner(enclaveWallet.address);
      await expect(
        contract.relayVerifiedWeb2Data("0x1234", ethers.ZeroHash, ethers.ZeroHash)
      ).to.be.revertedWithCustomError(contract, "MalformedProof");
    });

    it("reverts UnsupportedProofVersion for a bad version byte", async () => {
      const { contract, enclaveWallet } = await loadFixture(deployFixture);
      await contract.registerZkTlsSigner(enclaveWallet.address);
      const urlHash = ethers.keccak256(ethers.toUtf8Bytes("https://example.com/v"));
      const dataHash = ethers.keccak256(ethers.toUtf8Bytes("1"));
      // Version byte 9 (unsupported) — the signature is irrelevant; the
      // version gate fires first.
      const proof = buildProof({
        signer: enclaveWallet,
        urlHash,
        dataHash,
        responseHash: ethers.ZeroHash,
        certFingerprint: ethers.ZeroHash,
        ts: BigInt(await time.latest()),
        nonce: ethers.hexlify(ethers.randomBytes(16)),
        version: 9,
      });
      await mine(1);
      await expect(contract.relayVerifiedWeb2Data(proof, urlHash, dataHash))
        .to.be.revertedWithCustomError(contract, "UnsupportedProofVersion")
        .withArgs(9);
    });
  });

  describe("3. VerifiableRAG integration (Prompt 272)", () => {
    it("VerifiableRAG reads verified zkTLS data through the configured relayer", async () => {
      const [owner] = await ethers.getSigners();
      const RelayerFactory = await ethers.getContractFactory("ZkTlsRelayer");
      const relayer = (await RelayerFactory.deploy(owner.address)) as ZkTlsRelayer;
      await relayer.waitForDeployment();
      const RagFactory = await ethers.getContractFactory("VerifiableRAG");
      const rag = (await RagFactory.deploy(
        owner.address,
        REGISTRY,
        DIGEST_A
      )) as VerifiableRAG;
      await rag.waitForDeployment();

      const enclaveWallet = ethers.Wallet.createRandom();
      await relayer.registerZkTlsSigner(enclaveWallet.address);
      await rag.updateZkTlsRelayer(await relayer.getAddress());

      const urlHash = ethers.keccak256(ethers.toUtf8Bytes("https://jsonplaceholder.typicode.com/todos/1"));
      const dataHash = ethers.keccak256(ethers.toUtf8Bytes("true"));
      const proof = buildProof({
        signer: enclaveWallet,
        urlHash,
        dataHash,
        responseHash: ethers.keccak256(ethers.toUtf8Bytes('{"completed":true}')),
        certFingerprint: ethers.ZeroHash,
        ts: BigInt(await time.latest()),
        nonce: ethers.hexlify(ethers.randomBytes(16)),
      });
      await mine(1);
      await relayer.relayVerifiedWeb2Data(proof, urlHash, dataHash);

      // VerifiableRAG reads the verified data THROUGH the relayer.
      const [ragDataHash, ragVerifiedAt] = await rag.verifiedZkTlsData(urlHash);
      expect(ragDataHash).to.equal(dataHash);
      expect(ragVerifiedAt).to.be.a("bigint");
      expect(ragVerifiedAt).to.not.equal(0n);
    });

    it("VerifiableRAG reverts ZeroZkTlsRelayer until a relayer is configured", async () => {
      const [owner] = await ethers.getSigners();
      const RagFactory = await ethers.getContractFactory("VerifiableRAG");
      const rag = (await RagFactory.deploy(
        owner.address,
        REGISTRY,
        DIGEST_A
      )) as VerifiableRAG;
      await rag.waitForDeployment();
      await expect(rag.verifiedZkTlsData(ethers.ZeroHash)).to.be.revertedWithCustomError(
        rag,
        "ZeroZkTlsRelayer"
      );
    });
  });
});
