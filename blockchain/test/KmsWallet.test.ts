/**
 * KmsWallet.test.ts — Phase 13 KMS MPC wallet on-chain tests (Prompt 251).
 *
 * Covers the IKmsVerifiedWallet surface implemented by VerifiableRAG.sol:
 *   1. registerKmsSigner / deregisterKmsSigner — owner-only registry with
 *      ZeroKmsSigner / KmsSignerAlreadyRegistered / KmsSignerNotRegistered
 *      fail-closed guards.
 *   2. isKmsSigner — membership check.
 *   3. requireKmsSignature — the ecrecover gate: a REAL secp256k1 signature
 *      (ethers Wallet.signMessage — the same math the enclave's k256 signer
 *      produces: ECDSA over secp256k1 with a keccak256 digest) recovers the
 *      signer; unregistered signers revert UnauthorizedSigner; garbage
 *      signatures revert ZeroSigner.
 *   4. executeKmsSignedAction — the enclave-initiated action path: registers
 *      an MPC wallet address, signs an action hash with its private key,
 *      relays it, and asserts the KmsActionExecuted event with the recovered
 *      signer. Unregistered signer -> revert.
 *
 * The signatures here are REAL: ethers uses the secp256k1 curve via its own
 * signing path (the same v,r,s layout the enclave emits after combining its
 * 2-of-2 KMS shares). No fake v/r/s literals — everything is produced by a
 * real wallet key.
 */
import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import type { VerifiableRAG } from "../typechain-types/contracts/VerifiableRAG";

// Canonical FlareContractRegistry bootstrap (same on every Flare network).
const REGISTRY = "0x" + "aD67FE66660Fb8dFE9d6b1b4240d8650e30F6019";
// Real enclave image digest (sha256: prefix stripped), as in VerifiableRAG.test.ts.
const DIGEST_A = "0x" + "25f55814e809632f5af58eaa2b1d48cec1c49aa6a451c82b6af9fe9de934f421";

async function deployFixture() {
  const [owner, stranger] = await ethers.getSigners();
  const Factory = await ethers.getContractFactory("VerifiableRAG");
  const contract = await Factory.deploy(owner.address, REGISTRY, DIGEST_A);
  await contract.waitForDeployment();
  // An independent enclave MPC wallet: a real random key (the test stands in
  // for the composed 2-of-2 key — in production the address is derived from
  // the composed public key off-chain and registered by the owner).
  const mpcWallet = ethers.Wallet.createRandom();
  return { contract, owner, stranger, mpcWallet };
}

/** Sign a RAW 32-byte digest (no EIP-191 prefix) — exactly what the enclave's
 *  k256 signer emits over keccak256(0x02||RLP). ethers' `signMessage` would
 *  apply the "\x19Ethereum Signed Message" prefix, which the contract's
 *  `ecrecover(hash,...)` does NOT expect — this helper returns the raw
 *  signature (v,r,s) matching the enclave.
 */
function signRawDigest(wallet: ethers.Wallet, digest: string) {
  // ethers v6: signMessage applies EIP-191; to sign a raw digest we use the
  // low-level signing key path (private key -> secp256k1 over the digest).
  const sig = wallet.signingKey.sign(ethers.getBytes(digest));
  return ethers.Signature.from(sig.serialized);
}

describe("KmsWallet (Phase 13)", function () {
  this.timeout(300_000);

  describe("1. signer registry", () => {
    it("registers a signer (owner) and reports membership", async () => {
      const { contract, owner } = await loadFixture(deployFixture);
      await expect(contract.registerKmsSigner(owner.address))
        .to.emit(contract, "KmsSignerRegistered")
        .withArgs(owner.address);
      expect(await contract.isKmsSigner(owner.address)).to.equal(true);
    });

    it("reverts ZeroKmsSigner when registering address(0)", async () => {
      const { contract } = await loadFixture(deployFixture);
      await expect(contract.registerKmsSigner(ethers.ZeroAddress)).to.be.revertedWithCustomError(
        contract,
        "ZeroKmsSigner"
      );
    });

    it("reverts KmsSignerAlreadyRegistered on a no-op re-register", async () => {
      const { contract, owner } = await loadFixture(deployFixture);
      await contract.registerKmsSigner(owner.address);
      await expect(contract.registerKmsSigner(owner.address)).to.be.revertedWithCustomError(
        contract,
        "KmsSignerAlreadyRegistered"
      );
    });

    it("deregisters a signer and reverts KmsSignerNotRegistered on no-op", async () => {
      const { contract, owner } = await loadFixture(deployFixture);
      await contract.registerKmsSigner(owner.address);
      await expect(contract.deregisterKmsSigner(owner.address))
        .to.emit(contract, "KmsSignerDeregistered")
        .withArgs(owner.address);
      expect(await contract.isKmsSigner(owner.address)).to.equal(false);
      await expect(contract.deregisterKmsSigner(owner.address)).to.be.revertedWithCustomError(
        contract,
        "KmsSignerNotRegistered"
      );
    });

    it("non-owner cannot register or deregister signers", async () => {
      const { contract, stranger, owner } = await loadFixture(deployFixture);
      await expect(contract.connect(stranger).registerKmsSigner(stranger.address)).to.be.revertedWithCustomError(
        contract,
        "OwnableUnauthorizedAccount"
      );
      await contract.registerKmsSigner(owner.address);
      await expect(contract.connect(stranger).deregisterKmsSigner(owner.address)).to.be.revertedWithCustomError(
        contract,
        "OwnableUnauthorizedAccount"
      );
    });
  });

  describe("2. requireKmsSignature (ecrecover gate)", () => {
    it("recovers the signer of a real signature", async () => {
      const { contract, mpcWallet } = await loadFixture(deployFixture);
      await contract.registerKmsSigner(mpcWallet.address);

      const message = ethers.id("enclave-action:settle:0xabc");
      // Sign the RAW digest (no EIP-191 prefix) — exactly what the enclave's
      // k256 signer does over keccak256(0x02||RLP), so the contract's
      // ecrecover(message,...) matches the enclave's signature.
      const { v, r, s } = signRawDigest(mpcWallet, message);

      const recovered = await contract.requireKmsSignature(message, v, r, s);
      expect(recovered).to.equal(mpcWallet.address);
    });

    it("reverts UnauthorizedSigner for a signature by an unregistered key", async () => {
      const { contract, mpcWallet } = await loadFixture(deployFixture);
      // Register a DIFFERENT wallet; sign with an unregistered one.
      await contract.registerKmsSigner(mpcWallet.address);
      const rogue = ethers.Wallet.createRandom();

      const message = ethers.id("enclave-action:unauthorized");
      const { v, r, s } = signRawDigest(rogue, message);

      await expect(contract.requireKmsSignature(message, v, r, s))
        .to.be.revertedWithCustomError(contract, "UnauthorizedSigner")
        .withArgs(rogue.address);
    });

    it("reverts ZeroSigner for garbage signature bytes", async () => {
      const { contract } = await loadFixture(deployFixture);
      const message = ethers.id("whatever");
      const garbage = ethers.Signature.from(
        "0x" + "11".repeat(64) + "00" // r=0x11.., s=0x11.., v=0
      );
      await expect(
        contract.requireKmsSignature(message, garbage.v, garbage.r, garbage.s)
      ).to.be.revertedWithCustomError(contract, "ZeroSigner");
    });
  });

  describe("3. executeKmsSignedAction", () => {
    it("executes an action signed by a registered MPC wallet", async () => {
      const { contract, mpcWallet } = await loadFixture(deployFixture);
      // The enclave MPC wallet address is registered by the owner; in the
      // real flow this address is derived from the composed public key.
      await contract.registerKmsSigner(mpcWallet.address);

      const actionHash = ethers.id("settle:query-1:10000");
      const { v, r, s } = signRawDigest(mpcWallet, actionHash);

      const tx = await contract.executeKmsSignedAction(actionHash, v, r, s);
      const receipt = await tx.wait();
      const event = receipt!.logs
        .map((l) => {
          try {
            return contract.interface.parseLog(l);
          } catch {
            return null;
          }
        })
        .find((p) => p?.name === "KmsActionExecuted");
      expect(event).to.not.equal(undefined);
      expect(event!.args.signer).to.equal(mpcWallet.address);
      expect(event!.args.actionId).to.equal(actionHash);
      expect(event!.args.timestamp).to.be.a("bigint");
    });

    it("reverts UnauthorizedSigner when the signer is not registered", async () => {
      const { contract, mpcWallet } = await loadFixture(deployFixture);
      await contract.registerKmsSigner(mpcWallet.address);
      const rogue = ethers.Wallet.createRandom();
      const actionHash = ethers.id("settle:query-1:10000");
      const { v, r, s } = signRawDigest(rogue, actionHash);

      await expect(contract.executeKmsSignedAction(actionHash, v, r, s))
        .to.be.revertedWithCustomError(contract, "UnauthorizedSigner")
        .withArgs(rogue.address);
    });

    it("reverts ZeroQueryHash for a zero action hash", async () => {
      const { contract, mpcWallet } = await loadFixture(deployFixture);
      await contract.registerKmsSigner(mpcWallet.address);
      const { v, r, s } = signRawDigest(mpcWallet, ethers.ZeroHash);

      await expect(contract.executeKmsSignedAction(ethers.ZeroHash, v, r, s))
        .to.be.revertedWithCustomError(contract, "ZeroQueryHash");
    });
  });
});
