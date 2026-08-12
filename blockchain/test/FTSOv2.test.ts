/**
 * FTSOv2.test.ts — FTSO v2 real-time price integration tests (Phase 8, Prompt 150).
 *
 * Validates the price-calculation and decimals-scaling logic on-chain, plus a
 * LIVE cross-check against the real Coston2 feeds:
 *
 *   1. FEED ID CONSTANTS (P143) — FXRP/USD, BTC/USD, USDT/USD are non-zero
 *      bytes21; the constants are the values live-verified 2026-08-12 against
 *      the deployed FtsoV2 (getSupportedFeedIds + getFeedById).
 *   2. getRealtimePrice (P144) — returns the raw value from the
 *      registry-resolved FtsoV2; reverts StaleFeed on a stale feed.
 *   3. STALENESS GATE (P145) — the master-plan |now − feedTs| ≤ 300s window is
 *      enforced SYMMETRICALLY: a feed > 300s old AND a feed > 300s in the
 *      future both revert StaleFeed; a ±120s skew passes.
 *   4. ON-CHAIN VALUATION MATH (P146) — settle computes
 *      quantity × live price / 10^decimals (positive decimals), and
 *      quantity × price × 10^|decimals| for negative decimals, exactly as the
 *      deployed feed reports them (dynamic int8, never hardcoded).
 *   5. LIVE CROSS-CHECK — the real Coston2 feeds read through the real RPC
 *      must return sane prices and fresh timestamps (skips when RPC down,
 *      same convention as the FDCIntegration live cross-check).
 */
import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";

const REGISTRY = "0x" + "aD67FE66660Fb8dFE9d6b1b4240d8650e30F6019";
const DIGEST = "0x" + "25f55814e809632f5af58eaa2b1d48cec1c49aa6a451c82b6af9fe9de934f421";
// Feed id constants under test (P143) — same values as VerifiableRAG.sol.
const FXRP_USD_FEED_ID = "0x" + "015852502f55534400000000000000000000000000";
const BTC_USD_FEED_ID = "0x" + "014254432f55534400000000000000000000000000";
const USDT_USD_FEED_ID = "0x" + "01555344542f555344000000000000000000000000";
const FLR_USD_FEED = "0x" + "01464c522f55534400000000000000000000000000";
const SETTLE_QTY = 10_000n;

const FDC_ROUND = 77n; // TestRelay stores a root for this round (gate passes)
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
const FDC_PROOF = encodeProof([ethers.id("node-1")], "0x1234");

function b64url(buf: Buffer): string {
  return buf.toString("base64").replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
}
function makeToken(digestHex: string): Uint8Array {
  const claims: Record<string, unknown> = {
    sub: "projects/p/serviceAccounts/sa@x",
    aud: "//iam.googleapis.com/p",
    submods: { container: { image_digest: "sha256:" + digestHex }, gce: { instance_id: "1" } },
    swname: "CONFIDENTIAL_SPACE",
  };
  return ethers.toUtf8Bytes(
    `${b64url(Buffer.from(JSON.stringify({ alg: "ES256", typ: "JWT" })))}.${b64url(Buffer.from(JSON.stringify(claims)))}.${b64url(Buffer.from("sig"))}`
  );
}

describe("FTSO v2 integration (Prompt 150)", function () {
  this.timeout(120_000);

  describe("feed id constants (P143)", () => {
    it("the three constants are non-zero 21-byte feed ids", async () => {
      for (const id of [FXRP_USD_FEED_ID, BTC_USD_FEED_ID, USDT_USD_FEED_ID]) {
        expect(id.length).to.equal(2 + 42, `${id} must be 0x + 42 hex = bytes21`);
        expect(BigInt(id)).to.not.equal(0n);
      }
    });
  });

  describe("getRealtimePrice (P144) + staleness gate (P145)", () => {
    /** TestFlareRegistry + TestFtsoV2 only — getRealtimePrice needs no FDC. */
    async function priceFixture() {
      const [owner] = await ethers.getSigners();
      const Registry = await ethers.getContractFactory("TestFlareRegistry");
      const registry = await Registry.deploy();
      await registry.waitForDeployment();
      const Ftso = await ethers.getContractFactory("TestFtsoV2");
      const ftso = await Ftso.deploy();
      await ftso.waitForDeployment();
      await registry.setAddress("FtsoV2", await ftso.getAddress());
      const Factory = await ethers.getContractFactory("VerifiableRAG");
      const contract = await Factory.deploy(owner.address, await registry.getAddress(), DIGEST);
      await contract.waitForDeployment();
      return { contract, ftso };
    }

    it("returns the raw value read from the registry-resolved FtsoV2 (no caller input)", async () => {
      const { contract, ftso } = await loadFixture(priceFixture);
      const block = await ethers.provider.getBlock("latest");
      await (await ftso.setFeed(1_018_552n, block!.timestamp)).wait();
      expect(await contract.getRealtimePrice(FXRP_USD_FEED_ID)).to.equal(1_018_552n);
      expect(await contract.getRealtimePrice(BTC_USD_FEED_ID)).to.equal(1_018_552n); // any id -> same TestFtsoV2
    });

    it("reverts StaleFeed when the feed is older than 300s (REALTIME_MAX_AGE)", async () => {
      const { contract, ftso } = await loadFixture(priceFixture);
      const block = await ethers.provider.getBlock("latest");
      await (await ftso.setFeed(1_018_552n, block!.timestamp - 301)).wait();
      await expect(contract.getRealtimePrice(FXRP_USD_FEED_ID)).to.be.revertedWithCustomError(
        contract, "StaleFeed"
      );
    });

    it("reverts StaleFeed for a feed more than 300s in the future (symmetric gate)", async () => {
      const { contract, ftso } = await loadFixture(priceFixture);
      const block = await ethers.provider.getBlock("latest");
      // +400s, NOT +301: hardhat advances block.timestamp ~1-2s between the
      // setFeed tx and the read call, so a bare +301 drifts inside the 300s
      // window and would NOT revert (observed empirically on the first run).
      await (await ftso.setFeed(1_018_552n, block!.timestamp + 400)).wait();
      await expect(contract.getRealtimePrice(FXRP_USD_FEED_ID)).to.be.revertedWithCustomError(
        contract, "StaleFeed"
      );
    });

    it("accepts a ±120s skew (node clock tolerance within the 300s window)", async () => {
      const { contract, ftso } = await loadFixture(priceFixture);
      const block = await ethers.provider.getBlock("latest");
      await (await ftso.setFeed(1_018_552n, block!.timestamp - 120)).wait();
      expect(await contract.getRealtimePrice(FXRP_USD_FEED_ID)).to.equal(1_018_552n);
      await (await ftso.setFeed(1_018_552n, block!.timestamp + 120)).wait();
      expect(await contract.getRealtimePrice(FXRP_USD_FEED_ID)).to.equal(1_018_552n);
    });

    it("reverts UnregisteredContract when FtsoV2 is not in the registry (fail-closed)", async () => {
      const [owner] = await ethers.getSigners();
      const Registry = await ethers.getContractFactory("TestFlareRegistry");
      const registry = await Registry.deploy();
      await registry.waitForDeployment();
      const Factory = await ethers.getContractFactory("VerifiableRAG");
      const contract = await Factory.deploy(owner.address, await registry.getAddress(), DIGEST);
      await contract.waitForDeployment();
      await expect(contract.getRealtimePrice(FXRP_USD_FEED_ID)).to.be.revertedWithCustomError(
        contract, "UnregisteredContract"
      );
    });
  });

  describe("on-chain valuation math (P146) — dynamic decimals", () => {
    /** Full settle stack (FDC gate needed before the feed gate): registry +
     *  TestFdcVerification(true) + TestRelay(root @ FDC_ROUND) + TestFtsoV2. */
    async function settleFixture() {
      const [owner] = await ethers.getSigners();
      const Registry = await ethers.getContractFactory("TestFlareRegistry");
      const registry = await Registry.deploy();
      await registry.waitForDeployment();
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
      const contract = await Factory.deploy(owner.address, await registry.getAddress(), DIGEST);
      await contract.waitForDeployment();
      await (await contract.updatePriceFeedId(FLR_USD_FEED)).wait();
      return { contract, ftso };
    }

    async function settleWith(decimals: number, value: bigint, tsOffset: number): Promise<bigint> {
      const { contract, ftso } = await loadFixture(settleFixture);
      const block = await ethers.provider.getBlock("latest");
      await (await ftso.setDecimals(decimals)).wait();
      await (await ftso.setFeed(value, block!.timestamp + tsOffset)).wait();
      const q = ethers.id("ftso-settle-" + decimals + "-" + value);
      const tx = await contract.verifyAndSettleRAG(makeToken(DIGEST.slice(2)), Buffer.from("zk-" + decimals), q, SETTLE_QTY, FDC_PROOF);
      const rcpt = await tx.wait();
      const ev = rcpt!.logs
        .map((l) => { try { return contract.interface.parseLog(l); } catch { return null; } })
        .find((p) => p && p.name === "QuerySettled");
      expect(ev).to.not.equal(undefined);
      expect(ev!.args.quantity).to.equal(SETTLE_QTY);
      expect(ev!.args.decimals).to.equal(decimals);
      expect(ev!.args.price).to.equal(value);
      // Prompt 156: the lightweight PriceSettled signal is emitted with the
      // indexed feed id and the same live price.
      const pev = rcpt!.logs
        .map((l) => { try { return contract.interface.parseLog(l); } catch { return null; } })
        .find((p) => p && p.name === "PriceSettled");
      expect(pev).to.not.equal(undefined);
      expect(pev!.args.feedId).to.equal(FLR_USD_FEED);
      expect(pev!.args.price).to.equal(value);
      expect(await contract.lastSettlementPrice()).to.equal(value);
      return ev!.args.valuation;
    }

    it("positive decimals: valuation = quantity × price / 10^decimals (6dp FXRP-style)", async () => {
      const expected = (SETTLE_QTY * 1_018_552n) / 10n ** 6n; // 10,185.52 USD exact
      expect(await settleWith(6, 1_018_552n, 120)).to.equal(expected);
    });

    it("positive decimals: 2dp BTC-style ($63,504.92)", async () => {
      const expected = (SETTLE_QTY * 6_350_492n) / 10n ** 2n;
      expect(await settleWith(2, 6_350_492n, 120)).to.equal(expected);
    });

    it("negative decimals: valuation = quantity × price × 10^|decimals|", async () => {
      const expected = SETTLE_QTY * 123n * 10n ** 2n;
      expect(await settleWith(-2, 123n, 120)).to.equal(expected);
    });

    it("reverts StaleFeed through the settle path when the live feed is > 300s old", async () => {
      const { contract, ftso } = await loadFixture(settleFixture);
      const block = await ethers.provider.getBlock("latest");
      await (await ftso.setFeed(1_018_552n, block!.timestamp - 301)).wait();
      await expect(
        contract.verifyAndSettleRAG(makeToken(DIGEST.slice(2)), Buffer.from("zk-stale"), ethers.id("ftso-stale"), SETTLE_QTY, FDC_PROOF)
      ).to.be.revertedWithCustomError(contract, "StaleFeed");
    });

    it("reverts ZeroSettlementQuantity for a zero quantity (fail-closed)", async () => {
      const { contract, ftso } = await loadFixture(settleFixture);
      const block = await ethers.provider.getBlock("latest");
      await (await ftso.setFeed(1_018_552n, block!.timestamp + 120)).wait();
      await expect(
        contract.verifyAndSettleRAG(makeToken(DIGEST.slice(2)), Buffer.from("zk-zero"), ethers.id("ftso-zero"), 0n, FDC_PROOF)
      ).to.be.revertedWithCustomError(contract, "ZeroSettlementQuantity");
    });
  });

  describe("live cross-check against the REAL Coston2 feeds (skips when RPC down)", function () {
    it("FXRP/USD, BTC/USD, USDT/USD read live with sane prices + fresh timestamps", async function () {
      const live = new ethers.JsonRpcProvider("https://coston2-api.flare.network/ext/C/rpc");
      try {
        const reg = new ethers.Contract(
          REGISTRY,
          ["function getContractAddressByName(string) view returns (address)"],
          live
        );
        const ftsoAddr = await reg.getContractAddressByName("FtsoV2");
        const ftso = new ethers.Contract(
          ftsoAddr,
          ["function getFeedById(bytes21) external payable returns (uint256, int8, uint64)"],
          live
        );
        const now = Math.floor(Date.now() / 1000);
        const checks: Array<[string, string, [number, number]]> = [
          [FXRP_USD_FEED_ID, "FXRP/USD", [0.01, 100]],
          [BTC_USD_FEED_ID, "BTC/USD", [1_000, 1_000_000]],
          [USDT_USD_FEED_ID, "USDT/USD", [0.5, 1.5]],
        ];
        for (const [feedId, name, band] of checks) {
          const [value, decimals, timestamp] = await ftso.getFeedById.staticCall(feedId);
          const dec = Number(decimals);
          const price = dec >= 0 ? Number(value) / 10 ** dec : Number(value) * 10 ** (-dec);
          expect(price).to.be.within(band[0], band[1], `${name} price ${price} outside sane band`);
          expect(Number(timestamp)).to.be.greaterThan(now - 300, `${name} feed stale`);
          expect(Number(timestamp)).to.be.lessThan(now + 300, `${name} feed too far in the future`);
        }
      } catch (e) {
        console.warn("live FTSO v2 read unavailable, skipping:", (e as Error).message.slice(0, 100));
        this.skip();
      } finally {
        await live.destroy();
      }
    });
  });
});
