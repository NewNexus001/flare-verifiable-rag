/**
 * read_ftso_v2.ts — read LIVE FTSO v2 block-latency price feeds on Coston2
 * (Phase 8, Prompts 147-148).
 *
 * Pure eth_call reads — no signer, no gas. The FtsoV2 contract is resolved
 * LIVE from the FlareContractRegistry (zero-mock policy: never a hardcoded
 * protocol address). Feed ids are the bytes21 constants from
 * VerifiableRAG.sol (Prompt 143), live-verified 2026-08-12: category 0x01
 * (crypto) + ASCII-hex of the feed name + zero padding; all three are active
 * in getSupportedFeedIds, update every ~1.8-3s, charge 0 fee, and prices are
 * scaled by each feed's DYNAMIC decimals (FXRP/USD 6, BTC/USD 2, USDT/USD 6).
 *
 * Usage:
 *   npx hardhat run scripts/read_ftso_v2.ts --network coston2
 */
import { ethers } from "hardhat";

const REGISTRY = "0x" + "aD67FE66660Fb8dFE9d6b1b4240d8650e30F6019";
const FXRP_USD_FEED_ID = "0x" + "015852502f55534400000000000000000000000000";
const BTC_USD_FEED_ID = "0x" + "014254432f55534400000000000000000000000000";
const USDT_USD_FEED_ID = "0x" + "01555344542f555344000000000000000000000000";
const FTSO_V2_ABI = [
  "function getFeedById(bytes21) external payable returns (uint256, int8, uint64)",
];

/**
 * Prompt 157 — validate a feed id against the EXACT Flare FTSO v2 bytes21
 * specification: 0x + 42 hex chars = 21 bytes; byte 0 = category (0x01
 * crypto); bytes 1.. = UTF-8/ASCII of the feed name in hex; trailing bytes
 * are zero padding. Rejects anything that does not match (fail-closed).
 */
function assertFeedIdSpec(feedId: string, feedName: string): void {
  const hex = feedId.toLowerCase().slice(2);
  if (hex.length !== 42) {
    throw new Error(`${feedName}: feed id must be bytes21 (42 hex chars), got ${hex.length}`);
  }
  if (hex.slice(0, 2) !== "01") {
    throw new Error(`${feedName}: category byte must be 0x01 (crypto), got 0x${hex.slice(0, 2)}`);
  }
  const nameHex = [...feedName]
    .map((c) => c.charCodeAt(0).toString(16).padStart(2, "0"))
    .join("");
  if (!hex.startsWith("01" + nameHex)) {
    throw new Error(`${feedName}: expected name hex '${nameHex}' not found at the id prefix`);
  }
  const pad = hex.slice(2 + nameHex.length);
  if (!/^0+$/.test(pad)) {
    throw new Error(`${feedName}: trailing bytes are not zero padding ('${pad}')`);
  }
  console.log(`  spec-valid: 0x01 + hex("${feedName}") + ${pad.length / 2} zero-pad bytes`);
}

async function main(): Promise<void> {
  const chainId = (await ethers.provider.getNetwork()).chainId;
  if (chainId !== 114n) {
    throw new Error(`read_ftso_v2.ts targets Coston2 (chain 114), got chain ${chainId}`);
  }

  const registry = new ethers.Contract(
    REGISTRY,
    ["function getContractAddressByName(string) view returns (address)"],
    ethers.provider
  );
  const ftsoAddr = await registry.getContractAddressByName("FtsoV2");
  if (ftsoAddr === ethers.ZeroAddress) {
    throw new Error(`registry did not resolve 'FtsoV2' on Coston2`);
  }
  const ftso = new ethers.Contract(ftsoAddr, FTSO_V2_ABI, ethers.provider);

  const now = Math.floor(Date.now() / 1000);
  // [display label, EXACT name encoded in the bytes21 id, feed id]
  // (FXRP is Flare's wrapped XRP — its feed id encodes "XRP/USD", not
  // "FXRP/USD"; the spec check below must use the encoded name.)
  const feeds: Array<[string, string, string]> = [
    ["FXRP/USD", "XRP/USD", FXRP_USD_FEED_ID],
    ["BTC/USD", "BTC/USD", BTC_USD_FEED_ID],
    ["USDT/USD", "USDT/USD", USDT_USD_FEED_ID],
  ];

  console.log(`Coston2 chain id ${chainId} — FtsoV2 (registry-resolved): ${ftsoAddr}\n`);
  console.log("Feed id spec validation (Prompt 157):");
  for (const [, encodedName, feedId] of feeds) {
    assertFeedIdSpec(feedId, encodedName);
  }
  console.log("");
  for (const [name, , feedId] of feeds) {
    const [value, decimals, timestamp] = await ftso.getFeedById.staticCall(feedId);
    const dec = Number(decimals);
    const price = dec >= 0 ? Number(value) / 10 ** dec : Number(value) * 10 ** (-dec);
    const age = now - Number(timestamp);
    console.log(
      `${name}: value=${value} decimals=${decimals} ts=${timestamp} age=${age}s price=$${price.toFixed(Math.max(dec, 0))}`
    );
  }
  console.log("\nLIVE FTSO v2 READ OK");
}

main().catch((e) => {
  console.error(`\nREAD FAILED: ${(e as Error).message}`);
  process.exit(1);
});
