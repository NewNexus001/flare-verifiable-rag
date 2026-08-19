/**
 * CopilotEngine.test.ts — copilot engine code-generation tests (P350).
 *
 * The FDC byte-identity vectors below are GROUND TRUTH produced by the
 * blockchain workspace's own ethers AbiCoder (the exact encoder used in
 * scripts/request_fdc_attestation.ts) — run once and frozen here. If the
 * frontend encoder ever drifts from the repo's on-chain encoding, these
 * tests fail.
 */
import {
  answerQuery,
  encodeFdcWeb2JsonRequest,
  generateFdcSelector,
  generateSolidityBoilerplate,
  toFtsoFeedId,
  validateJq,
  validateUrl,
} from "@/lib/copilot_engine";

// Ground-truth vectors from the blockchain workspace (ethers AbiCoder, MIC zeroed).
const OPENWEATHER_VECTOR =
  "576562324a736f6e0000000000000000000000000000000000000000000000005075626c696357656232000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000e0000000000000000000000000000000000000000000000000000000000000016000000000000000000000000000000000000000000000000000000000000001a000000000000000000000000000000000000000000000000000000000000001e00000000000000000000000000000000000000000000000000000000000000220000000000000000000000000000000000000000000000000000000000000026000000000000000000000000000000000000000000000000000000000000002a0000000000000000000000000000000000000000000000000000000000000004b68747470733a2f2f6170692e6f70656e776561746865726d61702e6f72672f646174612f322e352f776561746865723f713d4c6f6e646f6e2661707069643d594f55525f4150495f4b45590000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003474554000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000027b7d00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000027b7d00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000027b7d000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a2e6d61696e2e74656d7000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000775696e7432353600000000000000000000000000000000000000000000000000";

const TODOS_VECTOR =
  "576562324a736f6e0000000000000000000000000000000000000000000000005075626c696357656232000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000e00000000000000000000000000000000000000000000000000000000000000140000000000000000000000000000000000000000000000000000000000000018000000000000000000000000000000000000000000000000000000000000001c0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000002400000000000000000000000000000000000000000000000000000000000000280000000000000000000000000000000000000000000000000000000000000002c68747470733a2f2f6a736f6e706c616365686f6c6465722e74797069636f64652e636f6d2f746f646f732f3100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003474554000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000027b7d00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000027b7d00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000027b7d000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a2e636f6d706c65746564000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004626f6f6c00000000000000000000000000000000000000000000000000000000";

describe("encodeFdcWeb2JsonRequest — byte-identity vs repo ethers encoder", () => {
  it("matches the OpenWeather ground-truth vector", () => {
    const body = {
      url: "https://api.openweathermap.org/data/2.5/weather?q=London&appid=YOUR_API_KEY",
      httpMethod: "GET",
      headers: "{}",
      queryParams: "{}",
      body: "{}",
      postProcessJq: ".main.temp",
      abiSignature: "uint256",
    };
    expect(encodeFdcWeb2JsonRequest(body).slice(2)).toBe(OPENWEATHER_VECTOR);
  });

  it("matches the jsonplaceholder ground-truth vector", () => {
    const body = {
      url: "https://jsonplaceholder.typicode.com/todos/1",
      httpMethod: "GET",
      headers: "{}",
      queryParams: "{}",
      body: "{}",
      postProcessJq: ".completed",
      abiSignature: "bool",
    };
    expect(encodeFdcWeb2JsonRequest(body).slice(2)).toBe(TODOS_VECTOR);
  });
});

describe("generateFdcSelector", () => {
  it("builds a valid config for the OpenWeather API (P355 scenario)", () => {
    const out = generateFdcSelector(
      "https://api.openweathermap.org/data/2.5/weather?q=London&appid=YOUR_API_KEY",
      ".main.temp",
      "uint256"
    );
    expect(out).not.toHaveProperty("ok", false);
    if (!("ok" in out) || out.ok) {
      const config = out as { byteLength: number; attestationType: string; sourceId: string };
      expect(config.byteLength).toBe(OPENWEATHER_VECTOR.length / 2);
      expect(config.attestationType).toBe("Web2Json");
      expect(config.sourceId).toBe("PublicWeb2");
    }
  });

  it("rejects non-HTTPS URLs", () => {
    expect(validateUrl("http://insecure.example.com")).toEqual({
      ok: false,
      error: "The FDC only attests HTTPS endpoints.",
    });
    const out = generateFdcSelector("http://insecure.example.com/x", ".a");
    expect(out).toHaveProperty("ok", false);
  });

  it("rejects malformed jq paths", () => {
    expect(validateJq("; rm -rf /")).toEqual({ ok: false, error: expect.any(String) });
    const out = generateFdcSelector("https://api.example.com/x", "$.secret");
    expect(out).toHaveProperty("ok", false);
  });
});

describe("generateSolidityBoilerplate (P345)", () => {
  it("emits IFdcVerification integration for Web2Json", () => {
    const out = generateSolidityBoilerplate("Web2Json");
    expect(out).toHaveProperty("ok", true);
    if ("code" in out) {
      expect(out.code).toContain("verifyWeb2Json");
      expect(out.code).toContain("IWeb2Json.Proof");
    }
  });

  it("emits IFtsoV2 integration for FtsoV2", () => {
    const out = generateSolidityBoilerplate("FtsoV2");
    expect(out).toHaveProperty("ok", true);
    if ("code" in out) {
      expect(out.code).toContain("getFeedById");
      expect(out.code).toContain("bytes21");
    }
  });
});

describe("toFtsoFeedId", () => {
  it("derives the canonical FXRP/USD feed id", () => {
    expect(toFtsoFeedId("XRP/USD")).toBe("0x015852502f55534400000000000000000000000000");
  });
});

describe("answerQuery rules", () => {
  it("routes Solidity boilerplate requests", () => {
    const r = answerQuery("Solidity boilerplate for Web2Json");
    expect(r.kind).toBe("solidity");
    expect(r.code).toContain("verifyWeb2Json");
  });

  it("routes FDC selector requests and extracts url/jq/abi", () => {
    const r = answerQuery(
      "FDC selector for https://jsonplaceholder.typicode.com/todos/1 with .completed as bool"
    );
    expect(r.kind).toBe("fdc-selector");
    if (r.config) {
      expect(r.config.postProcessJq).toBe(".completed");
      expect(r.config.abiSignature).toBe("bool");
    }
  });

  it("lists FTSO feeds", () => {
    const r = answerQuery("list FTSO v2 feeds");
    expect(r.kind).toBe("ftso");
  });

  it("helps on empty input", () => {
    expect(answerQuery("").kind).toBe("help");
  });

  it("answers architecture questions about TEE", () => {
    const r = answerQuery("How does the TEE enclave work?");
    expect(r.kind).toBe("architecture");
    expect(r.text).toContain("Confidential");
    expect(r.text.toLowerCase()).toContain("attestation");
  });

  it("answers questions about the FDC", () => {
    const r = answerQuery("What is the Flare Data Connector?");
    expect(r.kind).toBe("architecture");
    expect(r.text).toContain("Merkle");
  });

  it("answers questions about FTSO price feeds", () => {
    const r = answerQuery("How does FTSO price feeds work on-chain?");
    expect(r.kind).toBe("architecture");
    expect(r.text).toContain("Fast Updates");
  });

  it("answers deployment questions", () => {
    const r = answerQuery("How do I deploy this?");
    expect(r.kind).toBe("architecture");
    expect(r.text).toContain("pnpm install");
  });

  it("answers security questions about MPC wallet", () => {
    const r = answerQuery("How does the MPC wallet sign transactions?");
    expect(r.kind).toBe("architecture");
    expect(r.text).toContain("threshold");
    expect(r.text).toContain("secp256k1");
  });

  it("answers questions about testing", () => {
    const r = answerQuery("What tests exist?");
    expect(r.kind).toBe("architecture");
    expect(r.text).toContain("609");
  });

  it("answers questions about zkTLS", () => {
    const r = answerQuery("What is the zkTLS proxy?");
    expect(r.kind).toBe("architecture");
    expect(r.text.toLowerCase()).toContain("sub-second");
  });

  it("answers questions about Bazel", () => {
    const r = answerQuery("How does the Bazel build work?");
    expect(r.kind).toBe("architecture");
    expect(r.text).toContain("hermetic");
  });

  it("answers questions about i18n", () => {
    const r = answerQuery("How does localization work?");
    expect(r.kind).toBe("architecture");
    expect(r.text).toContain("Arabic");
  });

  it("answers questions about the copilot itself", () => {
    const r = answerQuery("What can the copilot do?");
    expect(r.kind).toBe("architecture");
    expect(r.text).toContain("FDC");
  });

  it("returns fallback for unrecognized queries", () => {
    const r = answerQuery("xyzzy foobar");
    expect(r.kind).toBe("help");
    expect(r.text).toContain("FDC");
  });
});
