/**
 * copilot.worker.ts — AI Copilot engine worker (Phase 18, P343/P353).
 *
 * The entire pattern-matching + artifact generation engine runs HERE, off the
 * main thread, with zero network access: no AI API, no third-party servers,
 * nothing leaves the client. The main thread posts {query} and receives the
 * deterministic CopilotResponse (and the generated FDC hex when applicable).
 *
 * Bundled by webpack via `new Worker(new URL("../workers/copilot.worker.ts",
 * import.meta.url))` — Next.js 14 supports this natively.
 */
import { answerQuery, generateFdcSelector, generateSolidityBoilerplate } from "@/lib/copilot_engine";

export interface CopilotWorkerRequest {
  id: number;
  type: "query" | "fdc-selector" | "solidity";
  query?: string;
  url?: string;
  jsonPath?: string;
  abiSignature?: string;
  attestationType?: string;
}

export type CopilotWorkerResult =
  | ReturnType<typeof answerQuery>
  | ReturnType<typeof generateFdcSelector>
  | ReturnType<typeof generateSolidityBoilerplate>;

export interface CopilotWorkerResponse {
  id: number;
  result: CopilotWorkerResult;
}

self.onmessage = (event: MessageEvent<CopilotWorkerRequest>) => {
  const { id, type, query, url, jsonPath, abiSignature, attestationType } = event.data;
  let result: CopilotWorkerResponse["result"];

  switch (type) {
    case "query":
      result = answerQuery(query ?? "");
      break;
    case "fdc-selector":
      result = generateFdcSelector(url ?? "", jsonPath ?? "", abiSignature ?? "bool");
      break;
    case "solidity":
      result = generateSolidityBoilerplate(attestationType ?? "");
      break;
    default:
      result = { ok: false, error: `Unknown copilot request type: ${String(type)}` };
  }

  const response: CopilotWorkerResponse = { id, result };
  self.postMessage(response);
};
