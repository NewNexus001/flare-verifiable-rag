# Video Pitch Guide — Flare Verifiable RAG (DoraHacks Flare Track 2)

Rephrased for the **actual, verified state** of the project (Prompts 1–200 complete).
Everything in this guide is real and runnable on this machine right now — nothing
aspirational, nothing fabricated. The 201–400 features (Tokio gRPC, Intel TDX EAT,
Cloud KMS MPC, zkTLS, Bazel) are **not built** and are deliberately **not** in this
script. If a judge asks about them: "that is the next milestone on our roadmap."

**Total runtime target: 3:30 max.** Judges reward tight, truthful, live demos.

---

## What we actually have to show (verified facts)

| Asset | Proof | How to film it |
| --- | --- | --- |
| Dashboard (Next.js 14.2.35) | Running at `http://127.0.0.1:3100` | Full-screen browser, dark theme |
| Live FTSO v2 price | FXRP/USD live-read from VerifiableRAG on Coston2 | Dashboard "Live settlement feed" card |
| Client encryption | AES-GCM-256 via Web Crypto (tests 7/7) | Upload flow in SecureUploader |
| vTPM attestation | Confidential Space OIDC token, `/v1/token`, enclave `/attestation` | AttestationBadge + curl of `/v1/attestation` |
| FDC Web2Json | Live voting round verified (round 1422772, tx receipt status 1) | `request_fdc_attestation.ts` in terminal |
| FTSO v2 feeds | Live reads: FXRP/USD, BTC/USD, USDT/USD | `read_ftso_v2.ts` in terminal |
| Deployed contract | `0x403be0A89183078e4eC09e7E61b9F0EE3c5E9897` on Coston2 | Coston2 Explorer |
| Test suites | 504 enclave pytest · 120 Rust cargo · 94 Hardhat · 7 frontend · lint clean | Terminal, zoom on pass lines |
| Data integrity audit | `.github/scripts/audit-data-integrity.sh` → exit 0 | Terminal |

---

## The 20 steps

### Step 1 — Install the stack
OBS Studio (recording), CapCut Desktop (editing), Audacity (audio), VS Code.
Free, open source. Nothing else needed.

### Step 2 — The script (3 segments)
- **0:00–0:40 — The problem.** Enterprises need AI answers they can *prove*.
  LLM output is unverifiable: no guarantee the answer came from your data,
  no guarantee it wasn't tampered with, no receipt. Flare gives us the pieces
  to fix this — FDC for provable web data, FTSO v2 for provable prices,
  Coston2 for settlement.
- **0:40–2:00 — The architecture.** One line per layer, then the demo:
  1. **Client** — Next.js dashboard; documents encrypted in-browser
     (AES-GCM-256) before they ever leave the machine.
  2. **Blind proxy** — the server only ever sees ciphertext; no logging of content.
  3. **Enclave** — GCP Confidential Space (AMD SEV-SNP). vTPM attestation
     proves the exact binary that's running. Inside: a deterministic Rust
     symbolic graph engine (no probabilistic embeddings) that mints
     halo2 zero-knowledge proofs over BN254 — proof that the query logic
     ran unmodified, no hallucination, no context tampering.
  4. **On-chain settlement** — `VerifiableRAG.sol` on Coston2. Prices settle
     against the live FTSO v2 feed; web data is attested by the Flare Data
     Connector; the enclave's attestation is bound to the contract.
- **2:00–3:30 — Live on-chain demo.** Four things, all real (steps 7–11).

### Step 3 — OBS settings
1080p / 60 FPS, canvas 1920×1080, x264, 160 kbps audio. Same as planned.

### Step 4 — Voiceover
Microsoft Edge TTS or Piper, `en-US-AndrewMultilingualNeural`. Calm, deliberate,
slightly slower than normal. Record the script from Step 2 in 3 files
(one per segment) so re-recording one part doesn't cost the whole take.

### Step 5 — Audio cleanup
Audacity: Noise Reduction → Compression → normalize to -1.0 dB. Same as planned.

### Step 6 — Architecture walkthrough (record this LAST, narrate FIRST)
Build one clean diagram with the **4 real layers only** (client → blind proxy →
Confidential Space enclave → VerifiableRAG.sol, with FDC + FTSO v2 as side rails
into the contract). A simple dark-themed slide (matching the dashboard's zinc/sky
palette) is fine — you do not need a tool; PowerPoint/Canva/Figma all work.
Record the screen while the voiceover for segment 2 plays.

### Step 7 — Live dashboard demo (segment 3, take 1)
1. Open `http://127.0.0.1:3100` full-screen.
2. **Connect a wallet** (RainbowKit, Coston2). Show the address chip appear.
3. Point at the **Live settlement feed** card — "this price is read live from
   our deployed contract on Coston2, which reads the FTSO v2 fast-update feed."
4. Scroll to the three feature cards — say one sentence each: TEE Enclave,
   Verified Data, Blind Proxy Client.
5. In **SecureUploader**, drop a real document, submit it, and show the
   ProofViewer populating with the on-chain execution record (real tx).
   This is the money shot: encrypted upload → enclave → proof → settlement.

### Step 8 — Attestation proof (segment 3, take 2, ~20s)
1. Show the AttestationBadge on the dashboard (green = verified).
2. In a terminal: `curl http://127.0.0.1:8000/v1/attestation` (or the enclave's
   health endpoint) and show the OIDC claims — swname, image digest, expiry.
3. One line: "This is the Confidential Space vTPM attestation — proof of the
   exact image that is running, live."

### Step 9 — Live FDC Web2Json verification (~30s)
In a terminal, from `blockchain/`:
```bash
npx hardhat run scripts/request_fdc_attestation.ts --network coston2
```
Let it run; zoom on: the live-resolved FdcHub address from the
FlareContractRegistry, the submitted request, and the **confirmed transaction
receipt (status 1)**. Say: "The Flare Data Connector attests a real web2 JSON
response, settled on-chain — no oracle delay trick, no hardcoded answer."

### Step 10 — Live FTSO v2 feed read (~20s)
In a terminal, from `blockchain/`:
```bash
npx hardhat run scripts/read_ftso_v2.ts --network coston2
```
Zoom on FXRP/USD, BTC/USD, USDT/USD values with their decimals.
Say: "Sub-2-second fast updates, read live from Coston2."

### Step 11 — Block explorer evidence (~20s)
Open
`https://coston2-explorer.flare.network/address/0x403be0A89183078e4eC09e7E61b9F0EE3c5E9897`
Zoom slowly into the address and one confirmed transaction.
Say: "Deployed and settled on Coston2 — every demo you just saw is on-chain."

### Step 12 — Import into CapCut
New project, import: 3 voiceover files + screen captures + the diagram recording.
Order clips: problem VO → diagram → dashboard → attestation → FDC → FTSO →
explorer → closing.

### Step 13 — Sync audio and video
Align each clip to its voiceover. Trim terminal wait time — cut to the result
the moment it prints. If a live call is slow, cut mid-wait; never fake the output.

### Step 14 — Text callouts (professional wording only)
- "GCP Confidential Space · AMD SEV-SNP" (not "Intel TDX")
- "Live FTSO v2 feeds · sub-2s fast updates"
- "Live-verified data — every value read from Coston2"
- "AES-GCM-256 client-side encryption"
- "halo2 ZK proofs · O(k) deterministic retrieval"
Avoid: "zero-mock", "no simulation", "hackathon" chat-language. Say
"live-verified" instead.

### Step 15 — Transitions
Subtle 0.2–0.3s fades only. No flashy wipes.

### Step 16 — Zoom effects
One slow digital zoom on: (a) the green test pass lines, (b) the live price
card, (c) the FDC tx receipt, (d) the explorer address. 2–3s each, no more.

### Step 17 — Music
Low-volume instrumental bed, ducked -22 dB under speech.

### Step 18 — Subtitles
CapCut auto-caption, white text with dark outline. Fix any mis-captions of
technical terms (halo2, FTSO, Confidential Space).

### Step 19 — Export
MP4, H.264, 1080p, 12 Mbps, 60 FPS. Watch it once all the way through with
sound before uploading — check every terminal line is real and every claim
matches this guide.

### Step 20 — Upload and submit
1. Upload to YouTube as **Unlisted**; verify playback.
2. On DoraHacks: repo link (`github.com/NewNexus001/flare-verifiable-rag`),
   video link, and in the description: deployed contract
   `0x403be0A89183078e4eC09e7E61b9F0EE3c5E9897` on Coston2,
   `SYSTEM-VERIFICATION-REPORT.md` (200 prompts, all verified live), and the
   test totals (504 + 120 + 94 + 7).
3. If asked about 201–400: "next milestone, roadmap published in the repo."

---

## Anti-overclaim checklist (before you export)
- [ ] No "Intel TDX" (we run AMD SEV-SNP Confidential Space)
- [ ] No "zkTLS", "Bazel", "KMS MPC wallet", "Copilot", "i18n", "popover menu"
- [ ] No fabricated terminal output — every clip is a real run
- [ ] Prices shown are live reads, not screenshots of a chart
- [ ] "Live-verified data", not "zero-mock data"
