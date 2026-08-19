# Post-Submission Todo (saved 2026-08-15, ~2h before deadline)

Submission: https://dorahacks.io/buidl/47880 — flare-verifiable-rag (SUBMITTED ✅)
Deadline: 2026/08/14 19:59 · Judging Aug 15–21 · Winners Aug 24

## 🔴 Must-do (priority order)

- [ ] **Film the 4-shot demo video** (everything was verified running):
  1. Dashboard `http://127.0.0.1:3100` — live price card (FXRP/USD from deployed contract)
  2. `curl.exe -s http://127.0.0.1:9000/health` — `"engine_ready": true`
  3. `cd C:\Users\hp\flare-verifiable-rag\blockchain; npx hardhat run scripts/read_ftso_v2.ts --network coston2` — live prices + wallet 0xDA5a…56A7
  4. `npx hardhat run scripts/request_fdc_attestation.ts --network coston2` — tx hash → paste into coston2-explorer.flare.network → zoom status 1
- [ ] **Upload video to YouTube** channel "Web 3 maam": https://www.youtube.com/channel/UCK2BPaNdby1RelQy17X7U_A
      → channel link was used in the form, so the video appears automatically — NO form edit needed
- [ ] **Pin video as Featured** on the channel so it's the first thing judges see
- [ ] **Rename YouTube channel** — "Web 3 maam" is not professional; judges see it (free, 1 min)
- [ ] Add channel **banner + avatar** so the channel page looks polished
- [ ] **Rotate/revoke the Vercel token** shared in chat (Vercel account settings → Tokens → delete the compromised token)
- [ ] Fill **Team info** line if still empty: "Solo developer building verifiable AI infrastructure on Flare — hardware-attested RAG with live oracle data, proven on-chain."

## 🟡 Post-submission upgrades (judging week — README must be updated as each lands)

- [ ] **SVG logo** — user explicitly flagged: "this project has not svg man we gotta fix that" (quick, visible win)
- [ ] **Phase 201–220: Tokio Rust gRPC core** — single most impressive "new work" flag
- [ ] Phase 221–240: TDX/EAT attestation — needs real hardware; document intent, don't fake
- [ ] Phase 241–260: GCP KMS MPC wallet — research-grade, unlikely to finish in a week
- [ ] Phase 261–280: zkTLS proxy — research-grade
- [ ] Phase 281–300: FTSO v2 provider node
- [ ] Update **README + form text** (if editable) as each phase lands — coherent story for judges

## ⚪ Optional / open questions

- [ ] Check hackathon BUIDLs tab → count real competition in **Bounty 2 (Confidential Compute Apps)** — never done
- [ ] Verify BTC/USDT feeds load on deployed Vercel site (only FXRP was confirmed)
- [ ] Enclave tunnel (ngrok/cloudflared) so deployed site shows live connection — rejected as fragile + security smell, probably skip
- [ ] Unknown: does DoraHacks lock form text at deadline? (channel link + GitHub + Vercel all auto-update regardless)
