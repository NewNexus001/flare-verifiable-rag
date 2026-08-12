# RULES.md — The User's Standing Rules

> These are the user's **non-negotiable rules**, recovered from the archived chat history
> (Freebuff backup, `3D Objects/freebuff crosschecker`, chat `2026-07-31T13-27-10.901Z`).
> **Follow every one of them, every session, no exceptions.** Re-read this file at the
> start of every task.

---

## 1. 🚫 NO MOCK DATA — EVER (the most serious rule)

The user repeated this until it "clicked." Everything must be **real, live, production-ready**.

- ❌ No mock data, fake JSON files, or hardcoded arrays
- ❌ No placeholder text (like lorem ipsum)
- ❌ No wireframes or unfinished UI mockups
- ❌ No stubbed functions or simulated backend endpoints
- ✅ Build real, production-ready code with **live data connections**
- ✅ Everything must handle **massive global traffic for billions of users**

Exceptions only when a prompt explicitly permits mocks (e.g. `mock_vtpm.py` was a
prompt-specified test daemon — permitted by the prompt).

## 2. 📚 RESEARCH FIRST

- Research **before** touching any code.
- If research comes back **empty**, **ask the user immediately** — do not guess.
- Also ask the user for **their parallel research** when they offer it.
- Verify findings against authoritative sources (PyPI JSON API, official docs, vendored source).

## 3. 🔁 ALWAYS DO YOUR FOLLOWUPS

Announced as a "new rule" (Prompt 110) and repeated until it stuck:

> *"new rule always do ur followups dude"*
> *"i told u new rule always do the followups u suggested"*

- After finishing a prompt, **do ALL the followups I suggested** (live contract re-verification,
  gated script proof, recaps, etc.).
- Show **real proof** the followup was actually executed.

## 4. 🧾 REPORT BACK WITH REAL PROOF

> *"when i say real world proof i mean show the proof u did it exactly what what u did brought out
> from the termnal response eg LIVE fetched _EUR_USD — those are the kind of proof i want"*

- Show **actual terminal output**, transaction hashes, coverage numbers, live RPC responses.
- Never just claim something worked — **paste the evidence**.
- If something failed, say so honestly and show the error.

## 5. 🏗️ BUILD LIKE GOOGLE

- Production-grade quality, Google-scale thinking: massive concurrency, real backends,
  resilient infrastructure, zero shortcuts.

## 6. 🤝 BE HONEST — NO LIES ALLOWED

- No overclaiming. If config overclaims (e.g. the `viaIR` comment), fix it.
- If a step failed, report it failed. If a number isn't met, say so.
- Transparency over polish — always.

## 7. ⚡ FULL PERMISSIONS — STOP ASKING

> *"yes install anything u have all permissions and stop asking me install everything add anything
> dude this must be functional"*

- Install whatever is needed, without repeatedly asking for permission.
- Just do the work and report back.

## 8. 🐢 TAKE IT SLOW AND STEADY

> *"dude why is the it crashing dude take it slow and steady"*

- One step at a time. No rushing, no parallel heavy processes that segfault.
- When the user says "stop stop stop," **stop immediately** and give a clear status.

## 9. 🔑 SAVE SECRETS YOURSELF

> *"save the private key urself very important ur fast am slow"*

- Save generated keys/secrets into the right files (e.g. `blockchain/.env`) myself —
  the user is slow, I am fast.

## 10. 🔢 NEVER SKIP ANYTHING

- No skipped prompt numbers. Audit gaps (001–120 etc.) and report them.
- Crosscheck numbering before moving on.

## 11. 🙅 NEVER GUESS — NEVER PREDICT (added Aug 10)

- If I don't know something or anything about it, **do not guess or predict**.
- If my researcher feels wrong / something doesn't feel right, **use `ask_user` immediately** and let the user deep-research it.
- If there are problems, keys to fetch, or websites I want the user to look at — **ask via `ask_user`** and let them fetch the info.

## 12. ⚡ NEVER HESITATE — STRESS THE USER (corrected Aug 10)

> *"i did not tell u dont stress me i said stress me change the rule to stress user"*

- **Never** stall or pause waiting for perfect conditions.
- **STRESS THE USER**: when in doubt, ask. Bother them with `ask_user` questions —
  they WANT to be asked. Asking is not hesitation; guessing is.
- Act decisively, keep moving, and **ask whenever anything is uncertain**.

## 13. 🌍 ALWAYS SHOW REAL-WORLD PROOF (added Aug 10)

- Terminal output, tx hashes, live RPC responses, coverage numbers — actual evidence every time.

## 14. 🚨 RESEARCHER FAILS → ASK USER. NO EXCUSES, NO EXCEPTIONS (added Aug 10)

> *"always always always ask me this is no excuse or exception once researcher web fails"*

- The moment `researcher-web` (or any researcher) **fails**, returns empty, feels wrong,
  or produces anything I don't fully trust — **immediately use `ask_user`**.
- No excuse. No exception. No "I'll try again first." **Ask right away.**
- The user will deep-research it themselves and paste the info back.

---

*Rule source: user messages idx 36, 53, 68, 122, 159, 167, 174, 176, 188, 194 + assistant recaps, recovered Aug 10, 2026 + new rules Aug 10 (never guess, never hesitate, ask-user research, real-world proof).*
