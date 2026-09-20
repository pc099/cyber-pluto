# Decision 0002 — Gate-1 validation integrity (Item-0 follow-on)

**Status:** PROVISIONAL. Board huddle Round 1 complete for 3 of 4 members
(harness-architect, cybersecurity, griller). The **QA-tester** agent hit the
Anthropic **session rate limit** (resets 09:30 UTC) and did not return; a
**Round 2 cross-reaction** has not been run. Do NOT treat this as ratified —
per the board process, changes wait until all four agree. This records the
strong Round-1 convergence so it isn't lost.

Proposal under review: `docs/proposals/gate1-validation-integrity.md`.

## What the three returning members AGREED on (no dissent)

1. **Reject Option A (root re-runs the validator against the target).**
   Unanimous. Root doing target I/O bypasses the `meta skuid pluto` egress
   allowlist (root egress is unrestricted) → out-of-scope reachability, no rate
   discipline, and offensive execution moved into root. A **net safety loss**
   that buys back a residual the human Gate 2 already bounds. Out.

2. **This residual is primarily a ROBUSTNESS problem, not a safety one.** The
   only externally-consequential path — submission — is already behind the human
   Gate 2, and `markSubmitted`'s automated check *passes* on a fully-forged chain
   (the signature genuinely verifies), so automated defenses give **zero**
   protection here; the human is the sole backstop. A hijacked pluto also has
   better exfil channels (provider prompt channel, DNS resolver) than laundering
   a finding a human must still approve. So the cost is *wasted agent effort on
   self-forged findings*, not an unauthorized external consequence.

3. **Sequencing: this follow-on is NOT the top priority.** The **ungated
   free-text report bug** outranks it — the harness has already once emitted a
   fabricated "engagement complete" report with **no hijack required**, and it
   reaches the human as truth (the exact failure mode the integrity mandate
   guards against). Hardening an already-tamper-evident gate against a
   *hijacked-agent* threat is lower priority than fixing an unforced integrity
   failure. Shodan is below both.

4. **A cheap, high-leverage hardening, independent of which big option wins:**
   bind a **content hash of the evidence bytes into the signed promotion claim**
   (today `evidenceRef` is a path only). This doesn't stop *pre-sign* forgery,
   but it makes *post-sign* evidence tampering detectable and gives the Gate-2
   human a deterministic check that the bytes reviewed are the bytes signed.
   Surfaced independently by architect (Slice 1b) and cybersecurity.

5. **If Option C (human Gate-2 review) is adopted, it must be reframed
   honestly:** a valid signature attests **authenticity of the signer, not
   genuineness of the evidence**. The dominant risk is the *rubber stamp* — a
   green signature invites the human to stop reading the evidence. The Gate-2
   surface must force the authentic-vs-genuine distinction, or C adds nothing
   over Item 0.

6. **Option B (privileged capture proxy) is the only real tamper-proofing, but
   the general form is a large re-architecture** with a new **root-side
   parsing-of-attacker-bytes LPE surface** (TLS interception, per-class verdict
   recompute duplicated root-side and liable to drift, raw-TCP/non-HTTP, blind
   classes bypass an HTTP proxy). Build only narrow slices, not a blanket layer.
   - **The OOB callback collector is the one high-value, low-cost B-slice**
     (architect): for blind/§4.7 classes the verdict is just "did the correlated
     token arrive at a root-owned listener" — no per-class recompute, the "parse"
     is a token comparison. Build this before any HTTP proxy.

## Provisional consensus direction (pending QA + Round 2)

**A sharpened Option D:**
- **Reject A.** (Firm.)
- **Now (cheap, low-risk, endorsed by ≥2 with no dissent):**
  - Bind the evidence content-hash into the signed claim (#4).
  - Ship C *as documented posture only* — surface `listUntrustedValidated`, mark
    autonomous `validated` as **advisory**, and force the authentic-vs-genuine
    framing at Gate 2 (#5). Claim **no** security reduction from C beyond Item 0.
  - Griller's addition: make evidence files **append-only, root-owned at capture**
    (a capture-only slice of B, no recompute engine).
- **Next (medium):** root-owned **OOB callback collector** → blind classes become
  genuinely tamper-proof (#6).
- **Later / only if agent efficiency demands it:** HTTP(S)-class record+recompute
  proxy, gated on QA's red-team forge script proving closure first.
- **Re-sequence the roadmap:** ungated-report fix **first**, then this
  follow-on's cheap slices, then Shodan.

## Still OWED before ratification (honesty)

- **QA-tester Round 1** (rate-limited): the exact runnable red-team acceptance
  test (forge a `passed` validations row + evidence → prove it can no longer
  reach a signed, submittable `validated`), and which options are *testable*
  vs rest on unfalsifiable human diligence. Griller also demanded this script be
  shipped *now* to convert "we think it's residual" into a measured fact.
- **Round 2 cross-reaction:** the three positions converged but have not
  explicitly reacted to each other; the biggest unresolved tension is whether the
  evidence-hash slice (#4) is worth building before QA defines the acceptance
  test. Run after the rate limit resets.
