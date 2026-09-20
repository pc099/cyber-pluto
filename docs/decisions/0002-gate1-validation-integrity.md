# Decision 0002 — Gate-1 validation integrity (Item-0 follow-on)

**Status:** RATIFIED (all four members). Round 1 returned from harness-architect,
cybersecurity, and griller; the QA-tester (initially rate-limited) returned on
retry with a cross-aware position reacting to the other three — serving as the
huddle's cross-reaction. The four converge on a **sharpened Option D** with QA's
testing guardrails; no unresolved disagreement remains. QA holds a hard **NO-GO
on any "tamper-proof" claim** until the red-team sentinel (below) flips red.

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

## QA-tester position (the fourth voice) — resolves the open items

- **Ship the red-team forge SENTINEL now** (risk-free, gates everything). Run as
  `pluto` against a real DB + live daemon: create a candidate → `INSERT` a
  `passed` validations row (no real validator ran) → write self-consistent fake
  evidence → call the REAL signer → `promote()`. **Today the pass criterion is
  that the forge SUCCEEDS** (reaches a signed, submittable `validated`): the test
  documents the open hole as a standing assertion. A real fix (B/A) later flips
  exactly that assertion to "signer refuses / not trustworthy". If a change can't
  flip it, it didn't close the forge. This converts "we think it's residual" into
  a measured fact.
- **C is NOT testable as security** — only its plumbing is (`listUntrustedValidated`
  rows, advisory rendering, the Gate-2 authentic-vs-genuine warning actually
  displaying). QA will **block any commit/doc that calls C a mitigation of this
  forge.**
- **Evidence-hash slice: GO to build, with a pinned limit.** Test: mutate an
  evidence byte post-sign → verification flips false. **Mandatory second
  assertion:** a *pre-sign* forge with self-consistent bytes STILL passes (the
  hash is over pluto's own fake bytes). Build it AFTER the sentinel so the
  sentinel pins its exact limit and it isn't oversold.
- **Correction to griller's "append-only root-owned evidence":** that only helps
  if **root** writes the true wire bytes; if `pluto` writes into a root-owned
  append-only file it still controls the content → tamper-*evident* again, not
  proof. Any such slice's QA test must prove root, not pluto, is the writer.
- **Only Option B (or A) flips the sentinel** for network-observable classes.
  Hash + C + OOB-for-blind leave the network-class assertion green (forgeable).
  For blind/§4.7 classes the OOB collector needs its own forge test (fake
  callback receipt written by pluto vs the root listener's own record).

## RATIFIED decision (sharpened D + QA guardrails)

1. **Reject Option A.** (Root target I/O bypasses the pluto egress allowlist —
   net safety loss; also offensive execution as root.) Firm, unanimous.
2. **Build order, gated by QA:**
   - **(a) NOW — the red-team forge sentinel test** (a committed characterization
     test asserting the residual currently reaches a signed/submittable
     `validated`, plus a regression guard that the Item-0 direct flip is still
     caught). Risk-free; makes the residual a measured, watched fact.
   - **(b) Evidence-content-hash bound into the signed claim** — with the
     limit-pinning test (post-sign tamper caught; pre-sign self-consistent forge
     still passes). Never described as closing the forge.
   - **(c) C strictly as documented posture** — advisory rendering + Gate-2
     authentic-vs-genuine warning; claim **no** security beyond Item 0. (Cockpit
     enforcement + `listUntrustedValidated` surfacing already shipped this
     session in `7e4bdff`.)
   - **(d) Later / medium — root-owned OOB collector** for blind classes (the one
     cheap genuinely-tamper-proof slice), with its own forge test.
   - **Defer the general capture-proxy (B-for-network-classes)** — a large
     re-architecture with a new root-side parsing-of-attacker-bytes LPE surface;
     scope it separately, only if agent-efficiency (not safety) demands it.
3. **Naming discipline (QA hard NO-GO):** Gate 1 stays **tamper-EVIDENT**, never
   called **tamper-PROOF**, until the sentinel's core assertion goes red for the
   class in question. Only B/A can do that.
4. **Re-sequence vs other work:** the ungated free-text report bug (higher
   priority than this follow-on per the board) was FIXED this session
   (`5ca5b6c`). Shodan REST extension follows this follow-on's cheap slices.
