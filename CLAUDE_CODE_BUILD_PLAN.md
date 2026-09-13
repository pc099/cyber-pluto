# Cyber Pluto — Claude Code Build Plan

*Session-by-session sequence for building Pluto end-to-end with Claude Code.*

This plan turns the architecture reference into an ordered set of **focused Claude Code sessions**. The guiding rule: **one session = one tight scope**, ending in a working, committed increment. Keeping each session narrow is deliberate — Claude Code works best when the context window holds one problem, not the whole system. Resist the urge to build breadth before the first vertical slice runs end to end.

**Model guidance:** Sonnet 5 for the bulk of the work; step up to Opus 5 for the two trickiest pieces — the red-lines pre-execution hook (Session 6) and agent-delegation isolation (Session 9).

---

## How to use this

- Work the sessions in order. Each lists its **goal**, **prerequisites**, **tasks**, and a **definition of done** you can check before moving on.
- Start each Claude Code session by pointing it at `SKILL.md` (the repo build skill) and the architecture reference so it inherits the invariants.
- Commit at the end of every session. A session that isn't committed isn't done.
- Don't skip the vertical slice (Sessions 2–4) to chase breadth. Prove the loop on one vulnerability class first.

---

## Phase 0 — Environment & Scaffolding

### Session 0 — Repo scaffolding and environment
**Goal:** A clean repo Claude Code can build in, on the hardened Kali VPS.
**Prereqs:** VPS provisioned with Kali GUI (see the *Kali GUI VPS Setup Guide*). Node.js + Python installed. Pluto running inside a container (Pi inherits the launching user's permissions, so isolate it).
**Tasks:**
- Initialize the repo; add `SKILL.md` and `CLAUDE.md` (project context) at the root.
- Set up the split toolchain: TypeScript workspace for Pi extensions, a Python venv for KB / embeddings / Metasploit bridge.
- Add `.gitignore`, a secrets pattern (never commit VNC/SSH/API credentials), and a top-level `README`.
**Done when:** `git log` shows an initial commit; both toolchains build a hello-world; the container boots Pluto's shell.

---

## Phase 1 — The Vertical Slice (prove the loop)

### Session 1 — Fork Pi, bare-bones reasoning-to-shell loop
**Goal:** Claude drives a shell command through Pi and reads the result back.
**Prereqs:** Session 0.
**Tasks:**
- Fork Pi (`earendil-works/pi`) into the repo; get the base agent loop running unmodified.
- Confirm the reasoning core can issue a shell command (e.g. `nmap -sV` against a lab target) and observe structured output.
- Log every tool invocation in full from day one — this is the audit trail *and* the future self-learned-KB dataset.
**Done when:** A single prompt results in a real command executing and its output returning to the reasoning core, fully logged.

### Session 2 — SQLite state schema
**Goal:** The Layer 2 state model exists as real tables with real inserts.
**Prereqs:** Session 1.
**Tasks:**
- Implement the schema from Architecture §4: `targets`, `nodes` (self-referencing tree), `findings`, `credentials`, `attempts`, plus the gate tables `validations` and `submissions`.
- Add the indexes (`idx_nodes_target_status`, `idx_findings_fingerprint`, `idx_attempts_tool`, etc.).
- Wire the loop from Session 1 to write `attempts` rows on every tool call.
**Done when:** A recon run populates `targets`, `nodes`, and `attempts`; a fingerprinted service writes a `candidate` row in `findings`.

### Session 3 — Recon → candidate finding
**Goal:** The observe-act loop grows the tree and records findings as `candidate`.
**Prereqs:** Session 2.
**Tasks:**
- Implement the feedback loop (Layer 4): execute → observe → update state → decide next.
- Seed per-service child nodes at priority (default-cred / misconfig checks *before* CVE-path nodes, per §5.1).
- Enforce the `candidate` status honestly — nothing is `validated` yet.
**Done when:** Against a lab box, Pluto produces a small investigation tree with at least one `candidate` finding and no premature `validated` rows.

### Session 4 — Gate 1 validator (SQL injection first)
**Goal:** One deterministic, non-LLM validator promotes `candidate → validated`.
**Prereqs:** Session 3. **(Consider Opus 5 for the gate logic.)**
**Tasks:**
- Implement the SQLi validator from the §4.5 table: technical signal (error string / timing delta) **and** impact artifact (extracted data), baseline vs. attack compared.
- Write a `validations` row (validator, baseline_ref, attack_ref, diff_summary, passed).
- Apply verifiable-step chaining (§3.5): check each step, not just the end claim.
**Done when:** A real SQLi candidate is deterministically reproduced and promoted to `validated` with a complete `validations` record; a non-reproducible one is marked `rejected`.

---

## Phase 2 — Safety Before Real Targets

### Session 5 — Red-lines pre-execution check + kill switch
**Goal:** No tool call runs without passing the red-lines gate; Chaitanya can halt at any moment.
**Prereqs:** Session 4. **(Opus 5 recommended — this is load-bearing.)**
**Tasks:**
- Implement the §10.4 red-lines list as a pre-execution check in front of the tool layer (all 7 categories).
- Ensure the check is injected into the main agent **and** propagates to every delegated sub-agent.
- Wire the human kill switch (halt-at-any-moment) as the floor of the human role.
**Done when:** A deliberately red-lined action (e.g. an out-of-scope scan) is blocked before execution; the kill switch stops an in-progress engagement cleanly.

---

## Phase 3 — Breadth & Intelligence

### Session 6 — Seeded knowledge base + fingerprint-triggered query
**Goal:** Layer 5 seeded tier answers "what do we know about this target/CVE," pulled in automatically.
**Prereqs:** Session 5.
**Tasks:**
- Stand up the vector store (Qdrant is the working candidate). Ingest in signal order: **CISA KEV → OWASP WSTG → PentestMonkey → CAPEC** (LLM4Pentest's four-source model).
- Wire the automatic query: a fingerprint write in `findings` triggers a KB query that can spawn a prioritized child node (§2.5).
**Done when:** Fingerprinting a known-vulnerable service automatically surfaces relevant KB hits and creates a new high-priority node.

### Session 7 — Vision pipeline
**Goal:** Headless-browser screenshots feed Claude's vision input at exploitation-relevant moments.
**Prereqs:** Session 5 (safety first).
**Tasks:**
- Build the custom Pi extension (§2.3.1): capture on payload submit / new page state / suspected CAPTCHA.
- Feed captured images to Claude vision; store as a new evidence type alongside findings.
**Done when:** A browser-driven step produces a screenshot Claude interprets, recorded in state.

### Session 8 — Metasploit integration (Metasploit-first, custom-on-demand)
**Goal:** The exploitation backend selects an MSF module when one fits, writes a custom payload when none does.
**Prereqs:** Sessions 4–5.
**Tasks:**
- Bridge Claude ↔ Metasploit via MCP (GH05TCREW's Metasploit MCP Server is the candidate).
- Implement the §2.3.2 decision: check for a fitting module first; fall back to custom payload + listener, logged as an `attempts` row with generated code retained, behind the gates.
**Done when:** Pluto uses an existing module on a matching target and writes a custom delivery on a bespoke one, both gated and logged.

### Session 9 — Agent delegation extension
**Goal:** Full-handoff and agent-as-tool delegation, each in an isolated context, all logged.
**Prereqs:** Session 5. **(Opus 5 for the isolation logic.)**
**Tasks:**
- Build the custom Pi delegation extension modeled on CAI (§6.4): spawn a separate Pi process per delegation with its own context.
- Support both modes; log which sub-agent, which mode, what it returned.
- Confirm the red-lines check propagates into every delegated agent.
**Done when:** A validated finding is handed off end-to-end to an exploitation specialist, and a bounded KB consultation returns via agent-as-tool without ceding control.

### Session 10 — Remaining validators + skill catalog
**Goal:** The other Gate 1 validator classes and the doctrine skill catalog exist.
**Prereqs:** Session 4 (validator pattern), Session 6.
**Tasks:**
- Extend the validator library to the remaining §4.5 classes (XSS, IDOR/BAC, command injection, path traversal, SSRF, auth bypass, privesc), including the OOB infrastructure (§4.7) for blind classes.
- Author the runtime skill catalog (§6.5.1) — one Markdown+YAML skill per class/framework/protocol/platform, each with a **required bypass/evasion section** (§6.5.2).
**Done when:** Each new validator promotes a real finding of its class; skills auto-select per task.
*Note: these runtime doctrine skills are distinct from this repo's build `SKILL.md` — see that file's header.*

### Session 11 — Engagement lifecycle
**Goal:** Deterministic hard caps, environmental pause, and stuck detection govern when to stop.
**Prereqs:** Sessions 3, 6.
**Tasks:**
- Hard caps: max wall-clock + max tool-call count per engagement (not dollar budget — subscription-based).
- Environmental pause on target-unhealthy signals (unresponsive / CAPTCHA / WAF / account-locked).
- Stuck detection off the state tree (no new nodes / repeated identical calls over a rolling window) → first triggers an untried KB/skill lookup, only then escalates. Bypass attempts (§6.5.2) count as progress, not stalls.
**Done when:** Each mechanism fires correctly against a contrived scenario without the reasoning core overriding it.

---

## Phase 4 — Prove It End to End

### Session 12 — HackTheBox dry run and iterate
**Goal:** A full engagement against a HackTheBox-style box, gates and lifecycle live.
**Prereqs:** All prior sessions.
**Tasks:**
- Run Pluto against a known box; watch the tree grow, Gate 1 validate, the red-lines gate hold, the lifecycle stop cleanly.
- Capture the gaps; feed them back as the next round of sessions.
**Done when:** Pluto solves (or measurably progresses on) a box end to end, with a clean audit trail and no gate bypassed.

---

## Deferred (intentionally, until after Session 12)

- **Reporting / submission formatting (Gate 2 output).** Its shape depends on what real findings look like. Build it once you have them, not before. Gate 2 itself (the human approval checkpoint) is already enforced in the schema and red-lines — only the *report artifact format* is deferred.

---

*Companion to the Cyber Pluto Architecture & Design Reference (v2.0) and the Kali GUI VPS Setup Guide. Section numbers above refer to the architecture reference.*
