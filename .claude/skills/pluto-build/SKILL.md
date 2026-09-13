---
name: pluto-build
description: "Build doctrine for the Cyber Pluto repo. Load this at the start of every Claude Code session working on Pluto. It encodes the non-negotiable architecture invariants (the two-gate model, the state schema, the red-lines safety gate), the split TypeScript/Python toolchain, the reference designs to follow, and the coding rules that keep the build aligned with the architecture reference. This is a BUILD skill for Claude Code writing Pluto's code — it is NOT one of Pluto's own runtime doctrine skills (those live in the runtime skill catalog per Architecture §6.5 and are a separate concern)."
---

# Pluto Build Skill

You are helping build **Pluto**, an autonomous cybersecurity testing harness with Claude as its reasoning core, forked from Pi (`earendil-works/pi`). The single source of truth is the **Cyber Pluto Architecture & Design Reference (v2.0)**. When this skill and the reference disagree, the reference wins — flag the conflict rather than guessing.

Build order is defined in `CLAUDE_CODE_BUILD_PLAN.md`. Work one session's scope at a time; do not build breadth before the vertical slice (plan Sessions 2–4) runs end to end.

---

## The invariants — never violate these

These are load-bearing. If a change would weaken any of them, stop and raise it.

1. **The two gates are absolute.**
   - **Gate 1 (validation):** no finding moves from `candidate` to `validated` without a **deterministic, non-LLM** check reproducing it (baseline → attack → compare). The reasoning core's confidence is never sufficient. Validation is run by a role *distinct* from the one that proposed the finding.
   - **Gate 2 (submission):** nothing is submitted externally without explicit human approval, recorded in a `submissions` row naming the approver. This is a **compliance requirement** (HackerOne/Bugcrowd prohibit autonomous submission), not a preference. Never automate around it.

2. **The red-lines check gates every tool call.** The §10.4 prohibited-action list is checked *before* any tool executes, in front of the tool layer — and it **propagates into every delegated sub-agent**, not just the main core. Never let a code path reach a tool invocation without passing this check.

3. **Status is the fact ledger.** `candidate` = speculation, `validated` = fact. The reasoning core must never act on a `candidate` as though it were `validated`. A version-string match can only raise a finding to `candidate` (backporting makes version strings unreliable) — only a validator advances it.

4. **Everything is logged.** Every tool invocation and every delegation writes a full `attempts`-style record (tool, exact command, output ref, ATT&CK tactic/technique). This is both the audit trail and the self-learned-KB dataset. No silent execution.

5. **Exploration is free; consequences are gated.** Keep the reasoning core aggressive and creative. Do not add safety by restricting the toolset — safety lives in the gates, the red-lines file, and logging. Broad shell + internet access is intentional.

---

## Toolchain — the split stack

- **TypeScript** for everything living inside Pi: the fork itself and all custom extensions — vision pipeline (§2.3.1), agent-delegation (§6.4), the red-lines hook (§10.4). Pi is TypeScript (`@earendil-works/pi-coding-agent`); match it.
- **Python** for the surrounding pieces: knowledge-base ingestion and embeddings, the vector store client, and the Metasploit MCP bridge.
- This split mirrors the field (CyberStrike splits TS orchestrator / Python backend). Keep the boundary clean; don't smear KB logic into the TS extensions or agent-loop logic into Python.

**Isolation:** Pi has no built-in permission system and inherits the launching user's permissions. Pluto runs containerized. Never assume Pi sandboxes anything.

---

## The state schema is the spine

Realize Architecture §4 exactly: `targets`, `nodes` (self-referencing tree), `findings`, `credentials`, `attempts`, `validations`, `submissions`, with the specified indexes. The tree holds structure/intent; the evidence tables hold facts; the tree references evidence by foreign key (a fact is stored once). **Dead ends are marked, never deleted** — negative results are signal. The two gates live in the data as the `status` lifecycle on `findings`.

---

## Reference designs — study, don't copy

Follow these for *architecture and logic*, but write Pluto's own code. Do not paste AGPL/other source in. (Copyright protects expression, not ideas — keep it that way.)

- **PentestGPT v1.0** — the task-tree pattern for long-session context.
- **CyberStrike** (AGPL) — the 3-gate PoC validation model for Gate 1.
- **pentest-ai-agents** — the hard-refusal list model for the red-lines file; SQLite findings DB.
- **Pentest-Swarm-AI** — the RECON → HYPOTHESIS → TEST → CONFIRM loop.
- **XBOW** — deterministic validators, verifiable-step chaining, health-monitored lifecycle.
- **CAI** — the two delegation modes (full handoff / agent-as-tool).
- **Strix** — runtime skill file structure; "no PoC, no finding."

If reusing any AGPL code literally (rather than as reference), stop and flag the licensing implication first.

---

## Coding rules

- **Match the session scope.** Implement what the current plan session asks; don't pre-build later sessions. Smaller, committed increments beat large uncommitted ones.
- **Commit at the end of every session** with a message tracing back to the plan session and the architecture section.
- **Tests for the gates.** Any change touching Gate 1, the red-lines check, or the status lifecycle needs a test proving both the pass and the block/reject path.
- **No credentials in the repo.** VNC/SSH/API keys, program secrets — never committed. Respect the secrets ignore pattern.
- **Scope adherence is a hard constraint.** Scanning stays bound to `targets.scope_notes`; never expand to adjacent or out-of-scope hosts. Going out of scope forfeits safe-harbor.
- **Prove access, don't harvest.** For any finding, demonstrate the minimum that shows impact, then stop — especially for RCE/SSTI (prove the door opens, don't walk through). Never exfiltrate or retain real sensitive data beyond evidence needs.
- **When uncertain about an architecture decision, ask or cite the reference** — don't invent a new pattern silently.

---

## What NOT to do

- Don't let the reasoning core self-validate a finding or self-approve a submission.
- Don't add a tool-execution path that bypasses the red-lines check.
- Don't treat a `candidate` as validated, or a version match as a finding.
- Don't build the reporting/submission *artifact format* yet — deferred until after the first end-to-end HackTheBox run (Gate 2 the checkpoint still stands; only the report format waits).
- Don't merge the knowledge base and the runtime skill catalog — KB is data that grows automatically; skills are static hand-authored doctrine.
