---
name: typescript-patterns
description: "TypeScript coding patterns for Pluto's Pi-extension layer. Load this whenever writing or editing TypeScript in the Pluto repo — the Pi fork itself and every custom extension (vision pipeline, agent-delegation, the red-lines pre-execution hook, the tool-call path, state-schema access from TS). Covers extension structure, typed state access, the blocking-hook pattern the red-lines check requires, async/error-handling rules, and gate-logic testing. Use alongside the pluto-build skill; defer to the Architecture Reference on any design question."
---

# TypeScript Patterns (Pi Extension Layer)

Everything living inside Pi is TypeScript — match Pi's own conventions (`@earendil-works/pi-coding-agent`) rather than importing a foreign style. These patterns keep the extensions aligned with the invariants in the `pluto-build` skill.

## Extension structure

- Each custom capability is its own extension module with a single clear responsibility: `vision/`, `delegation/`, `red-lines/`, `tool-log/`. Don't blend concerns into one mega-extension.
- Keep the agent-loop fork changes minimal and isolated from extensions, so Pi upstream changes stay mergeable. Extensions hook in; they don't rewrite the core.
- Export a typed init/register function per extension; no side effects at import time.

## Typed state access — the schema is the contract

- Model every table row (`targets`, `nodes`, `findings`, `attempts`, `validations`, `submissions`) as an explicit interface. No `any` on DB boundaries.
- Represent `status` and `node_type` as string-literal union types, not bare strings, so an illegal transition is a compile error (e.g. `type FindingStatus = "candidate" | "validated" | "submitted" | "rejected"`).
- Wrap DB access in a thin typed repository layer; extensions call `findings.promote(id, validationId)`, never raw SQL scattered through the codebase. This is where the status lifecycle is enforced in one place.

## The red-lines hook — blocking by construction

The red-lines check (Architecture §10.4) must run **before** any tool executes and must be impossible to skip.

- Implement it as a single choke-point the tool-call path is *forced* through — a wrapper every invocation passes, not an optional call sites remember to make.
- The check is **synchronous-blocking**: the tool call cannot proceed until the check resolves as allowed. Model the result as a discriminated union (`{ allowed: true } | { allowed: false; rule: RedLineRule; reason: string }`) so the caller must handle the blocked case.
- Ensure the same wrapper is applied inside every delegated sub-agent process, not just the main core. A delegation that spawns its own tool path re-applies the check.

## Async and error handling

- All tool calls, DB writes, and delegations are `async`; never fire-and-forget. Await and record the outcome.
- **Never silently swallow.** Every `catch` either logs a full `attempts`/error record and rethrows, or records a typed failure outcome. No empty catches — silent failure breaks the audit trail.
- Prefer `Result`-style returns (`{ ok: true; value } | { ok: false; error }`) over throwing for expected failures (a validator disproving a candidate is not exceptional). Reserve throws for genuine faults.

## Logging is not optional

- Every tool invocation writes a full `attempts` row (tool, exact command, output ref, ATT&CK tactic/technique) — this lives in the tool-call wrapper so it can't be forgotten.
- Log structured, not free-text: an object per event, so the self-learned-KB tier can mine it later.

## Testing

- Any change to the red-lines hook, a validator's TS side, or the status lifecycle ships with a test proving **both** the pass path and the block/reject path.
- Test that a blocked tool call never reaches execution — assert on the choke-point, not just the return value.
- Unit-test the repository layer's illegal-transition guards (e.g. promoting a `candidate` to `submitted` without passing through `validated` must fail).

## Don'ts

- No `any` on state or tool-call boundaries.
- No tool-execution path that bypasses the red-lines wrapper.
- No secrets in code or committed config.
- Don't rewrite Pi's core loop when an extension hook will do.
