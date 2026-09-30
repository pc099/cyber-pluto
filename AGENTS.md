# Cyber Pluto agent instructions

This repository builds an authorized cybersecurity testing harness on Pi, with
TypeScript extensions and Python services. Start work from this repository root.

## Resume and sources

- Read `progress/CODEX_HANDOFF.md`, then `progress/PROGRESS.md` before changing code.
- `docs/Cyber_Pluto_Architecture_Reference_v2.docx` is the architecture reference.
- `docs/decisions/` contains ratified changes. Prefer current code, recorded
  decisions and the latest session handoff over obsolete backlog statements.
  Raise an unresolved architecture conflict rather than inventing a resolution.
- `CLAUDE.md` and `.claude/skills/` remain the shared build instructions.
  Codex can discover the same four skills through `.agents/skills/` symlinks.
- The 12-session build plan is complete. Current work is post-plan harness
  hardening; do not restart the original build sequence.

## Build skills and invariants

Read `.agents/skills/pluto-build/SKILL.md` for build work. Load
`typescript-patterns`, `python-patterns`, or `cybersecurity-modules` when their
layer is involved. These are build skills. `runtime-skills/` is doctrine for
Pluto's target-testing agent; do not automatically import it as build instructions.

Preserve deterministic Gate 1 validation and recorded human approval at Gate 2.
The pre-execution red-lines check and audit logging must cover every tool path,
including delegated agents. Keep scope, evidence and status transitions honest.
Unsigned or unverifiable validated rows are not trusted validation facts.
The forged-validation-row residual remains open despite the signed promotion path.

Never claim a feature works end to end based only on unit tests or a dry-run.
Report what actually ran, what passed, and what remains unverified. Preserve
existing operator authorization, minimize unnecessary permission prompts, keep
secrets out of source control, and update the progress ledger in small increments.

## Agent review board

For significant architecture, security-model or run-model changes, use the
four-role board in `.agents/skills/pluto-review-board/SKILL.md`:
`pluto-harness-architect`, `pluto-cybersecurity`, `pluto-griller`, and
`pluto-qa-tester`. The operator explicitly requested this board in the imported
Claude session and again requested its import here.

Research a concrete proposal, collect independent positions, share those
positions in a huddle, and resolve required rewrites before implementation.
QA must execute relevant checks and distinguish empirical evidence from claims.
Use available delegation tools; with limited concurrency, run roles in batches.
Do not drop a board role or substitute a solo verdict for board consensus.
Small, well-scoped fixes and instruction imports do not require the full board.

Custom role files are in `.codex/agents/`. If this session cannot select those
files natively, read their instructions and pass them to delegated agents.
Leave models, permissions and concurrency inherited from the active environment.

## Current next task

The latest Claude handoff identifies sandbox startup failure under `/root` as
the next task. Review relocation of sandbox engagement workspaces outside
`/root`, migration of saved state, and coordination of the signing socket.
Validate confinement, trusted promotion, resume behavior and failure cleanup
before claiming the sandbox works. Do not present an unsandboxed run as proof
of sandbox operation or automatically launch a target engagement during setup.
