---
name: pluto-review-board
description: "Use Cyber Pluto's four-agent review board for consequential harness architecture, security-model, or run-model changes, or when the operator asks for board review. Research a concrete proposal, huddle independent reviewers to consensus, and require empirical QA. Routine small fixes and instruction imports do not need the full board."
---

# Cyber Pluto review board

The operator's board has four distinct roles:

- **Harness architect:** Pi fit, responsibility boundaries, maintainability,
  state transitions and mergeability.
- **Cybersecurity reviewer:** Gate 1 and Gate 2, red-lines propagation, scope,
  isolation, evidence integrity and concrete bypass paths; also methodology
  review of completed authorized lab runs when relevant.
- **Griller:** challenge assumptions with concrete failure scenarios, reject
  unsupported success claims, and push the simplest adequate design.
- **QA tester:** reproduce behavior, execute appropriate tests, inspect coverage,
  check regressions and failure paths, and distinguish measured facts from inference.

The reusable role files live in the repository's `.codex/agents/` directory.
Read the selected role file and provide its `developer_instructions` when the
active delegation tools cannot select a native custom role. Inherit the active
model and tool permissions; do not recreate old Claude model settings.

## Process

1. Inspect the relevant code, decisions and empirical evidence first. Give the
   board a grounded proposal with a concrete problem, constraints and proposed
   acceptance checks. Avoid feeding reviewers a preferred verdict.
2. Collect independent structured positions: `APPROVE`, `REWRITE-REQUIRED`, or
   `INSUFFICIENT-EVIDENCE`, with specific reasons and required changes.
3. Share all positions with the members and have them discuss disagreements.
   Use follow-up tasks/messages on the same agents where possible. Include all
   four voices; use batches when the available concurrency cannot fit the board.
4. Resolve required rewrites and record the converged design before implementing
   a consequential change. A reviewer proposing a fix is not its proof of correctness.
5. Have QA execute the affected behavior and appropriate regression checks after
   implementation. Report what actually ran, any failures, and what remains
   unverified. Record the consensus and evidence in the project progress/decisions.

Existing operator authorization continues to apply; the board is a review
workflow, not an additional user-permission gate for authorized implementation.
Routine small fixes do not need a full board.

## Source instructions

Read [the original Claude board process](references/claude-board-process.md)
for the operator's original wording and examples, and
[the integrity mandate](references/claude-build-integrity.md) for its verification
expectations. The original process has a stale three-agent description and
three-agent wording. Its explicit four-role enumeration, later session
practice, and operator integrity mandate establish the four-member board.
