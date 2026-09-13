# Pluto Build — Progress Ledger

**Resume protocol:** read this file top-to-bottom at the start of every session. It is the single source of truth for *where the build is right now*. Keep it current **as you work** — update it after every meaningful increment, not just at session end — so a usage-limit cutoff never loses more than the current small step.

## Current position
- **Phase:** 1 — The Vertical Slice
- **Active session:** Session 2 — SQLite state schema
- **Status:** done
- **Next concrete action:** Session 3 — Recon → candidate finding. Implement the real Layer 4 feedback loop (execute → observe → update state → decide next), seed per-service child nodes at priority (default-cred/misconfig checks before CVE-path nodes, §5.1), and make fingerprint → candidate-finding **automatic** (Session 2 proved the mechanism by inserting findings manually from real nmap output; Session 3 replaces that with the harness actually parsing tool output and deciding).

## In flight (granular — what is being done *right now*)
- (nothing — Session 2 closed out cleanly)

## Done (most recent first — with commit hash)
- `6986d33` — **Session 2: Layer 2 SQLite state schema, wired to real attempts rows.**
  - `extensions/src/state/schema.ts` implements Architecture §4 exactly: `targets`, `nodes`, `findings`, `credentials`, `attempts`, `validations`, `submissions`, all six specified indexes, plus `tactic`/`technique` columns on `attempts` per §5.4 (an explicit, small addition the reference itself calls for — "costs little to add to the schema"). Uses Node's built-in `node:sqlite` (`DatabaseSync`) — no external or native dependency, and we're already on Node 24. Bumped `extensions/package.json`'s `@types/node` to `^24` to get `node:sqlite` typings (missing from the `^20` Session 0 installed).
  - `extensions/src/state/{targets,nodes,attempts,findings}-repo.ts` — the typed repository layer (typescript-patterns: no raw SQL scattered through the codebase). `findings-repo.create()` only ever produces `status: 'candidate'` — there is no way to construct any other status here; promotion to `validated` is Gate 1's job (Session 4). `credentials`/`validations`/`submissions` have schema + row types now but no repo methods yet (unused until their sessions).
  - `extensions/src/tool-log/attempts-recorder.ts` bridges every `tool_call`/`tool_execution_end` into a real `attempts` row, alongside the existing JSONL capture (both kept — JSONL is the crash-safe raw half, the DB is the structured queryable half). Bootstraps one `targets` row + one root `recon` node per Pi session at `session_start` — deliberately simple, no per-engagement reuse or real branching yet (that's Session 3). Full tool output goes to `evidence/attempts/<id>.json`, referenced from `attempts.output_ref`.
  - `extensions/src/tool-log/attack-mapping.ts` — a small, explicit bash-command → ATT&CK tactic/technique lookup (nmap, gobuster, sqlmap, hydra, ...). Unmapped/ambiguous commands (curl, non-bash Pi tools like `read`/`edit`) are left untagged (`NULL`) rather than guessed — a wrong tag would undermine the audit trail's whole point.
  - Verified twice: a synthetic harness driving the compiled extension's handlers directly (no LLM, no cost), then the real live loop — reran the Session 1 nmap-vs-localhost prompt through Pi with `claude-haiku-4-5`, and `state/pluto.db` came out with one real `targets` row, one real `nodes` row, and one real `attempts` row (`tool='nmap'`, `tactic='Reconnaissance'`, `technique='T1595'`, `output_ref` pointing at the real captured nmap output). Then manually inserted the two real fingerprinted services (OpenSSH 10.0p2, Exim smtpd 4.98.2) as candidate findings via `findings-repo` — proving the mechanism works; the autonomous parsing that would do this without a manual step is explicitly Session 3's job, not built here.
  - Meets Session 2's build-plan Done condition exactly: "a recon run populates targets, nodes, and attempts; a fingerprinted service writes a candidate row in findings." `state/pluto.db`, `evidence/`, `logs/` are all gitignored runtime data — left in place on disk as evidence of the run, not committed.
- `3e7b061` (ledger) — **Session 1 closed out: the live reasoning→shell loop is proven.** Operator added an `ANTHROPIC_API_KEY` to Pi. Ran:
  `pi --provider anthropic --model claude-haiku-4-5 -e extensions/src/tool-log/index.ts --no-session -p "Run nmap -sV against localhost and summarize the open services you find, one line each."`
  (Haiku 4.5 and `--no-session` deliberately, to keep the operator's $5 budget essentially untouched — this is a one-shot print-mode call, not an open session.)
  - Claude decided to call the `bash` tool with `nmap -sV localhost`, Pi executed it for real, and Claude's final answer correctly summarized the two real open services it found (OpenSSH 10.0p2, Exim smtpd 4.98.2) — confirming the reasoning core reads real structured tool output back, not just issues commands blind.
  - `logs/tool-invocations.jsonl` (gitignored runtime data, not committed) captured both the `tool_call` record (exact command, exact toolCallId, timestamp) and the `tool_execution_end` record (full nmap stdout, `isError: false`) for this run — the tool-log extension works end-to-end against a live agent turn, not just the synthetic harness from the prior increment.
  - This satisfies Session 1's build-plan Done condition exactly: "a single prompt results in a real command executing and its output returning to the reasoning core, fully logged."
- `4cc442d` — Session 1: fork Pi in as a submodule, add tool-invocation logging.
  - `pi/pi` is now a git submodule (not vendored) tracking `https://github.com/pc099/pi`, pinned at `b215884` — the already-cloned nested repo from Session 0 converted in place with `git submodule add`, no history rewrite needed. Working tree inside the submodule is clean — the base agent loop is genuinely unmodified.
  - Node 20.19.2 (Session 0's provisioning) is below Pi's engine requirement (`>=22.19.0` on several packages). Installed Node v24.21.0 LTS to `/usr/local` (takes PATH precedence over the apt-installed v20, which is left in place unused). `npm install --ignore-scripts` and `npm run build` then succeeded clean inside `pi/pi` — CLI at `pi/pi/packages/coding-agent/dist/bundle/cli.js`, version `0.85.1`.
  - Installed `nmap` (7.95) via apt for the shell-command smoke test — wasn't present on this environment despite the "hardened Kali VPS" framing in CLAUDE.md.
  - Added `extensions/src/tool-log/index.ts` — a Pi extension hooking `tool_call` (before execution) and `tool_execution_end` (after) to append full, structured JSONL records to `logs/tool-invocations.jsonl`, correlated by `toolCallId`. Two lines per invocation (not one on completion) so an attempt is on the record even if the process dies mid-execution. Typed against `@earendil-works/pi-coding-agent` via a `devDependency` `file:` link to the submodule (`extensions/package.json`), so it typechecks with no `any` at the tool-call boundary — `npm run build` in `extensions/` is clean. This is the Session 1 stand-in for the Architecture §4 `attempts` table; Session 2 replaces it with real SQLite writes.
  - Verified the extension loads cleanly: `pi --no-env -e extensions/src/tool-log/index.ts -p "hello"` fails only on the expected "no API key" check — no exception from the extension factory or `session_start`.
  - `logs/` and `/.pi/` (Pi's project-local runtime config, created on first real run) added to `.gitignore` as runtime state, matching the existing `state/`/`evidence/` pattern.
  - **Not yet done — this is the resume point:** no Anthropic credentials exist on this VPS (`~/.pi` had never been initialized before this session). The reasoning core has never actually issued a tool call yet; only the wiring up to that point is proven. See Resume-here note.
- `95d1170` — Session 0: repo scaffolding — split TS/Python toolchain.
  - Provisioned the toolchain on the VPS itself: installed Node v20.19.2/npm 9.2.0 and Python 3.13.5 + venv/pip via apt (none were present before this session).
  - `extensions/` — TypeScript workspace for the future Pi extension layer (vision, delegation, red-lines, tool-log). `npm install && npm run hello` builds and runs. Plain tsconfig (ES2022/NodeNext, strict), no dependency on `pi/` yet.
  - `services/` — Python layer for the future KB/embeddings/vector-store/Metasploit-bridge code. `requirements.txt` pins pydantic, python-dotenv, requests, qdrant-client, pytest/pytest-asyncio. Venv at `services/.venv` (gitignored) verified: `python -m pluto_services.hello` runs.
  - Fleshed out `.gitignore` (build artifacts, venvs, secrets patterns, Pluto runtime state, and `/pi/` itself — see next bullet) and added a top-level `README.md` describing the layout, the split stack, the two gates, and the provisioning model (read from the Kali GUI VPS Setup Guide docx).
  - The Pi fork was already cloned at `pi/pi/` (nested `.git`) before this session started. Deliberately left **untracked** (`/pi/` added to `.gitignore`) and untouched — Session 1 decides how it's brought into this repo (submodule vs. vendored copy) and forks it for real.
  - Verified `git add -A -n` staged nothing sensitive before committing (no `node_modules/`, no `.venv/`, no `pi/`, no secrets).

## Session status board
- [x] Session 0  — Repo scaffolding
- [x] Session 1  — Fork Pi, bare-bones reasoning->shell loop
- [x] Session 2  — SQLite state schema
- [ ] Session 3  — Recon -> candidate finding
- [ ] Session 4  — Gate 1 validator (SQLi)            [Opus]
- [ ] Session 5  — Red-lines check + kill switch       [Opus]
- [ ] Session 6  — Seeded KB + fingerprint query
- [ ] Session 7  — Vision pipeline
- [ ] Session 8  — Metasploit integration
- [ ] Session 9  — Agent delegation                    [Opus]
- [ ] Session 10 — Remaining validators + skill catalog
- [ ] Session 11 — Engagement lifecycle
- [ ] Session 12 — HackTheBox dry run

## Open questions / blockers
- (none)

## Resume-here note (write before stopping, or when nearing a usage limit)
- **Session 2 is fully done.** Start the next session by loading `pluto-build` + `typescript-patterns`, then begin **Session 3 — Recon → candidate finding** per `CLAUDE_CODE_BUILD_PLAN.md`: implement the real Layer 4 feedback loop (execute → observe → update state → decide next) so Pluto actually grows the node tree and writes findings itself, instead of the hand-inserted single root node + manually-inserted findings that Session 2 used to prove the schema. Also seed per-service decision trees at the right priority (§5.1: default-cred/misconfig checks before CVE-path nodes) and "enforce the candidate status honestly — nothing is validated yet" (already true by construction since `findings-repo.create()` can't produce any other status, but Session 3 needs to keep it that way as real branching logic gets added).
- Toolchain notes: Node was upgraded from the Session-0-provisioned v20.19.2 to **v24.21.0**, installed to `/usr/local` (shadows the apt v20 install, which is untouched) — required because Pi's packages declare `engines.node >= 22.19.0`. `pi/pi` is a **submodule**, not vendored — `git submodule update --init` after a fresh clone. Pi is already built (`pi/pi/packages/coding-agent/dist/bundle/cli.js`); re-run `npm run build` in `pi/pi` only if the submodule pointer moves. `extensions/` also needs its own `npm run build` after a fresh clone (the state module is real TS now, not just hello-world).
- The Layer 2 state DB lives at `state/pluto.db` (gitignored, created on first `session_start`) — schema in `extensions/src/state/schema.ts`, typed repos in the same directory. Right now it has one target, one node, one attempts row, and two findings from the Session 2 smoke test; feel free to delete `state/pluto.db` for a clean slate when Session 3's real tree-growing logic needs to be tested from scratch, or keep it if continuing against the same "engagement."
- Pi has a working `ANTHROPIC_API_KEY` configured by the operator (not committed, per CLAUDE.md's secrets rule) — the operator is running a small budget ($5) against it, so **default to the cheapest model that fits the task** (`claude-haiku-4-5` has worked fine for every smoke test so far) and prefer one-shot `-p --no-session` invocations over open interactive sessions unless a session genuinely needs to persist, to avoid burning budget unnecessarily.
- Nothing is half-finished; the repo is in a clean, committed state.
