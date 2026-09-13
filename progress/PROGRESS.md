# Pluto Build — Progress Ledger

**Resume protocol:** read this file top-to-bottom at the start of every session. It is the single source of truth for *where the build is right now*. Keep it current **as you work** — update it after every meaningful increment, not just at session end — so a usage-limit cutoff never loses more than the current small step.

## Current position
- **Phase:** 1 — The Vertical Slice
- **Active session:** Session 1 — Fork Pi, bare-bones reasoning-to-shell loop
- **Status:** in flight — blocked on operator input (Pi has no Anthropic credentials on this VPS)
- **Next concrete action:** get an API key (or a completed `/login` OAuth) into Pi, then run the live smoke test: a real prompt through `pi` that issues `nmap -sV localhost` via the bash tool and reads the structured result back, with `logs/tool-invocations.jsonl` showing the full tool_call/tool_execution_end pair.

## In flight (granular — what is being done *right now*)
- Waiting on the operator to choose how to authenticate Pi (API key vs. interactive OAuth login) — see Open questions below. Everything else in Session 1's scope is done; only the live end-to-end run remains.

## Done (most recent first — with commit hash)
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
- [ ] Session 1  — Fork Pi, bare-bones reasoning->shell loop
- [ ] Session 2  — SQLite state schema
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
- **Pi has no Anthropic credentials on this VPS.** `~/.pi` doesn't exist yet — this is the first time Pi has been run here. Need the operator to choose: (a) supply an `ANTHROPIC_API_KEY` (env var or `--api-key`), or (b) run `pi` interactively themselves and complete `/login` (OAuth needs a browser, so it can't be done headlessly from this session). Asked the operator; awaiting their answer.

## Resume-here note (write before stopping, or when nearing a usage limit)
- **Session 1 is in flight, committed at `4cc442d`.** Everything is done except the live demo. Start the next session by loading `pluto-build` + `typescript-patterns`, then read the "Open questions" entry above first.
- **The moment credentials are available**, run the smoke test from the repo root:
  `./pi/pi/pi-test.sh -e extensions/src/tool-log/index.ts -p "Run nmap -sV against localhost and summarize the open services you find."`
  (`localhost` is the deliberate lab target — no external network dependency, unambiguously in-scope since it's this VPS itself, and Session 2+'s `targets.scope_notes` doesn't exist yet to authorize anything else.)
- **Definition of done for Session 1** (don't stop short of this): the prompt above actually runs `nmap` via Pi's bash tool, Pi reads the structured result back into its response, and `logs/tool-invocations.jsonl` shows a `tool_call`/`tool_execution_end` pair for it with the real command and real output captured. Then commit the log file's *existence* is not what's committed (it's gitignored, runtime data) — just confirm it, note the result in this ledger, and mark Session 1 done on the status board.
- Do **not** start Session 2 (SQLite state schema) in the same sitting unless explicitly asked — Session 1 ends at the shell-command proof, per the build plan.
- Toolchain notes for next time: Node was upgraded from the Session-0-provisioned v20.19.2 to **v24.21.0**, installed to `/usr/local` (shadows the apt v20 install, which is untouched) — this was required because Pi's packages declare `engines.node >= 22.19.0`. `pi/pi` is a **submodule**, not vendored — `git submodule update --init` after a fresh clone. Pi is already built (`pi/pi/packages/coding-agent/dist/bundle/cli.js`); re-run `npm run build` in `pi/pi` only if the submodule pointer moves.
- `extensions/` (TS) and `services/` (Python) both have a working hello-world plus now `tool-log`; `extensions/package.json` depends on `@earendil-works/pi-coding-agent` via a `file:` link into the submodule for types only (erased at Pi runtime via `import type`, so it isn't a runtime dependency).
- Nothing else is half-finished; the repo is otherwise in a clean, committed state.
