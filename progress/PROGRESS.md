# Pluto Build — Progress Ledger

**Resume protocol:** read this file top-to-bottom at the start of every session. It is the single source of truth for *where the build is right now*. Keep it current **as you work** — update it after every meaningful increment, not just at session end — so a usage-limit cutoff never loses more than the current small step.

## Current position
- **Phase:** 0 — Environment & Scaffolding
- **Active session:** Session 0 — Repo scaffolding
- **Status:** done
- **Next concrete action:** Session 1 — fork Pi into the repo for real, get the base agent loop running unmodified, confirm the reasoning core can issue a shell command and observe structured output, log every tool invocation from day one.

## In flight (granular — what is being done *right now*)
- (nothing — Session 0 closed out cleanly)

## Done (most recent first — with commit hash)
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
- (none)

## Resume-here note (write before stopping, or when nearing a usage limit)
- **Session 0 is done and committed (`95d1170`).** Start the next session by loading the `pluto-build` skill plus `typescript-patterns` (Pi fork work is TS).
- **Session 1 scope, exactly** (per `CLAUDE_CODE_BUILD_PLAN.md`): fork Pi (`earendil-works/pi`) into the repo — decide submodule vs. vendored copy for the already-cloned `pi/pi/` (currently untracked, gitignored via `/pi/`) — get its base agent loop running unmodified, confirm the reasoning core can issue a real shell command (e.g. `nmap -sV` against a lab target) through Pi and read structured output back, and log every tool invocation in full from day one (this doubles as the audit trail and the future self-learned-KB dataset). Don't touch the state schema (that's Session 2) or add any gate/red-lines logic yet (Sessions 4–5).
- Toolchain is already provisioned on this VPS: Node v20.19.2/npm 9.2.0, Python 3.13.5 with venv/pip. No need to reinstall.
- `extensions/` (TS) and `services/` (Python) both have a working hello-world — don't rebuild them, extend them.
- Nothing is half-finished; the repo is in a clean, committed state.
