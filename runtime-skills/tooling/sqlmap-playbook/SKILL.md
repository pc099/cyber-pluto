---
name: sqlmap-playbook
description: Operational command-line playbook for driving sqlmap effectively during SQL injection testing. Use when confirming or exploiting SQLi with sqlmap. Covers targeting, tuning, tamper-based WAF evasion, and the restraint boundary — distinct from the SQLi vulnerability logic itself.
metadata:
  category: tooling
  tool: sqlmap
  pairs_with: sql-injection
  attack_ids: [T1190]
---

# sqlmap Playbook

Operational how-to for the tool, not the vulnerability logic (see the
`sql-injection` skill for that).

## Targeting
- From a request file: `sqlmap -r request.txt` (preserves headers/cookies/body).
- URL + param: `sqlmap -u 'http://host/item?id=1' -p id`.
- Mark the injection point inline with `*` for complex inputs.
- Authenticated: pass `--cookie`, `--headers`, or `--load-cookies`.

## Tuning
- Start low and escalate: `--level` (1→5, more vectors) and `--risk` (1→3).
- Pin the DBMS when known: `--dbms=mysql` to cut noise.
- Technique select: `--technique=BEUSTQ` (boolean/error/union/stacked/time/inline).
- Enumerate incrementally: `--dbs`, `--tables`, `--columns`, then a BOUNDED
  `--dump` with `--where`/`--start`/`--stop` — never `--dump-all` (that trips
  the exfiltration red-line, §10.4).

## Bypass & evasion (required)
- **Tamper scripts**: `--tamper=space2comment,between,charencode,...` to defeat
  WAF signatures; chain several and rotate on a block.
- **Pacing**: `--delay`, `--time-sec`, `--randomize`, random user-agent
  (`--random-agent`) to survive rate limits/WAFs.
- **Traffic shaping**: `--chunked`, `--skip-waf`, proxy via `--proxy` for an
  in-scope traffic-ID header.
- A WAF block is a fresh sub-problem: change tamper chain/technique, don't
  repeat the blocked request (the stall detector counts this as progress, §5.3).

## Restraint & Gate 1
sqlmap output is a strong lead but Pluto's own deterministic validator makes
the call — a confirmed sqlmap injection still enters state as a `candidate`
until the Gate 1 SQLi validator reproduces it (baseline vs attack, signal +
marker). Prove access; do not harvest real data beyond evidence needs.
