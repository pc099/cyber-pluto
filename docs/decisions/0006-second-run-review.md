# Decision 0006 — Board review of the SECOND live run (black-box, 192.168.122.150)

Four-member board review of Pi session `01a0ce52` (engagement
`engagement-192-168-122-150`) — the re-run against a pristine box at a new IP,
on OpenAI, with the Decision-0005 remediation live. All four VERIFIED against the
ledger, tool log, and transcript.

## Verdict: PASS on integrity/remediation, INCOMPLETE (FAILED) on capability

- **The remediation WORKED (all four confirmed from the data):** zero disk-image
  access anywhere in the log (the cheat is gone), the provisioned tools were used
  (gobuster/hydra/ffuf/nikto/whatweb/steghide/binwalk, not hand-rolled curl),
  token use dropped 4.0M→1.08M, and the ledger is honest — 0 validated, 0 creds,
  0 promotions, **no fabricated "engagement complete"** (griller grepped: none;
  the final texts say "not productive," "no traction").
- **But it got 0 FOOTHOLD.** It found the surface (port-81 Basic-Auth "Meeting
  Place", `.php`/Upload refs, trinity.jpeg) and reasoned well (guessed themed
  creds, tried CVE-2021-41773 traversal, vhost fuzz, steg) but never reached
  `graffiti.php` and failed to crack the Basic Auth. **The griller's die-on
  condition — prove black-box recon finds a vuln over the network — was tested
  and FAILED.** Run 1 only "won" by cheating.
- **Honest incapacity is still incapacity (griller):** do not launder the
  negative into a positive. The fixes removed a cheat; they added no capability.
- **The run was CUT SHORT (griller):** it stopped at 57/200 calls, ~1.08M/4M
  tokens, ~42 min — mid-investigation (reasoning about a CVE), under every cap.
  Not victory, not genuine exhaustion — "still trying when it stopped."

## The two "0 validated" runs mean OPPOSITE things — and the ledger can't tell (QA)

Run 1 = real-but-uncounted RCE; Run 2 = nothing found. From the ledger alone QA
**cannot distinguish them** — there are no run-level outcome fields. This is the
metrics blind spot the whole effort exists to catch.

## Ratified fixes (priority order)

1. **Prove the `file_write_rce` validator LIVE (the still-open verification gap).**
   It is built + unit-tested but was **never invoked** (0 foothold), so the fix
   that started this remains live-UNVERIFIED. Cheapest closure: point
   `validate_file_write_rce` at `graffiti.php` **directly** (endpoint known from
   run 1), decoupled from recon — it must promote candidate→validated with a
   signed attestation + verified cleanup (zero `artifactRefs`). QA's gate.
2. **Recon dedup + real candidates.** `recon/index.ts growTreeFromNmapOutput`
   blind-`INSERT`s a finding per service per nmap (no lookup) → the 11 "findings"
   are 3 services re-recorded ~4× (a `-p-` scan even re-labels 81 `hosts2-ns`).
   Fix: `SELECT by (target_id, port, protocol)` then enrich nulls, never insert a
   duplicate. Also: these are bare *service fingerprints* at conf 0.5, not vuln
   candidates. Unit test: two nmap parses of one port → one candidate.
3. **Run-summary telemetry (QA).** A per-engagement outcome row: `max_phase`
   (recon/foothold/privesc), `foothold_bool`, `best_finding_status`,
   `stop_reason` (cap / stuck / agent-concluded / cut-short). Makes "0 validated"
   interpretable and `/summary` honest ("3 services, 0 vuln candidates", not
   "11 findings").
4. **Discovery METHODOLOGY, not just wordlists (griller vs architect — resolved
   as a stack).** Immediate/cheap (architect): provision **SecLists**
   (raft-large) as the default dir-brute list with `-x php` + an auto "no hits →
   escalate wordlist" pivot. Deeper/real (griller — the *disease*): clue-driven
   enumeration — mine page source / robots / image metadata / comments for
   target-specific paths, generate a custom wordlist (`cewl`), and treat a
   discovered clue as a lead to CHASE, not a checkbox. Wordlist is the symptom;
   methodology is the disease. Both ship; SecLists first, methodology is the
   larger build.
5. **Stuck/foothold-stall detection (architect + QA).** `detectStuck` only trips
   on exact repeated calls / no-new-nodes; nodes grew each nmap, so 57 fruitless
   attempts were invisible, and headless has no operator to page. Add a
   phase/foothold non-advancement signal.
6. **ATT&CK tagging gap (griller):** 44 of 57 attempts carry no technique tag —
   a violation of invariant #4 (everything logged + tagged). Fix the tagging path.
7. **Red-line FALSE POSITIVE (cybersecurity — new):** the one `out_of_scope_scanning`
   block fired on `127.0.0.1` that appeared only inside HTTP HEADERS
   (`X-Forwarded-For: 127.0.0.1`, `X-Real-IP: 127.0.0.1`) — a legitimate 401/ACL
   **auth-bypass** technique against the in-scope `…150:81`. The scope rule
   string-matches IP literals ANYWHERE in the command, not the connection target,
   so it killed one of the more promising attempts and shoved Pluto back to
   brute-forcing. Fix: key scope on the actual network DESTINATION, not
   payload/header substrings.
8. **Brute-force under-recording + no rate budget (cybersecurity — new, serious):**
   the hydra activity was NOT "2 runs / ~700 tries" — it was **8 invocations /
   ~173,000 Basic-Auth requests** at ~8,700/min for 20+ min, but the `attempts`
   ledger recorded only **2 of the 8** — the audit trail under-reports the
   noisiest activity by ~2 orders of magnitude (invariant #4 breach, same family
   as the tagging gap). Add a **brute-force volume/rate budget** (cap tries,
   pace) and ensure every invocation is recorded. Basic-Auth brute is almost
   never the intended path — it should sit BEHIND unauth surface-mapping.

## Cybersecurity's framing of the #1 fix

Make **unauthenticated attack-surface mapping the MANDATORY first phase** — real
content discovery (provision SecLists; systematically probe upload/write/
functional endpoints; convert theme hints into targeted guesses) — and **demote
credential brute-forcing behind it under a hard try-budget**. The miss was caused
directly by a thin wordlist + mis-prioritised effort (it brute-forced auth
because it had no better idea). This reinforces fix #4 (methodology) as the real
capability lever, and adds the try-budget from fix #8.

## Bottom line

Integrity: proven twice over. Capability: unproven — the harness cannot yet
solve an easy box black-box. The die-on stays OPEN. Next: verify the validator
live (1), make the ledger honest (2–3), then attack the discovery disease (4)
before re-running.
