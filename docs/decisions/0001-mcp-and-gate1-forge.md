# Decision 0001 — MCP integration + the Gate-1 forge (unanimous board)

Decided by the 4-agent review board (harness-architect, cybersecurity, griller,
QA) with a huddle. **Unanimously ratified.** The Architect withdrew its initial
MCP-bridge approval during the huddle.

## Decision

1. **Item 0 — BLOCKING P0: fix the Gate-1 forge, BEFORE any tool integration.**
   Under the sandbox, `pluto` can write `engagements/<label>/state/pluto.db`, so
   `sqlite3 pluto.db "UPDATE findings SET status='validated' WHERE id=42"`
   forges a validated finding. Red-lines does NOT catch it (its destructive-SQL
   rule only fires on a `WHERE`-less UPDATE; a targeted promotion has a WHERE).
   This breaches CLAUDE.md invariant #1 ("only a deterministic non-LLM validator
   promotes candidate→validated") and Gate-2 does NOT cover it (a human trusts
   the provenance stamp; a forged row is a lie wearing that stamp).
   - **Root cause:** the agent and the Gate-1 validator run as the SAME uid
     (`pluto`) in the sandbox, so no in-process secret can distinguish a
     legitimate promotion from a forged one.
   - **Fix (ratified direction):** promotion must be a PRIVILEGED path outside
     pluto's reach. Preferred: **asymmetric-signed promotions** — a root-held
     private key signs `(finding_id, validator, evidence_hash)` after
     re-verifying the passed validation; consumers (report builder, Gate-2,
     status counts, `/findings`) verify with a readable PUBLIC key and treat any
     `validated` row without a valid signature as tampered → demote to candidate
     + alert. A raw `UPDATE status='validated'` yields an unsigned row that every
     consumer rejects. (Alt: a root-owned authoritative store pluto can't write.)
   - This is a real architectural change, not a red-lines patch. It must land
     first; until it does, "results land as candidate and still need Gate-1" is
     not a real guarantee.

2. **No MCP bridge in v0.** Build thin per-vendor **REST extensions** modeled on
   `extensions/src/vision/` — hand-declared typed schema, explicit host param
   (e.g. `shodan_host(ip)`), result lands as **candidate only**, key
   env-injected, endpoint added to the egress allowlist by the root launcher.
   First: **Shodan**, with a **disclosure check** on the `ip` param (may this
   target identifier be sent to a third party? — the scope rule gates the wrong
   thing here, since Shodan never contacts the target). Log each call as a
   disclosure event (ATT&CK **T1596**).
   - Rationale (unanimous): for a gated harness, MCP adds no capability over a
     REST call through the same egress gate; its one feature (protocol tool
     auto-discovery) is a negative (you must hand-declare schemas so red-lines
     can reason about args); third-party MCP servers are unvetted in-process
     code as `pluto` + tool-descriptions-as-injection (violates the Never list);
     each stdio server is a resident process (OOM on a swapless 3.8 GB box); and
     every current-list tool has a REST/CLI surface.

3. **Defer — do NOT reject — the generic `mcp-bridge`,** behind a precise
   RE-OPEN TRIGGER (all three): (a) the capability needs iterative access to a
   running tool's INTERNAL LIVE STATE; (b) no documented REST/RPC/CLI gives
   equivalent programmatic access; (c) the server is first-party or small enough
   to fully audit + version-pin. Conceded genuine future cases: **Ghidra**
   (interactive decompilation DB), **Burp** (proxy-history/repeater, PortSwigger
   first-party MCP), and the **already-planned MSF bridge** (offensive → still
   behind the two gates). None of the current external-intel/CLI tools qualify.

4. **Offensive/CLI tools stay on bash** (Nmap/Nuclei/Metasploit). **Reject**
   Database MCP (raw SQL = Gate-1 bypass), Qdrant (dup of the KB), Playwright
   (dup of the vision pipeline) — regardless of transport.

5. **QA GO/NO-GO gate** for any tool that ships: the gate blocks an out-of-scope
   arg BEFORE execution (stub records zero calls); results are candidate-only;
   egress-DROP proven on the box as `pluto`; server/config not agent-writable;
   no regression (baseline 56/56). Fixtures: a stub server (happy / malicious-
   metadata / crash / hang / malformed) — never hit real Shodan in tests.

## Recorded residual / deferred

- **CDN egress enforceability** (Shodan/VT/Censys behind rotating CDN IPs;
  nftables allowlist is by IP) — needs the Milestone-2 DNS-set allowlisting, or
  an accepted+documented over-broad range. Transport-independent.

## Status

Ratified; not yet built. **Item 0 is the next build** and is a security-critical
architectural change to be built carefully (privileged signer + signed
promotions + consumer verification + tests), not rushed. The Shodan REST
extension follows Item 0.
