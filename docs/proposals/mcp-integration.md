# Proposal: MCP tool integration (for board review — NOT yet built)

Status: DRAFT for the 4-agent board. Blocked on building until the board
reviews (board subagents rate-limited; boarding when the limit resets). This is
a consequential, security-touching change, so it goes through the board.

## Verified facts (checked in Pi source, not assumed)

- **Pi has NO native MCP support.** One incidental *comment* mentions "MCP
  bridges"; there is no MCP client, transport, or server-connection code.
- **The integration seam is Pi's `registerTool()` / customTools extension API.**
  Plan: a Pi extension `mcp-bridge` that is an MCP CLIENT — connects to MCP
  servers (stdio/SSE), enumerates their tools over the protocol, and registers
  each as a Pi custom tool that proxies calls.
- **Red-lines GATES custom tools.** `agent-session.ts` installs a global
  `beforeToolCall` that fires the `tool_call` event for EVERY tool (built-in and
  registered) — so an MCP-bridged tool passes through the red-lines check and a
  `{block:true}` stops it. MCP is NOT a blanket gate bypass. (Caveat: red-lines'
  rules are tuned for bash command TEXT; for structured MCP args
  `toInvocation` scans `JSON.stringify(input)`, which catches an obvious
  `{"target":"8.8.8.8"}` but needs per-tool review for offensive actions and
  hosts not in an obvious field.)

## The requested servers, categorized by risk (operator's list)

- Recon/intel that EGRESSES externally: Shodan, Censys, VirusTotal, GitHub,
  Nmap/Nuclei (Nuclei/Nmap also touch the target). Under the sandbox these hit
  the egress allowlist — see the open questions.
- Offensive / must be gated by the two gates + red-lines: Metasploit (module
  search + controlled exploitation), Nuclei (template scanning), Nmap.
- Local analysis: Ghidra (RE), Playwright/browser (DOM/screenshots — overlaps
  the existing vision pipeline), BloodHound (AD), Qdrant/vector (overlaps the
  existing KB), Database (evidence/state queries — overlaps the state DB).

## The design questions the board must resolve

1. **Where do MCP servers run vs. the sandbox?** The v0 sandbox filters egress
   by `meta skuid pluto`. An MCP server that runs as `pluto` is egress-filtered
   (good); one that runs as another user (a system service) is NOT — its calls
   bypass the owner-match allowlist. So: run MCP servers AS `pluto` inside the
   same confinement, or treat a host-side MCP server as a trusted egress
   exemption? This is the crux.
2. **Two-gate integrity.** An MCP result ("Nuclei found CVE-X", "Shodan says
   port open") is a CANDIDATE, never a validated fact — it must land as
   `candidate` and still require a deterministic Gate-1 validator. MCP must not
   become a backdoor that promotes findings.
3. **Red-lines coverage of structured MCP args.** The scope/prohibited-action
   check must be extended to reason about MCP tool arguments (target host,
   action) per server, not just bash text — else a `metasploit.exploit(rhost=…)`
   could slip a category the bash-tuned rules miss.
4. **External-intel data handling + egress allowlist.** Shodan/Censys/VT/GitHub
   need their API endpoints on the egress allowlist and their API keys handled
   like provider creds (env-injected, not on disk). Sending target identifiers
   to 3rd-party intel is itself a disclosure — Gate/scoping implications for bug
   bounty.
5. **Overlap with existing capabilities.** Playwright≈vision, Qdrant≈KB,
   Database≈state DB, and provision_capability already installs tooling. Decide
   which MCP servers ADD capability vs. duplicate/replace existing extensions
   (avoid two sources of truth).
6. **Trust of the MCP servers themselves.** Third-party MCP servers are code +
   a prompt-injection surface (their tool descriptions enter the model context).
   Which are allowlisted, pinned by version, and run confined?
7. **Config surface.** MCP server list belongs in operator config (like
   `.pi/settings.json` / a scope file), applied at launch — never agent-writable
   (same principle as the egress allowlist).

## Proposed v0 (to be grilled, once boarded)

A single `mcp-bridge` extension + an operator-config list of MCP servers, each
run AS `pluto` inside the sandbox (so egress + red-lines + no_new_privs all
apply), tools registered via `registerTool()` (so the tool_call gate fires),
results recorded as `candidate` evidence that still needs Gate-1 validation,
external-intel API keys env-injected and their endpoints added to the egress
allowlist. Start with ONE low-risk server end-to-end (e.g. a Nmap or a
vector/KB MCP) to prove the bridge + gating, before adding offensive ones.

## Non-goals (v0)

The full 10-server suite at once; replacing the existing vision/KB/state
extensions; any MCP server that can't run confined as `pluto`.
