---
name: ssrf
description: Testing and confirming server-side request forgery, including blind SSRF. Use when the server fetches a user-supplied URL/host (webhooks, importers, PDF/image renderers, URL previews, proxies). Covers allowlist/filter evasion and ties confirmation to Pluto's out-of-band interaction server for blind cases (§4.7).
metadata:
  category: vulnerabilities
  attack_class: server-side
  validator: ssrf
  attack_ids: [T1090, T1135]
---

# Server-Side Request Forgery

## Attack surface
Any feature where the server makes an outbound request to a value you control:
webhook/callback URLs, document/image/PDF importers, URL preview/unfurl,
open proxies, XXE-driven fetches, and integrations that "fetch this URL".

## Methodology
1. Point the fetch at infrastructure you control and confirm the server
   connects.
2. Non-blind: read back internal resource content (cloud metadata
   `169.254.169.254`, internal admin, `file://`).
3. Blind (no response reflected): use the OOB channel — the only valid
   evidence is a correlated callback.

## Techniques
- **Internal targets**: `127.0.0.1`, link-local `169.254.169.254` (cloud
  metadata), internal hostnames, non-HTTP schemes (`file://`, `gopher://`,
  `dict://`).
- **Blind confirmation**: embed a unique OOB callback URL and watch for the
  DNS/HTTP hit (§4.7).
- **Port/host discovery**: response/timing differences reveal open internal
  services.

## Bypass & evasion (required)
- **Allowlist/filter bypass**: alternate IP encodings (decimal `2130706433`,
  octal, hex, IPv6 `[::1]`, `[::ffff:127.0.0.1]`), DNS rebinding, a domain that
  resolves to an internal IP, `@`-confusion (`http://allowed@internal/`),
  redirects (302 to internal), and case/trailing-dot host tricks.
- **Scheme filters**: try `gopher://`/`dict://` for non-HTTP interactions.
- Each blocked bypass is a fresh sub-problem — rotate the encoding/rebind.

## Validation (Gate 1)
Non-blind: the internal resource content returned proves it. Blind: confirmed
ONLY by a correlated out-of-band callback on a unique subdomain/id via Pluto's
self-hosted OAST server (`services/pluto_services/oob`, §4.7), polled
asynchronously since the callback may arrive late. A logged interaction on the
unique id is unambiguous — the target itself reached Pluto-controlled infra.
No PoC, no finding.
