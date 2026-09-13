---
name: cross-site-scripting
description: Testing and confirming XSS (reflected, stored, DOM-based). Use when user input is reflected into HTML/JS/attributes, or a sink like innerHTML/eval is reachable. Covers filter/WAF/CSP evasion and ties confirmation to Pluto's headless-browser Gate 1 XSS validator (execution, not reflection).
metadata:
  category: vulnerabilities
  attack_class: injection
  validator: xss
  attack_ids: [T1059.007]
---

# Cross-Site Scripting

## Attack surface
Anywhere input is rendered: HTML body/text, tag attributes, `<script>` blocks,
event handlers, URLs (`href`/`src`), and DOM sinks (`innerHTML`, `document.
write`, `eval`, `location`). Reflected (same request), stored (persisted), and
DOM-based (client-side only) each need a different trigger path.

## Methodology
1. Inject a unique marker string; find where and how it is reflected (HTML
   text vs attribute vs JS string vs URL).
2. Craft a context-appropriate breakout (`"><script>`, `';alert()//`,
   `javascript:`), aiming to EXECUTE, not merely appear.
3. Confirm execution by an observable side effect the browser performs.

## Techniques
- **Context breakout**: close the current tag/attribute/string first.
- **Attribute injection**: `" onmouseover=... autofocus`, `"><svg onload=...>`.
- **JS-string**: break the quote, terminate the statement, comment the rest.
- **DOM**: trace the source→sink; no server round-trip needed.
- **Stored**: place the payload where a victim/admin view renders it.

## Bypass & evasion (required)
- **Filter evasion**: alternate tags/events (`<svg>`, `<img>`, `onerror`,
  `onload`, `onpointerover`), case variation, no-space payloads (`/` as
  separator), HTML entities, nested/broken tags the sanitizer mis-parses.
- **WAF**: split keywords, encode (`&#x6a;` for `j`), use `data:`/`javascript:`
  schemes, template-literal or `eval(atob(...))` construction.
- **CSP**: hunt for allowed script sources, JSONP endpoints, `unsafe-inline`
  gaps, dangling-markup and DOM-clobbering when script injection is blocked.
- Treat each filter as a fresh sub-problem; rotate vector/encoding.

## Validation (Gate 1)
Confirmed ONLY by the headless-browser validator observing the injected script
actually execute in the page's own document context (it sets a nonce as
`document.title` and the post-render DOM matches) — reflection of the raw
payload is explicitly NOT proof. No PoC, no finding.
