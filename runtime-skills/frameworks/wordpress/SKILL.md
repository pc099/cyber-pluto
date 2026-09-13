---
name: wordpress
description: Testing WordPress sites and stacks. Use when WordPress is fingerprinted (wp-content, wp-login, generator meta, /wp-json). Covers core/plugin/theme enumeration, common WordPress vulnerability classes, WAF/hardening evasion, and ties confirmation back to Gate 1.
metadata:
  category: frameworks
  stack: wordpress
  attack_ids: [T1190, T1210]
---

# WordPress

## Attack surface
`wp-login.php`, `xmlrpc.php`, the REST API (`/wp-json/`), `wp-content/plugins`
and `themes`, `wp-config.php` exposure, uploads dir, and admin AJAX
(`admin-ajax.php`). Most real breaks are in **plugins/themes**, not core.

## Methodology
1. Fingerprint version (generator meta, `readme.html`, asset `?ver=`).
2. Enumerate plugins/themes and their versions; map each to known CVEs via the
   KB (fingerprint → CVE trigger, §2.5).
3. Prioritize §5.1's cheap wins: default/weak admin creds, user enumeration
   (`?author=1`, REST `/wp-json/wp/v2/users`), exposed backups/config.
4. Then the CVE path for a vulnerable plugin/theme.

## Techniques
- **User enum + auth**: author scans, XML-RPC `system.multicall` for fast
  credential testing, login brute (rate-limited).
- **Plugin/theme CVEs**: arbitrary upload, LFI, SQLi, auth bypass — feed each
  into the matching vulnerability skill + validator.
- **Config/backup exposure**: `wp-config.php~`, `.sql` dumps, debug logs.

## Bypass & evasion (required)
- **WAF (Wordfence-style)**: rotate SQLi/XSS encodings (see those skills),
  slow/throttle to dodge rate limits, vary user-agent and source.
- **XML-RPC when login is locked**: `system.multicall` amortizes attempts and
  often escapes login rate limits.
- **Login protection**: pivot to REST/xmlrpc auth surfaces; treat a block as a
  fresh sub-problem, not a stop.

## Validation (Gate 1)
A plugin/theme CVE is a candidate until its class validator (SQLi, upload→RCE,
LFI/traversal, etc.) deterministically reproduces it. A version match alone is
only a `candidate` (backporting) — never `validated`. No PoC, no finding.
