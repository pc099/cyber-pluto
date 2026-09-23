---
name: web-content-discovery
description: The web reconnaissance and content-discovery playbook — how to map a web target's UNAUTHENTICATED attack surface and find non-obvious entry points (upload/write endpoints, hidden files, admin panels) before touching authentication. Use at the start of every web engagement and whenever recon has stalled. Fixes the failure mode where enumeration = "gobuster with one stock wordlist", which misses paths that aren't dictionary words, then falls back to brute-forcing auth for lack of a better idea.
metadata:
  category: tooling
  tool: gobuster/ffuf/cewl
  pairs_with: file-write-rce
  attack_ids: [T1595, T1592, T1190]
---

# Web Content Discovery & Recon Methodology

The point of this skill: **most footholds are behind a path a stock wordlist run
does not reach.** On the Matrix-Breakout box, the foothold was `graffiti.php` on
port 80 — invisible to `dirb/common.txt`, reached only by a good wordlist run
**with the right extensions**, or by chasing a clue. Enumeration is a
*methodology*, not one gobuster command.

## Order of operations (do these BEFORE brute-forcing anything)

1. **Fingerprint every service and every vhost.** `whatweb -a 3 <url>`; note the
   server (Apache vs nginx — they often serve *different* apps on 80 vs 81),
   frameworks, and versions. Fuzz vhosts (`ffuf -H "Host: FUZZ.<target>"`).
2. **Read what the target tells you.** `curl` the root, `/robots.txt`,
   `/sitemap.xml`, `/.well-known/`, error pages; **view the HTML source and every
   linked JS/CSS file** for comments, paths, API routes, and hints. Pull image
   metadata (`exiftool`) and check for steganography (`steghide`, `binwalk`) —
   themed images often hide creds or hints.
3. **Mine the site for a custom wordlist.** `cewl -d 2 -m 4 <url> -w custom.txt`
   turns the page's own vocabulary (names, themes, product terms) into candidate
   paths — the words a generic dictionary lacks.
4. **Content discovery — the recipe that actually works:**
   ```
   gobuster dir -u http://<target>/ \
     -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt \
     -x php,txt,bak,html,zip,old -t 40
   # then raft-large-files.txt, then your cewl custom.txt
   ```
   - **ALWAYS pass `-x` extensions.** A `.php` file lands under its bare word in
     the DIR list (`graffiti` + `-x php` → `graffiti.php`). This single flag is
     the difference between finding the endpoint and missing it.
   - **Escalate wordlists on a miss:** small → `raft-large-*` → your cewl list →
     `directory-list-2.3-medium`. "No hits" means *use a bigger/other list*, not
     *give up*.
5. **Probe for functional / write endpoints specifically.** Look for
   `upload`, `graffiti`, `write`, `save`, `admin`, `dev`, `backup`, `.git`,
   `.php~`/`.bak` source-disclosure. For anything that takes input, test what it
   writes and where it surfaces (→ hand off to the `file-write-rce` validator).

## Chase clues; don't checkbox

A discovered hint (a name in an image, a theme, a comment, a redirect, a 403 that
implies something exists) is a **lead to pursue**, not a line item. If the site
is Matrix-themed, feed `neo/trinity/morpheus/cypher/graffiti` into paths AND
wordlists. Iterate: each finding narrows the next guess.

## Authentication is LAST, and budgeted

Credential brute-forcing (hydra, etc.) is **almost never the intended path** on a
CTF/target and is noisy + lockout-risky. Do it ONLY after the unauth surface is
fully mapped, and cap it: a bounded try-budget (one modest wordlist, a few
hundred tries), not tens of thousands of requests. If a small credential set
fails, that is a signal to go back to content discovery — the way in is usually
an unauthenticated endpoint you have not found yet, not a password you have not
guessed.

## Restraint

Passive/enumeration is fine; stay in scope, pace requests, and never DoS. Prove
the door exists (a 200 on a write endpoint, a served upload) and hand off to the
matching Gate-1 validator — do not walk through it.
