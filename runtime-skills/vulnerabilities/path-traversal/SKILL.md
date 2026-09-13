---
name: path-traversal
description: Testing and confirming path/directory traversal and local file inclusion. Use when a parameter names a file, path, template, or download. Covers filter/normalization evasion and ties confirmation to Pluto's Gate 1 path-traversal validator (a system file served from outside the web root).
metadata:
  category: vulnerabilities
  attack_class: injection
  validator: path_traversal
  attack_ids: [T1083, T1006]
---

# Path Traversal / LFI

## Attack surface
Parameters naming a file or path: `?file=`, `?page=`, `?template=`,
download/export endpoints, image/asset loaders, and anywhere a path is built
by concatenation without containment.

## Methodology
1. Baseline with a legitimate filename.
2. Inject traversal sequences toward a known, low-sensitivity system file
   (`/etc/passwd`, `C:\windows\win.ini`).
3. Confirm by matching the file's signature in the response — a file served
   from outside the intended root is both signal and impact.

## Techniques
- **Sequences**: `../`, `..\\`, absolute paths, deep nesting.
- **LFI-to-more**: PHP wrappers (`php://filter`, `data://`), log poisoning,
  `/proc/self/environ` — only to prove reachability.
- **Null/truncation** (legacy): `%00`, path length tricks.

## Bypass & evasion (required)
- **Encoding**: `%2e%2e%2f`, double-encode (`%252e`), unicode/overlong
  (`%c0%ae`), mixed separators (`..%5c`).
- **Filter-strip bypass**: nested sequences that survive one-pass removal
  (`....//`, `..././`), redundant separators, trailing dot/space on Windows.
- **Allowlist bypass**: append a required prefix/suffix the check expects
  then traverse (`allowed/../../etc/passwd`), or use a valid extension the
  wrapper ignores. Rotate encodings on a block.

## Validation (Gate 1)
Confirmed by the path-traversal validator: a traversal payload returns a known
system file's contents (e.g. `/etc/passwd` matching `root:x:0:0`) that the
normal endpoint never serves — signal and impact in one artifact, baseline vs
attack. Reads one well-known file to prove reachability; does not harvest app
data. No PoC, no finding.
