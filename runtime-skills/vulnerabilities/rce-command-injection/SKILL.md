---
name: rce-command-injection
description: Testing and confirming OS command injection and remote code execution. Use when input reaches a shell, exec, template, or deserialization sink, or when a service runs user-supplied data. Covers filter/WAF evasion and ties confirmation to Pluto's Gate 1 command-injection validator, proving the door opens without walking through it.
metadata:
  category: vulnerabilities
  attack_class: injection
  validator: command_injection
  attack_ids: [T1059, T1190]
---

# RCE / Command Injection

## Attack surface
Inputs reaching a shell (`system`, `exec`, backticks), argument builders,
filename/path handlers, `ping`/`nslookup`-style features, template engines
(SSTI), and unsafe deserialization. Also file-upload → execution paths (the
bespoke-delivery case, §2.3.2).

## Methodology
1. Identify a likely sink (a feature that shells out, renders a template, or
   deserializes).
2. Inject a benign marker command and look for its output in the response or
   an OOB callback.
3. Confirm real execution with read-only host recon (`id`, `uname`), then
   STOP — do NOT escalate to full control. Reachability proves impact (§4.5
   restraint).

## Techniques
- **Command separators**: `;`, `|`, `&`, `&&`, `||`, `$( )`, backticks,
  newline (`%0a`).
- **Blind**: no output → use time delay (`sleep 5`) or an OOB callback
  (`curl <oast>`), confirmed via §4.7.
- **SSTI**: `{{7*7}}`, `${7*7}`, `#{7*7}` to detect the engine, then its RCE
  gadget.
- **Deserialization**: language-specific gadget chains (only to prove
  reachability).

## Bypass & evasion (required)
- **Filter evasion**: quote/backslash insertion (`w'h'oami`), `$IFS` for
  spaces, brace expansion, variable indirection (`${PATH:0:1}` → `/`), hex/
  base64 (`echo ... | base64 -d | sh`).
- **WAF**: encode payloads, avoid blocked binaries via absolute paths or
  busybox, chunk the command, use globbing (`/???/c?t`).
- **Allowlist bypass**: argument injection, wildcard/option injection
  (`--`, `-o`), env-var abuse. Rotate rather than repeat.

## Validation (Gate 1)
Confirmed by the command-injection validator: an injected `echo <nonce>`
appears in the response (technical signal) AND `id`/`uname` output confirms
real host execution (impact). Blind RCE confirms via an OOB callback (§4.7).
No PoC, no finding — and never beyond proof-of-reachability.
