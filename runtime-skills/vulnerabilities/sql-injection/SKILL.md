---
name: sql-injection
description: Testing and confirming SQL injection (error-based, boolean/blind, UNION, time-based). Use when a parameter reaches a SQL query, a DB error surfaces, or a numeric/string input changes result sets. Covers WAF evasion and ties confirmation to Pluto's Gate 1 SQLi validator.
metadata:
  category: vulnerabilities
  attack_class: injection
  validator: sqli
  attack_ids: [T1190]
---

# SQL Injection

## Attack surface
Any input that reaches a SQL statement: query/body/header params, search
fields, sort/order clauses, JSON fields, cookies. Numeric contexts (`id=1`),
string contexts (`'...'`), and identifier contexts (ORDER BY, column names)
each need different breakouts.

## Methodology
1. Baseline the endpoint with a known-good value; record the normal response.
2. Probe for a signal: append `'`, `"`, `)`, `--` and watch for DB errors or
   response changes. Try a boolean pair (`AND 1=1` vs `AND 1=2`).
3. Determine the injection context and DBMS from errors/behaviour.
4. Escalate minimally to prove impact, then STOP — extraction of a
   self-chosen marker is enough; do not dump real data (restraint, §4.5).

## Techniques
- **Error-based**: malformed syntax returns a DBMS error string.
- **Boolean-blind**: true/false conditions flip the response deterministically.
- **UNION**: match column count (`ORDER BY n` / `UNION SELECT NULL,...`), then
  reflect a nonce marker to prove attacker-controlled output.
- **Time-based blind**: `SLEEP(5)` / `pg_sleep(5)` / `WAITFOR DELAY` — measure
  the delta. For fully blind, use the OOB channel (§4.7).

## Bypass & evasion (required)
A WAF block is a sub-problem, not a dead end.
- **Encoding**: URL/double-URL encode, hex (`0x...`), char() concatenation,
  unicode/overlong forms, comment insertion (`/**/`, `/*!50000...*/`).
- **Tamper-style mutation**: case randomization, whitespace alternatives
  (`/**/`, `%09`, `%0a`), `OR` → `||`, keyword splitting.
- **Parser discrepancies**: exploit differences between the WAF's parser and
  the DB's (nested comments, backticks, alternate operators).
- **Logic**: swap `AND`/`OR` for arithmetic, use subqueries the signature
  doesn't match. Rotate techniques rather than repeating a blocked payload.

## Validation (Gate 1)
Not a finding until the deterministic SQLi validator reproduces it: a
technical signal (DB error OR boolean differential) AND an impact artifact
(UNION-reflected marker), baseline vs attack. Blind cases confirm ONLY via a
correlated OOB callback (§4.7). No PoC, no finding.
