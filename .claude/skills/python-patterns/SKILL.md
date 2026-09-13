---
name: python-patterns
description: "Python coding patterns for Pluto's surrounding services — knowledge-base ingestion, embeddings, the vector-store (Qdrant) client, and the Metasploit MCP bridge. Load this whenever writing or editing Python in the Pluto repo. Covers project layout, the KB ingestion pipeline, structured-data typing, async OOB-callback polling for blind validators, and idempotent/testable ingestion. Use alongside the pluto-build skill; defer to the Architecture Reference on any design question."
---

# Python Patterns (KB / Embeddings / Bridge Layer)

Python owns the pieces *around* Pi: knowledge-base ingestion and embeddings, the vector-store client, and the Metasploit bridge. Keep the boundary with the TypeScript layer clean — no agent-loop logic here, no KB logic in the TS extensions.

## Project layout and environment

- One venv per the Python workspace; pin dependencies in `requirements.txt` or `pyproject.toml`. Never rely on system site-packages for repo code.
- Package by responsibility: `kb_ingest/`, `embeddings/`, `vectorstore/`, `msf_bridge/`. Each has a narrow public surface.
- Configuration via environment/config file, never hard-coded. Secrets (API keys, MSF RPC creds) come from the environment and are never committed.

## KB ingestion pipeline

- Ingest in signal order (Architecture §2.5, §6): **CISA KEV → OWASP WSTG → PentestMonkey → CAPEC**. Each source is its own ingester behind a common interface returning normalized records.
- **Idempotent by design:** re-running an ingest must not duplicate. Key each record by a stable natural id (e.g. CVE id + source) and upsert, don't blind-insert.
- Normalize to one internal record shape before embedding, so the fingerprint-triggered query (a write in `findings` triggers a KB lookup) joins against a consistent schema regardless of source.
- Make ingestion resumable and logged — a partial run should report what it got through.

## Structured data — type everything

- Use `dataclasses` or `pydantic` models for every record crossing a boundary (ingested KB record, embedding payload, MSF request/response). No bare dicts passed between modules.
- Full type hints on public functions; run a type checker in CI.

## Vector store (Qdrant candidate)

- Wrap the client in a thin repository module; the rest of the code calls `kb.query(fingerprint)` / `kb.upsert(records)`, not the raw client.
- Store rich metadata alongside vectors (source, CVE id, relevance) so retrieval supports both fingerprint-exact filtering and fuzzy similarity, per the KB design.
- Keep the seeded tier and the self-learned tier distinguishable in metadata — they grow by different mechanisms and shouldn't be conflated.

## Async OOB polling (blind validators — §4.7)

- The out-of-band interaction server (Interactsh-model, self-hosted) is polled **asynchronously**, never blocked-on synchronously — a callback may arrive late (cron/async worker), so the harness polls and correlates rather than waiting.
- Embed a unique correlation id per attempt; write the subdomain-to-attempt pairing at request time so a later callback joins back to the exact `attempts` row.
- Treat a logged interaction on the unique subdomain as unambiguous Gate 1 evidence; nothing else counts as confirmation for a blind case.

## Metasploit bridge

- Bridge Claude ↔ Metasploit over MCP (GH05TCREW's Metasploit MCP Server is the candidate). Wrap it so module selection and custom-payload paths are both callable behind one typed interface.
- Metasploit-first, custom-on-demand (§2.3.2): the interface exposes "find a fitting module" and "run a custom delivery" as distinct operations; both are gated and logged upstream in the TS tool path.
- Never let the bridge execute an offensive step that hasn't passed the gates — the bridge is a mechanism, not a decision-maker.

## Testing

- Ingesters get tests against fixture samples of each source — assert idempotency (double-ingest = no duplicates) and normalization.
- Mock the OOB server in tests; assert correlation-id round-tripping and async poll handling.
- Mock MSF RPC; never hit a live Metasploit in unit tests.

## Don'ts

- No blocking waits on OOB callbacks.
- No duplicate KB records on re-ingest.
- No bare dicts across module boundaries.
- No offensive execution from the bridge without the gates upstream.
- No secrets in code or committed config.
