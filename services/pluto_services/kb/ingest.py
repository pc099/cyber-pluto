"""Ingestion orchestration — runs sources in LLM4Pentest's signal order
(§2.5, §6): CISA KEV → OWASP WSTG → PentestMonkey → CAPEC.

CISA KEV is fully implemented (it powers the fingerprint→CVE trigger this
session delivers). The other three sources are declared here in order but not
yet wired — each is its own ingester behind the common interface (base.py), so
adding them is registering an ingester, not reworking the pipeline. They are
skipped with a log line rather than silently omitted, so a run reports exactly
what it got through (python-patterns: resumable and logged).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from .records import KbSource
from .sources.base import Ingester
from .sources.cisa_kev import CisaKevIngester
from .store import KbStore

logger = logging.getLogger("pluto.kb.ingest")

# The signal order is authoritative; ingestion always follows it.
SIGNAL_ORDER: tuple[KbSource, ...] = (
    KbSource.CISA_KEV,
    KbSource.OWASP_WSTG,
    KbSource.PENTESTMONKEY,
    KbSource.CAPEC,
)


@dataclass(frozen=True)
class SourceResult:
    source: KbSource
    ingested: int
    implemented: bool


def _ingester_for(source: KbSource) -> Ingester | None:
    if source is KbSource.CISA_KEV:
        return CisaKevIngester()
    # OWASP_WSTG / PENTESTMONKEY / CAPEC: adapters land in a KB-expansion
    # follow-up; the pipeline already runs them in order once registered.
    return None


def ingest_source(store: KbStore, ingester: Ingester) -> int:
    return store.upsert(ingester.ingest())


def ingest_all(store: KbStore) -> list[SourceResult]:
    results: list[SourceResult] = []
    for source in SIGNAL_ORDER:
        ingester = _ingester_for(source)
        if ingester is None:
            logger.info("skipping %s: ingester not yet implemented", source.value)
            results.append(SourceResult(source=source, ingested=0, implemented=False))
            continue
        count = ingest_source(store, ingester)
        logger.info("ingested %d records from %s", count, source.value)
        results.append(SourceResult(source=source, ingested=count, implemented=True))
    return results
