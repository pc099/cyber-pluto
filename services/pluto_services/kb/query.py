"""Fingerprint-triggered KB query (Architecture §2.5): given a service
fingerprint (product/version/service), return the seeded-tier entries most
relevant to it. This is what a `findings` write triggers — the result can spawn
a prioritized child node in the investigation tree.
"""

from __future__ import annotations

from .records import KbHit
from .store import KbStore


def fingerprint_query_text(product: str | None, version: str | None, service: str | None) -> str:
    return " ".join(p for p in (product, version, service) if p).strip()


def query_fingerprint(
    store: KbStore,
    *,
    product: str | None = None,
    version: str | None = None,
    service: str | None = None,
    limit: int = 5,
    min_score: float = 0.0,
) -> list[KbHit]:
    text = fingerprint_query_text(product, version, service)
    if not text:
        return []
    hits = store.query(text, limit=limit)
    return [h for h in hits if h.score >= min_score]
