"""Typed records crossing the KB boundary (python-patterns: type everything;
no bare dicts between modules).

Every ingester, whatever its source, normalizes to `KbRecord` before
embedding, so the fingerprint-triggered query joins against one consistent
shape regardless of source (Architecture §2.5, §6).
"""

from __future__ import annotations

from enum import Enum

import pydantic


class KbSource(str, Enum):
    """The seeded-tier sources, in LLM4Pentest's signal order (§2.5, §6).

    Ingestion runs in this order so the highest-signal source lands first.
    """

    CISA_KEV = "cisa_kev"
    OWASP_WSTG = "owasp_wstg"
    PENTESTMONKEY = "pentestmonkey"
    CAPEC = "capec"


class KbTier(str, Enum):
    """Seeded vs. self-learned — kept distinguishable in metadata because they
    grow by different mechanisms and must not be conflated (python-patterns,
    Architecture §2.5)."""

    SEEDED = "seeded"
    SELF_LEARNED = "self_learned"


class KbRecord(pydantic.BaseModel):
    """One normalized knowledge-base entry, ready to embed and upsert."""

    model_config = pydantic.ConfigDict(frozen=True)

    # Stable natural id: "<source>:<natural key>", e.g. "cisa_kev:CVE-2021-44228".
    # Idempotency key — re-ingesting the same entry upserts, never duplicates.
    id: str
    source: KbSource
    tier: KbTier = KbTier.SEEDED
    # The text that gets embedded for semantic retrieval.
    text: str
    # Optional structured fingerprint fields for filtering/joining.
    cve: str | None = None
    vendor: str | None = None
    product: str | None = None
    title: str | None = None
    summary: str | None = None

    def embedding_text(self) -> str:
        """The concatenated text used to build this record's vector. Product
        and vendor are repeated so a fingerprint query (product/version) has
        strong lexical overlap with the records that matter to it."""
        parts = [self.vendor, self.product, self.vendor, self.product, self.title, self.text]
        return " ".join(p for p in parts if p)


class KbHit(pydantic.BaseModel):
    """A scored retrieval result returned by a KB query."""

    id: str
    source: KbSource
    score: float
    cve: str | None = None
    vendor: str | None = None
    product: str | None = None
    title: str | None = None
    summary: str | None = None
