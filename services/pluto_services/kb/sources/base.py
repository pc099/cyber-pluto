"""The common ingester interface (python-patterns: each source is its own
ingester behind a common interface returning normalized records)."""

from __future__ import annotations

from typing import Iterable, Protocol

from ..records import KbRecord, KbSource


class Ingester(Protocol):
    source: KbSource

    def ingest(self) -> Iterable[KbRecord]:
        """Yield normalized KbRecords. Implementations must be idempotent at
        the record-id level (the store upserts by id), and should be resumable
        and logged so a partial run reports what it got through."""
        ...
