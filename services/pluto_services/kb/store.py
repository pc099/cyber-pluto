"""The vector store — a thin repository over Qdrant (python-patterns: wrap the
client; the rest of the code calls kb.upsert/kb.query, never the raw client).

Runs Qdrant in LOCAL (embedded) mode — `QdrantClient(path=...)` — so there is
no server or container to run; the same client API swaps to a hosted Qdrant
later by changing only construction. Idempotency is structural: each record's
stable string id maps to a deterministic UUID point id, so re-ingesting the
same record upserts in place rather than duplicating.
"""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Iterable

from qdrant_client import QdrantClient
from qdrant_client.models import Distance, FieldCondition, Filter, MatchValue, PointStruct, VectorParams

from .embedding import Embedder, HashingEmbedder
from .records import KbHit, KbRecord, KbSource

_COLLECTION = "pluto_kb"
_POINT_NAMESPACE = uuid.UUID("6f9b4c1e-0000-4000-8000-000000000001")


def _point_id(record_id: str) -> str:
    return str(uuid.uuid5(_POINT_NAMESPACE, record_id))


class KbStore:
    def __init__(self, path: str | Path, embedder: Embedder | None = None) -> None:
        self._embedder = embedder or HashingEmbedder()
        self._client = QdrantClient(path=str(path))
        self._ensure_collection()

    def _ensure_collection(self) -> None:
        if not self._client.collection_exists(_COLLECTION):
            self._client.create_collection(
                _COLLECTION,
                vectors_config=VectorParams(size=self._embedder.dim, distance=Distance.COSINE),
            )

    def upsert(self, records: Iterable[KbRecord]) -> int:
        points: list[PointStruct] = []
        for record in records:
            points.append(
                PointStruct(
                    id=_point_id(record.id),
                    vector=self._embedder.embed(record.embedding_text()),
                    payload=record.model_dump(mode="json"),
                )
            )
        if points:
            self._client.upsert(_COLLECTION, points=points)
        return len(points)

    def count(self) -> int:
        return self._client.count(_COLLECTION).count

    def query(self, text: str, *, limit: int = 5, source: KbSource | None = None) -> list[KbHit]:
        query_filter = None
        if source is not None:
            query_filter = Filter(must=[FieldCondition(key="source", match=MatchValue(value=source.value))])
        response = self._client.query_points(
            _COLLECTION,
            query=self._embedder.embed(text),
            limit=limit,
            query_filter=query_filter,
            with_payload=True,
        )
        hits: list[KbHit] = []
        for point in response.points:
            payload = point.payload or {}
            hits.append(
                KbHit(
                    id=str(payload.get("id", point.id)),
                    source=KbSource(payload["source"]),
                    score=float(point.score),
                    cve=payload.get("cve"),
                    vendor=payload.get("vendor"),
                    product=payload.get("product"),
                    title=payload.get("title"),
                    summary=payload.get("summary"),
                )
            )
        return hits

    def close(self) -> None:
        self._client.close()
