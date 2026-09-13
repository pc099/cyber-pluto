"""Embeddings for the KB.

The default embedder is a DETERMINISTIC hashing embedder: no model download,
no network, no heavyweight ML dependency, and byte-for-byte reproducible — so
ingestion and retrieval are testable offline and in CI (python-patterns:
idempotent, testable). It uses the hashing trick over word + character-ngram
tokens, which is enough for the fingerprint→CVE retrieval Session 6 needs
(a product/version query shares tokens with the KEV records that matter to it).

`Embedder` is a Protocol so a stronger semantic model (fastembed's ONNX models,
or sentence-transformers) can drop in later without touching the store or the
ingesters — only the embedding quality changes, not the architecture.
"""

from __future__ import annotations

import hashlib
import math
import re
from typing import Protocol

_TOKEN_RE = re.compile(r"[a-z0-9]+")


class Embedder(Protocol):
    dim: int

    def embed(self, text: str) -> list[float]: ...


def _char_ngrams(token: str, n: int = 3) -> list[str]:
    padded = f"^{token}$"
    if len(padded) <= n:
        return [padded]
    return [padded[i : i + n] for i in range(len(padded) - n + 1)]


def _tokens(text: str) -> list[str]:
    words = _TOKEN_RE.findall(text.lower())
    features: list[str] = list(words)
    for w in words:
        features.extend(_char_ngrams(w))
    return features


class HashingEmbedder:
    """Fixed-dimension L2-normalized hashing embedder."""

    def __init__(self, dim: int = 256) -> None:
        self.dim = dim

    def _bucket(self, feature: str) -> tuple[int, float]:
        digest = hashlib.blake2b(feature.encode("utf-8"), digest_size=8).digest()
        h = int.from_bytes(digest, "big")
        index = h % self.dim
        sign = 1.0 if (h >> 63) & 1 else -1.0
        return index, sign

    def embed(self, text: str) -> list[float]:
        vec = [0.0] * self.dim
        for feature in _tokens(text):
            index, sign = self._bucket(feature)
            vec[index] += sign
        norm = math.sqrt(sum(v * v for v in vec))
        if norm == 0.0:
            # Avoid a zero vector (undefined cosine); tiny deterministic nudge.
            vec[0] = 1.0
            return vec
        return [v / norm for v in vec]
