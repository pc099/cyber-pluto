"""The interaction registry — the core of the self-hosted OAST server (§4.7),
Interactsh-model. It mints unique correlation ids and records callbacks against
them. Thread-safe because the HTTP catcher records from handler threads while
the validator polls from another.

A logged interaction on a unique correlation id is unambiguous Gate 1 evidence
for a blind class: the target infrastructure itself reached out to
infrastructure Pluto controls, which cannot happen by coincidence.
"""

from __future__ import annotations

import secrets
import threading
from datetime import datetime, timezone

from .interaction import Interaction, Registration


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class InteractionRegistry:
    def __init__(self, base_url: str) -> None:
        # base_url like "http://oast.host:8895"; callback path is /c/<corrid>.
        self._base_url = base_url.rstrip("/")
        self._lock = threading.Lock()
        self._interactions: dict[str, list[Interaction]] = {}

    def register(self) -> Registration:
        corrid = secrets.token_hex(12)
        with self._lock:
            self._interactions[corrid] = []
        return Registration(correlation_id=corrid, callback_url=f"{self._base_url}/c/{corrid}")

    def record(self, corrid: str, *, protocol: str, remote_addr: str, method: str | None, path: str | None) -> bool:
        """Record a callback. Returns False if the correlation id is unknown
        (an uncorrelatable hit is not counted as evidence)."""
        with self._lock:
            if corrid not in self._interactions:
                return False
            self._interactions[corrid].append(
                Interaction(
                    correlation_id=corrid,
                    protocol=protocol,
                    remote_addr=remote_addr,
                    method=method,
                    path=path,
                    timestamp=_now(),
                )
            )
            return True

    def poll(self, corrid: str) -> list[Interaction]:
        """Non-destructive read of interactions seen so far for a corrid.
        Returns [] for an unknown or as-yet-unhit corrid — never blocks."""
        with self._lock:
            return list(self._interactions.get(corrid, []))

    def known(self, corrid: str) -> bool:
        with self._lock:
            return corrid in self._interactions
