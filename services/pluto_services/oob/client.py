"""Client + async confirmation for the OAST server (§4.7).

The confirmation discipline (python-patterns): a blind callback may arrive late
(the injected code might only run inside a cron job or async worker), so the
harness POLLS ASYNCHRONOUSLY and correlates, never blocking on a synchronous
wait. The subdomain/correlation-id -> attempt pairing is written at request
time (by the caller, into the attempts table) so a later callback joins back to
the exact injection point.
"""

from __future__ import annotations

import asyncio

import requests

from .interaction import Interaction, Registration


class OobClient:
    def __init__(self, base_url: str, timeout: int = 10) -> None:
        self._base = base_url.rstrip("/")
        self._timeout = timeout

    def register(self) -> Registration:
        resp = requests.post(f"{self._base}/register", timeout=self._timeout)
        resp.raise_for_status()
        return Registration(**resp.json())

    def poll(self, correlation_id: str) -> list[Interaction]:
        resp = requests.get(f"{self._base}/poll/{correlation_id}", timeout=self._timeout)
        resp.raise_for_status()
        return [Interaction(**i) for i in resp.json().get("interactions", [])]

    async def poll_until(
        self, correlation_id: str, *, timeout_s: float = 15.0, interval_s: float = 0.5
    ) -> list[Interaction]:
        """Poll asynchronously until an interaction is seen or the deadline
        passes. Returns as soon as any callback lands (empty on timeout). Never
        blocks the event loop between polls."""
        loop = asyncio.get_event_loop()
        deadline = loop.time() + timeout_s
        while loop.time() < deadline:
            interactions = await asyncio.to_thread(self.poll, correlation_id)
            if interactions:
                return interactions
            await asyncio.sleep(interval_s)
        return []
