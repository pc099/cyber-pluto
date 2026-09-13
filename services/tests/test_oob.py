"""OOB interaction server tests (§4.7). Covers the registry, correlation-id
round-tripping, non-blocking poll, and an end-to-end blind confirmation against
a REAL local OAST server with a simulated target callback (no external infra).
"""

from __future__ import annotations

import asyncio
import threading

import pytest
import requests

from pluto_services.oob.blind import confirm_blind
from pluto_services.oob.client import OobClient
from pluto_services.oob.registry import InteractionRegistry
from pluto_services.oob.server import serve


def test_registry_correlates_only_known_ids():
    reg = InteractionRegistry("http://oast.local")
    r = reg.register()
    assert r.callback_url.endswith(f"/c/{r.correlation_id}")
    # Unknown id is not recorded (an uncorrelatable hit is not evidence).
    assert reg.record("bogus", protocol="http", remote_addr="1.2.3.4", method="GET", path="/c/bogus") is False
    # Known id records and polls back.
    assert reg.record(r.correlation_id, protocol="http", remote_addr="1.2.3.4", method="GET", path="/x") is True
    hits = reg.poll(r.correlation_id)
    assert len(hits) == 1
    assert hits[0].remote_addr == "1.2.3.4"


def test_poll_is_non_blocking_and_empty_before_callback():
    reg = InteractionRegistry("http://oast.local")
    r = reg.register()
    assert reg.poll(r.correlation_id) == []  # returns immediately, no hit yet


@pytest.fixture()
def oast_server():
    server = serve("127.0.0.1", 0)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.shutdown()


def test_blind_confirmed_when_target_calls_back(oast_server):
    client = OobClient(oast_server)

    async def trigger(callback_url: str) -> None:
        # Simulate the target being induced to make the out-of-band request.
        await asyncio.to_thread(requests.get, callback_url, timeout=5)

    result = asyncio.run(confirm_blind(client, trigger, timeout_s=10))
    assert result.confirmed is True
    assert len(result.interactions) >= 1
    assert result.interactions[0].correlation_id == result.correlation_id
    assert "out-of-band callback" in result.diff_summary


def test_blind_rejected_when_no_callback(oast_server):
    client = OobClient(oast_server)

    async def trigger(_callback_url: str) -> None:
        # Target does NOT call back (not vulnerable / not reached).
        return None

    result = asyncio.run(confirm_blind(client, trigger, timeout_s=2))
    assert result.confirmed is False
    assert result.interactions == []
    assert "NOT reproduced" in result.diff_summary
