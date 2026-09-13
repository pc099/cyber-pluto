"""Blind-class Gate 1 confirmation via the OAST channel (§4.7) — for blind SQLi
and blind SSRF, which produce no visible output and so cannot be confirmed from
the same request/response pair. The only acceptable evidence is a correlated
out-of-band callback on a unique subdomain/id.
"""

from __future__ import annotations

from typing import Awaitable, Callable

import pydantic

from .client import OobClient
from .interaction import Interaction


class BlindResult(pydantic.BaseModel):
    confirmed: bool
    correlation_id: str
    callback_url: str
    interactions: list[Interaction]
    diff_summary: str


async def confirm_blind(
    client: OobClient,
    trigger: Callable[[str], Awaitable[None]],
    *,
    timeout_s: float = 15.0,
) -> BlindResult:
    """Register a unique callback, run `trigger(callback_url)` (which sends the
    payload embedding that URL to the target), then poll asynchronously. A hit
    on the unique id confirms the blind vulnerability; nothing else counts.

    The caller is responsible for writing the correlation_id -> attempts pairing
    at request time so a late callback still joins back to this injection point.
    """
    reg = client.register()
    await trigger(reg.callback_url)
    interactions = await client.poll_until(reg.correlation_id, timeout_s=timeout_s)
    confirmed = len(interactions) > 0
    return BlindResult(
        confirmed=confirmed,
        correlation_id=reg.correlation_id,
        callback_url=reg.callback_url,
        interactions=interactions,
        diff_summary=(
            f"Reproduced (blind): {len(interactions)} out-of-band callback(s) on unique id "
            f"{reg.correlation_id} — the target reached Pluto-controlled infrastructure."
            if confirmed
            else f"NOT reproduced (blind): no out-of-band callback on unique id {reg.correlation_id} within {timeout_s}s."
        ),
    )
