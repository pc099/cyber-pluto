"""Typed records for the out-of-band interaction server (§4.7)."""

from __future__ import annotations

import pydantic


class Registration(pydantic.BaseModel):
    """A freshly minted, disposable correlation handle. The `callback_url` is
    embedded in a payload; any hit on it is unambiguous proof the target
    reached infrastructure Pluto controls."""

    model_config = pydantic.ConfigDict(frozen=True)

    correlation_id: str
    callback_url: str


class Interaction(pydantic.BaseModel):
    """One logged callback on a correlation id."""

    model_config = pydantic.ConfigDict(frozen=True)

    correlation_id: str
    protocol: str  # http | dns | ...
    remote_addr: str
    method: str | None = None
    path: str | None = None
    timestamp: str
