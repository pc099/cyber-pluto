"""Typed records for the Metasploit bridge (python-patterns: type everything
crossing a boundary; no bare dicts). These are the shapes the TS exploitation
tool consumes as JSON.
"""

from __future__ import annotations

from enum import Enum

import pydantic


class ExploitTarget(pydantic.BaseModel):
    """A validated finding's fingerprint, as much as the exploitation layer
    needs to select a module or write a delivery."""

    model_config = pydantic.ConfigDict(frozen=True)

    host: str
    port: int | None = None
    service: str | None = None
    product: str | None = None
    version: str | None = None
    # Free-text description of a bespoke mechanism (e.g. "authenticated file
    # upload accepting .php") when the finding is not a stock service.
    mechanism: str | None = None


class ModuleMatch(pydantic.BaseModel):
    """A candidate Metasploit module for a target."""

    fullname: str  # e.g. "exploit/unix/ftp/vsftpd_234_backdoor"
    name: str
    rank: str  # e.g. "excellent", "great", "normal"
    # Deterministic confidence that this module fits the target's shape.
    fit: float


class PayloadMode(str, Enum):
    METASPLOIT_MODULE = "metasploit_module"
    CUSTOM_PAYLOAD = "custom_payload"


class CustomPayloadSpec(pydantic.BaseModel):
    """A bespoke delivery the reasoning core writes when no module fits
    (§2.3.2): the payload, the transport to get it through the target path, and
    the listener to catch the connection. `generated_code` is retained as
    evidence in the attempts row."""

    payload_type: str  # e.g. "php/meterpreter/reverse_tcp"
    lhost: str
    lport: int
    transport: str  # how it is delivered, e.g. "http-file-upload"
    encoder: str | None = None
    generated_code: str = ""


class ExploitPlan(pydantic.BaseModel):
    """The §2.3.2 decision, made explicit: use a fitting module, or write a
    custom delivery. This is a PROPOSAL — gating and execution are decided
    upstream in the TS tool path, never inside the bridge."""

    mode: PayloadMode
    target: ExploitTarget
    rationale: str
    module: ModuleMatch | None = None
    payload: CustomPayloadSpec | None = None


class ExploitResult(pydantic.BaseModel):
    """The outcome of actually running a plan (against real or mock MSF)."""

    ok: bool
    mode: PayloadMode
    module: str | None = None
    session_opened: bool = False
    session_id: int | None = None
    output: str = ""
