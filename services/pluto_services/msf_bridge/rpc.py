"""The RPC transport behind the bridge.

`MsfRpc` is a Protocol so the bridge is decoupled from any specific transport:
the tested/default backend is `MockMsfRpc` (python-patterns: never hit a live
Metasploit in unit tests), and `HttpMsfRpc` talks to a real `msfrpcd` over its
msgpack-RPC endpoint for when Metasploit is actually installed. The bridge and
the decision logic never know which one they're holding.
"""

from __future__ import annotations

from typing import Any, Protocol


class MsfRpc(Protocol):
    def call(self, method: str, *params: Any) -> dict[str, Any]: ...


# A small stand-in catalog so the mock can answer module.search realistically
# for the classic cases without a live MSF. fingerprint substring -> module.
_MOCK_MODULE_CATALOG: list[dict[str, Any]] = [
    {
        "match": "vsftpd",
        "fullname": "exploit/unix/ftp/vsftpd_234_backdoor",
        "name": "VSFTPD v2.3.4 Backdoor Command Execution",
        "rank": "excellent",
    },
    {
        "match": "unrealircd",
        "fullname": "exploit/unix/irc/unreal_ircd_3281_backdoor",
        "name": "UnrealIRCD 3.2.8.1 Backdoor Command Execution",
        "rank": "excellent",
    },
    {
        "match": "samba",
        "fullname": "exploit/multi/samba/usermap_script",
        "name": "Samba usermap_script Command Execution",
        "rank": "excellent",
    },
    {
        "match": "ms17-010",
        "fullname": "exploit/windows/smb/ms17_010_eternalblue",
        "name": "MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption",
        "rank": "average",
    },
]


class MockMsfRpc:
    """An in-memory fake msfrpcd. Deterministic, offline, no Metasploit needed.
    Supports the handful of RPC methods the bridge uses."""

    def __init__(self) -> None:
        self._next_session = 1
        self.executed: list[dict[str, Any]] = []

    def call(self, method: str, *params: Any) -> dict[str, Any]:
        if method == "module.search":
            query = str(params[0]).lower() if params else ""
            modules = [
                {"fullname": m["fullname"], "name": m["name"], "rank": m["rank"]}
                for m in _MOCK_MODULE_CATALOG
                if m["match"] in query
            ]
            return {"modules": modules}
        if method == "module.execute":
            # params: (module_type, module_name, options)
            self.executed.append({"module": params[1] if len(params) > 1 else None, "options": params[-1]})
            session_id = self._next_session
            self._next_session += 1
            return {"job_id": 1000 + session_id, "uuid": f"mock-{session_id}", "session_id": session_id}
        if method == "session.list":
            return {str(i): {"type": "meterpreter"} for i in range(1, self._next_session)}
        raise NotImplementedError(f"MockMsfRpc has no stub for RPC method {method!r}")


class HttpMsfRpc:
    """Real msfrpcd client (msgpack-RPC over HTTP). Requires `msgpack` and a
    running `msfrpcd`. Lazily imported so the bridge stays usable (with the
    mock) on hosts without Metasploit. This is the swap-in for a live
    integration; the bridge/decision code is unchanged."""

    def __init__(self, host: str, port: int, token: str, ssl: bool = True) -> None:
        self._host = host
        self._port = port
        self._token = token
        self._scheme = "https" if ssl else "http"

    def call(self, method: str, *params: Any) -> dict[str, Any]:
        import msgpack  # lazy: only needed for a live MSF
        import requests

        url = f"{self._scheme}://{self._host}:{self._port}/api/"
        body = msgpack.packb([method, self._token, *params], use_bin_type=True)
        resp = requests.post(url, data=body, headers={"Content-Type": "binary/message-pack"}, timeout=30)
        resp.raise_for_status()
        result = msgpack.unpackb(resp.content, raw=False)
        if isinstance(result, dict):
            return result
        return {"result": result}
