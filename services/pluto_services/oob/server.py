"""HTTP OAST catcher (§4.7). A threading HTTP server that:
  - POST /register        -> {correlation_id, callback_url}
  - GET  /poll/<corrid>   -> {interactions: [...]}
  - ANY  /c/<corrid>[...] -> records an interaction (the callback path)

Self-hosted so interaction data stays private to Pluto (the reference's reason
for not using public Interactsh infrastructure). This is HTTP/path-based; a
production deployment would also answer DNS for `<corrid>.oast.<domain>` and
record DNS/SMTP hits — the registry is transport-agnostic, so that is an added
catcher, not a redesign.

Run: python -m pluto_services.oob.server [--host H] [--port P] [--base-url URL]
"""

from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .registry import InteractionRegistry


class OastServer(ThreadingHTTPServer):
    """Holds the registry on the server instance so handlers see the real bound
    port (important when binding to port 0 for tests)."""

    registry: InteractionRegistry


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args: object) -> None:  # silence default logging
        return

    @property
    def _registry(self) -> InteractionRegistry:
        return self.server.registry  # type: ignore[attr-defined]

    def _json(self, status: int, payload: dict[str, object]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _corrid_from(self, prefix: str) -> str:
        return self.path[len(prefix) :].split("/", 1)[0].split("?", 1)[0]

    def _record_callback(self, corrid: str) -> None:
        ok = self._registry.record(
            corrid,
            protocol="http",
            remote_addr=self.client_address[0],
            method=self.command,
            path=self.path,
        )
        self._json(200 if ok else 404, {"ok": ok})

    def do_GET(self) -> None:  # noqa: N802
        if self.path.startswith("/poll/"):
            corrid = self._corrid_from("/poll/")
            return self._json(200, {"interactions": [i.model_dump(mode="json") for i in self._registry.poll(corrid)]})
        if self.path.startswith("/c/"):
            return self._record_callback(self._corrid_from("/c/"))
        return self._json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path == "/register":
            return self._json(200, self._registry.register().model_dump(mode="json"))
        if self.path.startswith("/c/"):
            return self._record_callback(self._corrid_from("/c/"))
        return self._json(404, {"error": "not found"})


def serve(host: str, port: int, base_url: str | None = None) -> OastServer:
    server = OastServer((host, port), _Handler)
    actual_port = server.server_address[1]
    server.registry = InteractionRegistry(base_url or f"http://{host}:{actual_port}")
    return server


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="pluto-oob")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8895)
    parser.add_argument("--base-url", default=None)
    args = parser.parse_args(argv)
    server = serve(args.host, args.port, args.base_url)
    print(f"[oob] interaction server on http://{args.host}:{server.server_address[1]} (callback path /c/<corrid>)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
