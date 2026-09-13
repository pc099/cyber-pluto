"""CLI boundary for the MSF bridge — the process edge the TS exploitation tool
calls (same pattern as the KB bridge). All exploitation MECHANISM lives here in
Python; the gates (validated-only, red-lines, human sign-off) live in the TS
tool path that invokes this.

Backend defaults to the mock (no Metasploit needed). Set PLUTO_MSF_BACKEND=http
with PLUTO_MSF_HOST/PORT/TOKEN to drive a real msfrpcd.
"""

from __future__ import annotations

import argparse
import json
import os

from .bridge import MsfBridge
from .decide import plan_exploit
from .records import ExploitTarget, ModuleMatch, PayloadMode
from .rpc import HttpMsfRpc, MockMsfRpc, MsfRpc


def make_rpc() -> MsfRpc:
    backend = os.environ.get("PLUTO_MSF_BACKEND", "mock").lower()
    if backend == "http":
        return HttpMsfRpc(
            host=os.environ["PLUTO_MSF_HOST"],
            port=int(os.environ.get("PLUTO_MSF_PORT", "55553")),
            token=os.environ["PLUTO_MSF_TOKEN"],
            ssl=os.environ.get("PLUTO_MSF_SSL", "1") != "0",
        )
    return MockMsfRpc()


def _target_from_args(args: argparse.Namespace) -> ExploitTarget:
    return ExploitTarget(
        host=args.host,
        port=args.port,
        service=args.service,
        product=args.product,
        version=args.version,
        mechanism=args.mechanism,
    )


def _cmd_plan(args: argparse.Namespace) -> int:
    bridge = MsfBridge(make_rpc())
    plan = plan_exploit(bridge, _target_from_args(args), lhost=args.lhost, lport=args.lport)
    print(json.dumps(plan.model_dump(mode="json")))
    return 0


def _cmd_run(args: argparse.Namespace) -> int:
    bridge = MsfBridge(make_rpc())
    module = ModuleMatch(fullname=args.module, name=args.module, rank="normal", fit=0.6)
    result = bridge.run_module(module, _target_from_args(args), payload=args.payload)
    print(json.dumps(result.model_dump(mode="json")))
    return 0


def _add_target_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--host", required=True)
    p.add_argument("--port", type=int)
    p.add_argument("--service")
    p.add_argument("--product")
    p.add_argument("--version")
    p.add_argument("--mechanism")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pluto-msf")
    sub = parser.add_subparsers(dest="command", required=True)

    p_plan = sub.add_parser("plan", help="Metasploit-first/custom-on-demand plan for a target")
    _add_target_args(p_plan)
    p_plan.add_argument("--lhost", default="127.0.0.1")
    p_plan.add_argument("--lport", type=int, default=4444)
    p_plan.set_defaults(func=_cmd_plan)

    p_run = sub.add_parser("run", help="run a chosen module (gating happens upstream)")
    _add_target_args(p_run)
    p_run.add_argument("--module", required=True)
    p_run.add_argument("--payload", default="generic/shell_reverse_tcp")
    p_run.set_defaults(func=_cmd_run)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
