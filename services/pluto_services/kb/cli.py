"""CLI bridge for the KB (Architecture boundary: the TypeScript extension layer
never contains KB logic — it shells out to this Python CLI and consumes JSON).

  ingest:  python -m pluto_services.kb.cli ingest [--kev-file PATH]
  query:   python -m pluto_services.kb.cli query --product X [--version Y] [--service S] [--json]

The default KB path is $PLUTO_KB_PATH or ./state/kb, so it sits under the
gitignored runtime state dir next to the SQLite state DB.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys

from .ingest import ingest_all, ingest_source
from .query import query_fingerprint
from .sources.cisa_kev import CisaKevIngester
from .store import KbStore

DEFAULT_KB_PATH = os.environ.get("PLUTO_KB_PATH", "state/kb")


def _cmd_ingest(args: argparse.Namespace) -> int:
    store = KbStore(args.kb_path)
    try:
        if args.kev_file:
            count = ingest_source(store, CisaKevIngester.from_file(args.kev_file))
            summary = {"cisa_kev": count, "total_in_store": store.count()}
        else:
            results = ingest_all(store)
            summary = {r.source.value: r.ingested for r in results}
            summary["total_in_store"] = store.count()
    finally:
        store.close()
    print(json.dumps(summary))
    return 0


def _cmd_query(args: argparse.Namespace) -> int:
    store = KbStore(args.kb_path)
    try:
        hits = query_fingerprint(
            store,
            product=args.product,
            version=args.version,
            service=args.service,
            limit=args.limit,
            min_score=args.min_score,
        )
    finally:
        store.close()
    payload = [h.model_dump(mode="json") for h in hits]
    if args.json:
        print(json.dumps(payload))
    else:
        for h in hits:
            print(f"[{h.score:.3f}] {h.cve or h.id} — {h.vendor or ''} {h.product or ''}: {h.title or ''}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pluto-kb")
    parser.add_argument("--kb-path", default=DEFAULT_KB_PATH, help="Qdrant local store path")
    sub = parser.add_subparsers(dest="command", required=True)

    p_ingest = sub.add_parser("ingest", help="ingest seeded sources in signal order")
    p_ingest.add_argument("--kev-file", help="ingest CISA KEV from a local JSON file instead of fetching")
    p_ingest.set_defaults(func=_cmd_ingest)

    p_query = sub.add_parser("query", help="fingerprint-triggered KB query")
    p_query.add_argument("--product")
    p_query.add_argument("--version")
    p_query.add_argument("--service")
    p_query.add_argument("--limit", type=int, default=5)
    p_query.add_argument("--min-score", type=float, default=0.0)
    p_query.add_argument("--json", action="store_true")
    p_query.set_defaults(func=_cmd_query)
    return parser


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.WARNING, stream=sys.stderr)
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
