"""Session 0 scaffolding check: proves the Python venv for the KB /
embeddings / vector-store / Metasploit-bridge layer is set up correctly.
No ingestion, embedding, or bridge logic lives here yet — kb_ingest/,
embeddings/, vectorstore/, and msf_bridge/ packages land in their own
build-plan sessions.
"""

from __future__ import annotations

import pydantic


class _HelloCheck(pydantic.BaseModel):
    message: str


def main() -> None:
    check = _HelloCheck(message="pluto/services: Python venv OK")
    print(check.message)


if __name__ == "__main__":
    main()
