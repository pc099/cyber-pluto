"""CISA KEV ingester — the highest-signal seeded source (§2.5, §6), and the
one that directly powers the fingerprint→CVE trigger: KEV entries are keyed by
vendor/product, exactly what a service fingerprint carries.

The feed is the public CISA Known Exploited Vulnerabilities catalog (JSON). The
ingester can read it from an already-loaded dict (tests, offline) or fetch it
over HTTP; either way it normalizes to KbRecords keyed by CVE id, so a
re-ingest upserts rather than duplicating.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

import requests

from ..records import KbRecord, KbSource

KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class CisaKevIngester:
    source = KbSource.CISA_KEV

    def __init__(self, raw: dict[str, Any] | None = None, *, url: str = KEV_FEED_URL, timeout: int = 30) -> None:
        self._raw = raw
        self._url = url
        self._timeout = timeout

    @classmethod
    def from_file(cls, path: str | Path) -> "CisaKevIngester":
        return cls(raw=json.loads(Path(path).read_text(encoding="utf-8")))

    def _load(self) -> dict[str, Any]:
        if self._raw is not None:
            return self._raw
        response = requests.get(self._url, timeout=self._timeout)
        response.raise_for_status()
        return response.json()

    def ingest(self) -> Iterable[KbRecord]:
        catalog = self._load()
        for vuln in catalog.get("vulnerabilities", []):
            cve = vuln.get("cveID")
            if not cve:
                continue
            title = vuln.get("vulnerabilityName") or cve
            short = vuln.get("shortDescription") or ""
            action = vuln.get("requiredAction") or ""
            ransomware = vuln.get("knownRansomwareCampaignUse") or ""
            text = f"{title}. {short}".strip()
            if action:
                text += f" Required action: {action}"
            if ransomware and ransomware.lower() not in {"", "unknown"}:
                text += f" Known ransomware campaign use: {ransomware}."
            yield KbRecord(
                id=f"{self.source.value}:{cve}",
                source=self.source,
                cve=cve,
                vendor=vuln.get("vendorProject"),
                product=vuln.get("product"),
                title=title,
                summary=short or None,
                text=text,
            )
