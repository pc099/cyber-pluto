"""KB ingestion + query tests (python-patterns: ingesters tested against
fixture samples; assert idempotency and normalization; no network)."""

from __future__ import annotations

from pluto_services.kb.embedding import HashingEmbedder
from pluto_services.kb.ingest import SIGNAL_ORDER, ingest_all
from pluto_services.kb.query import query_fingerprint
from pluto_services.kb.records import KbSource
from pluto_services.kb.sources.cisa_kev import CisaKevIngester
from pluto_services.kb.store import KbStore

KEV_FIXTURE = {
    "vulnerabilities": [
        {
            "cveID": "CVE-2021-44228",
            "vendorProject": "Apache",
            "product": "Log4j2",
            "vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability",
            "shortDescription": "Apache Log4j2 contains a JNDI injection flaw allowing remote code execution.",
            "requiredAction": "Apply updates.",
            "knownRansomwareCampaignUse": "Known",
        },
        {
            "cveID": "CVE-2014-0160",
            "vendorProject": "OpenSSL",
            "product": "OpenSSL",
            "vulnerabilityName": "OpenSSL Heartbleed Information Disclosure Vulnerability",
            "shortDescription": "OpenSSL TLS heartbeat read overflow discloses memory (Heartbleed).",
            "requiredAction": "Apply updates.",
            "knownRansomwareCampaignUse": "Unknown",
        },
        {
            "cveID": "CVE-2019-0708",
            "vendorProject": "Microsoft",
            "product": "Remote Desktop Services",
            "vulnerabilityName": "Microsoft Remote Desktop Services Remote Code Execution Vulnerability (BlueKeep)",
            "shortDescription": "RDP pre-auth remote code execution (BlueKeep).",
            "requiredAction": "Apply updates.",
        },
    ]
}


def _store(tmp_path) -> KbStore:
    return KbStore(tmp_path / "kb")


def test_cisa_kev_ingester_normalizes(tmp_path):
    records = list(CisaKevIngester(raw=KEV_FIXTURE).ingest())
    assert len(records) == 3
    log4j = next(r for r in records if r.cve == "CVE-2021-44228")
    assert log4j.id == "cisa_kev:CVE-2021-44228"
    assert log4j.source is KbSource.CISA_KEV
    assert log4j.vendor == "Apache"
    assert log4j.product == "Log4j2"
    assert "ransomware" in log4j.text.lower()


def test_ingest_is_idempotent(tmp_path):
    store = _store(tmp_path)
    try:
        ingester = CisaKevIngester(raw=KEV_FIXTURE)
        store.upsert(ingester.ingest())
        first = store.count()
        # Re-ingest the identical feed — must not duplicate.
        store.upsert(CisaKevIngester(raw=KEV_FIXTURE).ingest())
        second = store.count()
        assert first == 3
        assert second == 3
    finally:
        store.close()


def test_fingerprint_query_surfaces_relevant_cve(tmp_path):
    store = _store(tmp_path)
    try:
        store.upsert(CisaKevIngester(raw=KEV_FIXTURE).ingest())
        hits = query_fingerprint(store, product="OpenSSL", version="1.0.1", service="https", limit=3)
        assert hits, "expected at least one hit"
        assert hits[0].cve == "CVE-2014-0160", f"top hit should be Heartbleed, got {hits[0].cve}"
    finally:
        store.close()


def test_ingest_all_follows_signal_order(tmp_path, monkeypatch):
    # ingest_all uses the real CISA ingester (network); stub it to the fixture.
    from pluto_services.kb import ingest as ingest_mod

    monkeypatch.setattr(ingest_mod, "CisaKevIngester", lambda: CisaKevIngester(raw=KEV_FIXTURE))
    store = _store(tmp_path)
    try:
        results = ingest_all(store)
        assert [r.source for r in results] == list(SIGNAL_ORDER)
        assert results[0].source is KbSource.CISA_KEV
        assert results[0].implemented is True
        assert results[0].ingested == 3
        # The other three are declared in order but not yet implemented.
        assert all(not r.implemented for r in results[1:])
    finally:
        store.close()


def test_hashing_embedder_is_deterministic():
    e = HashingEmbedder(dim=64)
    assert e.embed("Apache Log4j2") == e.embed("Apache Log4j2")
    assert len(e.embed("x")) == 64
