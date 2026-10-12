import json

import pytest

from secwatch.collect.epss import parse_epss
from secwatch.collect.kev import parse_kev
from secwatch.collect.merge import fold_records
from secwatch.collect.pipeline import run_collect
from secwatch.collect.ransomware import parse_victims
from secwatch.collect.rss import parse_feed
from secwatch.config import PACKAGE_ROOT
from secwatch.http import HttpError
from secwatch.models import Record
from secwatch.store import Store


def test_rss_strips_html_and_reads_cdata():
    data = (PACKAGE_ROOT / "fixtures" / "boannews.xml").read_bytes()
    records = parse_feed(data, source="boannews", kind="news")
    highway = next(record for record in records if "NVR" in record.title)
    assert "<p>" not in highway.summary
    assert "CVE-2099-1403" in highway.cve_ids
    assert highway.published_at


def test_ransomware_drops_leak_fields():
    records = parse_victims((PACKAGE_ROOT / "fixtures" / "ransomware.json").read_bytes())
    korea = next(record for record in records if record.country == "KR")
    blob = json.dumps(korea.__dict__, ensure_ascii=False)
    assert "LEAKMARKER" not in blob
    assert ".onion" not in blob
    assert korea.url == "https://www.ransomware.live/"
    assert korea.title == "남해샘플도로"
    assert "infostealer" not in blob


def test_ransomware_rate_limit_message():
    with pytest.raises(ValueError):
        parse_victims(b'{"message": "1 per 1 minute"}')


def test_fold_merges_scores():
    parts = [
        Record(source="kev", external_id="CVE-1", kind="cve", title="이름", cve_ids=["CVE-2099-1"], kev=True, vendor="Fortinet", product="FortiOS"),
        Record(source="nvd", external_id="CVE-1", kind="cve", title="CVE-2099-1", cve_ids=["CVE-2099-1"], cvss=9.8),
        Record(source="epss", external_id="CVE-1", kind="cve", title="CVE-2099-1", cve_ids=["CVE-2099-1"], epss=0.5),
    ]
    merged = fold_records(parts)
    assert len(merged) == 1
    assert merged[0].source == "cve"
    assert merged[0].kev and merged[0].cvss == 9.8 and merged[0].epss == 0.5
    assert merged[0].vendor == "Fortinet"


def test_fold_ignores_epss_score_date():
    parts = [
        Record(source="kev", external_id="CVE-2099-1", kind="cve", title="이름", cve_ids=["CVE-2099-1"], kev=True, published_at="2026-10-10"),
        Record(source="nvd", external_id="CVE-2099-1", kind="cve", title="CVE-2099-1", cve_ids=["CVE-2099-1"], published_at="2026-10-09"),
        Record(source="epss", external_id="CVE-2099-1", kind="cve", title="CVE-2099-1", cve_ids=["CVE-2099-1"], epss=0.2, published_at="2026-10-12"),
    ]
    assert fold_records(parts)[0].published_at == "2026-10-10"


def test_demo_collect_is_offline_and_deduped(settings, monkeypatch):
    def boom(*_args, **_kwargs):
        raise AssertionError("demo path touched HTTP")

    monkeypatch.setattr("secwatch.http.HttpClient.get_bytes", boom)
    monkeypatch.setattr("secwatch.http.HttpClient.post_json", boom)
    cfg = settings()
    store = Store(cfg.db_path)
    result = run_collect(cfg, store, alert=False)
    assert result.errors == []
    assert result.inserted == 13
    assert store.count() == 13
    again = run_collect(cfg, store, alert=False)
    assert again.inserted == 13
    assert store.count() == 13
    blob = cfg.db_path.read_bytes()
    assert b"LEAKMARKER" not in blob
    assert b".onion" not in blob
    bridge = store.query(q="거가대교")[0]
    assert bridge.priority == 100
    assert bridge.band == "긴급"
    victim = store.query(q="남해샘플도로")[0]
    assert victim.priority == 46
    assert victim.kind == "victim"
    gadget = store.query(q="해외 가전")[0]
    assert gadget.band == "참고"


def test_live_pipeline_filters_with_fake_http(settings, tmp_path):
    kev = {
        "vulnerabilities": [
            {
                "cveID": "CVE-2099-1401",
                "vendorProject": "Fortinet",
                "product": "FortiOS",
                "vulnerabilityName": "FortiOS sample",
                "dateAdded": "D-1",
                "shortDescription": "sample",
                "requiredAction": "patch",
            },
            {
                "cveID": "CVE-2099-1800",
                "vendorProject": "WidgetCo",
                "product": "Toaster",
                "vulnerabilityName": "Widget toaster",
                "dateAdded": "D-1",
                "shortDescription": "unrelated consumer device",
                "requiredAction": "ignore",
            },
        ]
    }
    nvd = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2099-1401",
                    "published": "D-2",
                    "descriptions": [{"lang": "en", "value": "FortiOS sample"}],
                    "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {"baseScore": 9.8}}]},
                }
            }
        ]
    }
    epss = {"data": [{"cve": "CVE-2099-1401", "epss": "0.5", "date": "D-0"}]}
    victims = [{"victim": "남해샘플도로", "country": "KR", "group": "paper-lock", "activity": "Transportation", "discovered": "D-1", "claim_url": "http://x.onion/secret"}]

    class FakeHttp:
        def __init__(self):
            self.urls = []

        def get_bytes(self, url, headers=None, max_bytes=2_000_000, attempts=2):
            self.urls.append(url)
            if url.endswith("known_exploited_vulnerabilities.json"):
                return json.dumps(kev).encode()
            if "cveId=CVE-2099-1401" in url:
                return json.dumps(nvd).encode()
            if url.startswith("https://api.first.org/"):
                return json.dumps(epss).encode()
            if url.endswith("/countryvictims/KR"):
                return json.dumps(victims).encode()
            raise HttpError(f"unexpected {url}")

    fake = FakeHttp()
    cfg = settings(demo=False, db_path=tmp_path / "live.db")
    store = Store(cfg.db_path)
    result = run_collect(
        cfg,
        store,
        alert=False,
        sources=["kev", "nvd", "epss", "ransomware"],
        client=fake,
        pause=0,
    )
    assert result.errors == []
    titles = [record.title for record in store.query(limit=20)]
    assert any("FortiOS" in title for title in titles)
    assert not any("Widget" in title or "Toaster" in title for title in titles)
    assert not any("CVE-2099-1800" in url for url in fake.urls)
    assert any("cveId=CVE-2099-1401" in url for url in fake.urls)
    blob = cfg.db_path.read_bytes()
    assert b".onion" not in blob


def test_store_updates_same_key(settings):
    cfg = settings(demo=False)
    store = Store(cfg.db_path)
    record = Record(
        source="kisa",
        external_id="ntt:1",
        kind="notice",
        title="처음",
        published_at="2026-10-01",
    )
    assert store.upsert([record]) == (1, 0)
    record.title = "갱신"
    assert store.upsert([record]) == (0, 1)
    assert store.count() == 1
    assert store.find_key("kisa", "ntt:1").title == "갱신"


def test_kev_parser_ignores_blank_rows():
    records = parse_kev((PACKAGE_ROOT / "fixtures" / "kev.json").read_bytes())
    assert {record.external_id for record in records} == {
        "CVE-2099-1401",
        "CVE-2099-1402",
        "CVE-2099-1405",
    }
    assert all(record.kev for record in records)


def test_epss_parser():
    records = parse_epss((PACKAGE_ROOT / "fixtures" / "epss.json").read_bytes())
    assert records[0].epss == 0.94
    assert records[0].published_at
