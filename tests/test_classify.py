from secwatch.classify import band_of, classify
from secwatch.inventory import load_inventory, term_in
from secwatch.models import Record
from secwatch.config import PACKAGE_ROOT

INVENTORY = load_inventory(PACKAGE_ROOT / "assets" / "inventory.yaml")


def _record(**kwargs) -> Record:
    base = dict(source="news", external_id="x", kind="news", title="일반 소식")
    base.update(kwargs)
    return Record(**base)


def test_term_boundaries():
    assert term_in("Cisco Catalyst", "Cisco")
    assert not term_in("notcisco gear", "Cisco")
    assert not term_in("needs more time", "EDS")
    assert term_in("Moxa EDS-408A", "EDS")
    assert term_in("참고 https://road.example.kr/status", ".kr")
    assert term_in("포티게이트 점검", "포티게이트")
    assert term_in("국내 도로", "국내")
    assert not term_in("IOT gateway", "OT")


def test_fortinet_kev_is_urgent():
    record = _record(
        source="cve",
        external_id="CVE-2099-1401",
        kind="cve",
        title="FortiOS 관리 경로 취약점 샘플",
        vendor="Fortinet",
        product="FortiOS",
        cve_ids=["CVE-2099-1401"],
        cvss=9.8,
        epss=0.94,
        kev=True,
    )
    classify(record, INVENTORY)
    assert record.asset_hits == ["fortigate"]
    assert record.korea is False
    assert record.priority == 89
    assert record.band == "긴급"


def test_korea_its_news_is_watch():
    record = _record(title="국내 고속도로 교량 점검")
    classify(record, INVENTORY)
    assert record.korea and record.its
    assert record.asset_hits == []
    assert record.priority == 18
    assert record.band == "주의"


def test_korea_victim_bonus():
    record = _record(
        source="ransomware",
        kind="victim",
        title="남해샘플도로",
        country="KR",
        sector="Transportation",
    )
    classify(record, INVENTORY)
    assert record.priority == 46
    assert record.band == "높음"
    assert "교통" in record.its_tags


def test_unrelated_text_stays_low():
    record = _record(title="Francisco office picnic")
    classify(record, INVENTORY)
    assert record.asset_hits == []
    assert record.priority == 0
    assert record.band == "참고"


def test_band_edges():
    assert band_of(100) == "긴급"
    assert band_of(72) == "긴급"
    assert band_of(71) == "높음"
    assert band_of(46) == "높음"
    assert band_of(45) == "주의"
    assert band_of(18) == "주의"
    assert band_of(17) == "참고"


def test_shipped_inventory_covers_operator_stack():
    labels = " ".join(asset.label + " " + " ".join(asset.aliases) for asset in INVENTORY.assets)
    for word in ("Fortinet", "Cisco", "Ivanti", "Windows Server", "Ubuntu", "RHEL", "Wisenet", "SIMATIC"):
        assert word in labels
    assert INVENTORY.meta["owner"] == "최규선"
    assert "거가대교" in INVENTORY.meta["site"]
