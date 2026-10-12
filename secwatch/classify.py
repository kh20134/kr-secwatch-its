"""한국 연관, ITS·OT 태그, 자산 일치, 우선순위 점수.

배점(상한 100)
- CISA KEV 등재 36
- EPSS 확률 × 20, 최대 20
- CVSS / 10 × 16, 최대 16
- 자산대장 일치 18 (여러 자산이어도 1회)
- 한국 연관 8
- ITS·OT·인프라 10
- 국내 랜섬웨어 피해 주장 28

등급: 72 이상 긴급, 46 이상 높음, 18 이상 주의, 그 외 참고.
"""

from __future__ import annotations

from secwatch.inventory import Inventory, term_in
from secwatch.models import Record

KEV_POINTS = 36
EPSS_MAX = 20
CVSS_MAX = 16
ASSET_POINTS = 18
KOREA_POINTS = 8
ITS_POINTS = 10
KR_VICTIM_POINTS = 28
SCORE_CAP = 100
BAND_CRITICAL = 72
BAND_HIGH = 46
BAND_WATCH = 18

KOREA_TERMS: tuple[tuple[str, str], ...] = (
    ("대한민국", "대한민국"),
    ("한국", "한국"),
    ("국내", "국내"),
    ("South Korea", "south korea"),
    ("Republic of Korea", "republic of korea"),
    ("서울", "서울"),
    ("부산", "부산"),
    ("거제", "거제"),
    ("KISA", "kisa"),
    ("한국인터넷진흥원", "한국인터넷진흥원"),
    ("보호나라", "보호나라"),
    ("KrCERT", "krcert"),
    ("한국도로공사", "한국도로공사"),
    ("한국인프라관리", "한국인프라관리"),
    ("거가대교", "거가대교"),
    (".kr 도메인", ".kr"),
    ("Lazarus", "lazarus"),
    ("Kimsuky", "kimsuky"),
    ("Andariel", "andariel"),
)

ITS_RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("교통", ("지능형교통", "교통관제", "교통정보", "고속도로", "교량", "도로터널")),
    ("요금", ("하이패스", "톨게이트", "요금소", "차로제어")),
    ("전광", ("가변전광", "가변정보표지", "전광판", "variable message")),
    ("CCTV", ("cctv", "nvr", "dvr", "영상감시", "폐쇄회로")),
    ("OT", ("scada", "ics", "plc", "rtu", "hmi", "산업제어", "제어시스템", "iec 62443")),
    ("기반시설", ("국가기반시설", "기반시설")),
)

OPERATORS = ("거가대교", "한국인프라관리", "한국도로공사")

ITS_SECTORS = {
    "transportation": "교통",
    "transport": "교통",
    "energy": "에너지",
    "utilities": "에너지",
    "government": "공공",
    "telecommunications": "통신",
}


def iround(value: float) -> int:
    return int(value + 0.5)


def band_of(score: int) -> str:
    if score >= BAND_CRITICAL:
        return "긴급"
    if score >= BAND_HIGH:
        return "높음"
    if score >= BAND_WATCH:
        return "주의"
    return "참고"


def korea_hits(record: Record) -> list[str]:
    text = record.blob()
    hits: list[str] = []
    for label, term in KOREA_TERMS:
        if term_in(text, term) and label not in hits:
            hits.append(label)
    for name in OPERATORS:
        if name in text and "운영기관" not in hits:
            hits.append("운영기관")
    if record.source == "kisa":
        hits.append("KISA 공지")
    country = (record.country or "").strip()
    if country.upper() in {"KR", "KOR"}:
        hits.append("국가 코드 KR")
    elif country and term_in(country, "korea"):
        hits.append("국가명")
    return hits


def its_tags(record: Record) -> list[str]:
    text = record.blob()
    tags: list[str] = []
    for tag, terms in ITS_RULES:
        if any(term_in(text, term) for term in terms):
            tags.append(tag)
    if any(name in text for name in OPERATORS):
        tags.append("운영기관")
    sector_key = (record.sector or "").strip().casefold()
    sector_tag = ITS_SECTORS.get(sector_key)
    if sector_tag and sector_tag not in tags:
        tags.append(sector_tag)
    return tags


def _numeric(value: float | None, scale: float, cap: int) -> int:
    if value is None:
        return 0
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0
    if number < 0:
        return 0
    return min(cap, iround(number * scale))


def score_parts(record: Record) -> list[tuple[str, str, int]]:
    kev_points = KEV_POINTS if record.kev else 0
    epss_points = _numeric(record.epss, EPSS_MAX, EPSS_MAX)
    cvss_points = _numeric(record.cvss, CVSS_MAX / 10, CVSS_MAX)
    asset_points = ASSET_POINTS if record.asset_hits else 0
    korea_points = KOREA_POINTS if record.korea else 0
    its_points = ITS_POINTS if record.its else 0
    victim_points = KR_VICTIM_POINTS if record.kind == "victim" and record.korea else 0
    epss_text = "없음" if record.epss is None else f"{float(record.epss):.2f}"
    cvss_text = "없음" if record.cvss is None else f"{float(record.cvss):.1f}"
    return [
        ("KEV", "등재" if record.kev else "아님", kev_points),
        ("EPSS", epss_text, epss_points),
        ("CVSS", cvss_text, cvss_points),
        ("자산", "일치" if record.asset_hits else "없음", asset_points),
        ("한국", "연관" if record.korea else "아님", korea_points),
        ("ITS·OT", "해당" if record.its else "아님", its_points),
        ("국내 피해 주장", "해당" if victim_points else "아님", victim_points),
    ]


def priority_of(record: Record) -> int:
    return min(SCORE_CAP, sum(points for _, _, points in score_parts(record)))


def classify(record: Record, inventory: Inventory) -> Record:
    matched = inventory.match(record.blob())
    record.asset_hits = [asset.id for asset in matched]
    record.korea_hits = korea_hits(record)
    record.korea = bool(record.korea_hits)
    record.its_tags = its_tags(record)
    record.its = bool(record.its_tags)
    record.priority = priority_of(record)
    record.band = band_of(record.priority)
    return record


def in_scope(record: Record, inventory: Inventory) -> bool:
    """라이브 KEV를 관심 범위로 거른다. 점수는 매기지 않는다."""
    if inventory.match(record.blob()):
        return True
    return bool(korea_hits(record) or its_tags(record))
