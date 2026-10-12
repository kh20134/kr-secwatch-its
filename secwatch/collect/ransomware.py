"""ransomware.live 공개 API.

보관 필드: 조직명, 국가, 주장 그룹, 업종, 날짜.
claim_url, 유출 설명, infostealer, onion 주소는 버린다.
등록 내용은 범죄 그룹의 주장이며 확인된 사고가 아니다.
"""

from __future__ import annotations

import json

from secwatch.dates import normalize_date
from secwatch.models import Record
from secwatch.textutil import clip

RANSOM_KR_URL = "https://api.ransomware.live/v2/countryvictims/KR"
DROPPED_KEYS = {
    "claim_url",
    "description",
    "infostealer",
    "data_size",
    "press",
    "screenshot",
    "permalink",
    "website",
    "domain",
    "url",
    "updates",
}


class RansomError(ValueError):
    pass


def _rows(payload) -> list[dict]:
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    if isinstance(payload, dict):
        if "victim" in payload:
            return [payload]
        message = str(payload.get("message") or "")
        if message and "victim" not in payload:
            raise RansomError(f"API 제한 또는 오류: {message[:120]}")
        for key in ("victims", "data", "results"):
            value = payload.get(key)
            if isinstance(value, list):
                return [row for row in value if isinstance(row, dict)]
    raise RansomError("피해 목록 형식이 아니다")


def parse_victims(data: bytes) -> list[Record]:
    try:
        payload = json.loads(data.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RansomError("랜섬웨어 JSON 해석 실패") from exc
    records: list[Record] = []
    for row in _rows(payload):
        for key in DROPPED_KEYS:
            row.pop(key, None)
        name = clip(str(row.get("victim") or ""), 160)
        if not name:
            continue
        group = clip(str(row.get("group") or ""), 80)
        country = clip(str(row.get("country") or ""), 40).upper()
        sector = clip(str(row.get("activity") or row.get("sector") or ""), 80)
        published = normalize_date(
            str(row.get("discovered") or row.get("attackdate") or "")
        )
        external = "|".join([country, group.casefold(), name.casefold(), published])
        records.append(
            Record(
                source="ransomware",
                external_id=external[:200],
                kind="victim",
                title=name,
                summary="공개 추적기에 올라온 피해 주장이다. 사실 여부는 확인되지 않았다.",
                url="https://www.ransomware.live/",
                published_at=published,
                country=country,
                actor=group,
                sector=sector,
            )
        )
    return records
