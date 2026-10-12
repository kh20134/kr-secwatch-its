"""FIRST EPSS API. 확률 숫자만 보관한다."""

from __future__ import annotations

import json

from secwatch.dates import normalize_date
from secwatch.models import Record

EPSS_URL = "https://api.first.org/data/v1/epss"


class EpssError(ValueError):
    pass


def parse_epss(data: bytes) -> list[Record]:
    try:
        payload = json.loads(data.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EpssError("EPSS JSON 해석 실패") from exc
    rows = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(rows, list):
        raise EpssError("EPSS 목록이 없다")
    records: list[Record] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        cve = str(row.get("cve") or "").upper()
        if not cve.startswith("CVE-"):
            continue
        try:
            score = float(row.get("epss"))
        except (TypeError, ValueError):
            continue
        records.append(
            Record(
                source="epss",
                external_id=cve,
                kind="cve",
                title=cve,
                cve_ids=[cve],
                epss=score,
                published_at=normalize_date(str(row.get("date") or "")),
            )
        )
    return records
