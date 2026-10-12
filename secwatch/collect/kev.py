"""CISA Known Exploited Vulnerabilities 카탈로그."""

from __future__ import annotations

import json

from secwatch.dates import normalize_date
from secwatch.models import Record
from secwatch.textutil import clean_url, clip, extract_cves

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class KevError(ValueError):
    pass


def parse_kev(data: bytes) -> list[Record]:
    try:
        payload = json.loads(data.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise KevError("KEV JSON 해석 실패") from exc
    rows = payload.get("vulnerabilities") if isinstance(payload, dict) else None
    if not isinstance(rows, list):
        raise KevError("KEV 목록이 없다")
    records: list[Record] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        cve = str(row.get("cveID") or "").upper()
        if not cve.startswith("CVE-"):
            continue
        name = clip(str(row.get("vulnerabilityName") or cve), 240)
        summary = clip(str(row.get("shortDescription") or ""), 360)
        action = clip(str(row.get("requiredAction") or ""), 160)
        if action:
            summary = clip(f"{summary} 조치: {action}".strip(), 500)
        records.append(
            Record(
                source="kev",
                external_id=cve,
                kind="cve",
                title=name,
                summary=summary,
                url=clean_url(f"https://nvd.nist.gov/vuln/detail/{cve}"),
                published_at=normalize_date(str(row.get("dateAdded") or "")),
                cve_ids=extract_cves(cve) or [cve],
                kev=True,
                vendor=clip(str(row.get("vendorProject") or ""), 80),
                product=clip(str(row.get("product") or ""), 80),
            )
        )
    return records
