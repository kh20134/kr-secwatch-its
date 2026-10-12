"""NVD CVE API 2.0 응답에서 점수와 설명만 뽑는다."""

from __future__ import annotations

import json

from secwatch.dates import normalize_date
from secwatch.models import Record
from secwatch.textutil import clean_url, clip

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class NvdError(ValueError):
    pass


def _description(cve: dict) -> str:
    texts = cve.get("descriptions") or []
    if not isinstance(texts, list):
        return ""
    english = ""
    fallback = ""
    for item in texts:
        if not isinstance(item, dict):
            continue
        value = str(item.get("value") or "").strip()
        if not value:
            continue
        if str(item.get("lang") or "").lower() == "en" and not english:
            english = value
        elif not fallback:
            fallback = value
    return clip(english or fallback, 500)


def _cvss(cve: dict) -> float | None:
    metrics = cve.get("metrics") or {}
    if not isinstance(metrics, dict):
        return None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40"):
        rows = metrics.get(key) or []
        if not isinstance(rows, list):
            continue
        primary = None
        first = None
        for row in rows:
            if not isinstance(row, dict):
                continue
            data = row.get("cvssData") or {}
            score = data.get("baseScore")
            if score is None:
                continue
            if first is None:
                first = score
            if str(row.get("type") or "").lower() == "primary":
                primary = score
                break
        chosen = primary if primary is not None else first
        if chosen is not None:
            return float(chosen)
    return None


def parse_nvd(data: bytes) -> list[Record]:
    try:
        payload = json.loads(data.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise NvdError("NVD JSON 해석 실패") from exc
    rows = payload.get("vulnerabilities") if isinstance(payload, dict) else None
    if rows is None:
        raise NvdError("NVD 응답 형식이 아니다")
    records: list[Record] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        cve = row.get("cve") or {}
        cve_id = str(cve.get("id") or "").upper()
        if not cve_id.startswith("CVE-"):
            continue
        summary = _description(cve)
        records.append(
            Record(
                source="nvd",
                external_id=cve_id,
                kind="cve",
                title=clip(summary, 90) or cve_id,
                summary=summary,
                url=clean_url(f"https://nvd.nist.gov/vuln/detail/{cve_id}"),
                published_at=normalize_date(str(cve.get("published") or "")),
                cve_ids=[cve_id],
                cvss=_cvss(cve),
            )
        )
    return records
