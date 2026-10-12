"""KEV·NVD·EPSS를 CVE 한 장으로 합치고, 기사에 점수를 붙인다."""

from __future__ import annotations

from secwatch.models import Record
from secwatch.textutil import clean_url, clip, extract_cves

CVE_SOURCES = {"kev", "nvd", "epss"}


def _prefer(current: str, new: str) -> str:
    return current or new


def merge_cve(cve_id: str, parts: list[Record]) -> Record:
    kev = next((part for part in parts if part.source == "kev"), None)
    nvd = next((part for part in parts if part.source == "nvd"), None)
    epss = next((part for part in parts if part.source == "epss"), None)
    title = clip((kev.title if kev else "") or (nvd.title if nvd else "") or cve_id, 240)
    summary = (kev.summary if kev else "") or (nvd.summary if nvd else "")
    published_candidates = [
        part.published_at
        for part in (kev, nvd)
        if part is not None and part.published_at
    ]
    if not published_candidates and epss and epss.published_at:
        published_candidates.append(epss.published_at)
    cvss = nvd.cvss if nvd and nvd.cvss is not None else None
    if cvss is None:
        for part in parts:
            if part.cvss is not None:
                cvss = part.cvss
                break
    epss_score = epss.epss if epss else None
    return Record(
        source="cve",
        external_id=cve_id,
        kind="cve",
        title=title,
        summary=summary,
        url=clean_url(f"https://nvd.nist.gov/vuln/detail/{cve_id}"),
        published_at=max(published_candidates) if published_candidates else "",
        cve_ids=[cve_id],
        cvss=cvss,
        epss=epss_score,
        kev=any(part.kev or part.source == "kev" for part in parts),
        vendor=_prefer(kev.vendor if kev else "", nvd.vendor if nvd else ""),
        product=_prefer(kev.product if kev else "", nvd.product if nvd else ""),
    )


def fold_records(records: list[Record]) -> list[Record]:
    others: list[Record] = []
    grouped: dict[str, list[Record]] = {}
    for record in records:
        if record.kind == "cve" and record.source in CVE_SOURCES and record.cve_ids:
            grouped.setdefault(record.cve_ids[0], []).append(record)
        else:
            if not record.cve_ids:
                record.cve_ids = extract_cves(f"{record.title} {record.summary}")
            others.append(record)
    merged = [merge_cve(cve_id, parts) for cve_id, parts in grouped.items()]
    by_id = {record.cve_ids[0]: record for record in merged}
    for record in others:
        enrich(record, by_id)
    return others + merged


def enrich(record: Record, by_id: dict[str, Record]) -> None:
    related = [by_id[cve] for cve in record.cve_ids if cve in by_id]
    if not related:
        return
    if any(item.kev for item in related):
        record.kev = True
    cvss_values = [item.cvss for item in related if item.cvss is not None]
    epss_values = [item.epss for item in related if item.epss is not None]
    if cvss_values:
        record.cvss = max(cvss_values)
    if epss_values:
        record.epss = max(epss_values)
    if not record.vendor:
        record.vendor = next((item.vendor for item in related if item.vendor), "")
    if not record.product:
        record.product = next((item.product for item in related if item.product), "")
