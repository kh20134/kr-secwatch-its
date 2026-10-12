"""수집 한 건의 정규 레코드."""

from __future__ import annotations

import json
from dataclasses import dataclass, field


def _loads(value: str) -> list[str]:
    try:
        parsed = json.loads(value or "[]")
    except json.JSONDecodeError:
        return []
    if not isinstance(parsed, list):
        return []
    return [str(item) for item in parsed]


@dataclass
class Record:
    source: str
    external_id: str
    kind: str
    title: str
    summary: str = ""
    url: str = ""
    published_at: str = ""
    cve_ids: list[str] = field(default_factory=list)
    cvss: float | None = None
    epss: float | None = None
    kev: bool = False
    vendor: str = ""
    product: str = ""
    country: str = ""
    actor: str = ""
    sector: str = ""
    korea: bool = False
    korea_hits: list[str] = field(default_factory=list)
    its: bool = False
    its_tags: list[str] = field(default_factory=list)
    asset_hits: list[str] = field(default_factory=list)
    priority: int = 0
    band: str = "참고"
    id: int | None = None

    def blob(self) -> str:
        parts = [
            self.title,
            self.summary,
            self.vendor,
            self.product,
            self.sector,
            self.country,
            self.actor,
            " ".join(self.cve_ids),
        ]
        return " ".join(part for part in parts if part)

    def as_row(self, *, ingested_at: str, updated_at: str) -> tuple:
        return (
            self.source,
            self.external_id,
            self.kind,
            self.title,
            self.summary,
            self.url,
            self.published_at,
            json.dumps(self.cve_ids, ensure_ascii=False),
            self.cvss,
            self.epss,
            1 if self.kev else 0,
            self.vendor,
            self.product,
            self.country,
            self.actor,
            self.sector,
            1 if self.korea else 0,
            json.dumps(self.korea_hits, ensure_ascii=False),
            1 if self.its else 0,
            json.dumps(self.its_tags, ensure_ascii=False),
            json.dumps(self.asset_hits, ensure_ascii=False),
            self.priority,
            self.band,
            ingested_at,
            updated_at,
        )

    @classmethod
    def from_row(cls, row) -> Record:
        return cls(
            id=row["id"],
            source=row["source"],
            external_id=row["external_id"],
            kind=row["kind"],
            title=row["title"],
            summary=row["summary"],
            url=row["url"],
            published_at=row["published_at"],
            cve_ids=_loads(row["cve_ids"]),
            cvss=row["cvss"],
            epss=row["epss"],
            kev=bool(row["kev"]),
            vendor=row["vendor"],
            product=row["product"],
            country=row["country"],
            actor=row["actor"],
            sector=row["sector"],
            korea=bool(row["korea"]),
            korea_hits=_loads(row["korea_hits"]),
            its=bool(row["its"]),
            its_tags=_loads(row["its_tags"]),
            asset_hits=_loads(row["asset_hits"]),
            priority=row["priority"],
            band=row["band"],
        )
