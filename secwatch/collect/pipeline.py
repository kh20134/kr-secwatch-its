"""수집 한 번에 적재까지. 샘플 모드는 네트워크를 열지 않는다."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path

from secwatch.classify import classify, in_scope
from secwatch.collect.epss import EPSS_URL, parse_epss
from secwatch.collect.kev import KEV_URL, parse_kev
from secwatch.collect.merge import fold_records
from secwatch.collect.nvd import NVD_URL, parse_nvd
from secwatch.collect.ransomware import RANSOM_KR_URL, parse_victims
from secwatch.collect.rss import parse_feed
from secwatch.config import Settings
from secwatch.dates import stamp
from secwatch.http import HttpClient
from secwatch.inventory import Inventory, load_inventory
from secwatch.labels import source_label
from secwatch.models import Record
from secwatch.store import Store

ALL_SOURCES = (
    "kisa",
    "boannews",
    "dailysecu",
    "kev",
    "nvd",
    "epss",
    "ransomware",
)

KISA_URLS = (
    "https://www.boho.or.kr/kr/rss.do?bbsId=B0000133",
    "https://www.boho.or.kr/kr/rss.do?bbsId=B0000302",
)
NEWS_URLS = {
    "boannews": "https://cdn.boannews.com/rss/gn_rss_allArticle.xml",
    "dailysecu": "https://www.dailysecu.com/rss/allArticle.xml",
}
FEED_LIMIT = 40


@dataclass
class CollectResult:
    fetched: dict[str, int] = field(default_factory=dict)
    inserted: int = 0
    updated: int = 0
    alerts_sent: int = 0
    alerts_failed: int = 0
    errors: list[str] = field(default_factory=list)

    def summary(self) -> str:
        lines = ["수집 요약"]
        for source in ALL_SOURCES:
            if source not in self.fetched:
                continue
            lines.append(f"- {source_label(source)}: {self.fetched[source]}건")
        lines.append(f"- 신규 {self.inserted}건, 갱신 {self.updated}건")
        lines.append(f"- 알림 전송 {self.alerts_sent}건, 실패 {self.alerts_failed}건")
        if self.errors:
            lines.append("- 오류")
            lines.extend(f"  - {error}" for error in self.errors)
        return "\n".join(lines)


def normalize_sources(sources: list[str] | None) -> set[str]:
    if not sources:
        return set(ALL_SOURCES)
    selected: set[str] = set()
    for name in sources:
        if name == "news":
            selected.update({"boannews", "dailysecu"})
        elif name in ALL_SOURCES:
            selected.add(name)
        else:
            raise ValueError(f"알 수 없는 수집원: {name}")
    return selected


def _newest(records: list[Record], limit: int = FEED_LIMIT) -> list[Record]:
    ordered = sorted(records, key=lambda record: record.published_at or "", reverse=True)
    return ordered[:limit]


def allowed_cve_ids(records: list[Record], inventory: Inventory, limit: int) -> list[str]:
    mentioned: list[str] = []
    scoped: list[str] = []
    for record in records:
        if record.source == "kev" and record.cve_ids:
            if in_scope(record, inventory) and record.cve_ids[0] not in scoped:
                scoped.append(record.cve_ids[0])
            continue
        if record.source in {"nvd", "epss"}:
            continue
        for cve in record.cve_ids:
            if cve not in mentioned:
                mentioned.append(cve)
    ordered: list[str] = []
    for cve in scoped + mentioned:
        if cve not in ordered:
            ordered.append(cve)
    if limit > 0:
        return ordered[:limit]
    return ordered


def keep_allowed(records: list[Record], allowed: set[str]) -> list[Record]:
    kept: list[Record] = []
    for record in records:
        if record.source in {"kev", "nvd", "epss"}:
            if record.cve_ids and record.cve_ids[0] in allowed:
                kept.append(record)
        else:
            kept.append(record)
    return kept


def _read_demo(fixtures: Path, sources: set[str]) -> tuple[list[Record], dict[str, int], list[str]]:
    records: list[Record] = []
    fetched: dict[str, int] = {}
    errors: list[str] = []
    specs = {
        "kisa": ("kisa.xml", lambda data: parse_feed(data, source="kisa", kind="notice")),
        "boannews": ("boannews.xml", lambda data: parse_feed(data, source="boannews", kind="news")),
        "dailysecu": ("dailysecu.xml", lambda data: parse_feed(data, source="dailysecu", kind="news")),
        "kev": ("kev.json", parse_kev),
        "nvd": ("nvd.json", parse_nvd),
        "epss": ("epss.json", parse_epss),
        "ransomware": ("ransomware.json", parse_victims),
    }
    for source, (name, parser) in specs.items():
        if source not in sources:
            continue
        path = fixtures / name
        try:
            parsed = _newest(parser(path.read_bytes()))
        except (OSError, ValueError) as exc:
            errors.append(f"{source_label(source)}: {exc}")
            fetched[source] = 0
            continue
        fetched[source] = len(parsed)
        records.extend(parsed)
    return records, fetched, errors


def _live(
    client: HttpClient,
    sources: set[str],
) -> tuple[list[Record], dict[str, int], list[str]]:
    records: list[Record] = []
    fetched: dict[str, int] = {}
    errors: list[str] = []

    def take(source: str, loader, *, limit: int | None = FEED_LIMIT):
        try:
            parsed = loader()
            if limit is not None:
                parsed = _newest(parsed, limit)
        except Exception as exc:
            errors.append(f"{source_label(source)}: {exc}")
            fetched[source] = 0
            return
        fetched[source] = len(parsed)
        records.extend(parsed)

    if "kisa" in sources:
        def load_kisa():
            found: list[Record] = []
            for url in KISA_URLS:
                found.extend(parse_feed(client.get_bytes(url), source="kisa", kind="notice"))
            return found

        take("kisa", load_kisa)

    for source, url in NEWS_URLS.items():
        if source not in sources:
            continue
        take(
            source,
            lambda url=url, source=source: parse_feed(
                client.get_bytes(url), source=source, kind="news"
            ),
        )

    if "kev" in sources:
        take(
            "kev",
            lambda: parse_kev(client.get_bytes(KEV_URL, max_bytes=12_000_000)),
            limit=None,
        )

    if "ransomware" in sources:
        take(
            "ransomware",
            lambda: parse_victims(client.get_bytes(RANSOM_KR_URL, max_bytes=4_000_000)),
        )
    return records, fetched, errors, 


def _fetch_nvd(client: HttpClient, cve_ids: list[str], *, api_key: str, pause: float) -> tuple[list[Record], list[str]]:
    found: list[Record] = []
    errors: list[str] = []
    headers = {"apiKey": api_key} if api_key else None
    for index, cve in enumerate(cve_ids):
        if index and pause:
            time.sleep(pause)
        url = f"{NVD_URL}?cveId={cve}"
        try:
            found.extend(parse_nvd(client.get_bytes(url, headers=headers, max_bytes=1_500_000)))
        except Exception as exc:
            errors.append(f"NVD {cve}: {exc}")
    return found, errors


def _fetch_epss(client: HttpClient, cve_ids: list[str]) -> tuple[list[Record], list[str]]:
    found: list[Record] = []
    errors: list[str] = []
    for start in range(0, len(cve_ids), 100):
        chunk = cve_ids[start : start + 100]
        url = EPSS_URL + "?cve=" + ",".join(chunk)
        try:
            found.extend(parse_epss(client.get_bytes(url, max_bytes=2_000_000)))
        except Exception as exc:
            errors.append(f"EPSS: {exc}")
    return found, errors


def run_collect(
    settings: Settings,
    store: Store,
    *,
    alert: bool = True,
    sources: list[str] | None = None,
    client: HttpClient | None = None,
    inventory: Inventory | None = None,
    pause: float | None = None,
    slack_post=None,
    smtp_factory=None,
) -> CollectResult:
    selected = normalize_sources(sources)
    inventory = inventory or load_inventory(settings.inventory_path)
    if settings.demo:
        raw, fetched, errors = _read_demo(settings.fixtures_path, selected)
    else:
        http = client or HttpClient(timeout=settings.http_timeout)
        nvd_pause = pause if pause is not None else (0.6 if settings.nvd_api_key else 6.0)
        raw, fetched, errors = _live(http, selected)
        cve_ids = allowed_cve_ids(raw, inventory, settings.nvd_max)
        if "nvd" in selected and cve_ids:
            extra, extra_errors = _fetch_nvd(
                http, cve_ids, api_key=settings.nvd_api_key, pause=nvd_pause
            )
            errors.extend(extra_errors)
            fetched["nvd"] = len(extra)
            raw.extend(extra)
        if "epss" in selected and cve_ids:
            extra, extra_errors = _fetch_epss(http, cve_ids)
            errors.extend(extra_errors)
            fetched["epss"] = len(extra)
            raw.extend(extra)

    cve_ids = allowed_cve_ids(raw, inventory, settings.nvd_max or len(raw) or 1)
    raw = keep_allowed(raw, set(cve_ids))
    for source in ("kev", "nvd", "epss"):
        if source in fetched:
            fetched[source] = sum(record.source == source for record in raw)
    folded = fold_records(raw)
    for record in folded:
        classify(record, inventory)
    if settings.demo:
        store.reset()
    inserted, updated = store.upsert(folded)
    store.set_meta("last_collect", stamp())
    result = CollectResult(
        fetched=fetched,
        inserted=inserted,
        updated=updated,
        errors=errors,
    )
    if alert and not settings.demo and settings.alerts_configured:
        from secwatch.alerts import dispatch

        sent, failed = dispatch(
            settings,
            store,
            folded,
            inventory,
            slack_post=slack_post,
            smtp_factory=smtp_factory,
        )
        result.alerts_sent = sent
        result.alerts_failed = failed
    return result
