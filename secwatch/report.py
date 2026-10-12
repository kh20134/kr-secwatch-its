"""주간 현황. 마크다운과 HTML이 같은 묶음을 쓴다."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from secwatch.dates import now_kst, today_kst, window_start
from secwatch.inventory import Inventory
from secwatch.labels import kind_label, source_label
from secwatch.models import Record
from secwatch.store import Store

ACTIONS = (
    "자산대장에 적중한 KEV는 제조사 보안공지의 공식 업데이트 적용 여부를 확인한다.",
    "원격접속 장비는 관리 포트가 외부에 열려 있는지 점검한다.",
    "CCTV·NVR은 계정, 펌웨어, 관리 화면 노출을 대조한다.",
    "OT 구간은 현장 영향을 먼저 보고 패치 창을 따로 잡는다.",
    "랜섬웨어 항목은 조직명 주장만 있으므로 사실 확인 전에 사고 티켓으로 올리지 않는다.",
)


@dataclass
class ReportBundle:
    generated: str
    start: str
    end: str
    days: int
    owner: str
    organization: str
    site: str
    qualification: str
    totals: dict[str, int]
    highlights: list[Record] = field(default_factory=list)
    asset_cves: list[Record] = field(default_factory=list)
    korea_its: list[Record] = field(default_factory=list)
    victims: list[Record] = field(default_factory=list)
    by_source: list[tuple[str, int]] = field(default_factory=list)
    actions: tuple[str, ...] = ACTIONS


def build_report(store: Store, inventory: Inventory, *, days: int = 7) -> ReportBundle:
    start = window_start(days)
    end = today_kst()
    items = store.query(since=start.isoformat(), limit=500)
    meta = inventory.meta
    return ReportBundle(
        generated=now_kst().strftime("%Y-%m-%d %H:%M KST"),
        start=start.isoformat(),
        end=end.isoformat(),
        days=days,
        owner=str(meta.get("owner") or ""),
        organization=str(meta.get("organization") or ""),
        site=str(meta.get("site") or ""),
        qualification=str(meta.get("qualification") or ""),
        totals=_totals(items),
        highlights=[item for item in items if item.band in {"긴급", "높음"}],
        asset_cves=[item for item in items if item.kind == "cve" and item.asset_hits],
        korea_its=[
            item for item in items if item.korea and item.its and item.kind in {"news", "notice"}
        ],
        victims=[item for item in items if item.kind == "victim"],
        by_source=_by_source(items),
    )


def _totals(items: list[Record]) -> dict[str, int]:
    return {
        "total": len(items),
        "urgent": sum(item.band == "긴급" for item in items),
        "high": sum(item.band == "높음" for item in items),
        "watch": sum(item.band == "주의" for item in items),
        "info": sum(item.band == "참고" for item in items),
        "korea": sum(item.korea for item in items),
        "its": sum(item.its for item in items),
        "assets": sum(bool(item.asset_hits) for item in items),
        "kev": sum(item.kev for item in items),
    }


def _by_source(items: list[Record]) -> list[tuple[str, int]]:
    counts: dict[str, int] = {}
    for item in items:
        counts[item.source] = counts.get(item.source, 0) + 1
    return sorted(counts.items(), key=lambda pair: (-pair[1], pair[0]))


def _md_cell(value: str) -> str:
    return value.replace("|", "/").replace("\n", " ").strip()


def render_markdown(bundle: ReportBundle, inventory: Inventory) -> str:
    lines = [
        f"# 주간 보안 현황 ({bundle.start} ~ {bundle.end})",
        "",
        f"- 작성 시각: {bundle.generated}",
        f"- 관점: {bundle.owner} · {bundle.qualification} · {bundle.organization}({bundle.site})",
        "- 범위: 공개 피드와 샘플만. 공격 절차는 담지 않는다.",
        "",
        "## 요약",
        f"- 전체 {bundle.totals['total']}건",
        f"- 긴급 {bundle.totals['urgent']}건, 높음 {bundle.totals['high']}건, 주의 {bundle.totals['watch']}건, 참고 {bundle.totals['info']}건",
        f"- 한국 연관 {bundle.totals['korea']}건, ITS·OT {bundle.totals['its']}건, 자산 일치 {bundle.totals['assets']}건, KEV {bundle.totals['kev']}건",
        "",
        "## 긴급·높음",
    ]
    lines.extend(_md_items(bundle.highlights, inventory) or ["- 해당 없음"])
    lines.extend(["", "## 자산과 겹친 취약점"])
    lines.extend(_md_items(bundle.asset_cves, inventory) or ["- 해당 없음"])
    lines.extend(["", "## 한국·인프라 소식"])
    lines.extend(_md_items(bundle.korea_its, inventory) or ["- 해당 없음"])
    lines.extend(["", "## 랜섬웨어 피해 주장", "- 조직명만 표시한다. 유출 본문과 onion 주소는 보관하지 않는다.", "- 사실로 확인된 사고가 아니다."])
    if bundle.victims:
        for item in bundle.victims:
            lines.append(
                f"- {_md_cell(item.title)} / {item.country or '-'} / {item.actor or '-'} / {item.sector or '-'} / {item.band} {item.priority}점"
            )
    else:
        lines.append("- 해당 없음")
    lines.extend(["", "## 이번 주 권고"])
    lines.extend(f"- {action}" for action in bundle.actions)
    lines.extend(["", "## 출처별 건수"])
    if bundle.by_source:
        lines.extend(f"- {source_label(source)}: {count}건" for source, count in bundle.by_source)
    else:
        lines.append("- 해당 없음")
    lines.append("")
    return "\n".join(lines)


def _md_items(items: list[Record], inventory: Inventory) -> list[str]:
    rows = []
    for item in items:
        assets = ", ".join(inventory.label_of(asset_id) for asset_id in item.asset_hits)
        cve = ", ".join(item.cve_ids)
        bits = [item.band, f"{item.priority}점", kind_label(item.kind), _md_cell(item.title)]
        if cve:
            bits.append(cve)
        if assets:
            bits.append(assets)
        rows.append("- " + " / ".join(bits))
    return rows


def write_report(directory: Path, markdown: str, html: str) -> tuple[Path, Path]:
    directory.mkdir(parents=True, exist_ok=True)
    md_path = directory / "weekly.md"
    html_path = directory / "weekly.html"
    md_path.write_text(markdown, encoding="utf-8")
    html_path.write_text(html, encoding="utf-8")
    return md_path, html_path
