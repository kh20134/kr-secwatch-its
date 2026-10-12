"""RSS 2.0 / Atom 항목을 공지·뉴스 레코드로 읽는다."""

from __future__ import annotations

import xml.etree.ElementTree as ET

from secwatch.dates import normalize_date
from secwatch.models import Record
from secwatch.textutil import clean_url, clip, extract_cves, notice_id, strip_html


class FeedError(ValueError):
    pass


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _child_text(node: ET.Element, name: str) -> str:
    for child in list(node):
        if _local(child.tag) == name:
            return "".join(child.itertext()).strip()
    return ""


def _link_value(node: ET.Element) -> str:
    plain = _child_text(node, "link")
    if plain:
        return plain
    for child in list(node):
        if _local(child.tag) == "link" and child.attrib.get("href"):
            return child.attrib["href"].strip()
    return ""


def parse_feed(data: bytes, *, source: str, kind: str) -> list[Record]:
    if not data or not data.strip():
        raise FeedError(f"{source} 피드가 비어 있다")
    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        raise FeedError(f"{source} XML 해석 실패") from exc
    records: list[Record] = []
    for node in root.iter():
        if _local(node.tag) not in {"item", "entry"}:
            continue
        title = clip(_child_text(node, "title"), 240)
        if not title:
            continue
        link = clean_url(_link_value(node))
        summary_raw = (
            _child_text(node, "description")
            or _child_text(node, "summary")
            or _child_text(node, "encoded")
            or _child_text(node, "content")
        )
        summary = strip_html(summary_raw)
        published = normalize_date(
            _child_text(node, "pubDate")
            or _child_text(node, "published")
            or _child_text(node, "updated")
            or _child_text(node, "date")
        )
        guid = _child_text(node, "guid") or _child_text(node, "id")
        body = f"{title} {summary}"
        records.append(
            Record(
                source=source,
                external_id=notice_id(link, guid, title),
                kind=kind,
                title=title,
                summary=summary,
                url=link,
                published_at=published,
                cve_ids=extract_cves(body),
            )
        )
    return records
