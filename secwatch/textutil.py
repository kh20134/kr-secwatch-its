"""텍스트 정리. 본문 전문은 보관하지 않고 짧은 요약만 남긴다."""

from __future__ import annotations

import html
import re
from urllib.parse import parse_qs, urlparse

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_TAG_RE = re.compile(r"(?is)<(script|style).*?>.*?</\1>")
_ANY_TAG_RE = re.compile(r"(?s)<[^>]+>")
_SPACE_RE = re.compile(r"\s+")


def strip_html(value: str, *, limit: int = 500) -> str:
    text = value or ""
    text = _TAG_RE.sub(" ", text)
    text = _ANY_TAG_RE.sub(" ", text)
    text = html.unescape(text)
    text = _SPACE_RE.sub(" ", text).strip()
    if len(text) > limit:
        return text[: limit - 1].rstrip() + "…"
    return text


def extract_cves(text: str) -> list[str]:
    found: list[str] = []
    for match in CVE_RE.findall(text or ""):
        cve = match.upper()
        if cve not in found:
            found.append(cve)
    return found


def clean_url(url: str, *, limit: int = 500) -> str:
    raw = (url or "").strip()
    lowered = raw.lower()
    if ".onion" in lowered:
        return ""
    if not (lowered.startswith("https://") or lowered.startswith("http://")):
        return ""
    return raw[:limit]


def notice_id(link: str, guid: str, title: str) -> str:
    cleaned = (link or "").strip()
    if cleaned:
        query = parse_qs(urlparse(cleaned).query)
        ntt = (query.get("nttId") or [""])[0].strip()
        if ntt:
            return "ntt:" + ntt[:80]
        return "url:" + cleaned[:180]
    if guid and guid.strip():
        return "guid:" + guid.strip()[:180]
    digest = re.sub(r"\s+", " ", title or "").strip()
    return "title:" + digest[:120]


def clip(value: str, limit: int) -> str:
    text = _SPACE_RE.sub(" ", (value or "").strip())
    if len(text) > limit:
        return text[: limit - 1].rstrip() + "…"
    return text
