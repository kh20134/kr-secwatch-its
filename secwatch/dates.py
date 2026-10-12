"""날짜 정규화. 샘플 픽스처의 D-N 토큰은 한국 표준시 오늘 기준이다."""

from __future__ import annotations

import re
from datetime import date, datetime, timedelta, timezone
from email.utils import parsedate_to_datetime

KST = timezone(timedelta(hours=9))
_RELATIVE = re.compile(r"D-(\d{1,3})$")
_ISO_PREFIX = re.compile(r"(\d{4}-\d{2}-\d{2})")


def now_kst() -> datetime:
    return datetime.now(KST).replace(microsecond=0)


def today_kst() -> date:
    return now_kst().date()


def stamp(moment: datetime | None = None) -> str:
    current = moment or now_kst()
    if current.tzinfo is None:
        current = current.replace(tzinfo=KST)
    return current.astimezone(KST).replace(microsecond=0).isoformat()


def normalize_date(value: str, *, today: date | None = None) -> str:
    raw = (value or "").strip()
    if not raw:
        return ""
    relative = _RELATIVE.fullmatch(raw)
    if relative:
        base = today or today_kst()
        return (base - timedelta(days=int(relative.group(1)))).isoformat()
    iso = _ISO_PREFIX.search(raw)
    if iso and (raw[0].isdigit() or "T" in raw):
        return iso.group(1)
    try:
        parsed = parsedate_to_datetime(raw)
    except (TypeError, ValueError, IndexError, OverflowError):
        parsed = None
    if parsed is None:
        return ""
    return parsed.date().isoformat()


def window_start(days: int, *, today: date | None = None) -> date:
    span = max(int(days), 1)
    base = today or today_kst()
    return base - timedelta(days=span - 1)
