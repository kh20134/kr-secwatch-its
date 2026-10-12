"""YAML 자산대장과 별칭 대조."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

CATEGORY_LABELS = {
    "network": "네트워크",
    "remote-access": "원격접속",
    "server": "서버",
    "cctv": "CCTV·NVR",
    "its": "ITS·교통",
    "ot": "OT·제어",
}


@dataclass(frozen=True)
class Asset:
    id: str
    category: str
    vendor: str
    product: str
    role: str
    aliases: tuple[str, ...]

    @property
    def category_label(self) -> str:
        return CATEGORY_LABELS.get(self.category, self.category)

    @property
    def label(self) -> str:
        return f"{self.vendor} {self.product}".strip()


@dataclass(frozen=True)
class Inventory:
    meta: dict
    assets: tuple[Asset, ...]

    def by_id(self, asset_id: str) -> Asset | None:
        for asset in self.assets:
            if asset.id == asset_id:
                return asset
        return None

    def label_of(self, asset_id: str) -> str:
        asset = self.by_id(asset_id)
        return asset.label if asset else asset_id

    def match(self, text: str) -> list[Asset]:
        hits: list[Asset] = []
        for asset in self.assets:
            if any(term_in(text, alias) for alias in asset.aliases):
                hits.append(asset)
        return hits


def term_in(text: str, term: str) -> bool:
    needle = (term or "").strip()
    if not needle or not text:
        return False
    if needle == ".kr":
        return re.search(r"(?i)\.kr\b", text) is not None
    if re.search(r"[A-Za-z0-9]", needle):
        if len(needle) < 3:
            return False
        pattern = rf"(?i)(?<![A-Za-z0-9]){re.escape(needle)}(?![A-Za-z0-9])"
        return re.search(pattern, text) is not None
    return needle.casefold() in text.casefold()


def load_inventory(path: Path) -> Inventory:
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    meta = raw.get("meta") or {}
    assets: list[Asset] = []
    seen: set[str] = set()
    for entry in raw.get("assets") or []:
        asset_id = str(entry.get("id") or "").strip()
        if not asset_id:
            raise ValueError("자산 id가 비어 있다")
        if asset_id in seen:
            raise ValueError(f"자산 id 중복: {asset_id}")
        seen.add(asset_id)
        aliases = tuple(
            str(alias).strip() for alias in (entry.get("aliases") or []) if str(alias).strip()
        )
        assets.append(
            Asset(
                id=asset_id,
                category=str(entry.get("category") or "").strip(),
                vendor=str(entry.get("vendor") or "").strip(),
                product=str(entry.get("product") or "").strip(),
                role=str(entry.get("role") or "").strip(),
                aliases=aliases,
            )
        )
    return Inventory(meta=dict(meta), assets=tuple(assets))
