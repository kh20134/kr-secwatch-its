"""SQLite 저장. 같은 출처·외부 키는 한 행으로 갱신한다."""

from __future__ import annotations

import sqlite3
from collections import Counter
from pathlib import Path

from secwatch.dates import stamp
from secwatch.models import Record

SCHEMA = """
CREATE TABLE IF NOT EXISTS items (
    id INTEGER PRIMARY KEY,
    source TEXT NOT NULL,
    external_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    title TEXT NOT NULL,
    summary TEXT NOT NULL DEFAULT '',
    url TEXT NOT NULL DEFAULT '',
    published_at TEXT NOT NULL DEFAULT '',
    cve_ids TEXT NOT NULL DEFAULT '[]',
    cvss REAL,
    epss REAL,
    kev INTEGER NOT NULL DEFAULT 0,
    vendor TEXT NOT NULL DEFAULT '',
    product TEXT NOT NULL DEFAULT '',
    country TEXT NOT NULL DEFAULT '',
    actor TEXT NOT NULL DEFAULT '',
    sector TEXT NOT NULL DEFAULT '',
    korea INTEGER NOT NULL DEFAULT 0,
    korea_hits TEXT NOT NULL DEFAULT '[]',
    its INTEGER NOT NULL DEFAULT 0,
    its_tags TEXT NOT NULL DEFAULT '[]',
    asset_hits TEXT NOT NULL DEFAULT '[]',
    priority INTEGER NOT NULL DEFAULT 0,
    band TEXT NOT NULL DEFAULT '참고',
    ingested_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(source, external_id)
);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY,
    item_key TEXT NOT NULL,
    channel TEXT NOT NULL,
    status TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    UNIQUE(item_key, channel)
);
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_items_priority ON items(priority DESC, published_at DESC);
"""


class Store:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def reset(self) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM alerts")
            conn.execute("DELETE FROM items")
            conn.execute("DELETE FROM meta")

    def set_meta(self, key: str, value: str) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO meta(key, value) VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                (key, value),
            )

    def get_meta(self, key: str) -> str:
        with self._connect() as conn:
            row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else ""

    def upsert(self, records: list[Record]) -> tuple[int, int]:
        inserted = 0
        updated = 0
        moment = stamp()
        with self._connect() as conn:
            for record in records:
                row = record.as_row(ingested_at=moment, updated_at=moment)
                existing = conn.execute(
                    "SELECT id FROM items WHERE source = ? AND external_id = ?",
                    (record.source, record.external_id),
                ).fetchone()
                if existing is None:
                    conn.execute(
                        """
                        INSERT INTO items (
                            source, external_id, kind, title, summary, url, published_at,
                            cve_ids, cvss, epss, kev, vendor, product, country, actor, sector,
                            korea, korea_hits, its, its_tags, asset_hits, priority, band,
                            ingested_at, updated_at
                        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                        """,
                        row,
                    )
                    inserted += 1
                    continue
                conn.execute(
                    """
                    UPDATE items SET
                        kind=?, title=?, summary=?, url=?, published_at=?,
                        cve_ids=?, cvss=?, epss=?, kev=?, vendor=?, product=?,
                        country=?, actor=?, sector=?, korea=?, korea_hits=?,
                        its=?, its_tags=?, asset_hits=?, priority=?, band=?,
                        updated_at=?
                    WHERE id=?
                    """,
                    (*row[2:23], moment, existing["id"]),
                )
                updated += 1
        return inserted, updated

    def get(self, item_id: int) -> Record | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM items WHERE id = ?", (item_id,)).fetchone()
        return Record.from_row(row) if row else None

    def find_key(self, source: str, external_id: str) -> Record | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM items WHERE source = ? AND external_id = ?",
                (source, external_id),
            ).fetchone()
        return Record.from_row(row) if row else None

    def count(self) -> int:
        with self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) AS n FROM items").fetchone()
        return int(row["n"])

    def query(
        self,
        *,
        band: str = "",
        kind: str = "",
        scope: str = "",
        q: str = "",
        since: str = "",
        limit: int = 80,
    ) -> list[Record]:
        clauses = ["1=1"]
        params: list = []
        if band:
            clauses.append("band = ?")
            params.append(band)
        if kind:
            clauses.append("kind = ?")
            params.append(kind)
        if scope == "korea":
            clauses.append("korea = 1")
        elif scope == "its":
            clauses.append("its = 1")
        elif scope == "asset":
            clauses.append("asset_hits != '[]'")
        if since:
            clauses.append("published_at >= ?")
            params.append(since)
        if q:
            like = f"%{q.replace('%', '').replace('_', '')}%"
            clauses.append(
                "(title LIKE ? OR summary LIKE ? OR cve_ids LIKE ? OR vendor LIKE ? OR product LIKE ? OR actor LIKE ?)"
            )
            params.extend([like, like, like, like, like, like])
        params.append(int(limit))
        sql = (
            "SELECT * FROM items WHERE "
            + " AND ".join(clauses)
            + " ORDER BY priority DESC, published_at DESC, id DESC LIMIT ?"
        )
        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [Record.from_row(row) for row in rows]

    def stats(self) -> dict[str, int]:
        sql = """
        SELECT
            COUNT(*) AS total,
            SUM(CASE WHEN band = '긴급' THEN 1 ELSE 0 END) AS urgent,
            SUM(CASE WHEN band = '높음' THEN 1 ELSE 0 END) AS high,
            SUM(CASE WHEN band = '주의' THEN 1 ELSE 0 END) AS watch,
            SUM(CASE WHEN band = '참고' THEN 1 ELSE 0 END) AS info,
            SUM(CASE WHEN korea = 1 THEN 1 ELSE 0 END) AS korea,
            SUM(CASE WHEN its = 1 THEN 1 ELSE 0 END) AS its,
            SUM(CASE WHEN asset_hits != '[]' THEN 1 ELSE 0 END) AS assets,
            SUM(CASE WHEN kev = 1 THEN 1 ELSE 0 END) AS kev
        FROM items
        """
        with self._connect() as conn:
            row = conn.execute(sql).fetchone()
        return {key: int(row[key] or 0) for key in row.keys()}

    def source_counts(self) -> list[tuple[str, int]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT source, COUNT(*) AS n FROM items GROUP BY source ORDER BY n DESC, source"
            ).fetchall()
        return [(row["source"], int(row["n"])) for row in rows]

    def asset_counter(self) -> Counter:
        counter: Counter = Counter()
        for record in self.query(limit=5000):
            counter.update(record.asset_hits)
        return counter

    def alert_status(self, item_key: str, channel: str) -> str:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT status FROM alerts WHERE item_key = ? AND channel = ?",
                (item_key, channel),
            ).fetchone()
        return row["status"] if row else ""

    def save_alert(self, item_key: str, channel: str, status: str, detail: str) -> None:
        moment = stamp()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO alerts(item_key, channel, status, detail, created_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(item_key, channel) DO UPDATE SET
                    status = excluded.status,
                    detail = excluded.detail,
                    created_at = excluded.created_at
                """,
                (item_key, channel, status, detail[:500], moment),
            )
