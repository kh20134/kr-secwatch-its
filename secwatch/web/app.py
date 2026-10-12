"""읽기 전용 대시보드. 수집 실행은 CLI에서만 한다."""

from __future__ import annotations

from pathlib import Path

from flask import Flask, abort, render_template, request

from secwatch.classify import score_parts
from secwatch.config import Settings
from secwatch.inventory import Inventory, load_inventory
from secwatch.labels import BANDS, kind_label, source_label
from secwatch.report import ReportBundle, build_report
from secwatch.store import Store

WEB_ROOT = Path(__file__).resolve().parent
KIND_CHOICES = ("notice", "news", "cve", "victim")
SCOPE_CHOICES = ("korea", "its", "asset")


def create_app(settings: Settings, store: Store, inventory: Inventory | None = None) -> Flask:
    app = Flask(
        __name__,
        template_folder=str(WEB_ROOT / "templates"),
        static_folder=str(WEB_ROOT / "static"),
    )
    inventory = inventory or load_inventory(settings.inventory_path)
    app.config["STORE"] = store
    app.config["SETTINGS"] = settings
    app.config["INVENTORY"] = inventory

    @app.context_processor
    def inject():
        return {
            "source_label": source_label,
            "kind_label": kind_label,
            "score_parts": score_parts,
            "inventory": inventory,
            "settings": settings,
            "bands": BANDS,
        }

    @app.after_request
    def headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/healthz")
    def healthz():
        return {"ok": True, "demo": settings.demo}

    @app.get("/")
    def dashboard():
        filters = _filters(request.args)
        stats = store.stats()
        return render_template(
            "dashboard.html",
            filters=filters,
            stats=stats,
            mix=_mix(stats),
            items=_items(store, filters),
            top=store.query(limit=3),
            sources=store.source_counts(),
            last_collect=store.get_meta("last_collect"),
        )

    @app.get("/partials/feed")
    def feed():
        filters = _filters(request.args)
        return render_template("partials/feed.html", items=_items(store, filters), filters=filters)

    @app.get("/items/<int:item_id>")
    def item_page(item_id: int):
        item = store.get(item_id)
        if item is None:
            abort(404)
        return render_template("item.html", item=item, parts=score_parts(item))

    @app.get("/inventory")
    def inventory_page():
        counts = store.asset_counter()
        return render_template("inventory.html", counts=counts)

    @app.get("/report")
    def report_page():
        try:
            days = int(request.args.get("days") or "7")
        except ValueError:
            days = 7
        days = min(max(days, 1), 90)
        bundle = build_report(store, inventory, days=days)
        return render_template("report_page.html", bundle=bundle)

    @app.errorhandler(404)
    def missing(_exc):
        return render_template("error.html", message="요청한 화면이 없다."), 404

    return app


def render_standalone_report(app: Flask, bundle: ReportBundle, inventory: Inventory) -> str:
    css = (WEB_ROOT / "static" / "style.css").read_text(encoding="utf-8")
    with app.app_context():
        return render_template(
            "report_standalone.html",
            bundle=bundle,
            inventory=inventory,
            css=css,
        )


def _filters(args) -> dict[str, str]:
    band = args.get("band") or ""
    kind = args.get("kind") or ""
    scope = args.get("scope") or ""
    query = (args.get("q") or "").strip()[:80]
    if band not in BANDS:
        band = ""
    if kind not in KIND_CHOICES:
        kind = ""
    if scope not in SCOPE_CHOICES:
        scope = ""
    return {"band": band, "kind": kind, "scope": scope, "q": query}


def _items(store: Store, filters: dict[str, str]):
    return store.query(
        band=filters["band"],
        kind=filters["kind"],
        scope=filters["scope"],
        q=filters["q"],
        limit=80,
    )


def _mix(stats: dict[str, int]) -> list[dict]:
    total = max(stats.get("total", 0), 1)
    rows = [
        ("긴급", stats.get("urgent", 0)),
        ("높음", stats.get("high", 0)),
        ("주의", stats.get("watch", 0)),
        ("참고", stats.get("info", 0)),
    ]
    return [
        {"band": band, "count": count, "pct": round(100 * count / total, 2)}
        for band, count in rows
    ]
