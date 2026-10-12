"""python -m secwatch collect|serve|report"""

from __future__ import annotations

import argparse
from pathlib import Path

from secwatch.collect.pipeline import run_collect
from secwatch.config import load_settings
from secwatch.inventory import load_inventory
from secwatch.report import build_report, render_markdown, write_report
from secwatch.store import Store


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="secwatch", description="ITS 관점 보안 위협 모니터링")
    sub = parser.add_subparsers(dest="command", required=True)

    collect = sub.add_parser("collect", help="공개 피드 또는 샘플을 적재")
    _common(collect)
    collect.add_argument("--sources", default="", help="쉼표 구분. 예: kisa,news,kev")
    collect.add_argument("--no-alert", action="store_true", help="알림을 만들지 않음")

    serve = sub.add_parser("serve", help="대시보드 실행")
    _common(serve)
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8080)

    report = sub.add_parser("report", help="주간 보고 작성")
    _common(report)
    report.add_argument("--days", type=int, default=7)
    report.add_argument("--out", default="reports")
    return parser


def _common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--demo", action="store_true", help="네트워크 없이 샘플 픽스처 사용")
    parser.add_argument("--db", default="", help="SQLite 경로")


def _sources(raw: str) -> list[str] | None:
    if not raw.strip():
        return None
    return [part.strip() for part in raw.split(",") if part.strip()]


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    settings = load_settings(
        demo=args.demo,
        db=args.db or None,
        host=getattr(args, "host", None),
        port=getattr(args, "port", None),
    )
    store = Store(settings.db_path)
    if args.command == "collect":
        result = run_collect(
            settings,
            store,
            alert=not args.no_alert,
            sources=_sources(args.sources),
        )
        print(result.summary())
        if result.errors and sum(result.fetched.values()) == 0:
            return 1
        return 0
    if args.command == "serve":
        if settings.demo:
            result = run_collect(settings, store, alert=False)
            print(result.summary())
        from secwatch.web.app import create_app

        app = create_app(settings, store)
        app.run(host=settings.host, port=settings.port, debug=False, use_reloader=False, threaded=True)
        return 0
    inventory = load_inventory(settings.inventory_path)
    if settings.demo:
        run_collect(settings, store, alert=False)
    bundle = build_report(store, inventory, days=args.days)
    markdown = render_markdown(bundle, inventory)
    from secwatch.web.app import create_app, render_standalone_report

    html = render_standalone_report(create_app(settings, store), bundle, inventory)
    md_path, html_path = write_report(Path(args.out), markdown, html)
    print(f"markdown: {md_path}")
    print(f"html: {html_path}")
    return 0
