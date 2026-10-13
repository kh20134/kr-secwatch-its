"""gunicorn 진입점. SECWATCH_DEMO이면 serve --demo와 같이 샘플을 적재한다."""

from __future__ import annotations

from secwatch.collect.pipeline import run_collect
from secwatch.config import load_settings
from secwatch.store import Store
from secwatch.web.app import create_app

settings = load_settings()
store = Store(settings.db_path)
if settings.demo:
    run_collect(settings, store, alert=False)

app = create_app(settings, store)
