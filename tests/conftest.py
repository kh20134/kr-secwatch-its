import urllib.request

import pytest

from secwatch.config import PACKAGE_ROOT, Settings

_ENV_KEYS = (
    "SECWATCH_DEMO",
    "SECWATCH_DB",
    "SECWATCH_INVENTORY",
    "SECWATCH_MIN_PRIORITY",
    "SECWATCH_NVD_MAX",
    "SECWATCH_HTTP_TIMEOUT",
    "NVD_API_KEY",
    "SLACK_WEBHOOK_URL",
    "ALERT_EMAIL_TO",
    "ALERT_EMAIL_FROM",
    "SMTP_HOST",
    "SMTP_PORT",
    "SMTP_USER",
    "SMTP_PASSWORD",
    "SMTP_TLS",
)


@pytest.fixture(autouse=True)
def _isolated(monkeypatch):
    for key in _ENV_KEYS:
        monkeypatch.delenv(key, raising=False)

    def blocked(*_args, **_kwargs):
        raise RuntimeError("network blocked in tests")

    monkeypatch.setattr(urllib.request, "urlopen", blocked)


@pytest.fixture
def settings(tmp_path):
    def build(**overrides):
        data = dict(
            demo=True,
            db_path=tmp_path / "secwatch.db",
            inventory_path=PACKAGE_ROOT / "assets" / "inventory.yaml",
            fixtures_path=PACKAGE_ROOT / "fixtures",
            slack_webhook="",
            email_to="",
            email_from="",
            smtp_host="",
            smtp_port=587,
            smtp_user="",
            smtp_password="",
            smtp_tls=True,
            min_priority=46,
            nvd_api_key="",
            nvd_max=15,
            http_timeout=5.0,
            host="127.0.0.1",
            port=8080,
        )
        data.update(overrides)
        return Settings(**data)

    return build
