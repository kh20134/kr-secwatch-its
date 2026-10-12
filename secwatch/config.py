"""환경 변수와 실행 인자로 설정을 만든다. 비밀값은 코드에 두지 않는다."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parent


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def load_dotenv(path: Path | None = None) -> None:
    file = path or (Path.cwd() / ".env")
    if not file.is_file():
        return
    for line in file.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


@dataclass(frozen=True)
class Settings:
    demo: bool
    db_path: Path
    inventory_path: Path
    fixtures_path: Path
    slack_webhook: str
    email_to: str
    email_from: str
    smtp_host: str
    smtp_port: int
    smtp_user: str
    smtp_password: str
    smtp_tls: bool
    min_priority: int
    nvd_api_key: str
    nvd_max: int
    http_timeout: float
    host: str
    port: int

    @property
    def slack_enabled(self) -> bool:
        return bool(self.slack_webhook)

    @property
    def email_enabled(self) -> bool:
        return bool(self.smtp_host and self.email_to and self.email_from)

    @property
    def alerts_configured(self) -> bool:
        return self.slack_enabled or self.email_enabled


def load_settings(
    *,
    demo: bool = False,
    db: str | None = None,
    inventory: str | None = None,
    host: str | None = None,
    port: int | None = None,
) -> Settings:
    load_dotenv()
    demo_on = demo or _env_bool("SECWATCH_DEMO")
    db_value = db or os.environ.get("SECWATCH_DB") or (
        "data/demo.db" if demo_on else "data/secwatch.db"
    )
    db_path = Path(db_value)
    if not db_path.is_absolute():
        db_path = Path.cwd() / db_path
    inventory_value = inventory or os.environ.get("SECWATCH_INVENTORY")
    inventory_path = (
        Path(inventory_value) if inventory_value else PACKAGE_ROOT / "assets" / "inventory.yaml"
    )
    if not inventory_path.is_absolute():
        inventory_path = Path.cwd() / inventory_path
    try:
        smtp_port = int(os.environ.get("SMTP_PORT") or "587")
    except ValueError:
        smtp_port = 587
    try:
        min_priority = int(os.environ.get("SECWATCH_MIN_PRIORITY") or "46")
    except ValueError:
        min_priority = 46
    try:
        nvd_max = int(os.environ.get("SECWATCH_NVD_MAX") or "15")
    except ValueError:
        nvd_max = 15
    try:
        timeout = float(os.environ.get("SECWATCH_HTTP_TIMEOUT") or "20")
    except ValueError:
        timeout = 20.0
    return Settings(
        demo=demo_on,
        db_path=db_path,
        inventory_path=inventory_path,
        fixtures_path=PACKAGE_ROOT / "fixtures",
        slack_webhook=(os.environ.get("SLACK_WEBHOOK_URL") or "").strip(),
        email_to=(os.environ.get("ALERT_EMAIL_TO") or "").strip(),
        email_from=(os.environ.get("ALERT_EMAIL_FROM") or "").strip(),
        smtp_host=(os.environ.get("SMTP_HOST") or "").strip(),
        smtp_port=smtp_port,
        smtp_user=(os.environ.get("SMTP_USER") or "").strip(),
        smtp_password=os.environ.get("SMTP_PASSWORD") or "",
        smtp_tls=_env_bool("SMTP_TLS", True),
        min_priority=min_priority,
        nvd_api_key=(os.environ.get("NVD_API_KEY") or "").strip(),
        nvd_max=max(nvd_max, 0),
        http_timeout=timeout,
        host=host or "127.0.0.1",
        port=port if port is not None else 8080,
    )
