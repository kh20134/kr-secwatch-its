"""Slack·메일 알림. 채널 설정이 없으면 아무 것도 보내지 않는다."""

from __future__ import annotations

import json
import smtplib
from email.message import EmailMessage
from urllib.parse import urlparse

from secwatch.config import Settings
from secwatch.http import HttpClient, HttpError
from secwatch.inventory import Inventory
from secwatch.labels import kind_label, source_label
from secwatch.models import Record
from secwatch.store import Store

MAX_PER_RUN = 10


class AlertError(RuntimeError):
    pass


def should_notify(record: Record, min_priority: int) -> bool:
    if record.priority < min_priority:
        return False
    return bool(record.korea or record.its or record.asset_hits)


def item_key(record: Record) -> str:
    return f"{record.source}:{record.external_id}"


def render_text(record: Record, inventory: Inventory) -> str:
    assets = ", ".join(inventory.label_of(asset_id) for asset_id in record.asset_hits) or "없음"
    lines = [
        f"[KR-SecWatch ITS] {record.band} {record.priority}점",
        record.title,
        f"출처: {source_label(record.source)} / {kind_label(record.kind)}",
        f"자산: {assets}",
    ]
    if record.cve_ids:
        lines.append("CVE: " + ", ".join(record.cve_ids))
    if record.kind == "victim":
        lines.append("범죄 그룹의 주장일 뿐 확인된 사고가 아니다.")
        lines.append(f"국가: {record.country} / 그룹: {record.actor} / 업종: {record.sector}")
    elif record.summary:
        lines.append(record.summary[:180])
    if record.url:
        lines.append(record.url)
    return "\n".join(lines)


def slack_host_ok(url: str) -> bool:
    parsed = urlparse(url)
    return parsed.scheme == "https" and (parsed.hostname or "") == "hooks.slack.com"


def post_slack(url: str, text: str, timeout: float) -> None:
    if not slack_host_ok(url):
        raise AlertError("Slack webhook 은 https://hooks.slack.com/ 만 허용한다")
    body = json.dumps({"text": text}, ensure_ascii=False).encode("utf-8")
    HttpClient(timeout=timeout).post_json(url, body)


def send_email(settings: Settings, subject: str, body: str, smtp) -> None:
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = settings.email_from
    message["To"] = settings.email_to
    message.set_content(body)
    smtp.send_message(message)


def open_smtp(settings: Settings):
    smtp = smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=settings.http_timeout)
    try:
        if settings.smtp_tls:
            smtp.starttls()
        if settings.smtp_user:
            smtp.login(settings.smtp_user, settings.smtp_password)
    except Exception:
        smtp.close()
        raise
    return smtp


def dispatch(
    settings: Settings,
    store: Store,
    records: list[Record],
    inventory: Inventory,
    *,
    slack_post=None,
    smtp_factory=None,
) -> tuple[int, int]:
    sender = slack_post or post_slack
    factory = smtp_factory or (lambda: open_smtp(settings))
    ranked = sorted(
        [record for record in records if should_notify(record, settings.min_priority)],
        key=lambda record: record.priority,
        reverse=True,
    )
    sent = 0
    failed = 0
    smtp = None
    try:
        for record in ranked:
            if sent >= MAX_PER_RUN:
                break
            key = item_key(record)
            text = render_text(record, inventory)
            if settings.slack_enabled and store.alert_status(key, "slack") != "sent":
                try:
                    sender(settings.slack_webhook, text, settings.http_timeout)
                except (AlertError, HttpError, OSError) as exc:
                    store.save_alert(key, "slack", "failed", str(exc))
                    failed += 1
                else:
                    store.save_alert(key, "slack", "sent", "ok")
                    sent += 1
            if settings.email_enabled and store.alert_status(key, "email") != "sent":
                try:
                    if smtp is None:
                        smtp = factory()
                    subject = f"[KR-SecWatch ITS] {record.band} {record.title[:80]}"
                    send_email(settings, subject, text, smtp)
                except (OSError, smtplib.SMTPException, AlertError) as exc:
                    store.save_alert(key, "email", "failed", str(exc))
                    failed += 1
                else:
                    store.save_alert(key, "email", "sent", "ok")
                    sent += 1
    finally:
        if smtp is not None:
            try:
                smtp.quit()
            except Exception:
                pass
    return sent, failed
