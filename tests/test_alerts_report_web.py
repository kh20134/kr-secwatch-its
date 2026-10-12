from secwatch.alerts import AlertError, dispatch, post_slack, should_notify
from secwatch.classify import classify
from secwatch.cli import main
from secwatch.collect.pipeline import run_collect
from secwatch.config import PACKAGE_ROOT
from secwatch.inventory import load_inventory
from secwatch.models import Record
from secwatch.report import build_report, render_markdown
from secwatch.store import Store
from secwatch.web.app import create_app

INVENTORY = load_inventory(PACKAGE_ROOT / "assets" / "inventory.yaml")


def _urgent() -> Record:
    record = Record(
        source="cve",
        external_id="CVE-2099-1401",
        kind="cve",
        title="FortiOS 샘플",
        vendor="Fortinet",
        product="FortiOS",
        cve_ids=["CVE-2099-1401"],
        cvss=9.8,
        epss=0.94,
        kev=True,
        published_at="2099-01-01",
    )
    return classify(record, INVENTORY)


def test_alerts_stay_off_without_channels(settings, tmp_path):
    cfg = settings(demo=False, slack_webhook="", smtp_host="", email_to="ops@example.com")
    store = Store(cfg.db_path)
    record = _urgent()
    store.upsert([record])
    calls = []
    sent, failed = dispatch(
        cfg,
        store,
        [record],
        INVENTORY,
        slack_post=lambda *args: calls.append(args),
    )
    assert (sent, failed, calls) == (0, 0, [])
    assert should_notify(record, cfg.min_priority)


def test_slack_sends_once_and_rejects_other_hosts(settings):
    cfg = settings(
        demo=False,
        slack_webhook="https://hooks.slack.com/services/T/B/TEST",
    )
    store = Store(cfg.db_path)
    record = _urgent()
    store.upsert([record])
    calls = []

    def fake(url, text, timeout):
        calls.append((url, text, timeout))

    sent, failed = dispatch(cfg, store, [record], INVENTORY, slack_post=fake)
    assert sent == 1 and failed == 0
    assert calls[0][0].startswith("https://hooks.slack.com/")
    assert "FortiOS" in calls[0][1]
    assert ".onion" not in calls[0][1]
    sent_again, _failed = dispatch(cfg, store, [record], INVENTORY, slack_post=fake)
    assert sent_again == 0
    assert len(calls) == 1
    with __import__("pytest").raises(AlertError):
        post_slack("https://example.com/hook", "nope", 1)


def test_email_uses_injected_smtp(settings):
    cfg = settings(
        demo=False,
        smtp_host="smtp.example",
        email_from="secwatch@example.com",
        email_to="ops@example.com",
    )
    store = Store(cfg.db_path)
    record = _urgent()
    store.upsert([record])

    class FakeSmtp:
        def __init__(self):
            self.messages = []

        def send_message(self, message):
            self.messages.append(message)

        def quit(self):
            pass

    smtp = FakeSmtp()
    sent, failed = dispatch(cfg, store, [record], INVENTORY, smtp_factory=lambda: smtp)
    assert (sent, failed) == (1, 0)
    assert smtp.messages[0]["To"] == "ops@example.com"
    assert "FortiOS" in smtp.messages[0].get_content()


def test_weekly_report_and_cli(settings, tmp_path):
    cfg = settings()
    store = Store(cfg.db_path)
    run_collect(cfg, store, alert=False)
    store.upsert(
        [
            Record(
                source="news",
                external_id="old",
                kind="news",
                title="오래된항목",
                published_at="2000-01-01",
            )
        ]
    )
    bundle = build_report(store, INVENTORY, days=7)
    markdown = render_markdown(bundle, INVENTORY)
    assert "오래된항목" not in markdown
    assert "남해샘플도로" in markdown
    assert "LEAKMARKER" not in markdown
    assert ".onion" not in markdown
    assert "거가대교" in markdown
    out = tmp_path / "reports"
    code = main(["report", "--demo", "--db", str(cfg.db_path), "--out", str(out), "--days", "7"])
    assert code == 0
    html = (out / "weekly.html").read_text(encoding="utf-8")
    assert "주간 보안 현황" in html
    assert "viewport" in html
    assert ".onion" not in html
    text = (out / "weekly.md").read_text(encoding="utf-8")
    assert "이번 주 권고" in text


def test_dashboard_pages(settings):
    cfg = settings()
    store = Store(cfg.db_path)
    run_collect(cfg, store, alert=False)
    app = create_app(cfg, store, INVENTORY)
    client = app.test_client()
    home = client.get("/")
    assert home.status_code == 200
    body = home.get_data(as_text=True)
    assert "KR-SecWatch ITS" in body
    assert "거가대교" in body
    assert "htmx" in body
    assert "오프라인 샘플" in body
    urgent = client.get("/partials/feed?band=긴급")
    urgent_body = urgent.get_data(as_text=True)
    assert "FortiOS" in urgent_body
    assert "해외 가전" not in urgent_body
    found = client.get("/partials/feed?q=남해샘플도로")
    assert "남해샘플도로" in found.get_data(as_text=True)
    assert "FortiOS" not in found.get_data(as_text=True)
    item_id = store.query(q="남해샘플도로")[0].id
    detail = client.get(f"/items/{item_id}")
    assert "확인된 사고가 아니다" in detail.get_data(as_text=True)
    inventory = client.get("/inventory")
    assert "FortiGate" in inventory.get_data(as_text=True)
    assert "Wisenet" in inventory.get_data(as_text=True)
    report = client.get("/report")
    assert "주간 보안 현황" in report.get_data(as_text=True)
    health = client.get("/healthz")
    assert health.json["demo"] is True
    assert client.get("/missing").status_code == 404


def test_cli_collect_demo(settings, capsys):
    cfg = settings()
    code = main(["collect", "--demo", "--db", str(cfg.db_path), "--no-alert"])
    assert code == 0
    captured = capsys.readouterr().out
    assert "보호나라" in captured
    assert Store(cfg.db_path).count() == 13
