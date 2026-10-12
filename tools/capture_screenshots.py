"""데모 서버를 띄우고 대시보드·주간보고 화면을 캡처한다."""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "images"
PORT = 8765
BASE = f"http://127.0.0.1:{PORT}"


def wait_port(port: int, timeout: float = 20) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.4):
                return
        except OSError:
            time.sleep(0.2)
    raise SystemExit("서버가 열리지 않았다")


def shoot(page, name: str) -> None:
    page.screenshot(path=str(OUT / name), full_page=True)
    print("saved", name)


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["SECWATCH_DEMO"] = "1"
    db = ROOT / "data" / "screenshot.db"
    if db.exists():
        db.unlink()
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "secwatch",
            "serve",
            "--demo",
            "--host",
            "127.0.0.1",
            "--port",
            str(PORT),
            "--db",
            str(db),
        ],
        cwd=ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        wait_port(PORT)
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            desktop = browser.new_context(viewport={"width": 1440, "height": 900}, locale="ko-KR")
            page = desktop.new_page()
            page.goto(BASE, wait_until="networkidle")
            page.wait_for_selector("text=거가대교")
            font_ok = page.evaluate(
                "document.fonts.check('16px \"Noto Sans CJK KR\"')"
            )
            print("noto check", font_ok)
            if not font_ok:
                raise SystemExit("브라우저가 Noto Sans CJK KR 을 쓰지 못한다")
            shoot(page, "dashboard.png")
            with page.expect_response(lambda response: "/partials/feed" in response.url, timeout=5000):
                page.select_option("select[name=band]", "긴급")
            page.wait_for_selector("#feed >> text=FortiOS")
            if page.locator("#feed").locator("text=해외 가전").count():
                raise SystemExit("등급 필터가 동작하지 않았다")
            page.goto(f"{BASE}/report", wait_until="networkidle")
            page.wait_for_selector("text=주간 보안 현황")
            shoot(page, "report.png")
            mobile = browser.new_context(
                viewport={"width": 390, "height": 844},
                locale="ko-KR",
                device_scale_factor=2,
            )
            phone = mobile.new_page()
            phone.goto(BASE, wait_until="networkidle")
            phone.wait_for_selector("text=수집 항목")
            shoot(phone, "dashboard-mobile.png")
            browser.close()
    finally:
        proc.terminate()
        try:
            output, _ = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            output, _ = proc.communicate(timeout=5)
        if proc.returncode not in (0, -15, None) and output:
            print(output[-2000:])


if __name__ == "__main__":
    main()
