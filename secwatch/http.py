"""작은 HTTP 조회. 테스트는 이 클래스를 대체하고 소켓을 열지 않는다."""

from __future__ import annotations

import gzip
import time
import urllib.error
import urllib.request

USER_AGENT = "kr-secwatch-its/0.1 (+https://github.com/kh20134/kr-secwatch-its)"


class HttpError(RuntimeError):
    pass


class HttpClient:
    def __init__(self, *, timeout: float = 20.0, pause: float = 0.0):
        self.timeout = timeout
        self.pause = pause

    def get_bytes(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        max_bytes: int = 2_000_000,
        attempts: int = 2,
    ) -> bytes:
        last: Exception | None = None
        for attempt in range(attempts):
            try:
                return self._once(url, headers=headers, max_bytes=max_bytes)
            except HttpError as exc:
                last = exc
                if attempt + 1 >= attempts:
                    break
                if self.pause:
                    time.sleep(self.pause)
        raise HttpError(str(last) if last else "조회 실패")

    def _once(self, url: str, *, headers: dict[str, str] | None, max_bytes: int) -> bytes:
        request_headers = {
            "User-Agent": USER_AGENT,
            "Accept": "application/rss+xml, application/xml, application/json, text/xml;q=0.9, */*;q=0.1",
            "Accept-Encoding": "identity",
        }
        if headers:
            request_headers.update(headers)
        request = urllib.request.Request(url, headers=request_headers)
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                payload = response.read(max_bytes + 1)
        except urllib.error.URLError as exc:
            raise HttpError(f"{url} 조회 실패: {exc.reason}") from exc
        if len(payload) > max_bytes:
            raise HttpError(f"{url} 응답이 한도를 넘었다")
        if payload.startswith(b"\x1f\x8b"):
            try:
                payload = gzip.decompress(payload)
            except OSError as exc:
                raise HttpError("압축 해제 실패") from exc
        return payload

    def post_json(self, url: str, body: bytes, *, max_bytes: int = 200_000) -> bytes:
        request = urllib.request.Request(
            url,
            data=body,
            headers={
                "User-Agent": USER_AGENT,
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return response.read(max_bytes)
        except urllib.error.URLError as exc:
            raise HttpError(f"전송 실패: {exc.reason}") from exc
