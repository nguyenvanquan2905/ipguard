"""Chạy toàn bộ luồng trên trình duyệt thật với một website đặt bàn GIẢ LẬP chạy ở máy.

Không chạm tới website thật. Bật bằng:  IPGUARD_E2E=1 python -m pytest -q tests/test_e2e_browser.py
Cần: pip install playwright && playwright install chromium (và Chrome nếu muốn engine chrome).
"""
import asyncio
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

pytestmark = pytest.mark.skipif(os.environ.get("IPGUARD_E2E") != "1",
                                reason="đặt IPGUARD_E2E=1 để chạy test trình duyệt")

from ipguard import AntiBan, Policy, ProxyEndpoint  # noqa: E402
from ipguard.adapters import check_issues, guarded_goto, guarded_page  # noqa: E402

FORM = """<!doctype html><html><head><meta charset="utf-8"><title>Đặt bàn</title></head><body>
<h1>Đặt bàn</h1><form method="post" action="{action}">
<label for="p">Số khách</label><input id="p" name="p">
<label for="d">Ngày</label><input id="d" name="d">
<label for="t">Giờ</label><select id="t" name="t"><option>18:00</option><option>19:00</option></select>
<label for="n">Họ tên</label><input id="n" name="n">
<label for="ph">Điện thoại</label><input id="ph" name="ph">
<button type="submit">Đặt bàn</button></form></body></html>"""

POSTS = []


class Site(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, headers=()):
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/dat-ban":
            self._send(200, FORM.format(action="/xac-nhan"))
        elif path == "/dat-ban-bi-chan-sau-submit":
            self._send(200, FORM.format(action="/xac-nhan-chan"))
        elif path == "/cf":
            self._send(403, "<html><title>Just a moment...</title>"
                            "<script src='/cdn-cgi/challenge-platform/x.js'></script></html>",
                       [("Server", "cloudflare"), ("cf-ray", "abc-SIN")])
        elif path == "/blocked":
            self._send(403, "<h1>Access denied</h1>")
        elif path == "/429":
            self._send(429, "Too many requests", [("Retry-After", "5")])
        elif path == "/captcha":
            self._send(403, "<script src='https://geo.captcha-delivery.com/c.js'></script>",
                       [("x-datadome", "1")])
        else:
            self._send(404, "not found")

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        POSTS.append((self.path, self.rfile.read(n).decode()))
        if self.path == "/xac-nhan":
            self._send(200, "<p>Đặt bàn thành công</p><span class='booking-ref'>REF-42</span>")
        else:
            self._send(403, "<h1>Access denied</h1>")


@pytest.fixture(scope="module")
def base():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Site)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


async def _bundled(pw, s, profile_dir, headless):
    from ipguard.adapters import context_kwargs
    return await pw.chromium.launch_persistent_context(profile_dir, headless=headless,
                                                       **context_kwargs(s.proxy))


async def _chrome(pw, s, profile_dir, headless):
    from ipguard.adapters import context_kwargs
    return await pw.chromium.launch_persistent_context(profile_dir, channel="chrome",
                                                       headless=headless, **context_kwargs(s.proxy))


LAUNCHERS = {"chrome": _chrome, "chromium": _bundled}


def make_ab(tmp_path, dry_run=False):
    old = 1.0
    pxs = [ProxyEndpoint("d1", "direct", "VN", "isp", added_at=old),
           ProxyEndpoint("d2", "direct", "VN", "isp", added_at=old)]
    pol = Policy(jitter_min_s=0.02, jitter_max_s=0.05, domain_rpm_start=600, domain_rpm_max=600)
    ab = AntiBan(pxs, pol, health_check=False, dry_run=dry_run, engines=("chrome", "chromium"))
    ab.profile_root = str(tmp_path / "profiles")
    return ab


def booking_flow(ab, url, trace):
    async def flow(s):
        from playwright.async_api import async_playwright
        trace.append((s.engine, s.proxy.id))
        async with async_playwright() as pw:
            async with guarded_page(pw, s, profile_root=ab.profile_root, launchers=LAUNCHERS,
                                    headless=True) as (page, issues):
                await guarded_goto(page, s, url, issues)
                await page.get_by_label("Số khách").fill("4")
                await page.get_by_label("Ngày").fill("2026-11-28")
                await page.get_by_label("Giờ").select_option("19:00")
                await page.get_by_label("Họ tên").fill("Test")
                await page.get_by_label("Điện thoại").fill("0900000000")
                await page.screenshot(path=str(os.path.join(ab.profile_root, "form.png")))
                s.mark_submitted()
                await s.before_navigation()
                await page.get_by_role("button", name="Đặt bàn").click()
                await page.wait_for_load_state("domcontentloaded")
                await check_issues(issues)
                if await page.get_by_text("Đặt bàn thành công").count():
                    s.mark_booked()
                    return await page.locator(".booking-ref").inner_text()
                return None
    return flow


def book(ab, base, path, trace, **kw):
    return asyncio.run(ab.book("127.0.0.1", "u1", booking_flow(ab, base + path, trace),
                               country="VN", **kw))


def test_dry_run_fills_form_but_sends_nothing(base, tmp_path):
    POSTS.clear()
    ab, trace = make_ab(tmp_path, dry_run=True), []
    r = book(ab, base, "/dat-ban", trace, request_id="R1")
    assert r.outcome == "dry_run", r
    assert POSTS == []                                       # không có gì được gửi đi
    assert os.path.exists(os.path.join(ab.profile_root, "form.png"))
    assert "R1" not in ab.guard.requests                     # chạy thử không khóa request_id


def test_real_submit_on_local_site(base, tmp_path):
    POSTS.clear()
    ab, trace = make_ab(tmp_path), []
    r = book(ab, base, "/dat-ban", trace, request_id="R2")
    assert r.outcome == "booked" and r.value == "REF-42", r
    assert len(POSTS) == 1 and "p=4" in POSTS[0][1]
    r2 = book(ab, base, "/dat-ban", trace, request_id="R2")  # gọi lại -> không gửi lần 2
    assert r2.outcome == "booked" and len(POSTS) == 1


def test_challenge_switches_engine_keeps_ip(base, tmp_path):
    ab, trace = make_ab(tmp_path), []
    r = book(ab, base, "/cf", trace)
    assert r.outcome == "deeplink", r
    assert [e for e, _ in trace] == ["chrome", "chromium"]
    assert trace[0][1] == trace[1][1]                        # cùng IP
    assert [row[2] for row in r.log] == ["soft_challenge", "soft_challenge"]


def test_block_switches_ip_once(base, tmp_path):
    ab, trace = make_ab(tmp_path), []
    r = book(ab, base, "/blocked", trace)
    assert r.outcome == "deeplink", r
    assert len(trace) == 2 and trace[0][1] != trace[1][1]


def test_429_stops_without_switching(base, tmp_path):
    ab, trace = make_ab(tmp_path), []
    r = book(ab, base, "/429", trace)
    assert r.outcome == "deeplink" and len(trace) == 1, r
    assert ab.guard.limiter.paused_for("127.0.0.1") > 0


def test_captcha_hands_off(base, tmp_path):
    ab, trace = make_ab(tmp_path), []
    r = book(ab, base, "/captcha", trace)
    assert r.outcome == "handoff_user" and len(trace) == 1, r


def test_block_after_submit_is_caught_via_attach(base, tmp_path):
    POSTS.clear()
    ab, trace = make_ab(tmp_path), []
    r = book(ab, base, "/dat-ban-bi-chan-sau-submit", trace, request_id="R3")
    assert r.outcome == "failed" and "KHÔNG gửi lại" in r.detail, r
    assert len(POSTS) == 1 and len(trace) == 1               # không gửi lại
    assert ab.guard.requests["R3"][0] == "submitted_unknown"
