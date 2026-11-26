"""Kiểm tra chính hạ tầng sandbox (không cần trình duyệt, không cần LLM, không ra Internet)."""
import asyncio
import json
import urllib.error
import urllib.request

import pytest

from ipguard import AntiBan, Policy, ProxyEndpoint, classify
from ipguard.models import Signal
from sandbox.infra import Sandbox


@pytest.fixture(scope="module")
def sb():
    s = Sandbox.start()
    yield s
    s.stop()


def get(sb, proxy_id, url, data=None):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler(
        {"http": sb.proxy_url(proxy_id)}))
    try:
        with opener.open(urllib.request.Request(url, data=data), timeout=10) as r:
            return r.status, dict(r.headers), r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode()


def test_geo_service_reports_egress_per_proxy(sb):
    for pid, ip, cc in [("px-vn-1", "203.0.113.11", "VN"), ("px-vn-geo", "198.51.100.7", "SG")]:
        st, _, body = get(sb, pid, sb.geo_url)
        assert st == 200 and json.loads(body) == {"ip": ip, "country": cc, "org": "AS64500 Sandbox"}


def test_proxy_refuses_outside_sandbox(sb):
    st, _, body = get(sb, "px-vn-1", "http://example.com/")
    assert st == 403 and "ngoài sandbox" in body


@pytest.mark.parametrize("scn,signal", [
    ("ok", Signal.OK), ("cf", Signal.SOFT_CHALLENGE), ("captcha", Signal.CAPTCHA),
    ("blocked", Signal.BLOCKED), ("ratelimit", Signal.RATE_LIMITED), ("down", Signal.SERVER_ERROR),
])
def test_scenarios_classify_as_intended(sb, scn, signal):
    st, h, body = get(sb, "px-vn-2", sb.url(scn))
    assert classify(st, h, body).signal == signal


def test_ipban_bans_only_first_egress(sb):
    a = get(sb, "px-vn-3", sb.url("ipban"))
    b = get(sb, "px-vn-4", sb.url("ipban"))
    assert classify(a[0], a[1], a[2]).signal == Signal.BLOCKED
    assert classify(b[0], b[1], b[2]).signal == Signal.OK


def test_booking_post_is_recorded_with_egress(sb):
    sb.state.reset()
    st, _, body = get(sb, "px-vn-1", sb.url("ok", "/xac-nhan"),
                      b"party=2&date=2026-12-01&time=19:00&name=A&phone=0900")
    assert st == 200 and "Đặt bàn thành công" in body
    snap = sb.state.snapshot("ok.sandbox.test")
    assert len(snap["bookings"]) == 1 and snap["bookings"][0]["egress_ip"] == "203.0.113.11"


def test_health_check_drops_dead_and_wrong_geo_proxies(sb):
    pxs = [ProxyEndpoint(e.id, sb.proxy_url(e.id) if not e.dead else "http://127.0.0.1:9",
                         "VN", "isp", added_at=1.0) for e in sb.egress]
    ab = AntiBan(pxs, Policy(), geo_url=sb.geo_url)
    res = {r.ip_id: r for r in asyncio.run(ab.check_proxies())}
    assert res["px-vn-1"].ok and res["px-vn-1"].exit_ip == "203.0.113.11"
    assert not res["px-vn-dead"].ok
    assert res["px-vn-geo"].country == "SG" and res["px-vn-geo"].issues
    g = ab.pool.g
    assert g["px-vn-dead"].health_block.startswith("dead")
    assert g["px-vn-geo"].health_block.startswith("geo")
    assert not g["px-vn-1"].health_block
