import asyncio

import pytest

from ipguard import (Decision, Detection, IPGuard, IPPool, NoHealthyIP, Policy,
                     ProxyEndpoint, Signal, StopFlow, classify)


class Clock:
    def __init__(self, t=1_800_000_000.0):
        self.t = t

    def __call__(self):
        return self.t

    async def sleep(self, s):
        self.t += s


def make(n=4, country="VN", policy=None, clock=None):
    clock = clock or Clock()
    pxs = [ProxyEndpoint(f"ip{i}", f"http://u:p@10.0.0.{i}:8000", country, "isp",
                         added_at=clock() - 30 * 86400) for i in range(n)]
    pool = IPPool(pxs, policy or Policy(), clock=clock)
    return pool, clock


# ---------------- detector ----------------
def test_classify_basic():
    assert classify(200, {}, "<html>menu</html>").signal == Signal.OK
    assert classify(429, {"Retry-After": "120"}).retry_after_s == 120
    cf = classify(403, {"server": "cloudflare", "cf-ray": "x"}, "<title>Just a moment...</title>")
    assert cf.signal == Signal.SOFT_CHALLENGE
    assert classify(403, {"server": "cloudflare"}, "Error 1020 Access denied").signal == Signal.BLOCKED
    dd = classify(403, {"x-datadome": "1"}, "<script src='https://geo.captcha-delivery.com'>")
    assert dd.signal == Signal.CAPTCHA
    assert classify(None).signal == Signal.NETWORK_ERROR
    # reCAPTCHA hợp lệ trên form 200 không bị coi là chặn
    assert classify(200, {}, "<div class='g-recaptcha'></div>").signal == Signal.OK


# ---------------- pool ----------------
def test_affinity_sticky_for_returning_user():
    pool, _ = make()
    l1 = pool.acquire("a.vn", "user1", "VN")
    pool.release(l1, Detection(Signal.OK), booked=True)
    l2 = pool.acquire("a.vn", "user1", "VN")
    assert l2.proxy.id == l1.proxy.id


def test_different_users_get_different_ips():
    pool, _ = make()
    l1 = pool.acquire("a.vn", "u1", "VN"); pool.release(l1, Detection(Signal.OK))
    l2 = pool.acquire("a.vn", "u2", "VN")
    assert l2.proxy.id != l1.proxy.id


def test_block_quarantines_ip_on_domain_only():
    pool, clock = make(n=2)
    l = pool.acquire("a.vn", "u1", "VN")
    bad = l.proxy.id
    pool.release(l, Detection(Signal.BLOCKED))
    assert pool.acquire("a.vn", "u2", "VN").proxy.id != bad
    assert pool.why_ineligible(bad, "b.vn", "VN") is None      # domain khác vẫn dùng được
    clock.t += 16 * 60
    assert pool.why_ineligible(bad, "a.vn", "VN") is None      # hết cách ly 15 phút


def test_exponential_quarantine():
    pool, clock = make(n=1)
    for expected in (15 * 60, 30 * 60, 60 * 60):
        l = pool.acquire("a.vn", "u", "VN")
        pool.g[l.proxy.id].score = 1.0
        pool.release(l, Detection(Signal.RATE_LIMITED))
        q = pool.d[(l.proxy.id, "a.vn")].quarantine_until - clock()
        assert q == expected
        clock.t += expected + 1


def test_burned_after_three_domains():
    pool, _ = make(n=1)
    for dm in ("a.vn", "b.vn", "c.vn"):
        l = pool.acquire(dm, "u", "VN")
        pool.g[l.proxy.id].score = 1.0
        pool.release(l, Detection(Signal.BLOCKED))
    assert pool.g["ip0"].retired
    with pytest.raises(NoHealthyIP):
        pool.acquire("d.vn", "u", "VN")


def test_daily_cap_and_country():
    pool, _ = make(n=1, policy=Policy(ip_domain_daily_bookings=2))
    for _ in range(2):
        l = pool.acquire("a.vn", "u", "VN"); pool.release(l, Detection(Signal.OK), booked=True)
    with pytest.raises(NoHealthyIP):
        pool.acquire("a.vn", "u", "VN")
    with pytest.raises(NoHealthyIP):
        pool.acquire("b.sg", "u", "SG")


def test_warmup_halves_caps():
    clock = Clock()
    pool = IPPool([ProxyEndpoint("new", "http://h:1", "VN")], Policy(), clock=clock)
    assert pool._caps(pool.proxies["new"]) == (2, 20)


def test_state_roundtrip():
    pool, clock = make(n=2)
    l = pool.acquire("a.vn", "u", "VN"); pool.release(l, Detection(Signal.BLOCKED))
    raw = pool.dump_state()
    pool2, _ = make(n=2, clock=clock)
    pool2.load_state(raw)
    assert pool2.why_ineligible(l.proxy.id, "a.vn", "VN") == "domain_quarantine"


# ---------------- guard ----------------
def run(coro):
    return asyncio.run(coro)


def test_challenge_escalates_engine_keeps_ip():
    pool, clock = make()
    g = IPGuard(pool, clock=clock, sleep=clock.sleep)
    seen = []

    async def flow(s):
        seen.append((s.engine, s.proxy.id))
        await s.before_navigation()
        if s.engine == "patchright_chrome":
            s.check(403, {"cf-mitigated": "challenge"}, "")
        s.check(200, {}, "ok")
        s.mark_submitted(); s.mark_booked()
        return "ref123"

    r = run(g.run("a.vn", "u1", flow, country="VN"))
    assert r.outcome == "booked" and r.value == "ref123"
    assert [e for e, _ in seen] == ["patchright_chrome", "cloakbrowser"]
    assert seen[0][1] == seen[1][1]


def test_block_pre_submit_switches_ip_once_then_deeplink():
    pool, clock = make()
    g = IPGuard(pool, clock=clock, sleep=clock.sleep)
    ips = []

    async def flow(s):
        ips.append(s.proxy.id)
        s.check(403, {}, "Access denied")

    r = run(g.run("a.vn", "u1", flow, country="VN"))
    assert r.outcome == "deeplink"
    assert len(ips) == 2 and ips[0] != ips[1]


def test_no_retry_after_submit():
    pool, clock = make()
    g = IPGuard(pool, clock=clock, sleep=clock.sleep)
    calls = []

    async def flow(s):
        calls.append(1)
        s.mark_submitted()
        s.check(None)

    r = run(g.run("a.vn", "u1", flow, country="VN"))
    assert r.outcome == "failed" and len(calls) == 1


def test_rate_limit_does_not_switch_ip_and_slows_domain():
    pool, clock = make()
    g = IPGuard(pool, clock=clock, sleep=clock.sleep)
    calls = []

    async def flow(s):
        calls.append(1)
        s.check(429, {"Retry-After": "300"})

    before = g.limiter.rpm["a.vn"]
    r = run(g.run("a.vn", "u1", flow, country="VN"))
    assert r.outcome == "deeplink" and len(calls) == 1
    assert g.limiter.rpm["a.vn"] == before * 0.5
    assert g.limiter.paused_until["a.vn"] >= clock() + 299


def test_breaker_opens_after_distinct_ip_blocks():
    pool, clock = make(n=6)
    g = IPGuard(pool, clock=clock, sleep=clock.sleep)

    async def flow(s):
        s.check(403, {}, "Sorry, you have been blocked")

    for u in ("u1", "u2"):
        run(g.run("a.vn", u, flow, country="VN"))
    assert g.breaker.state("a.vn") == "open"
    r = run(g.run("a.vn", "u3", flow, country="VN"))
    assert r.outcome == "deeplink" and "cầu dao" in r.detail

    # sau 2h: half-open, 1 phiên thăm dò thành công -> đóng lại
    clock.t += 2 * 3600 + 1

    async def ok(s):
        s.check(200, {}, "ok"); s.mark_booked(); return 1

    assert run(g.run("a.vn", "u4", ok, country="VN")).outcome == "booked"
    assert g.breaker.state("a.vn") == "closed"


def test_rate_limiter_spacing():
    pool, clock = make()
    g = IPGuard(pool, Policy(domain_rpm_start=6), clock=clock, sleep=clock.sleep)

    async def go():
        t0 = clock()
        for _ in range(3):
            await g.limiter.acquire("a.vn")
        return clock() - t0

    assert run(go()) == pytest.approx(20.0)   # 6 rpm -> 10s/lần


# ---------------- các lỗi đã sửa ----------------
def test_server_error_is_not_ok_and_407_is_proxy():
    assert classify(500, {}, "<h1>Internal Server Error</h1>").signal == Signal.SERVER_ERROR
    assert classify(503, {}, "maintenance").signal == Signal.SERVER_ERROR
    assert classify(502, {}, "").signal == Signal.NETWORK_ERROR
    assert classify(407, {}, "<html>Proxy Auth Required</html>").signal == Signal.NETWORK_ERROR


def test_retry_after_http_date():
    from email.utils import formatdate
    now = 1_800_000_000.0
    det = classify(429, {"Retry-After": formatdate(now + 600, usegmt=True)}, now=now)
    assert det.retry_after_s == pytest.approx(600, abs=1)


def test_challenge_after_submit_never_reruns_flow():
    pool, clock = make()
    g = IPGuard(pool, clock=clock, sleep=clock.sleep)
    calls = []

    async def flow(s):
        calls.append(s.engine)
        s.mark_submitted()
        s.check(403, {"cf-mitigated": "challenge"}, "")

    r = run(g.run("a.vn", "u1", flow, country="VN"))
    assert r.outcome == "failed" and calls == ["patchright_chrome"]


def test_booking_counted_even_if_session_saw_challenge():
    pool, clock = make(n=1, policy=Policy(ip_domain_daily_bookings=1))
    g = IPGuard(pool, clock=clock, sleep=clock.sleep)

    async def flow(s):
        s.observe(200, {}, "<title>Just a moment...</title>")   # challenge tự qua
        s.observe(200, {}, "ok")
        s.mark_booked()
        return "ref"

    assert run(g.run("a.vn", "u1", flow, country="VN")).outcome == "booked"
    assert pool.why_ineligible("ip0", "a.vn", "VN") == "domain_daily_cap"


def test_stopflow_after_booked_still_booked():
    pool, clock = make()
    g = IPGuard(pool, clock=clock, sleep=clock.sleep)
    calls = []

    async def flow(s):
        calls.append(1)
        s.mark_submitted(); s.mark_booked()
        s.check(403, {}, "Access denied")

    r = run(g.run("a.vn", "u1", flow, country="VN"))
    assert r.outcome == "booked" and len(calls) == 1


def test_exception_after_submit_returns_failed_not_raise():
    pool, clock = make()
    g = IPGuard(pool, clock=clock, sleep=clock.sleep)

    async def flow(s):
        s.mark_submitted()
        raise TimeoutError("click timeout")

    r = run(g.run("a.vn", "u1", flow, country="VN"))
    assert r.outcome == "failed" and "KHÔNG gửi lại" in r.detail
    assert all(st.inflight == 0 for st in pool.d.values())


def test_exception_before_submit_propagates():
    pool, clock = make()
    g = IPGuard(pool, clock=clock, sleep=clock.sleep)

    async def flow(s):
        raise KeyError("bug in flow")

    with pytest.raises(KeyError):
        run(g.run("a.vn", "u1", flow, country="VN"))
    assert all(st.inflight == 0 for st in pool.d.values())


def test_unchecked_captcha_is_still_handled():
    pool, clock = make()
    g = IPGuard(pool, clock=clock, sleep=clock.sleep)

    async def flow(s):
        s.observe(403, {"x-datadome": "1"}, "captcha-delivery.com")   # quên check
        return None

    assert run(g.run("a.vn", "u1", flow, country="VN")).outcome == "handoff_user"


def test_engine_escalation_never_silently_changes_ip():
    pool, clock = make(n=3, policy=Policy(min_score=0.95))
    g = IPGuard(pool, clock=clock, sleep=clock.sleep)
    seen = []

    async def flow(s):
        seen.append(s.proxy.id)
        s.check(403, {"cf-mitigated": "challenge"}, "")

    r = run(g.run("a.vn", "u1", flow, country="VN"))
    # điểm rơi dưới ngưỡng sau challenge -> IP ghim không dùng được -> deeplink, không đổi IP
    assert r.outcome == "deeplink" and len(set(seen)) == 1


def test_score_recovers_over_time():
    pool, clock = make(n=1)
    pool.g["ip0"].score = 0.2
    pool.g["ip0"].score_at = clock()
    assert pool.why_ineligible("ip0", "a.vn", "VN") == "low_score"
    clock.t += 20 * 3600                      # +0.2
    assert pool.why_ineligible("ip0", "a.vn", "VN") is None


def test_strikes_reset_after_long_quiet_period():
    pool, clock = make(n=1)
    for _ in range(3):
        l = pool.acquire("a.vn", "u", "VN"); pool.g["ip0"].score = 1.0
        pool.release(l, Detection(Signal.RATE_LIMITED))
        clock.t += 24 * 3600
    clock.t += 8 * 86400
    l = pool.acquire("a.vn", "u", "VN"); pool.g["ip0"].score = 1.0
    pool.release(l, Detection(Signal.RATE_LIMITED))
    assert pool.d[("ip0", "a.vn")].quarantine_until - clock() == 15 * 60


def test_probe_flag_released_when_no_healthy_ip():
    pool, clock = make(n=1)
    g = IPGuard(pool, clock=clock, sleep=clock.sleep)
    g.breaker._opened_at["a.vn"] = clock() - 3 * 3600         # half-open
    pool.g["ip0"].retired = True

    async def flow(s):
        return None

    assert run(g.run("a.vn", "u1", flow, country="VN")).outcome == "deeplink"
    assert "a.vn" not in g.breaker._probe_inflight             # không kẹt half-open


def test_normal_session_does_not_clear_someone_elses_probe():
    pool, clock = make()
    g = IPGuard(pool, clock=clock, sleep=clock.sleep)

    async def scenario():
        async with g.session("a.vn", "u1", "VN") as s:          # vào khi cầu dao đóng
            g.breaker._opened_at["a.vn"] = clock() - 3 * 3600  # trong lúc đó: half-open
            assert g.breaker.admit("a.vn") is True             # phiên khác lấy probe
            s.observe(503, {}, "oops")                         # phiên thường kết thúc xấu
    run(scenario())
    assert "a.vn" in g.breaker._probe_inflight                 # probe vẫn thuộc phiên kia


def test_probe_cancelled_while_waiting_releases_flag():
    pool, clock = make(n=4)
    g = IPGuard(pool, Policy(domain_max_concurrency=1), clock=clock, sleep=clock.sleep)

    async def scenario():
        sem = g.concurrency.get("a.vn")
        await sem.acquire()                                    # domain đang bận
        g.breaker._opened_at["a.vn"] = clock() - 3 * 3600      # half-open

        async def enter():
            async with g.session("a.vn", "u1", "VN"):
                pass
        t = asyncio.ensure_future(enter())
        await asyncio.sleep(0)
        assert "a.vn" in g.breaker._probe_inflight
        t.cancel()
        with pytest.raises(asyncio.CancelledError):
            await t
        sem.release()

    run(scenario())
    assert "a.vn" not in g.breaker._probe_inflight


def test_rate_limit_during_probe_reopens_breaker():
    pool, clock = make()
    g = IPGuard(pool, clock=clock, sleep=clock.sleep)
    g.breaker._opened_at["a.vn"] = clock() - 3 * 3600

    async def flow(s):
        s.check(429, {})

    run(g.run("a.vn", "u1", flow, country="VN"))
    assert g.breaker.state("a.vn") == "open"


def test_long_pause_fails_fast_instead_of_sleeping():
    pool, clock = make()
    g = IPGuard(pool, clock=clock, sleep=clock.sleep)
    g.limiter.on_throttle("a.vn", pause_s=3600)
    t0 = clock()

    async def flow(s):
        await s.before_navigation()
        return None

    r = run(g.run("a.vn", "u1", flow, country="VN"))
    assert r.outcome == "deeplink" and "tạm dừng" in r.detail and clock() == t0


def test_guard_state_roundtrip_includes_breaker_and_limiter():
    pool, clock = make(n=6)
    g = IPGuard(pool, clock=clock, sleep=clock.sleep)

    async def flow(s):
        s.check(403, {}, "Sorry, you have been blocked")

    for u in ("u1", "u2"):
        run(g.run("a.vn", u, flow, country="VN"))
    raw = g.dump_state()
    pool2, _ = make(n=6, clock=clock)
    g2 = IPGuard(pool2, clock=clock, sleep=clock.sleep)
    g2.load_state(raw)
    assert g2.breaker.state("a.vn") == "open"
    assert g2.limiter.rpm["a.vn"] < Policy().domain_rpm_start


def test_load_state_ignores_unknown_fields():
    pool, _ = make(n=1)
    pool.load_state('{"g": {"ip0": {"score": 0.5, "future_field": 1}}, "d": {}, "affinity": {}}')
    assert pool.g["ip0"].score == 0.5


def test_adapter_dedupes_goto_response():
    from ipguard.adapters import Issues, guarded_goto

    pool, clock = make()
    g = IPGuard(pool, clock=clock, sleep=clock.sleep)

    class Resp:
        status = 200
        async def text(self): return "ok"
        async def all_headers(self): return {}

    resp = Resp()

    class Page:
        async def goto(self, url, **kw): return resp

    async def scenario():
        async with g.session("a.vn", "u1", "VN") as s:
            issues = Issues()
            issues.claim(resp)                        # attach() đã nhận response này
            await guarded_goto(Page(), s, "https://a.vn", issues)
            return s.observed

    assert run(scenario()) == 0


# ---------------- bổ sung lần 2 ----------------
def test_pause_set_mid_session_aborts_instead_of_waiting():
    pool, clock = make()
    g = IPGuard(pool, clock=clock, sleep=clock.sleep)
    t0 = clock()

    async def flow(s):
        s.check(200, {}, "ok")
        g.limiter.on_throttle("a.vn", pause_s=3600)       # phiên khác vừa nhận 429
        await s.before_navigation()
        s.check(200, {}, "ok")

    r = run(g.run("a.vn", "u1", flow, country="VN"))
    assert r.outcome == "deeplink" and "tạm dừng" in r.detail
    assert clock() - t0 < 60
    assert all(st.inflight == 0 for st in pool.d.values())


def test_request_id_prevents_duplicate_booking():
    pool, clock = make()
    g = IPGuard(pool, clock=clock, sleep=clock.sleep)
    calls = []

    async def lost(s):                     # submit xong thì mất kết nối
        calls.append(1)
        s.mark_submitted()
        s.check(None)

    assert run(g.run("a.vn", "u1", lost, country="VN", request_id="R1")).outcome == "failed"
    r = run(g.run("a.vn", "u1", lost, country="VN", request_id="R1"))
    assert r.outcome == "failed" and "resolve" in r.detail and len(calls) == 1

    g.resolve("R1")                        # đã kiểm tra: chưa đặt

    async def ok(s):
        calls.append(1)
        s.check(200, {}, "ok"); s.mark_submitted(); s.mark_booked(); return "ref"

    assert run(g.run("a.vn", "u1", ok, country="VN", request_id="R1")).outcome == "booked"
    r = run(g.run("a.vn", "u1", ok, country="VN", request_id="R1"))
    assert r.outcome == "booked" and len(calls) == 2           # không chạy flow lần 3

    g2 = IPGuard(make(clock=clock)[0], clock=clock, sleep=clock.sleep)
    g2.load_state(g.dump_state())
    assert g2.requests["R1"][0] == "booked"


def test_pre_submit_failure_does_not_lock_request():
    pool, clock = make()
    g = IPGuard(pool, clock=clock, sleep=clock.sleep)

    async def flow(s):
        s.check(429, {})

    run(g.run("a.vn", "u1", flow, country="VN", request_id="R2"))
    assert "R2" not in g.requests


def test_reinstate_and_affinity_pruning():
    pool, clock = make(n=1)
    l = pool.acquire("a.vn", "u", "VN"); pool.release(l, Detection(Signal.OK))
    pool.g["ip0"].retired = True
    assert pool.to_dict()["affinity"] == {}                 # IP bị loại -> bỏ gắn khách quen
    pool.reinstate("ip0")
    assert pool.why_ineligible("ip0", "a.vn", "VN") is None
    assert pool._caps(pool.proxies["ip0"]) == (2, 20)       # chạy lại warm-up
