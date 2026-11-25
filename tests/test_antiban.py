import asyncio
import json
import os

import pytest

from ipguard import (AntiBan, Detection, InMemoryStore, IPGuard, IPPool, Policy, ProxyEndpoint,
                     RedisStore, Signal)
from ipguard.adapters import GeoMismatch, guarded_page, verify_browser_geo
from ipguard.health import HealthChecker


class Clock:
    def __init__(self, t=1_800_000_000.0):
        self.t = t

    def __call__(self):
        return self.t

    async def sleep(self, s):
        self.t += s


def proxies(n=4, country="VN", clock=None):
    t0 = (clock() if clock else 1_800_000_000.0) - 30 * 86400
    return [ProxyEndpoint(f"ip{i}", f"http://u:p@10.0.0.{i}:8000", country, "isp", added_at=t0)
            for i in range(n)]


def run(c):
    return asyncio.run(c)


def worker(store, clock, n=4, policy=None, **kw):
    pool = IPPool(proxies(n, clock=clock), policy or Policy(), clock=clock)
    return IPGuard(pool, clock=clock, sleep=clock.sleep, store=store, **kw)


# ---------------- nhiều worker ----------------
def test_two_workers_share_ip_busy_and_domain_cap():
    clock, store = Clock(), InMemoryStore()
    a = worker(store, clock, n=2, policy=Policy(domain_max_concurrency=1, max_pause_wait_s=10))
    b = worker(store, clock, n=2, policy=Policy(domain_max_concurrency=1, max_pause_wait_s=10))

    async def scenario():
        async with a.session("x.vn", "u1", "VN") as sa:
            # worker B: domain đã đủ phiên trên toàn cụm -> chờ tối đa 10s rồi trả deep link
            t0 = clock()
            r = await b.run("x.vn", "u2", lambda s: asyncio.sleep(0), country="VN")
            assert r.outcome == "deeplink" and "đủ phiên" in r.detail
            assert 10 <= clock() - t0 <= 13
            # domain khác thì vẫn chạy được
            async with b.session("y.vn", "u2", "VN"):
                pass
            sa.observe(200, {}, "ok")

    run(scenario())
    data = json.loads(store.raw)
    assert data["pool"]["leases"] == {}


def test_signals_and_breaker_visible_across_workers():
    clock, store = Clock(), InMemoryStore()
    ws = [worker(store, clock, n=6) for _ in range(3)]

    async def blocked(s):
        s.check(403, {}, "Sorry, you have been blocked")

    for i, w in enumerate(ws[:2]):
        run(w.run("x.vn", f"u{i}", blocked, country="VN"))   # 2 lượt x 2 IP = 4 IP bị chặn
    r = run(ws[2].run("x.vn", "u9", blocked, country="VN"))
    assert r.outcome == "deeplink" and "cầu dao" in r.detail
    async def latest_rpm(w):
        async with w.sync():                                  # nạp trạng thái mới nhất
            return w.limiter.rpm["x.vn"]
    assert run(latest_rpm(ws[2])) < Policy().domain_rpm_start


def test_request_id_dedup_across_workers():
    clock, store = Clock(), InMemoryStore()
    a, b = worker(store, clock), worker(store, clock)

    async def ok(s):
        s.check(200, {}, "ok"); s.mark_submitted(); s.mark_booked(); return "ref"

    assert run(a.run("x.vn", "u", ok, country="VN", request_id="R")).outcome == "booked"
    calls = []

    async def again(s):
        calls.append(1)

    r = run(b.run("x.vn", "u", again, country="VN", request_id="R"))
    assert r.outcome == "booked" and calls == []


def test_dead_worker_lease_and_probe_expire():
    clock, store = Clock(), InMemoryStore()
    a = worker(store, clock, n=1)
    b = worker(store, clock, n=1)

    async def a_dies():
        async with a.sync():
            a.pool.acquire("x.vn", "u1", "VN")              # cấp IP rồi "chết", không trả
    run(a_dies())

    async def ok(s):
        s.check(200, {}, "ok"); s.mark_booked()

    assert run(b.run("x.vn", "u2", ok, country="VN")).outcome == "deeplink"   # IP còn bận
    clock.t += Policy().lease_ttl_s + 1
    assert run(b.run("x.vn", "u2", ok, country="VN")).outcome == "booked"


def test_redis_store_with_fake_client():
    class FakeRedis:
        def __init__(self):
            self.kv = {}

        async def set(self, k, v, nx=False, px=None):
            if nx and k in self.kv:
                return None
            self.kv[k] = v.encode() if isinstance(v, str) else v
            return True

        async def get(self, k):
            return self.kv.get(k)

        async def eval(self, script, n, key, token):
            if self.kv.get(key) == token.encode():
                del self.kv[key]
                return 1
            return 0

    fake = FakeRedis()
    clock = Clock()
    a = worker(RedisStore(fake, key="t"), clock)
    b = worker(RedisStore(fake, key="t"), clock)

    async def ok(s):
        s.check(200, {}, "ok"); s.mark_booked(); return 1

    assert run(a.run("x.vn", "u1", ok, country="VN", request_id="R1")).outcome == "booked"
    assert "t:lock" not in fake.kv                              # khóa đã nhả
    assert run(b.run("x.vn", "u1", ok, country="VN", request_id="R1")).detail.startswith("lượt")


# ---------------- kiểm tra proxy ----------------
def fake_fetch(table):
    async def fetch(proxy_url, url, timeout):
        v = table[proxy_url]
        if isinstance(v, Exception):
            raise v
        return 200, json.dumps(v)
    return fetch


def test_health_check_blocks_bad_proxies_and_recovers():
    clock = Clock()
    g = worker(None, clock, n=4)
    events = []
    g.on_alert = events.append
    table = {
        "http://u:p@10.0.0.0:8000": {"ip": "1.1.1.1", "country": "VN"},
        "http://u:p@10.0.0.1:8000": {"ip": "2.2.2.2", "country": "US"},   # sai quốc gia
        "http://u:p@10.0.0.2:8000": ConnectionError("refused"),            # chết
        "http://u:p@10.0.0.3:8000": {"ip": "1.1.1.1", "country": "VN"},   # trùng IP ra với ip0
    }
    hc = HealthChecker(g, fetch=fake_fetch(table))
    run(hc.check(force=True))
    blocks = {k: v.health_block for k, v in g.pool.g.items()}
    assert blocks["ip0"] == ""
    assert blocks["ip1"].startswith("geo")
    assert blocks["ip2"].startswith("dead")
    assert blocks["ip3"].startswith("duplicate")
    assert g.pool.why_ineligible("ip1", "x.vn", "VN") == "health"
    assert {e["kind"] for e in events} == {"health_issue"}

    # proxy sửa xong -> lần kiểm tra sau gỡ chặn
    table["http://u:p@10.0.0.1:8000"] = {"ip": "3.3.3.3", "country": "VN"}
    run(hc.check(force=True))
    assert g.pool.g["ip1"].health_block == ""


def test_health_check_ip_change_restarts_warmup():
    clock = Clock()
    g = worker(None, clock, n=1)
    table = {"http://u:p@10.0.0.0:8000": {"ip": "1.1.1.1", "country": "VN"}}
    hc = HealthChecker(g, fetch=fake_fetch(table))
    run(hc.check(force=True))
    assert g.pool._caps(g.pool.proxies["ip0"]) == (4, 40)
    table["http://u:p@10.0.0.0:8000"] = {"ip": "9.9.9.9", "country": "VN"}
    run(hc.check(force=True))
    assert g.pool._caps(g.pool.proxies["ip0"]) == (2, 20)
    assert any(e["kind"] == "ip_changed" for e in g.metrics.events)


def test_health_service_down_does_not_block_everything():
    clock = Clock()
    g = worker(None, clock, n=2)
    table = {f"http://u:p@10.0.0.{i}:8000": TimeoutError("geo down") for i in range(2)}
    run(HealthChecker(g, fetch=fake_fetch(table)).check(force=True))
    assert all(not gs.health_block for gs in g.pool.g.values())
    assert g.metrics.events[-1]["kind"] == "health_unavailable"


def test_health_check_only_when_due():
    clock = Clock()
    g = worker(None, clock, n=2)
    calls = []

    async def fetch(p, u, t):
        calls.append(p)
        return 200, json.dumps({"ip": p[-10:], "country": "VN"})

    hc = HealthChecker(g, fetch=fetch)
    run(hc.check()); run(hc.check())
    assert len(calls) == 2
    clock.t += Policy().health_interval_s + 1
    run(hc.check())
    assert len(calls) == 4


# ---------------- AntiBan: 1 đầu vào ----------------
CONFIG = """
engines = ["patchright_chrome"]
[state]
backend = "file"
path = "state/ipguard_state.json"
[policy]
ip_domain_daily_bookings = 2
[[proxy]]
id = "vn-1"
url = "${PX_TEST_1}"
country = "VN"
kind = "isp"
[[proxy]]
id = "vn-2"
url = "http://u:p@10.0.0.2:8000"
country = "VN"
"""


def test_antiban_from_config_book_and_persist(tmp_path, monkeypatch):
    monkeypatch.setenv("PX_TEST_1", "http://u:p@10.0.0.1:8000")
    cfg = tmp_path / "ipguard.toml"
    cfg.write_text(CONFIG, encoding="utf-8")
    clock = Clock()
    table = {"http://u:p@10.0.0.1:8000": {"ip": "1.1.1.1", "country": "VN"},
             "http://u:p@10.0.0.2:8000": {"ip": "2.2.2.2", "country": "VN"}}
    ab = AntiBan.from_config(str(cfg), fetch=fake_fetch(table), clock=clock, sleep=clock.sleep)
    assert ab.policy.ip_domain_daily_bookings == 2 and ab.engines == ("patchright_chrome",)

    async def ok(s):
        s.check(200, {}, "ok"); s.mark_submitted(); s.mark_booked(); return "ref"

    async def go():
        async with ab:
            return await ab.book("x.vn", "u1", ok, country="VN", request_id="R1")

    r = run(go())
    assert r.outcome == "booked" and r.value == "ref"
    state = tmp_path / "state" / "ipguard_state.json"
    assert state.exists()

    ab2 = AntiBan.from_config(str(cfg), fetch=fake_fetch(table), clock=clock, sleep=clock.sleep)
    assert ab2.guard.requests["R1"][0] == "booked"
    assert ab2.pool.g["vn-1"].exit_ip in ("1.1.1.1", "")
    rep = run(ab2.report())
    assert rep["domains"]["x.vn"]["outcomes"] == {"booked": 1}


def test_config_errors(tmp_path, monkeypatch):
    monkeypatch.delenv("PX_TEST_1", raising=False)
    cfg = tmp_path / "c.toml"
    cfg.write_text(CONFIG, encoding="utf-8")
    with pytest.raises(KeyError):
        AntiBan.from_config(str(cfg))
    cfg.write_text(CONFIG.replace("ip_domain_daily_bookings", "typo_key")
                   .replace("${PX_TEST_1}", "http://h:1"), encoding="utf-8")
    with pytest.raises(ValueError):
        AntiBan.from_config(str(cfg))


def test_warmup_not_restarted_on_process_restart(tmp_path):
    clock = Clock()
    path = str(tmp_path / "s.json")
    pxs = lambda: [ProxyEndpoint("new", "http://h:1", "VN")]   # noqa: E731
    ab = AntiBan(pxs(), state_path=path, health_check=False, clock=clock, sleep=clock.sleep)
    ab.save()
    clock.t += 4 * 86400                                     # qua 3 ngày warm-up
    ab2 = AntiBan(pxs(), state_path=path, health_check=False, clock=clock, sleep=clock.sleep)
    assert ab2.pool._caps(ab2.pool.proxies["new"]) == (4, 40)


def test_alerts_and_report():
    clock = Clock()
    alerts = []
    ab = AntiBan(proxies(6, clock=clock), health_check=False, on_alert=alerts.append,
                 clock=clock, sleep=clock.sleep)

    async def blocked(s):
        s.observe(200, {}, "ok")
        s.check(403, {}, "Access denied")

    for u in ("u1", "u2"):
        run(ab.book("x.vn", u, blocked, country="VN"))
    assert any(a["kind"] == "breaker_open" for a in alerts)
    rep = run(ab.report())
    d = rep["domains"]["x.vn"]
    assert d["breaker"] == "open" and d["block_rate"] == 0.5
    from ipguard.__main__ import format_report
    assert "cầu dao open" in format_report(rep)


# ---------------- trình duyệt ----------------
class FakePage:
    def __init__(self, tz, lang):
        self.v = [tz, lang]

    async def evaluate(self, js):
        return self.v

    def on(self, *a):
        pass


class FakeCtx:
    def __init__(self, page):
        self.pages = [page]
        self.closed = False

    async def close(self):
        self.closed = True


def test_verify_browser_geo():
    px = ProxyEndpoint("a", "http://h:1", "VN")
    assert run(verify_browser_geo(FakePage("Asia/Ho_Chi_Minh", "vi-VN"), px)) == []
    assert run(verify_browser_geo(FakePage("Asia/Saigon", "vi"), px)) == []   # tên cũ của Chrome
    probs = run(verify_browser_geo(FakePage("UTC", "en-US"), px))
    assert len(probs) == 2


def test_guarded_page_refuses_geo_mismatch_and_closes():
    clock = Clock()
    g = worker(None, clock, n=1)
    ctx = FakeCtx(FakePage("Europe/London", "en-GB"))

    async def launcher(pw, s, profile_dir, headless):
        assert os.path.join("u_1", "x.vn") in profile_dir       # user_id đã được làm sạch
        return ctx

    async def scenario():
        async with g.session("x.vn", "u/1", "VN", engine="mine") as s:
            with pytest.raises(GeoMismatch):
                async with guarded_page(None, s, launchers={"mine": launcher}):
                    pass
    run(scenario())
    assert ctx.closed


def test_guarded_page_unknown_engine():
    clock = Clock()
    g = worker(None, clock, n=1)

    async def scenario():
        async with g.session("x.vn", "u", "VN", engine="camoufox") as s:
            with pytest.raises(NotImplementedError):
                async with guarded_page(None, s):
                    pass
    run(scenario())
