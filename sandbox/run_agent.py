"""Agent browser-use (LLM) đặt bàn qua ipguard trong sandbox, rồi kiểm chứng từng cơ chế.

    .venv/Scripts/python -m sandbox.run_agent                 # mọi kịch bản
    .venv/Scripts/python -m sandbox.run_agent ok cf walls     # chọn kịch bản
    .venv/Scripts/python -m sandbox.run_agent --headed --model gpt-5.6-luna

Cần: OPENAI_API_KEY (+ OPENAI_BASE_URL, OPENAI_MODEL nếu có). Không gì ra Internet ngoài lời gọi LLM:
trình duyệt chỉ đi qua proxy sandbox, proxy chỉ chuyển tới *.sandbox.test.

Mỗi kịch bản so 2 nguồn: điều ipguard trả về (RunResult) và SỰ THẬT phía site (request nào,
từ IP ra nào, form nào thực sự được POST, timezone/ngôn ngữ trình duyệt báo về).
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import shutil
import sys
import time
import traceback
from dataclasses import dataclass, field
from typing import Callable, Optional

os.environ.setdefault("ANONYMIZED_TELEMETRY", "false")   # không gửi telemetry của browser-use
os.environ.setdefault("BH_TELEMETRY", "0")

from ipguard import AntiBan, Policy, ProxyEndpoint  # noqa: E402
from ipguard.browser_use_adapter import ENGINES, browser_use_flow  # noqa: E402
from sandbox.infra import SCENARIOS, Sandbox  # noqa: E402

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sandbox_out")
BAD_PROXIES = {"px-vn-geo", "px-vn-dead"}

REQ = {"party": 4, "date": "2026-12-05", "time": "19:00", "name": "Khách Sandbox",
       "phone": "0900000042"}
TASK = ("Đặt bàn tại nhà hàng trên trang đang mở: {party} khách, ngày {date}, lúc {time}, "
        "tên người đặt '{name}', số điện thoại {phone}. Không cần ghi chú. "
        "Nếu trang có nhiều bước thì đi lần lượt. Khi form cuối đã điền đủ, gọi submit_booking.")


def success_check(text: str) -> Optional[str]:
    if "Đặt bàn thành công" in text:
        m = re.search(r"SBX-[0-9A-F]{6}", text)
        return m.group(0) if m else "?"
    return None


# ----------------------------------------------------------------------
@dataclass
class Ctx:
    sb: Sandbox
    llm: object
    headed: bool
    case_dir: str
    runs: list = field(default_factory=list)          # AgentRun của mọi phiên trong kịch bản
    expect_leaks: bool = False
    results: list = field(default_factory=list)       # RunResult theo từng lượt book()

    def antiban(self, *, dry_run=False, **pol) -> AntiBan:
        pxs = []
        for e in self.sb.egress:
            url = "http://127.0.0.1:9" if e.dead else self.sb.proxy_url(e.id)
            pxs.append(ProxyEndpoint(e.id, url, "VN", "isp", added_at=1.0))  # đã qua warm-up
        policy = Policy(jitter_min_s=0.3, jitter_max_s=0.8, domain_rpm_start=20, **pol)
        return AntiBan(pxs, policy, geo_url=self.sb.geo_url, engines=ENGINES, dry_run=dry_run)

    async def book(self, ab: AntiBan, scn: str, *, user="u1", request_id=None, path="/dat-ban",
                   llm=None):
        flow = browser_use_flow(TASK.format(**REQ), self.sb.url(scn, path), llm=llm or self.llm,
                                success=success_check, headless=not self.headed,
                                profile_root=os.path.join(self.case_dir, "profiles"),
                                runs=self.runs, max_steps=20, timeout_s=240)
        r = await ab.book(self.sb.domain(scn), user, flow, country="VN", request_id=request_id)
        self.results.append(r)
        return r


class Check:
    def __init__(self):
        self.items: list[tuple[bool, str]] = []

    def __call__(self, cond, msg: str):
        self.items.append((bool(cond), msg))
        return bool(cond)

    @property
    def ok(self):
        return all(c for c, _ in self.items)


# ----------------------------------------------------------------------
# Kịch bản: (mô tả, coroutine(ctx, check))
async def c_ok(x: Ctx, ck: Check):
    ab = x.antiban()
    r = await x.book(ab, "ok", request_id="R-ok")
    site = x.sb.state.snapshot("ok.sandbox.test")
    acc = [b for b in site["bookings"] if b.get("accepted")]
    ck(r.outcome == "booked", f"outcome booked (được {r.outcome}: {r.detail})")
    ck(len(site["bookings"]) == 1 and len(acc) == 1, f"site nhận đúng 1 POST ({len(site['bookings'])})")
    if acc:
        f = acc[0]["form"]
        ck(f.get("party") == "4" and f.get("time") == "19:00" and f.get("phone") == REQ["phone"],
           f"LLM điền đúng dữ liệu {f}")
        ck(r.value == acc[0]["ref"], f"mã đặt bàn ipguard trả ({r.value}) = mã site ({acc[0]['ref']})")
    r2 = await x.book(ab, "ok", request_id="R-ok")
    site2 = x.sb.state.snapshot("ok.sandbox.test")
    ck(r2.outcome == "booked" and len(site2["bookings"]) == 1,
       "gọi lại cùng request_id: không đặt lần 2, không tải trang")
    ck(len(site2["requests"]) == len(site["requests"]), "lượt gọi lại không chạm tới site")


async def c_en(x: Ctx, ck: Check):
    r = await x.book(x.antiban(), "en")
    site = x.sb.state.snapshot("en.sandbox.test")
    ck(r.outcome == "booked", f"form tiếng Anh, 1 trang: booked (được {r.outcome}: {r.detail})")
    ck(len(site["bookings"]) == 1, f"đúng 1 POST ({len(site['bookings'])})")


async def c_dry(x: Ctx, ck: Check):
    ab = x.antiban(dry_run=True)
    r = await x.book(ab, "ok", request_id="R-dry")
    site = x.sb.state.snapshot("ok.sandbox.test")
    ck(r.outcome == "dry_run", f"outcome dry_run (được {r.outcome}: {r.detail})")
    ck(site["bookings"] == [], "chạy thử: site KHÔNG nhận POST nào")
    ck(any("thong-tin" in q["path"] for q in site["requests"]), "agent vẫn đi tới bước cuối")
    ck("R-dry" not in ab.guard.requests, "chạy thử không khóa request_id")


async def c_cf(x: Ctx, ck: Check):
    r = await x.book(x.antiban(), "cf")
    ck(r.outcome == "deeplink", f"challenge -> deeplink (được {r.outcome})")
    ck([e for e, *_ in r.log] == list(ENGINES), f"đổi engine theo thứ tự {[e for e, *_ in r.log]}")
    ck(len({ip for _, ip, *_ in r.log}) == 1, "GIỮ nguyên IP khi đổi engine")
    ua = {q["user_agent"] for q in x.sb.state.snapshot("cf.sandbox.test")["requests"]}
    ck(len(ua) >= 1, f"site thấy {len(ua)} user-agent")


async def c_captcha(x: Ctx, ck: Check):
    r = await x.book(x.antiban(), "captcha")
    ck(r.outcome == "handoff_user", f"CAPTCHA -> handoff_user (được {r.outcome})")
    ck(len(r.log) == 1, "không thử lại / không đổi IP")


async def c_blocked(x: Ctx, ck: Check):
    r = await x.book(x.antiban(), "blocked")
    ips = [ip for _, ip, *_ in r.log]
    ck(r.outcome == "deeplink", f"chặn cứng -> deeplink (được {r.outcome})")
    ck(len(ips) == 2 and ips[0] != ips[1], f"đổi IP đúng 1 lần {ips}")
    seen = {q["proxy_id"] for q in x.sb.state.snapshot("blocked.sandbox.test")["requests"]}
    ck(seen == set(ips), f"site chỉ thấy 2 IP đó {sorted(seen)}")


async def c_ratelimit(x: Ctx, ck: Check):
    ab = x.antiban()
    r = await x.book(ab, "ratelimit")
    ck(r.outcome == "deeplink" and len(r.log) == 1, f"429 -> dừng, không đổi IP ({r.outcome}, {len(r.log)} phiên)")
    ck(ab.guard.limiter.paused_for("ratelimit.sandbox.test") > 0, "domain bị tạm dừng theo Retry-After")
    first = [q for q in x.sb.state.snapshot("ratelimit.sandbox.test")["requests"] if q["document"]]
    r2 = await x.book(ab, "ratelimit")
    docs = [q for q in x.sb.state.snapshot("ratelimit.sandbox.test")["requests"] if q["document"]]
    ck(r2.outcome == "deeplink", f"gọi ngay lần 2: {r2.outcome} — {r2.detail[:60]}")
    if len(docs) > len(first):
        gap = docs[len(first)]["ts"] - first[-1]["ts"]
        ck(gap >= 5.0, f"lần 2 chờ hết Retry-After 5s mới tải lại ({gap:.1f}s)")
        ck(docs[len(first)]["proxy_id"] != first[-1]["proxy_id"],
           "cặp (IP, domain) bị 429 được cách ly: lượt sau dùng IP khác")


async def c_down(x: Ctx, ck: Check):
    ab = x.antiban()
    r = await x.book(ab, "down")
    ck(r.outcome == "deeplink" and len(r.log) == 1, f"503 -> dừng, không đổi IP ({r.outcome}, {len(r.log)} phiên)")
    ip = r.log[0][1] if r.log else None
    ck(ip and ab.pool.g[ip].score >= 1.0 - 1e-9, "5xx của site không trừ điểm IP")


async def c_ipban(x: Ctx, ck: Check):
    ab = x.antiban()
    r = await x.book(ab, "ipban")
    ips = [ip for _, ip, *_ in r.log]
    site = x.sb.state.snapshot("ipban.sandbox.test")
    ck(r.outcome == "booked", f"IP đầu bị cấm -> đổi IP 1 lần -> booked (được {r.outcome}: {r.detail})")
    ck(len(ips) == 2 and ips[0] != ips[1], f"2 phiên, 2 IP {ips}")
    acc = [b for b in site["bookings"] if b.get("accepted")]
    ck(len(site["bookings"]) == 1 and acc and acc[0]["proxy_id"] == ips[-1],
       "POST duy nhất đi từ IP thứ hai")
    ck(ab.pool.g[ips[0]].score < 1.0, f"IP bị cấm bị trừ điểm ({ab.pool.g[ips[0]].score:.2f})")


async def c_midblock(x: Ctx, ck: Check):
    r = await x.book(x.antiban(), "midblock")
    site = x.sb.state.snapshot("midblock.sandbox.test")
    ck(r.outcome == "deeplink", f"bị chặn ở bước 2 do AGENT tự điều hướng -> deeplink (được {r.outcome}: {r.detail})")
    ck(len(r.log) == 2 and all(row[2] == "blocked" for row in r.log), f"phát hiện chặn trong lúc agent chạy {r.log}")
    ck(site["bookings"] == [], "chưa từng POST")


async def c_afterblock(x: Ctx, ck: Check):
    ab = x.antiban()
    r = await x.book(ab, "afterblock", request_id="R-ab")
    site = x.sb.state.snapshot("afterblock.sandbox.test")
    ck(r.outcome == "failed" and "KHÔNG gửi lại" in r.detail, f"chặn sau submit -> failed ({r.outcome}: {r.detail})")
    ck(len(site["bookings"]) == 1 and len(r.log) == 1, f"đúng 1 POST, không đổi IP ({len(site['bookings'])})")
    ck(ab.guard.requests.get("R-ab", ("",))[0] == "submitted_unknown", "request_id bị khóa chờ kiểm tra")
    r2 = await x.book(ab, "afterblock", request_id="R-ab")
    ck(r2.outcome == "failed" and len(x.sb.state.snapshot("afterblock.sandbox.test")["bookings"]) == 1,
       "phía gọi tự retry: vẫn không gửi lại")


async def c_aftercaptcha(x: Ctx, ck: Check):
    r = await x.book(x.antiban(), "aftercaptcha", request_id="R-ac")
    site = x.sb.state.snapshot("aftercaptcha.sandbox.test")
    ck(r.outcome == "handoff_user", f"CAPTCHA sau submit -> handoff_user (được {r.outcome})")
    ck(len(site["bookings"]) == 1, "đúng 1 POST")


async def c_walls(x: Ctx, ck: Check):
    ab = x.antiban()
    r1 = await x.book(ab, "walls", user="u1")
    r2 = await x.book(ab, "walls", user="u2")
    ips = {ip for r in (r1, r2) for _, ip, *_ in r.log}
    ck(len(ips) >= 3, f"{len(ips)} IP khác nhau bị chặn: {sorted(ips)}")
    ck(ab.guard.breaker.state("walls.sandbox.test") != "closed", "cầu dao domain đã mở")
    before = len(x.sb.state.snapshot("walls.sandbox.test")["requests"])
    r3 = await x.book(ab, "walls", user="u3")
    after = len(x.sb.state.snapshot("walls.sandbox.test")["requests"])
    ck(r3.outcome == "deeplink" and "cầu dao" in r3.detail, f"lượt 3: {r3.outcome} — {r3.detail}")
    ck(after == before, "cầu dao mở: không chạm tới site")


async def c_rogue(x: Ctx, ck: Check):
    """Agent "hư" (kịch bản cố định): tự bấm nút gửi thay vì dùng tool, và gọi http_get() đi thẳng."""
    from sandbox.scripted_llm import scripted_model
    r = await x.book(x.antiban(), "ok", request_id="R-rogue", llm=scripted_model(REQ, rogue=True))
    site = x.sb.state.snapshot("ok.sandbox.test")
    blocked = sum(len(s.gate.blocked_posts) for s in x.runs if s.gate)
    ck(blocked >= 1, f"cổng chặn POST tự bấm của agent ({blocked} lần)")
    ck(len(site["bookings"]) == 1, f"site chỉ nhận POST đi qua submit_booking ({len(site['bookings'])})")
    ck(r.outcome == "booked", f"vẫn đặt được qua tool ({r.outcome}: {r.detail})")
    ck(len(x.sb.leaks) >= 1, f"bẫy bắt được http_get() đi vòng qua ipguard: {[l['request'] for l in x.sb.leaks]}")
    x.expect_leaks = True


CASES: dict[str, tuple[str, Callable]] = {
    "ok": ("2 bước, booked + chống đặt trùng theo request_id", c_ok),
    "en": ("form tiếng Anh (agent phải tự hiểu trang)", c_en),
    "dry_run": ("chạy thử: đi tới bước cuối, không gửi", c_dry),
    "cf": ("Cloudflare challenge: đổi engine, giữ IP", c_cf),
    "captcha": ("CAPTCHA: giao người dùng", c_captcha),
    "blocked": ("chặn cứng: đổi IP 1 lần rồi deep link", c_blocked),
    "ratelimit": ("429: dừng, không đổi IP, tôn trọng Retry-After", c_ratelimit),
    "down": ("503: không phạt IP", c_down),
    "ipban": ("cấm 1 IP: đổi IP rồi đặt được", c_ipban),
    "midblock": ("bị chặn giữa lúc agent tự điều hướng", c_midblock),
    "afterblock": ("bị chặn sau submit: không gửi lại", c_afterblock),
    "aftercaptcha": ("CAPTCHA sau submit", c_aftercaptcha),
    "walls": ("3 IP bị chặn: mở cầu dao domain", c_walls),
    "rogue": ("agent tự bấm gửi + http_get đi thẳng: cổng và bẫy phải bắt được", c_rogue),
}


# ----------------------------------------------------------------------
def global_checks(x: Ctx, ck: Check, hosts: set[str]):
    """Bất biến phải đúng với MỌI kịch bản, kiểm bằng dữ liệu phía site/proxy."""
    reqs = [q for q in x.sb.state.requests if q["host"] in hosts]
    ck(all(q["proxy_id"] not in BAD_PROXIES and q["proxy_id"] != "direct" for q in reqs),
       "mọi request tới site đi qua proxy khỏe (không IP lệch geo/chết, không đi thẳng)")
    langs = {q["accept_language"].split(",")[0] for q in reqs if q["method"] == "GET"}
    ck(langs <= {"vi-VN"}, f"Accept-Language khớp VN {sorted(langs)}")
    beacons = [b for b in x.sb.state.beacons if b["host"] in hosts]
    bad = [b for b in beacons if b.get("tz") not in ("Asia/Ho_Chi_Minh", "Asia/Saigon")
           or not str(b.get("lang", "")).startswith("vi")]
    if beacons:
        ck(not bad, f"timezone/ngôn ngữ trình duyệt khớp IP ({len(beacons)} beacon, lệch: {bad[:2]})")
    browser = [q for q in reqs if not q["user_agent"].startswith("ipguard-healthcheck")]
    ck(browser, f"có {len(browser)} request từ trình duyệt để kiểm")
    headless = {q["user_agent"] for q in browser if "headless" in (q["user_agent"] + q["sec_ch_ua"]).lower()}
    ck(not headless, f"không lộ 'HeadlessChrome' trong UA/Sec-CH-UA {sorted(headless)[:1]}")
    ck(not any(b.get("wd") for b in beacons), "navigator.webdriver = false")
    acc = [b for b in x.sb.state.bookings if b["host"] in hosts and b.get("duplicate")]
    ck(not acc, "không có lượt đặt trùng ở phía site")
    outside = sorted({p["host"] for p in x.sb.proxy_log if p.get("refused")})
    if outside:   # đi qua proxy của lease (không đi thẳng), sandbox chặn lại: chỉ ghi nhận
        ck(True, f"ℹ traffic nền của Chrome qua proxy, sandbox đã chặn: {', '.join(outside)}")
    if not x.expect_leaks:
        ck(not x.sb.leaks, f"agent không gửi request nào đi vòng qua ipguard {[l['request'] for l in x.sb.leaks][:3]}")
    blocked_posts = sum(len(r.gate.blocked_posts) for r in x.runs if r.gate)
    if blocked_posts and not x.expect_leaks:
        ck(True, f"CẢNH BÁO: agent tự bấm gửi {blocked_posts} lần, cổng đã chặn")
    for host in hosts:
        docs = sorted(q["ts"] for q in reqs if q["host"] == host and q["document"])
        gaps = [b - a for a, b in zip(docs, docs[1:])]
        if gaps:
            ck(min(gaps) >= 0.25, f"{host}: giãn cách tải trang nhỏ nhất {min(gaps):.2f}s")


async def run_case(name: str, sb: Sandbox, llm, headed: bool) -> dict:
    desc, fn = CASES[name]
    case_dir = os.path.join(OUT, name)
    shutil.rmtree(case_dir, ignore_errors=True)
    os.makedirs(case_dir, exist_ok=True)
    sb.state.reset()
    sb.proxy_log.clear()
    sb.leaks.clear()
    x, ck = Ctx(sb, llm, headed, case_dir), Check()
    t0 = time.time()
    err = None
    try:
        await fn(x, ck)
    except Exception as e:
        err = "".join(traceback.format_exception(e))[-1500:]
        ck(False, f"exception: {e!r}")
    hosts = {q["host"] for q in sb.state.requests} - {"geo.sandbox.test"}
    global_checks(x, ck, hosts)
    rep = {
        "case": name, "desc": desc, "ok": ck.ok, "seconds": round(time.time() - t0, 1),
        "checks": [{"ok": c, "msg": m} for c, m in ck.items],
        "results": [{"outcome": r.outcome, "detail": r.detail, "value": r.value, "log": r.log}
                    for r in x.results],
        "sessions": [{"engine": r.engine, "proxy": r.proxy_id, "agent": r.agent_status,
                      "agent_error": r.agent_error, "final": str(r.final)[:300],
                      "navigations": r.gate.navigations if r.gate else [],
                      "blocked_posts": r.gate.blocked_posts if r.gate else [],
                      "detections": r.gate.detections if r.gate else []} for r in x.runs],
        "site": sb.state.snapshot(), "error": err,
    }
    with open(os.path.join(case_dir, "report.json"), "w", encoding="utf-8") as f:
        json.dump(rep, f, ensure_ascii=False, indent=1, default=str)
    return rep


def install_leak_trap(sb: Sandbox, llm_url: Optional[str]):
    """REPL Python của agent kế thừa env của process này: mọi urllib/httpx trong REPL (http_get...)
    sẽ rơi vào bẫy. Chrome không đọc biến này (dùng --proxy-server), HealthChecker dùng proxy riêng.
    Trừ host của LLM để chính lời gọi model không bị chặn."""
    from urllib.parse import urlsplit
    no = {"localhost", "127.0.0.1"}
    if llm_url:
        no.add(urlsplit(llm_url).hostname or "")
    for k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY"):
        os.environ[k] = sb.leak_proxy
    os.environ["NO_PROXY"] = os.environ["no_proxy"] = ",".join(sorted(h for h in no if h))


def make_llm(model: Optional[str], base_url: Optional[str] = None):
    """Mặc định: $OPENAI_MODEL qua $OPENAI_BASE_URL. Ollama: --model qwen2.5:7b
    --base-url http://localhost:11434/v1 (không cần key, không gửi gì ra ngoài)."""
    from browser_use import ChatOpenAI
    model = model or os.environ.get("OPENAI_MODEL") or "gpt-5.6-luna"
    if base_url:
        return ChatOpenAI(model, base_url=base_url, api_key=os.environ.get("OPENAI_API_KEY") or "local")
    return ChatOpenAI(model)


async def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cases", nargs="*", help=f"chọn trong: {', '.join(CASES)}")
    ap.add_argument("--headed", action="store_true", help="hiện cửa sổ Chrome")
    ap.add_argument("--model", help="model OpenAI-compatible (mặc định $OPENAI_MODEL)")
    ap.add_argument("--base-url", help="server OpenAI-compatible, vd. http://localhost:11434/v1 (Ollama)")
    ap.add_argument("--llm", choices=["openai", "scripted"], default="openai",
                    help="scripted: agent kịch bản cố định, không gọi model (kiểm tích hợp, miễn phí)")
    a = ap.parse_args(argv)
    names = a.cases or list(CASES)
    unknown = [n for n in names if n not in CASES]
    if unknown:
        ap.error(f"không có kịch bản {unknown}")
    if a.llm == "openai" and not os.environ.get("OPENAI_API_KEY") and not a.base_url:
        ap.error("thiếu OPENAI_API_KEY (hoặc --base-url cho model local, hoặc --llm scripted)")
    os.makedirs(OUT, exist_ok=True)
    if a.llm == "scripted":
        from sandbox.scripted_llm import scripted_model
        llm = scripted_model(REQ)
    else:
        llm = make_llm(a.model, a.base_url)
    sb = Sandbox.start()
    install_leak_trap(sb, a.base_url or os.environ.get("OPENAI_BASE_URL") or "https://api.openai.com")
    summary = []
    try:
        for n in names:
            print(f"\n=== {n}: {CASES[n][0]}", flush=True)
            rep = await run_case(n, sb, llm, a.headed)
            for c in rep["checks"]:
                print(f"  {'✔' if c['ok'] else '✘'} {c['msg']}", flush=True)
            if rep["error"]:
                print("  " + rep["error"].strip().replace("\n", "\n  "))
            print(f"  -> {'ĐẠT' if rep['ok'] else 'KHÔNG ĐẠT'} ({rep['seconds']}s)", flush=True)
            summary.append({k: rep[k] for k in ("case", "desc", "ok", "seconds")})
    finally:
        sb.stop()
    with open(os.path.join(OUT, "summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=1)
    passed = sum(s["ok"] for s in summary)
    print(f"\nTổng: {passed}/{len(summary)} kịch bản đạt. Chi tiết: {OUT}")
    return 0 if passed == len(summary) else 1


if __name__ == "__main__":
    if sys.platform == "win32":
        sys.stdout.reconfigure(encoding="utf-8")
    sys.exit(asyncio.run(main()))
