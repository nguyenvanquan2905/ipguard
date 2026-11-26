"""Nối IPGuard vào agent browser-use 1.0 (agent LLM tự viết Python điều khiển Chrome qua CDP).

browser-use 1.0 không còn nhận proxy/timezone/locale cho trình duyệt local, và agent có toàn quyền
điều khiển trang. Vì vậy ipguard **tự mở Chrome** theo danh tính của lease rồi đứng cạnh agent
bằng một kết nối CDP riêng ("guard sidecar"):

    Chrome (proxy của lease, profile theo user/domain, --lang)  <── CDP ──  CDPGuard (ipguard)
          ^                                                             │ timezone/locale override
          └──────────── CDP ── browser-use Agent (LLM)                  │ Fetch: giữ nhịp mọi lượt tải
                                                                        │       trang + CHẶN POST khi
                                                                        │       chưa mark_submitted()
                                                                        └ Network: phân loại response

Các bất biến ipguard giữ được dù agent làm gì trong trình duyệt:
- mọi lượt tải trang (document) của MỌI tab đều đi qua `s.before_navigation()` (nhịp + tạm dừng);
- mọi response document của main frame đều được `classify()`; tín hiệu xấu -> hủy agent -> StopFlow;
- không POST document nào lọt ra trước `s.mark_submitted()`. Chỉ tool `submit_booking` mở cổng,
  và mở đúng 1 lần (chế độ chạy thử thì không mở);
- timezone + ngôn ngữ khớp IP được kiểm tra trước khi tải trang đầu tiên.

Giới hạn: REPL Python của agent chạy trên máy, nên request agent tự gửi bằng Python (urllib...)
KHÔNG đi qua proxy. Trong sandbox các host *.sandbox.test không phân giải được nếu không qua proxy,
nên kiểu rò rỉ này sẽ lộ ra thành lỗi. Proxy có user:pass thì chưa hỗ trợ (cần proxy whitelist IP).
"""
from __future__ import annotations

import asyncio
import itertools
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Optional
from urllib.parse import urlsplit

from .adapters import GeoMismatch, Issues, _safe, check_issues, geo_of, is_direct, same_timezone
from .detector import classify
from .guard import DomainUnavailable, DryRunStop, GuardSession
from .models import Decision, Detection, Signal

ENGINES = ("browser_use_chrome", "browser_use_chromium")


# ======================================================================
# CDP tối giản (websockets đi kèm browser-use)
# ======================================================================
class CDPError(RuntimeError):
    pass


class CDP:
    def __init__(self, ws):
        self.ws = ws
        self._ids = itertools.count(1)
        self._wait: dict[int, asyncio.Future] = {}
        self.handlers: dict[str, list[Callable[[dict, Optional[str]], Any]]] = {}
        self._reader = asyncio.ensure_future(self._read())

    @classmethod
    async def connect(cls, ws_url: str) -> "CDP":
        from websockets.asyncio.client import connect
        return cls(await connect(ws_url, max_size=None, ping_interval=None))

    def on(self, method: str, fn) -> None:
        self.handlers.setdefault(method, []).append(fn)

    async def send(self, method: str, session: Optional[str] = None, **params) -> dict:
        i = next(self._ids)
        fut = asyncio.get_running_loop().create_future()
        self._wait[i] = fut
        msg = {"id": i, "method": method, "params": params}
        if session:
            msg["sessionId"] = session
        await self.ws.send(json.dumps(msg))
        return await asyncio.wait_for(fut, 30)

    async def _read(self):
        try:
            async for raw in self.ws:
                m = json.loads(raw)
                if "id" in m:
                    fut = self._wait.pop(m["id"], None)
                    if fut and not fut.done():
                        if "error" in m:
                            fut.set_exception(CDPError(f"{m['error'].get('message')}"))
                        else:
                            fut.set_result(m.get("result", {}))
                else:
                    for fn in self.handlers.get(m.get("method", ""), []):
                        try:
                            r = fn(m.get("params", {}), m.get("sessionId"))
                            if asyncio.iscoroutine(r):
                                asyncio.ensure_future(r)
                        except Exception:
                            pass
        except Exception:
            pass
        finally:
            for fut in self._wait.values():
                if not fut.done():
                    fut.set_exception(CDPError("CDP đóng"))

    async def close(self):
        self._reader.cancel()
        try:
            await self.ws.close()
        except Exception:
            pass


# ======================================================================
# Guard sidecar
# ======================================================================
@dataclass
class GateLog:
    """Những gì sidecar thấy, để test/kiểm toán."""
    navigations: list = field(default_factory=list)   # (ts, method, url)
    blocked_posts: list = field(default_factory=list)  # POST bị chặn vì chưa mark_submitted()
    detections: list = field(default_factory=list)    # (url, status, signal, reason)
    fatal: Optional[BaseException] = None              # DomainUnavailable... trong lúc giữ nhịp


class CDPGuard:
    def __init__(self, cdp: CDP, s: GuardSession, issues: Issues,
                 on_bad: Callable[[], None] = lambda: None):
        self.cdp, self.s, self.issues, self.on_bad = cdp, s, issues, on_bad
        self.tz, self.locale = geo_of(s.proxy)
        lang = self.locale.split("-")[0]
        self.accept_language = f"{self.locale},{lang};q=0.9"
        self.log = GateLog()
        self.pages: dict[str, str] = {}               # sessionId -> targetId (= main frame id)
        self.last_doc: dict[str, tuple[float, str]] = {}  # sessionId -> (ts, url) document gần nhất
        self._resp: dict[tuple[str, str], tuple[int, dict, str]] = {}
        self._doc_done: dict[str, asyncio.Event] = {}
        self._post_budget = 0                         # số POST được phép (submit_booking mở 1)
        self._attached: set[str] = set()
        self._ignore: set = set()                     # networkId của POST do cổng tự trả 204

    # ---------- khởi động ----------
    async def start(self):
        c = self.cdp
        c.on("Target.attachedToTarget", self._on_attached)
        c.on("Fetch.requestPaused", self._on_paused)
        c.on("Network.responseReceived", self._on_response)
        c.on("Network.loadingFinished", self._on_finished)
        c.on("Network.loadingFailed", self._on_failed)
        self.ua = await self._user_agent()
        await c.send("Target.setDiscoverTargets", discover=True)
        await c.send("Target.setAutoAttach", autoAttach=True, waitForDebuggerOnStart=True,
                     flatten=True)
        for t in (await c.send("Target.getTargets"))["targetInfos"]:
            if t["type"] == "page" and t["targetId"] not in self._attached:
                try:
                    await c.send("Target.attachToTarget", targetId=t["targetId"], flatten=True)
                except CDPError:
                    pass
        for _ in range(50):                           # chờ tab đầu tiên được thiết lập xong
            if self.pages:
                break
            await asyncio.sleep(0.05)

    async def _on_attached(self, p: dict, _):
        sid, info = p["sessionId"], p["targetInfo"]
        c = self.cdp
        try:
            if info["type"] == "page" and info["targetId"] not in self._attached:
                self._attached.add(info["targetId"])
                await c.send("Emulation.setTimezoneOverride", sid, timezoneId=self.tz)
                await c.send("Emulation.setLocaleOverride", sid, locale=self.locale)
                await c.send("Network.enable", sid)
                await c.send("Network.setUserAgentOverride", sid, **self.ua)
                await c.send("Network.setExtraHTTPHeaders", sid,
                             headers={"Accept-Language": self.accept_language})
                await c.send("Fetch.enable", sid, patterns=[
                    {"urlPattern": "*", "resourceType": "Document", "requestStage": "Request"}])
                self.pages[sid] = info["targetId"]
        except CDPError:
            pass
        finally:
            if p.get("waitingForDebugger"):
                try:
                    await c.send("Runtime.runIfWaitingForDebugger", sid)
                except CDPError:
                    pass

    async def _user_agent(self) -> dict:
        """Chrome headless tự xưng 'HeadlessChrome' trong UA và Sec-CH-UA: dấu hiệu bot lộ nhất.
        Thay bằng UA/brand của Chrome thường, cùng phiên bản, cùng ngôn ngữ với IP."""
        v = await self.cdp.send("Browser.getVersion")
        ua = v["userAgent"].replace("HeadlessChrome", "Chrome")
        full = v["product"].split("/")[-1]
        major = full.split(".")[0]
        brand = "Google Chrome" if "browser_use_chrome" == self.s.engine else "Chromium"
        platform = {"win32": "Windows", "darwin": "macOS"}.get(__import__("sys").platform, "Linux")
        return {"userAgent": ua, "acceptLanguage": self.accept_language,
                "platform": {"Windows": "Win32", "macOS": "MacIntel"}.get(platform, "Linux x86_64"),
                "userAgentMetadata": {
                    "brands": [{"brand": brand, "version": major},
                               {"brand": "Chromium", "version": major},
                               {"brand": "Not_A Brand", "version": "24"}],
                    "fullVersionList": [{"brand": brand, "version": full},
                                        {"brand": "Chromium", "version": full},
                                        {"brand": "Not_A Brand", "version": "24.0.0.0"}],
                    "fullVersion": full, "platform": platform,
                    "platformVersion": "10.0.0" if platform == "Windows" else "",
                    "architecture": "x86", "model": "", "mobile": False, "bitness": "64"}}

    # ---------- cổng: nhịp + chặn POST ----------
    async def _on_paused(self, p: dict, sid: Optional[str]):
        rid, req = p["requestId"], p["request"]
        url, method = req["url"], req.get("method", "GET").upper()
        try:
            if not url.startswith(("http://", "https://")):
                return await self.cdp.send("Fetch.continueRequest", sid, requestId=rid)
            if method != "GET" and (self.s.dry_run or not self.s.submitted or self._post_budget <= 0):
                # 204 cho điều hướng = "ở yên": trình duyệt giữ nguyên trang + form đã điền,
                # site không nhận được gì. (failRequest sẽ thay tab bằng trang lỗi.)
                self.log.blocked_posts.append((time.time(), method, url))
                self._ignore.add(p.get("networkId"))
                return await self.cdp.send("Fetch.fulfillRequest", sid, requestId=rid,
                                           responseCode=204, responseHeaders=[], body="")
            if method != "GET":
                self._post_budget -= 1
            try:
                await self.s.before_navigation()      # nhịp theo domain, dừng nếu site bắt chờ lâu
            except DomainUnavailable as e:
                self.log.fatal = e
                self.on_bad()
                return await self.cdp.send("Fetch.failRequest", sid, requestId=rid,
                                           errorReason="BlockedByClient")
            self.log.navigations.append((time.time(), method, url))
            await self.cdp.send("Fetch.continueRequest", sid, requestId=rid)
        except CDPError:
            pass

    def allow_one_post(self):
        self._post_budget = 1

    # ---------- phân loại response ----------
    def _main(self, sid, frame_id) -> bool:
        return sid in self.pages and frame_id == self.pages[sid]

    def _on_response(self, p: dict, sid):
        if (p.get("type") != "Document" or not self._main(sid, p.get("frameId"))
                or p["requestId"] in self._ignore):
            return
        r = p["response"]
        self._resp[(sid, p["requestId"])] = (r["status"], r.get("headers", {}), r["url"])
        self.last_doc[sid] = (time.time(), r["url"])

    def _on_finished(self, p: dict, sid):
        key = (sid, p["requestId"])
        if key not in self._resp:
            return
        t = asyncio.ensure_future(self._classify(key))
        self.issues.pending.add(t)
        t.add_done_callback(self.issues.pending.discard)

    def _on_failed(self, p: dict, sid):
        if p.get("type") != "Document" or sid not in self.pages:
            return
        err = p.get("errorText", "")
        if p.get("blockedReason") or "BLOCKED_BY_CLIENT" in err or p.get("canceled") \
                or "ERR_ABORTED" in err:
            return                                    # do chính cổng chặn / điều hướng bị thay thế
        det = Detection(Signal.NETWORK_ERROR, reason=err[:120])
        self._record(det, "?", None)
        self._signal_done(sid)

    async def _classify(self, key):
        sid, rid = key
        status, headers, url = self._resp.pop(key)
        body = ""
        try:
            res = await self.cdp.send("Network.getResponseBody", sid, requestId=rid)
            body = res.get("body", "")[:60_000] if not res.get("base64Encoded") else ""
        except CDPError:
            pass
        det = classify(status, headers, body, now=self.s.guard.clock())
        self._record(det, url, status)
        self._signal_done(sid)

    def _record(self, det: Detection, url: str, status):
        self.log.detections.append((url, status, det.signal.value, det.reason))
        dec = self.s.observe_detection(det)
        if dec != Decision.CONTINUE:
            self.issues.append((dec, det))
            self.on_bad()

    def _signal_done(self, sid):
        ev = self._doc_done.get(sid)
        if ev:
            ev.set()

    # ---------- tiện ích cho flow / tool ----------
    def current_session(self) -> Optional[str]:
        """Tab vừa tải document gần nhất (tab agent đang làm việc)."""
        if self.last_doc:
            return max(self.last_doc, key=lambda k: self.last_doc[k][0])
        return next(iter(self.pages), None)

    async def evaluate(self, expr: str, sid: Optional[str] = None):
        sid = sid or self.current_session()
        r = await self.cdp.send("Runtime.evaluate", sid, expression=expr, returnByValue=True,
                                awaitPromise=True)
        if "exceptionDetails" in r:
            raise CDPError(str(r["exceptionDetails"].get("text")))
        return r.get("result", {}).get("value")

    async def wait_document(self, sid: str, action: Callable[[], Awaitable[Any]],
                            timeout: float = 30.0) -> bool:
        """Chạy action (điều hướng) rồi chờ document mới của tab đó tải xong + được phân loại."""
        ev = asyncio.Event()
        self._doc_done[sid] = ev
        try:
            await action()
            await asyncio.wait_for(ev.wait(), timeout)
            await self.issues.settle()
            return True
        except asyncio.TimeoutError:
            return False
        finally:
            self._doc_done.pop(sid, None)

    async def navigate(self, url: str, sid: Optional[str] = None, timeout: float = 30.0) -> bool:
        sid = sid or self.current_session()
        return await self.wait_document(
            sid, lambda: self.cdp.send("Page.navigate", sid, url=url), timeout)

    async def verify_geo(self) -> list[str]:
        sid = next(iter(self.pages))
        got_tz, got_lang = await self.evaluate(
            "[Intl.DateTimeFormat().resolvedOptions().timeZone, navigator.language]", sid)
        problems = []
        if not same_timezone(str(got_tz), self.tz):
            problems.append(f"timezone {got_tz} ≠ {self.tz}")
        if str(got_lang).split("-")[0].lower() != self.locale.split("-")[0].lower():
            problems.append(f"ngôn ngữ {got_lang} ≠ {self.locale}")
        return problems


# ======================================================================
# Mở Chrome theo danh tính của lease
# ======================================================================
def find_chrome(engine: str) -> str:
    from browser_use.browser import local
    if engine == "browser_use_chromium":
        found = [p for p in local.playwright_chromium() if os.path.isfile(p)]
        if found:
            return found[0]
        raise FileNotFoundError("chưa có Chromium của Playwright: `browser-use install`")
    return local.find_binary(chrome_only=True)


def chrome_launch_args(s: GuardSession, profile_dir: str, headless: bool) -> list[str]:
    tz, loc = geo_of(s.proxy)
    args = [f"--user-data-dir={profile_dir}", "--remote-debugging-port=0", "--no-first-run",
            "--no-default-browser-check", "--disable-background-timer-throttling",
            "--disable-renderer-backgrounding", "--disable-backgrounding-occluded-windows",
            f"--lang={loc}", f"--accept-lang={loc},{loc.split('-')[0]}",
            # site nhà hàng nhỏ thường chỉ có http: không để Chrome tự nâng cấp/thử QUIC ra ngoài proxy
            "--disable-features=HttpsUpgrades,HttpsFirstBalancedModeAutoEnable,"
            "OptimizationHints,OptimizationGuideModelDownloading,MediaRouter,Translate,"
            "AutofillServerCommunication,CertificateTransparencyComponentUpdater",
            "--disable-quic", "--disable-sync", "--no-pings", "--disable-background-networking",
            "--disable-component-update", "--disable-domain-reliability",
            "--disable-client-side-phishing-detection", "--safebrowsing-disable-auto-update",
            "--disable-default-apps", "--metrics-recording-only", "--disable-field-trial-config",
            "--no-service-autorun", "--password-store=basic",
            "--disable-blink-features=AutomationControlled"]   # headless bật navigator.webdriver
    if not is_direct(s.proxy):
        u = urlsplit(s.proxy.url)
        if u.username:
            raise NotImplementedError("proxy có user:pass: dùng proxy whitelist IP cho browser-use")
        args.append(f"--proxy-server={u.scheme}://{u.hostname}:{u.port}")
        args.append("--proxy-bypass-list=<-loopback>")  # kể cả localhost cũng phải qua proxy
    if headless:
        args += ["--headless=new", "--window-size=1440,900"]
    return [*args, "about:blank"]


@asynccontextmanager
async def launch_chrome(s: GuardSession, profile_root: str, headless: bool):
    profile_dir = os.path.abspath(os.path.join(profile_root, _safe(s.lease.user_id),
                                               _safe(s.lease.domain), _safe(s.engine)))
    os.makedirs(profile_dir, exist_ok=True)
    port_file = os.path.join(profile_dir, "DevToolsActivePort")
    if os.path.exists(port_file):
        os.remove(port_file)
    exe = find_chrome(s.engine)
    log = tempfile.TemporaryFile()
    proc = subprocess.Popen([exe, *chrome_launch_args(s, profile_dir, headless)],
                            stdout=log, stderr=log)
    try:
        ws = None
        for _ in range(200):
            if proc.poll() is not None:
                raise RuntimeError(f"Chrome thoát ngay (mã {proc.returncode})")
            try:
                lines = open(port_file, encoding="utf-8").read().splitlines()
                if len(lines) >= 2:
                    ws = f"ws://127.0.0.1:{lines[0].strip()}{lines[1].strip()}"
                    break
            except OSError:
                pass
            await asyncio.sleep(0.05)
        if not ws:
            raise RuntimeError("Chrome không mở cổng DevTools")
        yield ws
    finally:
        proc.terminate()
        try:
            proc.wait(10)
        except subprocess.TimeoutExpired:
            proc.kill()
        log.close()


# ======================================================================
# Flow ipguard chạy bằng agent browser-use
# ======================================================================
_DEFAULT_SUCCESS = re.compile(r"đặt bàn thành công|booking confirmed|reservation confirmed", re.I)

SUBMIT_JS = r"""
(() => {
  const vis = e => !!(e.offsetWidth || e.offsetHeight || e.getClientRects().length);
  const btns = [...document.querySelectorAll('form button, form input[type=submit]')]
      .filter(b => vis(b) && (b.type || 'submit') === 'submit');
  if (!btns.length) return {ok:false, why:'không thấy nút gửi trong form'};
  const b = btns[btns.length - 1], f = b.form;
  const empty = [...f.querySelectorAll('input:not([type=hidden]), select, textarea')]
      .filter(e => vis(e) && !e.value && e.name !== 'note').map(e => e.labels?.[0]?.innerText || e.name);
  if (empty.length) return {ok:false, why:'còn trống: ' + empty.join(', ')};
  setTimeout(() => f.requestSubmit(b), 0);
  return {ok:true, button:(b.innerText || b.value || '').trim(), method:(f.method||'get')};
})()
"""


@dataclass
class AgentRun:
    """Kết quả phụ của 1 phiên (cho test/kiểm toán)."""
    engine: str = ""
    proxy_id: str = ""
    gate: Optional[GateLog] = None
    agent_status: str = ""
    agent_error: str = ""
    final: Any = None
    steps: int = 0


def browser_use_flow(task: str, start_url: str, *, llm: Any,
                     success: Callable[[str], Optional[str]] | None = None,
                     profile_root: str = "profiles", headless: bool = True,
                     max_steps: int = 25, timeout_s: float = 300,
                     runs: Optional[list] = None, agent_kwargs: Optional[dict] = None):
    """Tạo `flow(s)` cho `AntiBan.book()`: ipguard mở trang đặt bàn, agent LLM điền form,
    chỉ tool `submit_booking` được gửi form (1 lần), kết quả do trang quyết định chứ không do LLM.

    success(text) -> mã đặt bàn hoặc None: đọc trang sau khi gửi để biết đã đặt chưa.
    runs: list nhận AgentRun của từng phiên (mỗi lần ipguard đổi IP/engine là 1 phiên)."""
    success = success or (lambda text: "ok" if _DEFAULT_SUCCESS.search(text) else None)

    async def flow(s: GuardSession):
        from browser_use import Agent, Browser, Tools

        rec = AgentRun(engine=s.engine, proxy_id=s.proxy.id)
        if runs is not None:
            runs.append(rec)
        issues = Issues()
        agent_task: Optional[asyncio.Task] = None
        stop_reason: dict = {}

        def on_bad():
            if agent_task and not agent_task.done():
                agent_task.cancel()

        async with launch_chrome(s, profile_root, headless) as ws:
            cdp = await CDP.connect(ws)
            try:
                g = CDPGuard(cdp, s, issues, on_bad)
                rec.gate = g.log
                await g.start()
                problems = await g.verify_geo()
                if problems:
                    raise GeoMismatch("; ".join(problems))

                # 1) ipguard tự mở trang đầu (chưa tốn LLM nếu đã bị chặn ngay)
                ok = await g.navigate(start_url)
                if g.log.fatal:
                    raise g.log.fatal
                await check_issues(issues)
                if not ok:
                    s.observe_detection(Detection(Signal.NETWORK_ERROR, reason="timeout tải trang"))
                    await check_issues([(Decision.ABORT, s.worst)])

                # 2) tool duy nhất được gửi form
                tools = Tools()

                @tools.action("Gửi form đặt bàn (bấm nút xác nhận cuối cùng). Chỉ gọi MỘT lần, "
                              "khi mọi trường bắt buộc đã điền đúng. Đừng tự bấm nút xác nhận.")
                async def submit_booking() -> str:
                    if s.submitted:
                        return "Đã gửi rồi: KHÔNG gửi lại. Hãy kết thúc (finish)."
                    sid = g.current_session()
                    try:
                        s.mark_submitted()               # chạy thử: ném DryRunStop
                    except DryRunStop:
                        stop_reason["dry_run"] = True
                        on_bad()
                        return "Chạy thử: dừng trước khi gửi."
                    g.allow_one_post()
                    holder: dict = {}

                    async def click():
                        holder["r"] = await g.evaluate(SUBMIT_JS, sid)
                        if not holder["r"].get("ok"):
                            raise ValueError(holder["r"].get("why"))
                    try:
                        await g.wait_document(sid, click, timeout=30)
                    except ValueError as e:              # chưa gửi được gì: gỡ cờ submit
                        s.submitted = False
                        g._post_budget = 0
                        return f"Chưa gửi: {e}. Điền nốt rồi gọi lại submit_booking."
                    if issues:
                        return "Đã gửi, site phản hồi bất thường. Dừng."
                    text = await g.evaluate("document.body.innerText", sid) or ""
                    ref = success(text)
                    if ref:
                        s.mark_booked()
                        stop_reason["ref"] = ref
                        return f"Đặt bàn thành công, mã {ref}. Hãy kết thúc (finish)."
                    return ("Đã gửi nhưng chưa thấy xác nhận. KHÔNG gửi lại; mô tả trang "
                            "hiện tại rồi kết thúc.\n" + text[:500])

                browser = Browser(cdp_url=ws, allowed_domains=[s.lease.domain, f"*.{s.lease.domain}"])
                agent = Agent(
                    task=task, llm=llm, browser=browser, tools=tools, judge=False,
                    extend_system_message=(
                        "Bạn đang chạy dưới ipguard. Trang đặt bàn ĐÃ mở sẵn ở tab hiện tại. "
                        "Không mở trang khác ngoài domain này, không tải lại trang liên tục, "
                        "không thử vượt CAPTCHA/chặn. KHÔNG dùng http_get() hay thư viện HTTP trong "
                        "Python: chúng đi thẳng từ máy chủ, bỏ qua IP của trình duyệt. Điền form như người thật; với bước trung gian "
                        "(nút Tiếp tục) thì bấm bình thường. Bấm nút xác nhận đặt bàn CUỐI CÙNG chỉ "
                        "bằng tool submit_booking, đúng 1 lần, rồi finish."),
                    **(agent_kwargs or {}))
                agent_task = asyncio.ensure_future(agent.run(max_steps=max_steps, timeout=timeout_s))
                try:
                    hist = await agent_task
                    rec.agent_status, rec.steps = hist.status, hist.steps
                    rec.agent_error = (hist.error or "")[:300]
                    rec.final = hist.final_result()
                    if hist.error:
                        rec.agent_status = "error"
                except asyncio.CancelledError:
                    if asyncio.current_task().cancelling():
                        raise                         # chính flow bị hủy từ bên ngoài
                    rec.agent_status = "stopped_by_guard"
                except Exception as e:
                    rec.agent_status, rec.agent_error = "error", repr(e)[:300]
                finally:
                    try:
                        await browser.stop()
                    except Exception:
                        pass

                if stop_reason.get("dry_run"):
                    raise DryRunStop()
                if g.log.fatal:
                    raise g.log.fatal
                await check_issues(issues)
                if s.booked:
                    return stop_reason.get("ref")
                if rec.agent_status == "error" and not s.submitted:
                    # lỗi agent/LLM trước khi gửi: không phải tín hiệu ban -> để lộ ra
                    raise RuntimeError(f"agent lỗi trước khi gửi form: {rec.agent_error}")
                return None
            finally:
                await cdp.close()

    return flow
