"""Điều phối: mỗi lượt đặt bàn = 1 phiên có danh tính cố định (IP + geo),
đi qua giới hạn nhịp, cầu dao domain, và quy tắc thử lại an toàn.

Chạy nhiều worker: truyền `store=RedisStore(...)`. Khi đó mọi thay đổi trạng thái đi qua
`sync()` (khóa toàn cụm, tải bản mới nhất, sửa, lưu). Tín hiệu quan sát được giữa hai
điểm đồng bộ được xếp hàng rồi áp vào ở điểm đồng bộ kế tiếp.
"""
from __future__ import annotations

import asyncio
import json
import random
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Mapping, Optional, Sequence

from .breaker import CLOSED, DomainBreaker
from .config import Policy
from .detector import classify
from .metrics import ALERT_KINDS, Metrics
from .models import DECISION, SEVERITY, Decision, Detection, Lease, Signal
from .pool import DomainBusy, IPPool, NoHealthyIP
from .ratelimit import DomainConcurrency, DomainRateLimiter
from .store import SharedStore, _LoopLock


class DomainUnavailable(Exception):
    """Domain đang bị ngắt (cầu dao mở), tạm dừng theo Retry-After, hoặc đã đủ phiên:
    không tự động hóa, chuyển deep link cho người dùng."""


class DryRunStop(Exception):
    """Chế độ chạy thử: flow vừa gọi mark_submitted() -> dừng, KHÔNG gửi form."""


class StopFlow(Exception):
    def __init__(self, decision: Decision, detection: Detection):
        super().__init__(f"{decision.value}: {detection.signal.value} {detection.reason}")
        self.decision, self.detection = decision, detection


@dataclass
class RunResult:
    outcome: str                 # booked | handoff_user | deeplink | failed
    detail: str = ""
    value: Any = None
    log: list = field(default_factory=list)


class GuardSession:
    def __init__(self, guard: "IPGuard", lease: Lease, engine: str, dry_run: bool = False):
        self.guard, self.lease, self.engine = guard, lease, engine
        self.dry_run = dry_run
        self.worst = Detection(Signal.OK)
        self.observed = 0
        self.submitted = False
        self.booked = False

    # ----- danh tính để cấu hình trình duyệt -----
    @property
    def proxy(self):
        return self.lease.proxy

    # ----- nhịp -----
    async def before_navigation(self) -> None:
        """Gọi trước mỗi lần tải trang (goto, submit, chuyển bước).
        Nếu domain vừa bị tạm dừng lâu (Retry-After), dừng ngay thay vì
        ngồi giữ IP + slot đồng thời hàng giờ."""
        g, dm = self.guard, self.lease.domain
        async with g.sync():
            pause = g.limiter.paused_for(dm)
            if pause > g.p.max_pause_wait_s:
                raise DomainUnavailable(f"{dm}: tạm dừng thêm {pause:.0f}s theo yêu cầu của site")
            wait = g.limiter.reserve(dm)
            g.pool.renew(self.lease)
        if wait > 0:
            await g.sleep(wait)
        await self.human_pause()

    async def human_pause(self) -> None:
        p = self.guard.p
        await self.guard.sleep(self.guard.rng.uniform(p.jitter_min_s, p.jitter_max_s))

    # ----- quan sát -----
    def observe(self, status: Optional[int], headers: Mapping[str, str] | None = None,
                body: str | None = None) -> Decision:
        det = classify(status, headers, body, now=self.guard.clock())
        return self.observe_detection(det)

    def observe_detection(self, det: Detection) -> Decision:
        self.observed += 1
        if SEVERITY[det.signal] > SEVERITY[self.worst.signal]:
            self.worst = det
        g, dm = self.guard, self.lease.domain
        g._apply("metric", dm, self.engine, det.signal.value)
        if det.signal == Signal.OK:
            g._apply("success", dm)
        elif det.signal == Signal.RATE_LIMITED:
            g._apply("throttle", dm, det.retry_after_s or 60)
            g._apply("probe_throttle", dm)
        elif det.signal == Signal.BLOCKED:
            g._apply("throttle", dm, 0)
            g._apply("block", dm, self.lease.proxy.id)
        elif det.signal == Signal.SERVER_ERROR:
            g._apply("throttle", dm, det.retry_after_s or 0)
        return DECISION[det.signal]

    def check(self, status: Optional[int], headers: Mapping[str, str] | None = None,
              body: str | None = None) -> None:
        """Như observe() nhưng ném StopFlow nếu không được tiếp tục."""
        dec = self.observe(status, headers, body)
        if dec != Decision.CONTINUE:
            raise StopFlow(dec, self.worst)

    def mark_submitted(self) -> None:
        """Gọi NGAY TRƯỚC khi bấm nút xác nhận đặt bàn. Sau mốc này không đổi IP/engine thử lại
        (tránh đặt trùng và tránh hành vi 'đổi IP để lách').
        Chế độ chạy thử: ném DryRunStop thay vì cho phép bấm gửi."""
        if self.dry_run:
            raise DryRunStop()
        self.submitted = True

    def mark_booked(self) -> None:
        self.booked = True


class IPGuard:
    def __init__(self, pool: IPPool, policy: Policy | None = None,
                 clock: Callable[[], float] = time.time,
                 sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
                 rng: random.Random | None = None,
                 store: SharedStore | None = None,
                 on_alert: Callable[[dict], Any] | None = None):
        self.p = policy or pool.p
        self.pool = pool
        self.clock, self.sleep = clock, sleep
        self.rng = rng or random.Random()
        self.limiter = DomainRateLimiter(self.p, clock, sleep)
        self.concurrency = DomainConcurrency(self.p)
        self.breaker = DomainBreaker(self.p, clock)
        self.metrics = Metrics(clock)
        self.store = store
        self.on_alert = on_alert
        self._ops: list = []
        self._local = _LoopLock()
        self.pool.on_event = self._event
        self.breaker.on_event = self._event
        # request_id -> (trạng thái, ts): "submitted_unknown" | "booked"
        self.requests: dict[str, tuple[str, float]] = {}

    # ---------- sự kiện & cảnh báo ----------
    def _event(self, kind: str, data: dict) -> None:
        ev = self.metrics.event(kind, data)
        if self.on_alert and kind in ALERT_KINDS:
            try:
                self.on_alert(ev)
            except Exception:
                pass

    # ---------- đồng bộ trạng thái dùng chung ----------
    def _apply(self, op: str, *args) -> None:
        if self.store is None:
            self._do(op, *args)
        else:
            self._ops.append((op, args))

    def _do(self, op: str, *a) -> None:
        if op == "success":
            self.limiter.on_success(a[0])
        elif op == "throttle":
            self.limiter.on_throttle(a[0], pause_s=a[1])
        elif op == "probe_throttle":
            self.breaker.record_throttle(a[0])
        elif op == "block":
            self.breaker.record_block(a[0], a[1])
        elif op == "metric":
            self.metrics.observe(*a)

    @asynccontextmanager
    async def sync(self):
        """Khối thao tác nguyên tử trên trạng thái (toàn cụm nếu có store)."""
        if self.store is None:
            yield
            return
        async with self._local.get():
            async with self.store.lock():
                raw = await self.store.load()
                if raw:
                    self._load(json.loads(raw), live=True)
                ops, self._ops = self._ops, []
                for op, args in ops:
                    self._do(op, *args)
                try:
                    yield
                finally:
                    await self.store.save(self.dump_state())

    # ---------- chống đặt trùng giữa các lần gọi run() ----------
    def _request_block(self, request_id: Optional[str]) -> Optional[RunResult]:
        if not request_id:
            return None
        now = self.clock()
        self.requests = {k: v for k, v in self.requests.items()
                         if now - v[1] <= self.p.request_memory_s}
        st = self.requests.get(request_id)
        if st is None:
            return None
        if st[0] == "booked":
            return RunResult("booked", "lượt này đã đặt thành công trước đó: không đặt lại")
        return RunResult("failed", "lượt này đã submit trước đó mà chưa rõ kết quả: kiểm tra "
                         "trạng thái, rồi gọi guard.resolve(request_id) nếu chắc chắn chưa đặt")

    def resolve(self, request_id: str) -> None:
        """Xác nhận (sau khi kiểm tra thủ công) rằng lượt chưa được đặt -> cho phép chạy lại.
        Với store dùng chung: gọi trong `async with guard.sync():`."""
        self.requests.pop(request_id, None)

    def _remember(self, request_id: Optional[str], r: RunResult, submitted: bool) -> None:
        if request_id:
            if r.outcome == "booked":
                self.requests[request_id] = ("booked", self.clock())
            elif submitted:
                self.requests[request_id] = ("submitted_unknown", self.clock())

    # ---------- phiên ----------
    async def _acquire_lease(self, domain, user_id, country, exclude, prefer, pin) -> Lease:
        deadline = self.clock() + self.p.max_pause_wait_s
        while True:
            async with self.sync():
                try:
                    return self.pool.acquire(domain, user_id, country, exclude=exclude,
                                             prefer=prefer, pin=pin)
                except DomainBusy:
                    pass
            if self.clock() >= deadline:
                raise DomainUnavailable(f"{domain}: đã đủ phiên song song trên toàn hệ thống")
            await self.sleep(self.p.busy_poll_s)

    @asynccontextmanager
    async def session(self, domain: str, user_id: str, country: Optional[str] = None,
                      engine: str = "patchright_chrome", exclude: Sequence[str] = (),
                      prefer: Optional[str] = None, pin: bool = False,
                      dry_run: bool = False):
        async with self.sync():
            is_probe = self.breaker.admit(domain)
            if is_probe is None:
                raise DomainUnavailable(f"{domain}: cầu dao domain đang mở")
            wait = self.limiter.paused_for(domain)
            if wait > self.p.max_pause_wait_s:
                if is_probe:
                    self.breaker.release_probe(domain)
                raise DomainUnavailable(f"{domain}: tạm dừng thêm {wait:.0f}s theo yêu cầu của site")
        settled = False
        try:
            async with self.concurrency.get(domain):
                lease = await self._acquire_lease(domain, user_id, country, exclude, prefer, pin)
                s = GuardSession(self, lease, engine, dry_run=dry_run)
                try:
                    yield s
                finally:
                    settled = True
                    async with self.sync():
                        if s.observed == 0:
                            self.pool.release_neutral(lease)
                            if is_probe:
                                self.breaker.release_probe(domain)
                        else:
                            self.pool.release(lease, s.worst, booked=s.booked)
                            if s.worst.signal == Signal.OK:
                                self.breaker.record_success(domain)
                            elif is_probe:
                                self.breaker.release_probe(domain)
        finally:
            # bị hủy khi đang chờ, NoHealthyIP, domain bận...: trả cờ thăm dò,
            # nếu không domain kẹt ở half-open.
            if not settled and is_probe:
                async with self.sync():
                    self.breaker.release_probe(domain)

    async def run(self, domain: str, user_id: str,
                  flow: Callable[[GuardSession], Awaitable[Any]],
                  country: Optional[str] = None,
                  engines: Sequence[str] = ("patchright_chrome", "cloakbrowser", "camoufox"),
                  request_id: Optional[str] = None,
                  dry_run: bool = False,
                  ) -> RunResult:
        """request_id (vd. id đơn đặt bàn của người dùng): nếu lần chạy trước đã submit mà
        chưa rõ kết quả, hoặc đã đặt thành công, thì KHÔNG chạy lại -> chống đặt trùng
        khi phía gọi tự retry."""
        async with self.sync():
            blocked = self._request_block(request_id)
        if blocked is not None:
            return blocked
        sessions: list[GuardSession] = []
        try:
            r = await self._run(domain, user_id, flow, country, engines, sessions, dry_run)
        except BaseException:
            if any(s.submitted for s in sessions) and request_id:
                async with self.sync():
                    self.requests[request_id] = ("submitted_unknown", self.clock())
            raise
        async with self.sync():
            self._remember(request_id, r, any(s.submitted for s in sessions))
            self.metrics.outcome(domain, r.outcome)
        return r

    async def _run(self, domain: str, user_id: str,
                   flow: Callable[[GuardSession], Awaitable[Any]],
                   country: Optional[str], engines: Sequence[str],
                   sessions: list, dry_run: bool = False) -> RunResult:
        """Chạy 1 lượt đặt bàn với các quy tắc:
        - SOFT_CHALLENGE  -> đổi engine, GIỮ IP (danh tính không đổi); chỉ khi CHƯA submit
        - CAPTCHA         -> giao người dùng
        - RATE_LIMITED    -> dừng, không đổi IP (đó là giới hạn của domain, phải tôn trọng)
        - BLOCKED / lỗi mạng trước khi submit -> đổi IP tối đa N lần; sau submit thì không
        - Lỗi bất kỳ sau submit -> 'failed', KHÔNG chạy lại flow (tránh đặt trùng)
        """
        log: list = []
        exclude: list[str] = []
        engine_i, ip_switches, prefer, pin = 0, 0, None, False
        while True:
            engine = engines[engine_i]
            try:
                async with self.session(domain, user_id, country, engine,
                                        exclude=exclude, prefer=prefer, pin=pin,
                                        dry_run=dry_run) as s:
                    sessions.append(s)
                    ip_id = s.proxy.id
                    value, det, dec = None, None, None
                    try:
                        value = await flow(s)
                    except StopFlow as e:
                        det, dec = e.detection, e.decision
                    except DryRunStop:
                        log.append((engine, ip_id, s.worst.signal.value, "dry_run"))
                        return RunResult("dry_run", "chạy thử: dừng ngay trước khi gửi form, "
                                         "không có gì được gửi đi", log=log)
                    except DomainUnavailable:
                        raise                           # dừng trước khi tải trang -> deep link
                    except Exception as e:
                        if not (s.submitted or s.booked):
                            raise                       # lỗi code trước submit: để lộ ra
                        log.append((engine, ip_id, "exception", repr(e)[:120]))
                        if s.booked:
                            return RunResult("booked", f"đã đặt, lỗi sau đó: {e!r}", log=log)
                        return RunResult("failed", "lỗi sau khi submit: kiểm tra trạng thái "
                                         "đặt bàn, KHÔNG gửi lại tự động", log=log)

                    if s.booked:                        # đã đặt xong thì không bao giờ chạy lại
                        log.append((engine, ip_id, "ok" if det is None else det.signal.value,
                                    "" if det is None else det.reason))
                        return RunResult("booked", "" if det is None else
                                         f"cảnh báo sau khi đặt: {det.signal.value}",
                                         value=value, log=log)
                    if det is None:
                        if s.worst.signal == Signal.OK:
                            log.append((engine, ip_id, "ok", ""))
                            return RunResult("failed", "flow kết thúc nhưng chưa đặt được",
                                             value=value, log=log)
                        # flow dùng observe()/attach() nhưng quên kiểm tra -> xử lý như StopFlow
                        det = s.worst
                        dec = DECISION[det.signal]
                    log.append((engine, ip_id, det.signal.value, det.reason))
                    sig, submitted = det.signal, s.submitted
            except DomainUnavailable as e:
                return RunResult("deeplink", str(e), log=log)
            except NoHealthyIP as e:
                return RunResult("deeplink", str(e), log=log)

            if submitted:
                if dec == Decision.HANDOFF_USER:
                    return RunResult("handoff_user", "CAPTCHA sau khi submit: người dùng xử lý "
                                     "và kiểm tra trạng thái đặt bàn", log=log)
                return RunResult("failed", "lỗi sau khi submit: kiểm tra trạng thái đặt bàn, "
                                 "KHÔNG gửi lại tự động", log=log)
            if dec == Decision.ESCALATE_BODY and engine_i + 1 < len(engines):
                engine_i += 1
                prefer, pin = ip_id, True
                continue
            if dec == Decision.HANDOFF_USER:
                return RunResult("handoff_user", "cần người dùng giải CAPTCHA", log=log)
            if (sig in (Signal.BLOCKED, Signal.NETWORK_ERROR)
                    and ip_switches < self.p.max_ip_switches_pre_submit
                    and self.breaker.state(domain) == CLOSED):
                ip_switches += 1
                exclude.append(ip_id)
                prefer, pin = None, False
                continue
            return RunResult("deeplink", f"{sig.value}: dừng tự động, chuyển người dùng", log=log)

    # ---------- báo cáo ----------
    def report(self) -> dict:
        """Ảnh chụp tình trạng. Với store dùng chung: gọi trong `async with guard.sync():`."""
        domains = set(self.limiter.rpm) | set(self.breaker._opened_at) | \
            {dm for (_, dm) in self.pool.d} | {k.split("|", 1)[0] for k in self.metrics.outcomes}
        dom = {}
        stats = self.metrics.by_domain()
        for dm in sorted(domains):
            dom[dm] = {"breaker": self.breaker.state(dm),
                       "rpm": round(self.limiter.rpm[dm], 1),
                       "paused_s": round(self.limiter.paused_for(dm)),
                       "active_sessions": self.pool.domain_active(dm),
                       **stats.get(dm, {})}
        return {"at": self.clock(), "since": self.metrics.since, "ips": self.pool.stats(),
                "domains": dom, "events": list(self.metrics.events[-50:]),
                "pending_requests": sorted(k for k, v in self.requests.items()
                                           if v[0] == "submitted_unknown")}

    # ---------- lưu trạng thái ----------
    def dump_state(self) -> str:
        return json.dumps({"pool": self.pool.to_dict(), "breaker": self.breaker.to_dict(),
                           "limiter": self.limiter.to_dict(), "metrics": self.metrics.to_dict(),
                           "requests": {k: list(v) for k, v in self.requests.items()}})

    def _load(self, data: dict, live: bool) -> None:
        if "pool" not in data:              # file cũ chỉ có pool.dump_state()
            self.pool.from_dict(data, live=live)
            return
        self.pool.from_dict(data["pool"], live=live)
        self.breaker.from_dict(data.get("breaker", {}), live=live)
        self.limiter.from_dict(data.get("limiter", {}), live=live)
        self.metrics.from_dict(data.get("metrics", {}), live=live)
        if live:
            self.requests = {}
        for k, v in data.get("requests", {}).items():
            self.requests[k] = (v[0], v[1])

    def load_state(self, raw: str) -> None:
        self._load(json.loads(raw), live=False)
