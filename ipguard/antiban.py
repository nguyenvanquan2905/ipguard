"""Một đầu vào cho cả cơ chế chống ban IP.

    ab = AntiBan.from_config("ipguard.toml")
    async with ab:
        r = await ab.book("nhahang.vn", user_id, flow, country="VN", request_id=order_id)

AntiBan gói: pool IP + nhịp + cầu dao + phân loại (IPGuard), kiểm tra proxy chủ động
(HealthChecker), lưu trạng thái (file cho 1 process, Redis cho nhiều worker), số liệu và
cảnh báo.
"""
from __future__ import annotations

import asyncio
import os
import re
import time
from dataclasses import fields
from typing import Any, Awaitable, Callable, Iterable, Optional, Sequence

from .config import Policy
from .guard import GuardSession, IPGuard, RunResult
from .health import DEFAULT_GEO_URL, Fetch, HealthChecker, HealthResult
from .models import ProxyEndpoint
from .pool import IPPool
from .store import RedisStore, SharedStore

DEFAULT_ENGINES = ("patchright_chrome", "cloakbrowser", "camoufox")


def _expand(value: str) -> str:
    def sub(m):
        name = m.group(1)
        if name not in os.environ:
            raise KeyError(f"thiếu biến môi trường {name} (dùng trong file cấu hình)")
        return os.environ[name]
    return re.sub(r"\$\{(\w+)\}", sub, value)


def load_config(path: str) -> dict:
    import tomllib
    with open(path, "rb") as f:
        return tomllib.load(f)


def policy_from(data: dict) -> Policy:
    names = {f.name for f in fields(Policy)}
    unknown = set(data) - names
    if unknown:
        raise ValueError(f"[policy] có khóa không tồn tại: {sorted(unknown)}")
    return Policy(**data)


class AntiBan:
    def __init__(self, proxies: Iterable[ProxyEndpoint], policy: Policy | None = None, *,
                 state_path: Optional[str] = None,
                 store: SharedStore | None = None,
                 engines: Sequence[str] = DEFAULT_ENGINES,
                 health_check: bool = True,
                 geo_url: str = DEFAULT_GEO_URL,
                 fetch: Optional[Fetch] = None,
                 on_alert: Callable[[dict], Any] | None = None,
                 dry_run: bool = False,
                 clock: Callable[[], float] = time.time,
                 sleep: Callable[[float], Awaitable[None]] = asyncio.sleep):
        if state_path and store is not None:
            raise ValueError("chọn một: state_path (1 process) hoặc store (nhiều worker)")
        self.policy = policy or Policy()
        self.pool = IPPool(proxies, self.policy, clock=clock)
        self.guard = IPGuard(self.pool, self.policy, clock=clock, sleep=sleep,
                             store=store, on_alert=on_alert)
        self.health = HealthChecker(self.guard, geo_url, fetch) if health_check else None
        self.engines = tuple(engines)
        self.state_path = state_path
        self.dry_run = dry_run
        if state_path and os.path.exists(state_path):
            with open(state_path, encoding="utf-8") as f:
                self.guard.load_state(f.read())

    # ---------- tạo từ file cấu hình ----------
    @classmethod
    def from_config(cls, path: str, **overrides) -> "AntiBan":
        cfg = load_config(path)
        proxies = []
        for p in cfg.get("proxy", []):
            proxies.append(ProxyEndpoint(
                id=p["id"], url=_expand(p["url"]), country=p["country"],
                kind=p.get("kind", "residential"), timezone=p.get("timezone"),
                locale=p.get("locale")))
        if not proxies:
            raise ValueError(f"{path}: chưa khai báo [[proxy]] nào")
        if len({p.id for p in proxies}) != len(proxies):
            raise ValueError(f"{path}: trùng id proxy")

        st = cfg.get("state", {})
        backend = st.get("backend", "file")
        kw: dict = {}
        if backend == "file":
            base = os.path.dirname(os.path.abspath(path))
            kw["state_path"] = os.path.join(base, st.get("path", "ipguard_state.json"))
        elif backend == "redis":
            kw["store"] = RedisStore.from_url(_expand(st["url"]), key=st.get("key", "ipguard"))
        elif backend != "memory":
            raise ValueError(f"[state] backend không hợp lệ: {backend}")

        h = cfg.get("health", {})
        kw["health_check"] = h.get("enabled", True)
        kw["geo_url"] = h.get("geo_url", DEFAULT_GEO_URL)
        if "engines" in cfg:
            kw["engines"] = cfg["engines"]
        kw.update(overrides)
        return cls(proxies, policy_from(cfg.get("policy", {})), **kw)

    # ---------- dùng ----------
    async def __aenter__(self) -> "AntiBan":
        return self

    async def __aexit__(self, *exc) -> None:
        self.save()

    async def book(self, domain: str, user_id: str,
                   flow: Callable[[GuardSession], Awaitable[Any]], *,
                   country: Optional[str] = None, request_id: Optional[str] = None,
                   engines: Optional[Sequence[str]] = None,
                   dry_run: Optional[bool] = None) -> RunResult:
        """Một lượt đặt bàn có bảo vệ. Kết quả: booked | handoff_user | deeplink | failed
        (| dry_run khi chạy thử: dừng ở mark_submitted(), không gửi form)."""
        if self.health:
            await self.health.check()             # chỉ kiểm tra IP đã quá hạn
        try:
            return await self.guard.run(domain, user_id, flow, country=country,
                                        engines=engines or self.engines, request_id=request_id,
                                        dry_run=self.dry_run if dry_run is None else dry_run)
        finally:
            self.save()

    async def check_proxies(self, force: bool = True) -> list[HealthResult]:
        if not self.health:
            return []
        res = await self.health.check(force=force)
        self.save()
        return res

    async def report(self) -> dict:
        async with self.guard.sync():
            return self.guard.report()

    async def resolve(self, request_id: str) -> None:
        """Đã kiểm tra và chắc chắn lượt `request_id` chưa được đặt -> cho phép chạy lại."""
        async with self.guard.sync():
            self.guard.resolve(request_id)
        self.save()

    async def reinstate(self, ip_id: str) -> None:
        async with self.guard.sync():
            self.pool.reinstate(ip_id)
        self.save()

    def save(self) -> None:
        if not self.state_path:
            return
        tmp = self.state_path + ".tmp"
        os.makedirs(os.path.dirname(os.path.abspath(self.state_path)), exist_ok=True)
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(self.guard.dump_state())
        os.replace(tmp, self.state_path)
