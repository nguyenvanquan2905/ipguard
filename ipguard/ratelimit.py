"""Giới hạn nhịp theo domain kiểu AIMD + giới hạn đồng thời."""
from __future__ import annotations

import asyncio
from collections import defaultdict
from typing import Awaitable, Callable

from .config import Policy


class DomainRateLimiter:
    """Token bucket mỗi domain; tốc độ tự điều chỉnh:
    OK -> tăng cộng dần; 429/chặn -> giảm một nửa (giống TCP congestion control).
    """

    def __init__(self, policy: Policy, clock: Callable[[], float],
                 sleep: Callable[[float], Awaitable[None]] = asyncio.sleep):
        self.p = policy
        self.clock = clock
        self.sleep = sleep
        self.rpm: dict[str, float] = defaultdict(lambda: policy.domain_rpm_start)
        self._next_slot: dict[str, float] = defaultdict(float)
        self._locks: dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)
        self.paused_until: dict[str, float] = defaultdict(float)

    def reserve(self, domain: str) -> float:
        """Giữ chỗ lượt tải trang kế tiếp, trả về số giây phải chờ (không ngủ)."""
        now = self.clock()
        start = max(now, self._next_slot[domain], self.paused_until[domain])
        self._next_slot[domain] = start + 60.0 / self.rpm[domain]
        return start - now

    async def acquire(self, domain: str) -> None:
        async with self._locks[domain]:
            wait = self.reserve(domain)
        if wait > 0:
            await self.sleep(wait)

    def paused_for(self, domain: str) -> float:
        return max(0.0, self.paused_until.get(domain, 0.0) - self.clock())

    def on_success(self, domain: str) -> None:
        self.rpm[domain] = min(self.p.domain_rpm_max, self.rpm[domain] + self.p.domain_rpm_step_up)

    def on_throttle(self, domain: str, pause_s: float = 0.0) -> None:
        self.rpm[domain] = max(self.p.domain_rpm_min, self.rpm[domain] * self.p.domain_rpm_backoff)
        if pause_s:
            self.paused_until[domain] = max(self.paused_until[domain], self.clock() + pause_s)

    # ---------- lưu trạng thái ----------
    def to_dict(self) -> dict:
        now = self.clock()
        return {"rpm": dict(self.rpm),
                "paused_until": {d: t for d, t in self.paused_until.items() if t > now},
                "next_slot": {d: t for d, t in self._next_slot.items() if t > now}}

    def from_dict(self, data: dict, live: bool = False) -> None:
        if live:
            self.rpm = defaultdict(lambda: self.p.domain_rpm_start)
            self.paused_until = defaultdict(float)
            self._next_slot = defaultdict(float)
            self._next_slot.update(data.get("next_slot", {}))
        self.rpm.update(data.get("rpm", {}))
        self.paused_until.update(data.get("paused_until", {}))


class DomainConcurrency:
    def __init__(self, policy: Policy):
        self._sems: dict[str, asyncio.Semaphore] = defaultdict(
            lambda: asyncio.Semaphore(policy.domain_max_concurrency))

    def get(self, domain: str) -> asyncio.Semaphore:
        return self._sems[domain]
