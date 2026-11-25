"""Cầu dao theo domain.

Nếu nhiều IP *khác nhau* bị chặn trên cùng một domain trong thời gian ngắn,
vấn đề không nằm ở IP mà ở chỗ domain đang chặn tự động hóa. Đổi IP tiếp
chỉ đốt thêm IP và làm domain siết chặt hơn -> ngắt, chuyển sang deep link.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Callable, Optional

from .config import Policy

CLOSED, OPEN, HALF_OPEN = "closed", "open", "half_open"


class DomainBreaker:
    def __init__(self, policy: Policy, clock: Callable[[], float]):
        self.p = policy
        self.clock = clock
        self._blocks: dict[str, dict[str, float]] = defaultdict(dict)  # domain -> ip_id -> ts
        self._opened_at: dict[str, float] = {}
        self._probe_inflight: dict[str, float] = {}    # domain -> lúc bắt đầu thăm dò
        self.on_event: Callable[[str, dict], None] = lambda kind, data: None

    def state(self, domain: str) -> str:
        opened = self._opened_at.get(domain)
        if opened is None:
            return CLOSED
        if self.clock() - opened < self.p.breaker_open_s:
            return OPEN
        return HALF_OPEN

    def _probe_busy(self, domain: str) -> bool:
        ts = self._probe_inflight.get(domain)
        if ts is None:
            return False
        if self.clock() - ts > self.p.lease_ttl_s:     # worker thăm dò đã chết
            self._probe_inflight.pop(domain, None)
            return False
        return True

    def admit(self, domain: str) -> Optional[bool]:
        """None = từ chối; True = được vào với tư cách phiên thăm dò; False = phiên thường."""
        st = self.state(domain)
        if st == CLOSED:
            return False
        if st == HALF_OPEN and not self._probe_busy(domain):
            self._probe_inflight[domain] = self.clock()   # chỉ 1 phiên thăm dò
            return True
        return None

    def allow(self, domain: str) -> bool:
        return self.admit(domain) is not None

    def _open(self, domain: str, why: str) -> None:
        self._opened_at[domain] = self.clock()
        self._probe_inflight.pop(domain, None)
        self.on_event("breaker_open", {"domain": domain, "why": why})

    def record_block(self, domain: str, ip_id: str) -> None:
        now = self.clock()
        if self.state(domain) == HALF_OPEN:        # thăm dò thất bại -> mở lại
            self._open(domain, "probe blocked")
            return
        if self.state(domain) == OPEN:
            return
        recent = {k: t for k, t in self._blocks[domain].items()
                  if now - t <= self.p.breaker_window_s}
        recent[ip_id] = now
        self._blocks[domain] = recent
        if len(recent) >= self.p.breaker_distinct_ips:
            self._open(domain, f"{len(recent)} IPs blocked")

    def record_throttle(self, domain: str) -> None:
        """429 trong lúc thăm dò cũng là thăm dò thất bại."""
        if self.state(domain) == HALF_OPEN:
            self._open(domain, "probe rate-limited")

    def record_success(self, domain: str) -> None:
        if self.state(domain) == HALF_OPEN:
            self._opened_at.pop(domain, None)
            self._blocks[domain].clear()
            self.on_event("breaker_closed", {"domain": domain})
        self._probe_inflight.pop(domain, None)

    def release_probe(self, domain: str) -> None:
        self._probe_inflight.pop(domain, None)

    # ---------- lưu trạng thái ----------
    def to_dict(self) -> dict:
        return {"opened_at": dict(self._opened_at),
                "blocks": {dm: dict(v) for dm, v in self._blocks.items() if v},
                "probes": dict(self._probe_inflight)}

    def from_dict(self, data: dict, live: bool = False) -> None:
        if live:
            self._opened_at, self._probe_inflight = {}, {}
            self._blocks = defaultdict(dict)
            self._probe_inflight.update(data.get("probes", {}))
        self._opened_at.update(data.get("opened_at", {}))
        for dm, v in data.get("blocks", {}).items():
            self._blocks[dm].update(v)
