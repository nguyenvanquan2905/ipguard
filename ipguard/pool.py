"""Pool IP cố định (sticky) với chấm điểm sức khỏe, cách ly và gắn khách quen."""
from __future__ import annotations

import json
import time
from collections import defaultdict
from dataclasses import asdict, fields
from typing import Callable, Iterable, Optional

from .config import Policy
from .models import (Detection, IPDomainState, IPGlobalState, Lease, ProxyEndpoint,
                     Signal)

_KIND_WEIGHT = {"isp": 1.0, "residential": 0.95, "mobile": 0.9, "datacenter": 0.5}
_SCORE_DELTA = {
    Signal.OK: +0.05,
    Signal.SOFT_CHALLENGE: -0.08,
    Signal.CAPTCHA: -0.15,
    Signal.RATE_LIMITED: -0.2,
    Signal.BLOCKED: -0.35,
    Signal.NETWORK_ERROR: -0.05,
    Signal.SERVER_ERROR: 0.0,          # lỗi của website, không phải của IP
}


class NoHealthyIP(Exception):
    pass


class DomainBusy(Exception):
    """Domain đã đủ số phiên song song trên toàn cụm worker."""


def _from_dict(cls, data: dict):
    """Tạo dataclass từ dict, bỏ qua khóa lạ (state cũ/mới khác phiên bản)."""
    names = {f.name for f in fields(cls)}
    return cls(**{k: v for k, v in data.items() if k in names})


class IPPool:
    def __init__(self, proxies: Iterable[ProxyEndpoint], policy: Policy | None = None,
                 clock: Callable[[], float] = time.time):
        self.p = policy or Policy()
        self.clock = clock
        self.proxies: dict[str, ProxyEndpoint] = {}
        self.g: dict[str, IPGlobalState] = {}
        self.d: dict[tuple[str, str], IPDomainState] = defaultdict(IPDomainState)
        self.affinity: dict[tuple[str, str], tuple[str, float]] = {}  # (user, domain) -> (ip, ts)
        self.leases: dict[str, list] = {}     # lease_id -> [ip, domain, expires_at]
        self.on_event: Callable[[str, dict], None] = lambda kind, data: None
        for px in proxies:
            self.add(px)

    # ---------- quản lý ----------
    def _fresh(self, px: ProxyEndpoint) -> IPGlobalState:
        return IPGlobalState(score_at=self.clock(), first_seen=px.added_at)

    def add(self, px: ProxyEndpoint) -> None:
        if not px.added_at:
            px.added_at = self.clock()
        self.proxies[px.id] = px
        self.g.setdefault(px.id, self._fresh(px))

    def reinstate(self, ip_id: str) -> None:
        """Đưa lại IP đã bị loại (vd. nhà cung cấp đã cấp IP mới cho cùng endpoint).
        Chạy lại từ hạn mức warm-up vì với website đây là một IP lạ."""
        now = self.clock()
        self.g[ip_id] = IPGlobalState(score_at=now, first_seen=now)
        for (ip, dm) in list(self.d):
            if ip == ip_id:
                del self.d[(ip, dm)]
        for lid, (ip, dm, _) in list(self.leases.items()):
            if ip == ip_id:                       # phiên đang chạy vẫn được đếm
                self.d[(ip, dm)].inflight += 1
        self.on_event("ip_reinstated", {"ip": ip_id})

    def _prune_affinity(self) -> None:
        now = self.clock()
        self.affinity = {k: v for k, v in self.affinity.items()
                         if now - v[1] <= self.p.affinity_ttl_s and v[0] in self.proxies
                         and not self.g[v[0]].retired}

    def _reap(self) -> None:
        """Trả lại lease đã hết hạn (worker chết giữa phiên)."""
        now = self.clock()
        for lid, (ip, dm, exp) in list(self.leases.items()):
            if exp <= now:
                del self.leases[lid]
                ds = self.d[(ip, dm)]
                ds.inflight = max(0, ds.inflight - 1)
                self.on_event("lease_expired", {"ip": ip, "domain": dm})

    def domain_active(self, domain: str) -> int:
        return sum(1 for v in self.leases.values() if v[1] == domain)

    def renew(self, lease: Lease) -> None:
        if lease.lease_id in self.leases:
            self.leases[lease.lease_id][2] = self.clock() + self.p.lease_ttl_s

    def _today(self) -> str:
        return time.strftime("%Y-%m-%d", time.gmtime(self.clock() + 7 * 3600))  # theo giờ VN

    def _roll_day(self, gs: IPGlobalState, ds: IPDomainState) -> None:
        today = self._today()
        if gs.day != today:
            gs.day, gs.bookings_today = today, 0
        if ds.day != today:
            ds.day, ds.bookings_today = today, 0

    def _heal(self, gs: IPGlobalState) -> None:
        """Điểm hồi phục dần khi IP được nghỉ; nếu không, IP rớt dưới min_score sẽ bị
        bỏ rơi vĩnh viễn một cách âm thầm (khác với 'retired' có lý do rõ ràng)."""
        now = self.clock()
        if gs.score_at and gs.score < 1.0 and now > gs.score_at:
            gs.score = min(1.0, gs.score + self.p.score_recovery_per_h * (now - gs.score_at) / 3600)
        gs.score_at = now

    def _caps(self, px: ProxyEndpoint) -> tuple[int, int]:
        start = self.g[px.id].first_seen or px.added_at
        f = self.p.warmup_factor if self.clock() - start < self.p.warmup_days * 86400 else 1.0
        return (max(1, int(self.p.ip_domain_daily_bookings * f)),
                max(1, int(self.p.ip_daily_bookings_total * f)))

    def why_ineligible(self, ip_id: str, domain: str, country: Optional[str]) -> Optional[str]:
        px, gs, ds = self.proxies[ip_id], self.g[ip_id], self.d[(ip_id, domain)]
        now = self.clock()
        self._roll_day(gs, ds)
        self._heal(gs)
        dom_cap, total_cap = self._caps(px)
        if gs.retired:
            return "retired"
        if gs.health_block:
            return "health"
        if country and px.country.upper() != country.upper():
            return "country"
        if now < gs.cooldown_until:
            return "global_cooldown"
        if now < ds.quarantine_until:
            return "domain_quarantine"
        if gs.score < self.p.min_score:
            return "low_score"
        if ds.inflight >= self.p.ip_domain_max_concurrency:
            return "busy"
        if ds.bookings_today >= dom_cap:
            return "domain_daily_cap"
        if gs.bookings_today >= total_cap:
            return "total_daily_cap"
        return None

    # ---------- cấp / trả ----------
    def acquire(self, domain: str, user_id: str, country: Optional[str] = None,
                exclude: Iterable[str] = (), prefer: Optional[str] = None,
                pin: bool = False) -> Lease:
        """pin=True: bắt buộc dùng đúng IP `prefer` (đổi engine nhưng giữ danh tính).
        Nếu IP đó không còn dùng được thì báo NoHealthyIP thay vì lặng lẽ đổi sang IP khác,
        vì đổi cả engine lẫn IP cùng lúc chính là hành vi 'xoay để lách'."""
        self._reap()
        if self.domain_active(domain) >= self.p.domain_max_concurrency:
            raise DomainBusy(domain)
        now = self.clock()
        excluded = set(exclude)
        key = (user_id, domain)

        # 0) Giữ nguyên IP khi chỉ đổi engine trình duyệt (danh tính không đổi)
        if prefer and prefer in self.proxies and prefer not in excluded:
            why = self.why_ineligible(prefer, domain, country)
            if why is None:
                return self._lease(prefer, domain, user_id)
            if pin:
                raise NoHealthyIP(f"IP {prefer} không còn dùng được cho {domain} ({why})")
        elif pin:
            raise NoHealthyIP(f"IP ghim {prefer!r} không hợp lệ cho {domain}")

        # 1) Khách quen: dùng lại IP cũ nếu còn khỏe -> cookie + IP nhất quán
        self._prune_affinity()
        aff = self.affinity.get(key)
        if aff and aff[0] not in excluded and self.why_ineligible(aff[0], domain, country) is None:
            return self._lease(aff[0], domain, user_id)

        # 2) Chọn IP tốt nhất: điểm cao, loại IP tốt, ít dùng gần đây trên domain này,
        #    và chưa "thuộc về" khách khác trên domain này (tránh 1 IP = nhiều khách)
        owned = {ip for (u, dm), (ip, ts) in self.affinity.items()
                 if dm == domain and u != user_id}
        cands = []
        for ip_id, px in self.proxies.items():
            if ip_id in excluded or self.why_ineligible(ip_id, domain, country):
                continue
            ds = self.d[(ip_id, domain)]
            idle_h = min((now - ds.last_used) / 3600, 24) if ds.last_used else 24
            rank = (self.g[ip_id].score * _KIND_WEIGHT.get(px.kind, 0.7)
                    + 0.01 * idle_h - (0.3 if ip_id in owned else 0))
            cands.append((rank, ip_id))
        if not cands:
            raise NoHealthyIP(f"Không còn IP khỏe cho {domain} (country={country})")
        cands.sort(reverse=True)
        return self._lease(cands[0][1], domain, user_id)

    def _lease(self, ip_id: str, domain: str, user_id: str) -> Lease:
        ds = self.d[(ip_id, domain)]
        ds.inflight += 1
        ds.last_used = self.clock()
        lease = Lease(self.proxies[ip_id], domain, user_id, self.clock())
        self.leases[lease.lease_id] = [ip_id, domain, self.clock() + self.p.lease_ttl_s]
        return lease

    def _end_lease(self, lease: Lease) -> None:
        # lease đã hết hạn và bị thu hồi thì inflight đã được trừ rồi
        if self.leases.pop(lease.lease_id, None) is not None:
            ds = self.d[(lease.proxy.id, lease.domain)]
            ds.inflight = max(0, ds.inflight - 1)

    def release_neutral(self, lease: Lease) -> None:
        """Trả IP mà không chấm điểm (vd. lỗi trong code của flow, chưa chạm mạng)."""
        self._end_lease(lease)

    def release(self, lease: Lease, det: Detection, booked: bool = False) -> None:
        ip_id, domain, now = lease.proxy.id, lease.domain, self.clock()
        gs, ds = self.g[ip_id], self.d[(ip_id, domain)]
        self._roll_day(gs, ds)
        self._heal(gs)
        self._end_lease(lease)
        gs.score = min(1.0, max(0.0, gs.score + _SCORE_DELTA[det.signal]))

        # Đã đặt được bàn thì luôn tính vào hạn mức, kể cả khi phiên có gặp challenge
        # (nếu không, hạn mức ngày bị vượt qua âm thầm).
        if booked:
            ds.bookings_today += 1
            gs.bookings_today += 1

        if det.signal == Signal.NETWORK_ERROR:
            gs.consecutive_net_errors += 1
            if gs.consecutive_net_errors >= self.p.dead_proxy_errors:
                gs.cooldown_until = now + self.p.dead_proxy_cooldown_s
                gs.consecutive_net_errors = 0
                self.on_event("proxy_cooldown", {"ip": ip_id})
            return
        gs.consecutive_net_errors = 0

        if det.signal == Signal.OK:
            ds.strikes = max(0, ds.strikes - 1)
            self.affinity[(lease.user_id, domain)] = (ip_id, now)
            return

        if det.signal in (Signal.RATE_LIMITED, Signal.BLOCKED):
            if ds.last_strike_at and now - ds.last_strike_at > self.p.strike_reset_s:
                ds.strikes = 0                      # lần phạt cũ đã quá lâu
            ds.strikes += 1
            ds.last_strike_at = now
            backoff = min(self.p.quarantine_max_s,
                          self.p.quarantine_base_s * (2 ** (ds.strikes - 1)))
            ds.quarantine_until = max(ds.quarantine_until,
                                      now + max(backoff, det.retry_after_s or 0))
            # cắt gắn khách quen với IP đã bị domain này đánh dấu
            for k, (ip, _) in list(self.affinity.items()):
                if ip == ip_id and k[1] == domain:
                    del self.affinity[k]

        if det.signal == Signal.BLOCKED:
            gs.blocked_on[domain] = now
            gs.blocked_on = {dm: t for dm, t in gs.blocked_on.items()
                             if now - t <= self.p.burn_window_s}
            if len(gs.blocked_on) >= self.p.burn_domains_threshold and not gs.retired:
                gs.retired = True
                gs.retired_reason = f"blocked on {sorted(gs.blocked_on)}"
                self.on_event("ip_retired", {"ip": ip_id, "reason": gs.retired_reason})

    # ---------- quan sát & lưu trạng thái ----------
    def stats(self) -> list[dict]:
        out = []
        for ip_id, px in self.proxies.items():
            gs = self.g[ip_id]
            self._heal(gs)
            out.append({"ip": ip_id, "country": px.country, "kind": px.kind,
                        "score": round(gs.score, 2), "retired": gs.retired,
                        "reason": gs.retired_reason, "health": gs.health_block,
                        "exit_ip": gs.exit_ip, "exit_country": gs.exit_country,
                        "bookings_today": gs.bookings_today,
                        "blocked_on": sorted(gs.blocked_on),
                        "active": sum(1 for v in self.leases.values() if v[0] == ip_id)})
        return out

    def to_dict(self) -> dict:
        self._prune_affinity()
        return {
            "g": {k: asdict(v) for k, v in self.g.items()},
            "d": {f"{ip}|{dm}": asdict(v) for (ip, dm), v in self.d.items()},
            "affinity": {f"{u}|{dm}": list(v) for (u, dm), v in self.affinity.items()},
            "leases": {k: list(v) for k, v in self.leases.items()},
        }

    def from_dict(self, data: dict, live: bool = False) -> None:
        """live=False: nạp lại sau khởi động (phiên cũ đã chết -> bỏ lease, inflight=0).
        live=True: đồng bộ trạng thái dùng chung giữa các worker -> thay toàn bộ, giữ lease."""
        if live:
            self.g = {k: self._fresh(px) for k, px in self.proxies.items()}
            self.d = defaultdict(IPDomainState)
            self.affinity = {}
            self.leases = {k: list(v) for k, v in data.get("leases", {}).items()
                           if v[0] in self.proxies}
        for k, v in data.get("g", {}).items():
            if k in self.proxies:
                st = _from_dict(IPGlobalState, v)
                if not st.first_seen:                     # file cũ chưa có trường này
                    st.first_seen = self.proxies[k].added_at
                self.g[k] = st
        for k, v in data.get("d", {}).items():
            ip, dm = k.split("|", 1)
            if ip in self.proxies:
                st = _from_dict(IPDomainState, v)
                if not live:
                    st.inflight = 0          # phiên cũ đã chết khi khởi động lại
                self.d[(ip, dm)] = st
        for k, v in data.get("affinity", {}).items():
            u, dm = k.split("|", 1)
            if v[0] in self.proxies:
                self.affinity[(u, dm)] = (v[0], v[1])

    def dump_state(self) -> str:
        return json.dumps(self.to_dict())

    def load_state(self, raw: str) -> None:
        self.from_dict(json.loads(raw))
