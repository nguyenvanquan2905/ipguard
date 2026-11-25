"""Kiểm tra proxy chủ động, trước khi đem IP đi đặt bàn.

Phát hiện:
- proxy chết / sai mật khẩu        -> tạm ngừng cấp IP đó tới lần kiểm tra đạt kế tiếp
- IP ra không đúng quốc gia khai báo -> tạm ngừng (geo lệch là tín hiệu bot rõ nhất)
- nhà cung cấp lặng lẽ đổi IP ra    -> ghi sự kiện, chạy lại warm-up (với website đây là IP lạ)
- hai endpoint ra cùng một IP       -> chỉ giữ một (nếu không, 1 IP = nhiều "khách")

Chỉ gửi một request GET tới dịch vụ tra IP (mặc định ipinfo.io) qua từng proxy;
không gửi dữ liệu khách hàng. Đổi `geo_url` nếu muốn dùng dịch vụ khác/tự host.
"""
from __future__ import annotations

import asyncio
import json
import urllib.request
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Optional

DEFAULT_GEO_URL = "https://ipinfo.io/json"

Fetch = Callable[[str, str, float], Awaitable[tuple[int, str]]]


@dataclass
class HealthResult:
    ip_id: str
    ok: bool
    exit_ip: str = ""
    country: str = ""
    error: str = ""
    issues: list = field(default_factory=list)


async def urllib_fetch(proxy_url: str, url: str, timeout: float) -> tuple[int, str]:
    """GET qua proxy HTTP(S) bằng thư viện chuẩn. SOCKS: truyền `fetch` riêng."""
    if proxy_url.lower().startswith("socks"):
        raise ValueError("proxy SOCKS: cần truyền fetch riêng (vd. dùng httpx[socks])")

    def _do():
        proxies = {} if proxy_url.strip().lower() == "direct" else             {"http": proxy_url, "https": proxy_url}
        opener = urllib.request.build_opener(urllib.request.ProxyHandler(proxies))
        req = urllib.request.Request(url, headers={"User-Agent": "ipguard-healthcheck/1",
                                                   "Accept": "application/json"})
        with opener.open(req, timeout=timeout) as r:
            return r.status, r.read(65_536).decode("utf-8", "replace")

    return await asyncio.to_thread(_do)


def parse_geo(body: str) -> tuple[str, str]:
    try:
        data = json.loads(body)
    except ValueError:
        return "", ""
    ip = str(data.get("ip") or data.get("query") or "")
    country = str(data.get("country") or data.get("country_code")
                  or data.get("countryCode") or "")
    return ip, country.upper() if len(country) == 2 else ""


class HealthChecker:
    def __init__(self, guard, geo_url: str = DEFAULT_GEO_URL, fetch: Optional[Fetch] = None):
        self.g = guard
        self.geo_url = geo_url
        self.fetch = fetch or urllib_fetch

    async def check(self, force: bool = False) -> list[HealthResult]:
        """Kiểm tra các IP đã quá hạn kiểm tra (hoặc tất cả nếu force)."""
        g, pool = self.g, self.g.pool
        async with g.sync():
            now = g.clock()
            due = [px for ip, px in pool.proxies.items()
                   if not pool.g[ip].retired
                   and (force or now - pool.g[ip].checked_at >= g.p.health_interval_s)]
            for px in due:                         # đánh dấu để worker khác không kiểm tra trùng
                pool.g[px.id].checked_at = now
        if not due:
            return []
        results = await asyncio.gather(*(self._probe(px) for px in due))
        async with g.sync():
            self._apply(results)
        return list(results)

    async def _probe(self, px) -> HealthResult:
        try:
            status, body = await self.fetch(px.url, self.geo_url, self.g.p.health_timeout_s)
        except Exception as e:
            return HealthResult(px.id, False, error=f"{type(e).__name__}: {str(e)[:100]}")
        if status == 407:
            return HealthResult(px.id, False, error="proxy từ chối xác thực (407)")
        if status != 200:
            return HealthResult(px.id, False, error=f"HTTP {status}")
        ip, country = parse_geo(body)
        if not ip:
            return HealthResult(px.id, False, error="không đọc được IP ra")
        return HealthResult(px.id, True, ip, country)

    def _apply(self, results: list[HealthResult]) -> None:
        pool, now = self.g.pool, self.g.clock()
        # Không proxy nào qua được: nhiều khả năng dịch vụ tra IP hoặc mạng của máy chủ
        # đang lỗi, không phải mọi proxy cùng chết -> không chặn IP nào, chỉ ghi sự kiện.
        # (Proxy chết thật vẫn bị bắt qua lỗi mạng khi đặt bàn.)
        checker_down = results and not any(r.ok for r in results)
        if checker_down:
            pool.on_event("health_unavailable", {"error": results[0].error})
        for r in results:
            gs, px = pool.g[r.ip_id], pool.proxies[r.ip_id]
            gs.checked_at = now
            if not r.ok:
                if not checker_down:
                    r.issues.append(f"dead: {r.error}")
                continue
            if r.country and r.country != px.country.upper():
                r.issues.append(f"geo: IP ra ở {r.country}, khai báo {px.country.upper()}")
            if gs.exit_ip and r.exit_ip != gs.exit_ip:
                pool.on_event("ip_changed", {"ip": r.ip_id, "old": gs.exit_ip, "new": r.exit_ip})
                gs.first_seen = now                # IP lạ với website -> warm-up lại
            gs.exit_ip, gs.exit_country = r.exit_ip, r.country

        # trùng IP ra giữa các endpoint: giữ endpoint điểm cao nhất
        by_exit: dict[str, list[str]] = {}
        for ip_id, gs in pool.g.items():
            if gs.exit_ip and not gs.retired and ip_id in pool.proxies:
                by_exit.setdefault(gs.exit_ip, []).append(ip_id)
        dup_of: dict[str, str] = {}
        for ids in by_exit.values():
            if len(ids) > 1:
                ids.sort(key=lambda i: (-pool.g[i].score, i))
                for other in ids[1:]:
                    dup_of[other] = ids[0]

        for r in results:
            if checker_down:
                continue                           # giữ nguyên kết luận lần trước
            if r.ip_id in dup_of:
                r.issues.append(f"duplicate: cùng IP ra với {dup_of[r.ip_id]}")
            self._set_block(r.ip_id, "; ".join(r.issues))

    def _set_block(self, ip_id: str, block: str) -> None:
        pool = self.g.pool
        gs = pool.g[ip_id]
        if block and block != gs.health_block:
            pool.on_event("health_issue", {"ip": ip_id, "issue": block})
        elif not block and gs.health_block:
            pool.on_event("health_ok", {"ip": ip_id})
        gs.health_block = block
