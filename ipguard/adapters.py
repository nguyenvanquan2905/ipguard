"""Nối IPGuard vào Playwright / Patchright / CloakBrowser / Camoufox."""
from __future__ import annotations

import asyncio
import os
import re
from contextlib import asynccontextmanager
from typing import Optional
from urllib.parse import urlsplit

from .detector import classify
from .guard import GuardSession, StopFlow
from .models import SEVERITY, Decision, Detection, ProxyEndpoint, Signal

# Gợi ý timezone/locale khi endpoint không khai báo
_GEO = {
    "VN": ("Asia/Ho_Chi_Minh", "vi-VN"),
    "SG": ("Asia/Singapore", "en-SG"),
    "TH": ("Asia/Bangkok", "th-TH"),
    "JP": ("Asia/Tokyo", "ja-JP"),
    "KR": ("Asia/Seoul", "ko-KR"),
    "US": ("America/New_York", "en-US"),
    "GB": ("Europe/London", "en-GB"),
    "FR": ("Europe/Paris", "fr-FR"),
}


def is_direct(px: ProxyEndpoint) -> bool:
    """url = "direct": đi thẳng bằng IP của máy (chỉ để chạy thử, không dùng thật)."""
    return px.url.strip().lower() == "direct"


def playwright_proxy(px: ProxyEndpoint) -> Optional[dict]:
    if is_direct(px):
        return None
    u = urlsplit(px.url)
    out = {"server": f"{u.scheme}://{u.hostname}:{u.port}"}
    if u.username:
        out["username"] = u.username
        out["password"] = u.password or ""
    return out


def geo_of(px: ProxyEndpoint) -> tuple[str, str]:
    tz, loc = _GEO.get(px.country.upper(), ("UTC", "en-US"))
    return px.timezone or tz, px.locale or loc


def context_kwargs(px: ProxyEndpoint) -> dict:
    """Dùng cho browser.new_context(**...) hoặc launch_persistent_context(**...).
    Timezone/locale phải khớp IP, nếu không chính sự lệch này là tín hiệu bot."""
    tz, loc = geo_of(px)
    out = {"timezone_id": tz, "locale": loc,
           "extra_http_headers": {"Accept-Language": f"{loc},{loc.split('-')[0]};q=0.9"}}
    proxy = playwright_proxy(px)
    if proxy:
        out["proxy"] = proxy
    return out


def cloakbrowser_kwargs(px: ProxyEndpoint) -> dict:
    """Tham số cho cloakbrowser.launch(). Kiểm tra lại tên tham số với phiên bản bạn ghim."""
    tz, loc = geo_of(px)
    return {"proxy": None if is_direct(px) else px.url, "timezone": tz, "locale": loc,
            "humanize": True}


class Issues(list):
    """Danh sách (Decision, Detection) bất thường + chống đếm trùng 1 response
    (cả attach() lẫn guarded_goto() đều thấy response của page.goto)."""

    def __init__(self):
        super().__init__()
        self.seen: set = set()
        self.pending: set = set()

    def claim(self, resp) -> bool:
        """True nếu response này chưa được xử lý (và đánh dấu đã nhận)."""
        if resp in self.seen:
            return False
        self.seen.add(resp)
        return True

    async def settle(self, timeout: float = 10.0) -> None:
        """Chờ các handler on_response đang đọc body xong."""
        if self.pending:
            await asyncio.wait(set(self.pending), timeout=timeout)


def attach(page, s: GuardSession, body_limit: int = 60_000) -> Issues:
    """Theo dõi mọi response *document* của main frame và đưa vào s.observe().
    Trả về Issues để flow kiểm tra bằng check_issues() / raise_if_bad()."""
    issues = Issues()

    async def handle(resp):
        try:
            status, headers = resp.status, await resp.all_headers()
            body = ""
            if status >= 400 or int(headers.get("content-length", "0") or 0) < body_limit:
                try:
                    body = (await resp.text())[:body_limit]
                except Exception:
                    pass
            det = classify(status, headers, body, now=s.guard.clock())
            dec = s.observe_detection(det)
            if dec != Decision.CONTINUE:
                issues.append((dec, det))
        except Exception:
            pass

    def on_response(resp):
        try:
            if resp.request.resource_type != "document" or resp.frame != page.main_frame:
                return
        except Exception:
            return
        if not issues.claim(resp):
            return
        t = asyncio.ensure_future(handle(resp))
        issues.pending.add(t)
        t.add_done_callback(issues.pending.discard)

    page.on("response", on_response)
    return issues


def raise_if_bad(issues: list) -> None:
    if issues:
        dec, det = max(issues, key=lambda x: SEVERITY[x[1].signal])
        raise StopFlow(dec, det)


async def check_issues(issues: list) -> None:
    """Chờ handler xử lý xong rồi mới kiểm tra (tránh race sau click/submit)."""
    if isinstance(issues, Issues):
        await issues.settle()
    raise_if_bad(issues)


async def guarded_goto(page, s: GuardSession, url: str, issues: list, **kw):
    """goto có giới hạn nhịp + phân loại kết quả + bắt lỗi mạng."""
    await s.before_navigation()
    try:
        resp = await page.goto(url, **kw)
    except Exception as e:  # timeout / proxy chết
        s.observe_detection(Detection(Signal.NETWORK_ERROR, reason=str(e)[:120]))
        raise StopFlow(Decision.ABORT, s.worst)
    if resp is not None and (not isinstance(issues, Issues) or issues.claim(resp)):
        try:
            body = (await resp.text())[:60_000]
        except Exception:
            body = ""
        s.check(resp.status, await resp.all_headers(), body)
    await check_issues(issues)                 # gồm cả response do attach() xử lý
    return resp


# ---------------- trình duyệt gắn với phiên ----------------
# Tên múi giờ cũ/đồng nghĩa (tzdata "backward"): Chrome có thể báo tên cũ, vd. Asia/Saigon.
_TZ_ALIASES = {
    "Asia/Saigon": "Asia/Ho_Chi_Minh", "Asia/Calcutta": "Asia/Kolkata",
    "Asia/Rangoon": "Asia/Yangon", "Asia/Katmandu": "Asia/Kathmandu",
    "Asia/Ujung_Pandang": "Asia/Makassar", "Asia/Ulan_Bator": "Asia/Ulaanbaatar",
    "Asia/Thimbu": "Asia/Thimphu", "Asia/Dacca": "Asia/Dhaka", "Asia/Macao": "Asia/Macau",
    "Asia/Chongqing": "Asia/Shanghai", "Asia/Chungking": "Asia/Shanghai",
    "Asia/Harbin": "Asia/Shanghai", "Asia/Istanbul": "Europe/Istanbul",
    "Europe/Kiev": "Europe/Kyiv", "Singapore": "Asia/Singapore", "Japan": "Asia/Tokyo",
    "ROK": "Asia/Seoul", "GB": "Europe/London", "US/Eastern": "America/New_York",
    "America/Buenos_Aires": "America/Argentina/Buenos_Aires", "Etc/UTC": "UTC",
    "Etc/GMT": "UTC", "GMT": "UTC", "Universal": "UTC", "Zulu": "UTC",
}


def same_timezone(a: str, b: str) -> bool:
    norm = lambda z: _TZ_ALIASES.get(z, z)  # noqa: E731
    return norm(a) == norm(b)


class GeoMismatch(RuntimeError):
    """Timezone/ngôn ngữ của trình duyệt không khớp IP: dừng trước khi tải trang nào."""


async def verify_browser_geo(page, px: ProxyEndpoint) -> list[str]:
    """So timezone + ngôn ngữ trình duyệt báo ra với quốc gia của IP.
    (Kiểm tra IP ra/quốc gia của proxy nằm ở HealthChecker.)"""
    want_tz, want_loc = geo_of(px)
    got_tz, got_lang = await page.evaluate(
        "() => [Intl.DateTimeFormat().resolvedOptions().timeZone, navigator.language]")
    problems = []
    if not same_timezone(str(got_tz), want_tz):
        problems.append(f"timezone {got_tz} ≠ {want_tz}")
    if str(got_lang).split("-")[0].lower() != want_loc.split("-")[0].lower():
        problems.append(f"ngôn ngữ {got_lang} ≠ {want_loc}")
    return problems


def _safe(part: str) -> str:
    return re.sub(r"[^\w.-]", "_", part)[:80] or "_"


async def _launch_chrome(pw, s: GuardSession, profile_dir: str, headless: bool):
    return await pw.chromium.launch_persistent_context(
        profile_dir, channel="chrome", headless=headless, **context_kwargs(s.proxy))


@asynccontextmanager
async def guarded_page(pw, s: GuardSession, profile_root: str = "profiles",
                       launchers: Optional[dict] = None, headless: bool = False):
    """Mở trình duyệt cho phiên: profile lâu dài theo (user, domain), proxy + timezone +
    ngôn ngữ khớp IP, kiểm tra geo trước khi tải trang, theo dõi response.

    launchers: {engine: async (pw, s, profile_dir, headless) -> BrowserContext} cho
    CloakBrowser/Camoufox... Mặc định chỉ có "patchright_chrome" / "playwright_chrome".

        async with guarded_page(pw, s) as (page, issues):
            await guarded_goto(page, s, url, issues)
    """
    table = {"patchright_chrome": _launch_chrome, "playwright_chrome": _launch_chrome,
             **(launchers or {})}
    launch = table.get(s.engine)
    if launch is None:
        raise NotImplementedError(f"chưa có launcher cho engine {s.engine!r}; "
                                  f"truyền launchers={{'{s.engine}': ...}} hoặc bỏ engine này")
    profile_dir = os.path.join(profile_root, _safe(s.lease.user_id), _safe(s.lease.domain))
    ctx = await launch(pw, s, profile_dir, headless)
    try:
        page = ctx.pages[0] if ctx.pages else await ctx.new_page()
        problems = await verify_browser_geo(page, s.proxy)
        if problems:
            raise GeoMismatch("; ".join(problems))
        issues = attach(page, s)
        yield page, issues
    finally:
        await ctx.close()
