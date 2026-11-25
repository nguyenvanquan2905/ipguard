"""Phân loại phản hồi HTTP thành tín hiệu ban / thử thách.

Chỉ dùng cho response của *document* (trang chính), không dùng cho ảnh/JS/XHR.
Lưu ý: form đặt bàn có thể nhúng reCAPTCHA hợp lệ -> chỉ coi là CAPTCHA chặn
khi đi kèm mã lỗi hoặc trang interstitial của vendor anti-bot.
"""
from __future__ import annotations

import re
import time
from datetime import timezone
from email.utils import parsedate_to_datetime
from typing import Mapping, Optional

from .models import Detection, Signal

_CF_CHALLENGE = re.compile(
    r"(just a moment\.\.\.|cf-turnstile|challenge-platform|cf_chl_opt|checking your browser)", re.I
)
_BLOCK_MARKERS = [
    (re.compile(r"error 1020|sorry, you have been blocked|cf-error-details", re.I), "cloudflare"),
    (re.compile(r"captcha-delivery\.com|geo\.captcha-delivery", re.I), "datadome"),
    (re.compile(r"_incapsula_resource|request unsuccessful\. incapsula", re.I), "imperva"),
    (re.compile(r"pardon our interruption|px-captcha|perimeterx", re.I), "perimeterx"),
    (re.compile(r"akamai|reference&#32;&#35;|access denied", re.I), "akamai/generic"),
]
_CAPTCHA_VENDORS = {"datadome", "perimeterx"}


def _h(headers: Mapping[str, str], name: str) -> str:
    for k, v in headers.items():
        if k.lower() == name:
            return v or ""
    return ""


def _retry_after(headers: Mapping[str, str], now: Optional[float] = None) -> Optional[float]:
    v = _h(headers, "retry-after").strip()
    if not v:
        return None
    if v.isdigit():
        return float(v)
    try:                                   # dạng HTTP-date
        dt = parsedate_to_datetime(v)
    except (TypeError, ValueError, IndexError):
        return None
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return max(0.0, dt.timestamp() - (time.time() if now is None else now))


def classify(status: Optional[int], headers: Mapping[str, str] | None = None,
             body: str | None = None, now: Optional[float] = None) -> Detection:
    headers = headers or {}
    body = (body or "")[:200_000]

    if status is None:
        return Detection(Signal.NETWORK_ERROR, reason="no response")
    if status == 407:                                   # proxy đòi xác thực: luôn là lỗi proxy
        return Detection(Signal.NETWORK_ERROR, reason="proxy auth 407")
    if status in (502, 504) and not body:
        return Detection(Signal.NETWORK_ERROR, reason=f"proxy/gateway {status}")

    if status == 429:
        return Detection(Signal.RATE_LIMITED, retry_after_s=_retry_after(headers, now),
                         reason="HTTP 429")

    server = _h(headers, "server").lower()
    is_cf = "cloudflare" in server or bool(_h(headers, "cf-ray"))
    mitigated = _h(headers, "cf-mitigated").lower()

    if mitigated == "challenge" or (is_cf and status in (403, 503) and _CF_CHALLENGE.search(body)):
        return Detection(Signal.SOFT_CHALLENGE, vendor="cloudflare", reason="cf challenge")

    if status in (401, 403, 405, 406, 451, 503):
        for rx, vendor in _BLOCK_MARKERS:
            if rx.search(body) or (vendor == "datadome" and _h(headers, "x-datadome")):
                sig = Signal.CAPTCHA if vendor in _CAPTCHA_VENDORS else Signal.BLOCKED
                return Detection(sig, vendor=vendor, reason=f"{status} {vendor}")
        if status in (403, 451):
            return Detection(Signal.BLOCKED, vendor="cloudflare" if is_cf else None,
                             reason=f"HTTP {status}")

    # 5xx không có dấu hiệu anti-bot: website đang lỗi/quá tải -> không phải OK
    if status >= 500:
        return Detection(Signal.SERVER_ERROR, retry_after_s=_retry_after(headers, now),
                         reason=f"HTTP {status}")

    if 200 <= status < 400 and _CF_CHALLENGE.search(body) and len(body) < 30_000:
        return Detection(Signal.SOFT_CHALLENGE, vendor="cloudflare", reason="interstitial 2xx")

    return Detection(Signal.OK)
