from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Signal(str, Enum):
    OK = "ok"
    SOFT_CHALLENGE = "soft_challenge"   # JS challenge / Turnstile tự qua được
    CAPTCHA = "captcha"                 # cần người giải
    RATE_LIMITED = "rate_limited"       # 429 hoặc tương đương
    BLOCKED = "blocked"                 # trang chặn cứng (403 WAF, 1020, Access denied...)
    NETWORK_ERROR = "network_error"     # proxy chết / timeout
    SERVER_ERROR = "server_error"       # 5xx của chính website (không phải lỗi IP)


# Mức độ nghiêm trọng để chọn "tín hiệu tệ nhất" của một phiên
SEVERITY = {
    Signal.OK: 0,
    Signal.NETWORK_ERROR: 1,
    Signal.SERVER_ERROR: 2,
    Signal.SOFT_CHALLENGE: 3,
    Signal.CAPTCHA: 4,
    Signal.RATE_LIMITED: 5,
    Signal.BLOCKED: 6,
}


class Decision(str, Enum):
    CONTINUE = "continue"
    ESCALATE_BODY = "escalate_body"     # đổi engine (Patchright -> CloakBrowser -> Camoufox), giữ IP
    HANDOFF_USER = "handoff_user"       # đưa phiên/CAPTCHA cho người dùng
    ABORT = "abort"                     # dừng phiên, KHÔNG dội lại ngay


DECISION = {
    Signal.OK: Decision.CONTINUE,
    Signal.SOFT_CHALLENGE: Decision.ESCALATE_BODY,
    Signal.CAPTCHA: Decision.HANDOFF_USER,
    Signal.RATE_LIMITED: Decision.ABORT,
    Signal.BLOCKED: Decision.ABORT,
    Signal.NETWORK_ERROR: Decision.ABORT,
    Signal.SERVER_ERROR: Decision.ABORT,
}


@dataclass
class Detection:
    signal: Signal
    vendor: Optional[str] = None
    retry_after_s: Optional[float] = None
    reason: str = ""


@dataclass
class ProxyEndpoint:
    """Một lối ra mạng cố định (sticky).

    Với nhà cung cấp kiểu gateway, mỗi session id cố định (vd. user-...-session-abc)
    được coi là một endpoint riêng, vì nó giữ cùng một IP ra.
    """
    id: str
    url: str                      # http://user:pass@host:port
    country: str                  # "VN", "SG", "JP"...
    kind: str = "residential"     # residential | isp | mobile | datacenter
    timezone: Optional[str] = None
    locale: Optional[str] = None
    added_at: float = 0.0


@dataclass
class IPDomainState:
    inflight: int = 0
    last_used: float = 0.0
    day: str = ""
    bookings_today: int = 0
    quarantine_until: float = 0.0
    strikes: int = 0
    last_strike_at: float = 0.0


@dataclass
class IPGlobalState:
    score: float = 1.0
    score_at: float = 0.0          # lần cuối cập nhật điểm (để hồi phục theo thời gian)
    first_seen: float = 0.0        # mốc bắt đầu warm-up (lưu lại, không reset khi khởi động lại)
    health_block: str = ""         # lý do kiểm tra sức khỏe chặn cấp IP ("" = không chặn)
    exit_ip: str = ""              # IP ra thực tế lần kiểm tra gần nhất
    exit_country: str = ""
    checked_at: float = 0.0
    retired: bool = False
    retired_reason: str = ""
    cooldown_until: float = 0.0
    consecutive_net_errors: int = 0
    day: str = ""
    bookings_today: int = 0
    blocked_on: dict = field(default_factory=dict)   # domain -> ts lần bị chặn gần nhất


@dataclass
class Lease:
    proxy: ProxyEndpoint
    domain: str
    user_id: str
    acquired_at: float
    lease_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
