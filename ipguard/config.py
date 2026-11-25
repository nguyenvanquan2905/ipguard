"""Chính sách chống ban IP cho agent đặt bàn.

Các con số mặc định giả định khối lượng "khách thật": mỗi IP chỉ đặt vài bàn
mỗi ngày trên một domain, mỗi domain chỉ có vài phiên chạy song song.
Chỉnh theo dữ liệu benchmark của bạn, đừng tăng vọt.
"""
from dataclasses import dataclass


@dataclass
class Policy:
    # --- Nhịp truy cập theo domain (toàn hệ thống, AIMD) ---
    domain_rpm_start: float = 12.0      # số lần tải trang/phút khởi điểm cho mỗi domain
    domain_rpm_min: float = 2.0         # sàn khi bị throttle
    domain_rpm_max: float = 30.0        # trần khi mọi thứ trơn tru
    domain_rpm_step_up: float = 0.5     # cộng thêm sau mỗi lần OK (additive increase)
    domain_rpm_backoff: float = 0.5     # nhân khi 429/chặn (multiplicative decrease)
    domain_max_concurrency: int = 2     # số phiên đặt bàn song song tối đa trên 1 domain

    # --- Giới hạn trên mỗi IP ---
    ip_domain_max_concurrency: int = 1  # 1 IP chỉ chạy 1 phiên trên 1 domain tại 1 thời điểm
    ip_domain_daily_bookings: int = 4   # 1 IP đặt tối đa N bàn/ngày trên 1 domain
    ip_daily_bookings_total: int = 40   # tổng số lượt đặt/ngày của 1 IP trên mọi domain
    warmup_days: int = 3                # IP mới: giảm hạn mức trong vài ngày đầu
    warmup_factor: float = 0.5

    # --- Độ trễ giống người giữa các thao tác (giây) ---
    jitter_min_s: float = 0.8
    jitter_max_s: float = 2.5

    # --- Phạt & cách ly ---
    quarantine_base_s: float = 15 * 60          # cách ly (IP, domain) lần đầu: 15 phút
    quarantine_max_s: float = 24 * 3600         # tối đa 24h, tăng theo cấp số nhân
    burn_domains_threshold: int = 3             # bị chặn trên >=3 domain khác nhau trong 24h -> loại IP
    burn_window_s: float = 24 * 3600
    dead_proxy_errors: int = 3                  # 3 lỗi mạng liên tiếp -> nghỉ ngắn
    dead_proxy_cooldown_s: float = 10 * 60
    min_score: float = 0.35                     # điểm sức khỏe dưới mức này thì không cấp
    score_recovery_per_h: float = 0.01          # điểm tự hồi phục chậm theo thời gian (IP nghỉ ngơi)
    strike_reset_s: float = 7 * 24 * 3600       # không bị phạt thêm trong 7 ngày -> xóa bậc cách ly
    max_pause_wait_s: float = 120.0             # domain bị tạm dừng lâu hơn mức này -> từ chối ngay, không ngồi chờ

    # --- Cầu dao theo domain ---
    breaker_distinct_ips: int = 3               # >=3 IP khác nhau bị chặn trên 1 domain...
    breaker_window_s: float = 30 * 60           # ...trong 30 phút -> mở cầu dao
    breaker_open_s: float = 2 * 3600            # ngừng tự động hóa domain đó 2h, rồi thử 1 phiên

    # --- Gắn người dùng với IP (khách quen) ---
    affinity_ttl_s: float = 30 * 24 * 3600

    # --- Thử lại ---
    max_ip_switches_pre_submit: int = 1         # chỉ đổi IP tối đa 1 lần, và chỉ khi CHƯA gửi form
    request_memory_s: float = 30 * 24 * 3600    # nhớ request_id đã submit/đã đặt trong 30 ngày

    # --- Nhiều worker ---
    lease_ttl_s: float = 15 * 60                # worker chết giữa chừng: IP/probe tự được trả sau 15 phút
    busy_poll_s: float = 2.0                    # domain đủ phiên trên toàn cụm: thử lại sau mỗi 2s...
                                                # ...tối đa max_pause_wait_s rồi trả deep link

    # --- Kiểm tra proxy chủ động ---
    health_interval_s: float = 30 * 60          # kiểm tra lại mỗi IP sau 30 phút
    health_timeout_s: float = 15.0
