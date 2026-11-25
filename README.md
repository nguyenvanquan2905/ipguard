# ipguard — cơ chế chống ban IP cho agent đặt bàn

Triết lý: **không để bị ban ngay từ đầu, và khi bị ban thì khoanh vùng thiệt hại**,
chứ không xoay IP liên tục để lách. Mỗi lượt đặt bàn = một "khách thật":
một IP cố định, geo khớp, nhịp chậm, cookie của khách quen.

## Bắt đầu nhanh

```
pip install -e .                 # thêm [redis] để chạy nhiều worker, [browser] cho Patchright
cp ipguard.example.toml ipguard.toml
export PX_VN_1=http://user-session-a:pass@gw:8000 ...
python -m ipguard check          # kiểm tra proxy: còn sống, IP ra, đúng quốc gia
```

```python
from ipguard import AntiBan
from ipguard.adapters import check_issues, guarded_goto, guarded_page

ab = AntiBan.from_config("ipguard.toml", on_alert=gui_canh_bao)
async with ab:
    r = await ab.book("nhahang.vn", user_id, flow, country="VN", request_id=order_id)
```

`flow(s)` nhận một `GuardSession`. Bên trong flow:
- dùng `guarded_page(pw, s)` để mở trình duyệt đúng proxy, profile và geo;
- gọi `guarded_goto()` hoặc `s.before_navigation()` trước mỗi lần tải trang;
- gọi `s.mark_submitted()` ngay trước khi bấm xác nhận;
- gọi `s.mark_booked()` khi đặt thành công;
- gọi `await check_issues(issues)` sau mỗi click gây điều hướng.

Xem `example_playwright.py`.

| `r.outcome` | Ý nghĩa | Phía gọi nên làm |
|---|---|---|
| `booked` | đặt thành công, `r.value` là giá trị flow trả về | báo người dùng |
| `handoff_user` | gặp CAPTCHA | đưa người dùng tự hoàn tất |
| `deeplink` | bị chặn/429/5xx/cầu dao mở/domain bận/hết IP khỏe, **chưa submit** | gửi link để người dùng tự đặt |
| `failed` | đã submit nhưng không rõ kết quả, hoặc flow chạy hết mà chưa đặt được | **kiểm tra trạng thái trước**, không tự retry |

`r.detail` ghi lý do, còn `r.log` liệt kê từng lần thử theo dạng `(engine, ip, signal, reason)`.

Với cùng `request_id`: nếu lượt đó đã đặt thì không đặt lại. Nếu đã submit mà chưa rõ kết quả thì
không chạy lại cho tới khi bạn kiểm tra xong và gọi `ab.resolve(request_id)` hoặc
`python -m ipguard resolve <id>`. Lỗi trong code của flow **trước** khi submit vẫn được ném ra
để bạn thấy bug.

## Các lớp

| Lớp | Thành phần | Làm gì |
|---|---|---|
| 0. Kiểm tra proxy | `HealthChecker`, `guarded_page` | Mỗi 30′ trước khi cấp IP: proxy còn sống, IP ra đúng quốc gia, nhà cung cấp có lặng lẽ đổi IP không (đổi thì chạy lại warm-up), hai endpoint có ra cùng một IP không. Trong trình duyệt: timezone/ngôn ngữ phải khớp IP trước khi tải trang |
| 1. Phòng ngừa | `IPPool`, `Policy` | IP cố định suốt phiên; gắn (user, domain) → IP (khách quen); khớp quốc gia; 4 lượt/IP/domain/ngày và 40 lượt/IP/ngày; 1 phiên/IP/domain; IP mới chạy nửa hạn mức trong 3 ngày (mốc warm-up được lưu, không reset khi khởi động lại); điểm < 0.35 thì không cấp |
| 2. Nhịp | `DomainRateLimiter` | Token bucket mỗi domain (12 lượt tải/phút, trong khoảng 2–30), AIMD: OK thì tăng chậm, 429/chặn/5xx thì giảm một nửa; tôn trọng `Retry-After`; jitter 0.8–2.5s giữa thao tác; ≤2 phiên song song/domain **trên toàn hệ thống** |
| 3. Phát hiện | `classify()` | 200 / challenge Cloudflare / CAPTCHA DataDome-PerimeterX / chặn cứng (1020, Access denied, Imperva) / 429 (`Retry-After` dạng giây hoặc HTTP-date) / 5xx của site / lỗi mạng-proxy (407, 502/504 rỗng). reCAPTCHA hợp lệ trên form không bị tính là chặn |
| 4. Phản ứng | `IPGuard.run()`, `DomainBreaker` | Xem bảng dưới |
| 5. Theo dõi | `Metrics`, `on_alert`, CLI | Tỉ lệ challenge/CAPTCHA/chặn theo domain và engine, kết quả lượt đặt, nhật ký sự kiện; cảnh báo khi IP bị loại, cầu dao mở, proxy lỗi, IP ra bị đổi |

## Bảng phản ứng

| Tín hiệu | IP | Domain | Lượt đặt |
|---|---|---|---|
| OK | điểm +0.05, ghi khách quen | tăng nhịp | tiếp tục |
| Challenge | điểm −0.08 | — | **đổi engine, giữ IP** (Patchright → CloakBrowser → Camoufox), chỉ khi chưa submit; IP đó không còn dùng được → deep link, không đổi IP |
| CAPTCHA | điểm −0.15 | — | `handoff_user`: giao người dùng tự giải (kể cả khi đã submit) |
| 429 | điểm −0.2; cách ly (IP, domain) 15′→30′→1h…≤24h (hoặc lâu hơn nếu Retry-After dài hơn); bỏ gắn khách quen | giảm nhịp 50%, tạm dừng theo Retry-After (mặc định 60s) | dừng, **không đổi IP** |
| Chặn cứng | điểm −0.35; cách ly như 429 + ghi "bị chặn ở domain X" | giảm nhịp, báo cầu dao | đổi IP **1 lần nếu chưa submit**, rồi deep link |
| Bị chặn ở ≥3 domain/24h | **loại IP vĩnh viễn** (đưa lại bằng `reinstate`) | — | — |
| 3 IP khác nhau bị chặn / domain / 30′ | — | **mở cầu dao 2h**, sau đó thử 1 phiên | deep link |
| 5xx của site | không trừ điểm | giảm nhịp, dừng theo Retry-After | dừng, không đổi IP |
| Lỗi mạng | điểm −0.05; 3 lần liên tiếp thì nghỉ 10′ | — | đổi IP 1 lần nếu chưa submit |
| Proxy chết / sai quốc gia / trùng IP ra (kiểm tra chủ động) | không cấp tới lần kiểm tra đạt | — | — |
| Lỗi/exception sau submit | — | — | **không gửi lại**: `failed`, kiểm tra trạng thái để tránh đặt trùng |
| Đã `mark_booked()` rồi mới lỗi | — | — | vẫn trả `booked`, không chạy lại |
| Domain tạm dừng hoặc đủ phiên > 2′ | — | — | trả deep link ngay, không ngồi chờ |

Ngoài bảng:
- điểm IP tự hồi phục 0.01/giờ khi được nghỉ;
- bậc cách ly reset sau 7 ngày không bị phạt;
- lượt đã đặt luôn được tính vào hạn mức, kể cả khi phiên có gặp challenge;
- bị 429 trong phiên thăm dò cũng mở lại cầu dao;
- dịch vụ tra IP lỗi (mọi proxy cùng thất bại) thì không chặn IP nào, chỉ ghi sự kiện.

Mọi con số mặc định nằm trong `Policy` (`ipguard/config.py`). Muốn đổi thì ghi vào `[policy]`
trong `ipguard.toml`.

## Trạng thái và nhiều worker

Cấu hình `[state]` trong `ipguard.toml`:

- `backend = "file"`: dùng cho **một process**. Trạng thái lưu vào JSON sau mỗi lượt đặt (ghi
  nguyên tử). Vẫn đọc được file cũ của `pool.dump_state()`.
- `backend = "redis"`: dùng cho **nhiều worker / nhiều máy** (`pip install -e .[redis]`).
  Toàn bộ trạng thái là một bản JSON trong Redis. Mỗi thao tác quan trọng (cấp IP, giữ chỗ lượt
  tải trang, trả IP, ghi tín hiệu) chạy trong một khóa toàn cụm. Nhờ vậy hạn mức, cách ly, cầu
  dao, giới hạn phiên/domain và `request_id` đều đúng trên toàn hệ thống. IP và cờ thăm dò có
  thời hạn 15′ (tự gia hạn mỗi lần tải trang), nên worker chết giữa phiên không giữ IP mãi.
- `backend = "memory"`: không lưu gì.

Cách khóa toàn cụm này hợp với khối lượng đặt bàn thấp (vài thao tác/phút/domain). Nếu tăng lên
hàng trăm thao tác/giây thì phải tách trạng thái ra nhiều khóa.

## Quản trị (CLI)

```
python -m ipguard -c ipguard.toml report [--json]   # IP, domain, tỉ lệ chặn, sự kiện, lượt chờ kiểm tra
python -m ipguard -c ipguard.toml check             # kiểm tra mọi proxy ngay
python -m ipguard -c ipguard.toml reinstate vn-isp-1
python -m ipguard -c ipguard.toml resolve order_789
```

Cảnh báo: truyền `on_alert=callable` để nhận sự kiện `ip_retired`, `breaker_open`,
`health_issue`, `ip_changed`, `proxy_cooldown` (nối vào Slack/Telegram/email).

## Nguồn IP

- Dùng IP **ISP hoặc residential cố định (sticky), trả phí, cùng quốc gia với nhà hàng**.
  Với gateway kiểu `user-session-XYZ`, mỗi session id cố định là một `[[proxy]]`.
- Không dùng proxy miễn phí: dữ liệu khách (tên, SĐT, đặt cọc) đi qua máy người lạ.
- IP datacenter chỉ nên dùng cho domain không có chống bot (hệ số ưu tiên 0.5).
- Khối lượng đặt bàn thấp: vài chục IP là đủ, không cần pool xoay hàng nghìn IP.
- Kiểm tra proxy gọi `geo_url` (mặc định `https://ipinfo.io/json`) qua từng proxy để biết IP ra
  và quốc gia. Request này không chứa dữ liệu khách. Proxy SOCKS cần truyền `fetch` riêng.

## Giới hạn có chủ đích

Module này **không** xoay IP để vượt chặn, **không** giải CAPTCHA, **không** đổi IP khi bị 429,
**không** tiếp tục khi cầu dao mở, và **không** gửi lại form sau khi đã submit.
Các nền tảng mà ToS cấm tự động hóa nên đi qua API đối tác hoặc deep link, không đi qua đây.

## Chưa có (phía ứng dụng phải lo)

- **Giữ phiên cho `handoff_user`:** `run()` kết thúc thì trình duyệt cũng đóng; muốn người dùng
  giải CAPTCHA trên đúng phiên đó thì ứng dụng phải giữ phiên mở hoặc gửi link.
- **Kiểm tra trạng thái sau `failed`:** tra email xác nhận hoặc trang tra cứu, xong mới `resolve`.
- **Launcher CloakBrowser / Camoufox:** `guarded_page` mới có sẵn Chrome qua Patchright/Playwright.
  Engine khác truyền qua `launchers={...}`. Tên tham số trong `cloakbrowser_kwargs` cần đối
  chiếu với phiên bản bạn ghim.
- **Rò rỉ WebRTC/DNS** trong trình duyệt chưa được kiểm tra (mới kiểm tra timezone + ngôn ngữ).
- **Mã 4xx khác** (404, 400…) đang được tính là OK. **Ngày** tính hạn mức theo giờ Việt Nam.

## Test

```
python -m pytest -q                                   # 54 test, không cần mạng hay Redis
IPGUARD_E2E=1 python -m pytest -q tests/test_e2e_browser.py   # 7 test trên Chrome thật,
                                                      # với website đặt bàn giả lập chạy ở máy
```

**Chạy thử không gửi gì:** `AntiBan(..., dry_run=True)` hoặc `ab.book(..., dry_run=True)`.
Flow chạy bình thường tới `s.mark_submitted()` thì dừng, trả `outcome="dry_run"`, không bấm gửi
và không khóa `request_id`.

**Benchmark chỉ đọc trên trang thật:** `python bench_sites.py sites.txt [-c ipguard.toml]`.
Script tải trang chủ và trang đặt bàn, ghi tín hiệu, chụp màn hình, đếm ô form vào `bench_out/`.
Không điền và không gửi gì. Tự bỏ qua các nền tảng trung gian. Không có `-c` thì đi thẳng bằng IP
máy (`url = "direct"`), chỉ dùng để thử.

Chưa chạy qua proxy hay Redis thật.
