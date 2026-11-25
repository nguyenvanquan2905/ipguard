"""Ví dụ: một lượt đặt bàn trên website riêng của nhà hàng, có ipguard bảo vệ.

pip install -e .[browser] && patchright install chrome
cp ipguard.example.toml ipguard.toml   # rồi khai báo proxy (mật khẩu trong biến môi trường)
"""
import asyncio

from ipguard import AntiBan
from ipguard.adapters import check_issues, guarded_goto, guarded_page


def booking_flow(req):
    async def flow(s):
        from patchright.async_api import async_playwright
        async with async_playwright() as pw:
            # profile theo (user, domain), proxy + timezone + ngôn ngữ khớp IP, kiểm tra geo
            async with guarded_page(pw, s) as (page, issues):
                await guarded_goto(page, s, req["url"], issues)
                await s.human_pause()
                await page.get_by_label("Số khách").fill(str(req["party"]))
                await s.human_pause()
                await page.get_by_label("Ngày").fill(req["date"])
                await page.get_by_label("Giờ").select_option(req["time"])
                await page.get_by_label("Họ tên").fill(req["name"])
                await page.get_by_label("Điện thoại").fill(req["phone"])
                await s.human_pause()

                s.mark_submitted()                       # từ đây không tự thử lại
                await s.before_navigation()
                await page.get_by_role("button", name="Đặt bàn").click()
                await page.wait_for_load_state("domcontentloaded")
                await check_issues(issues)               # chờ handler đọc xong response
                if await page.get_by_text("Đặt bàn thành công").count():
                    s.mark_booked()
                    return await page.locator(".booking-ref").inner_text()
                return None
    return flow


def alert(ev):
    # nối vào Slack/Telegram/email tùy hệ thống
    print("[ipguard]", ev["kind"], {k: v for k, v in ev.items() if k not in ("ts", "kind")})


async def main():
    req = {"url": "https://nhahang-vidu.vn/dat-ban", "party": 4, "date": "2026-11-28",
           "time": "19:00", "name": "Nguyễn Văn A", "phone": "09xxxxxxxx"}
    ab = AntiBan.from_config("ipguard.toml", on_alert=alert)
    async with ab:
        r = await ab.book("nhahang-vidu.vn", user_id="u_123", flow=booking_flow(req),
                          country="VN", request_id="order_789")
    print(r.outcome, r.detail, r.value)
    for row in r.log:
        print("  ", row)
    # deeplink     -> gửi link điền sẵn cho người dùng tự đặt
    # handoff_user -> người dùng giải CAPTCHA
    # failed       -> KIỂM TRA trạng thái đặt bàn; chưa đặt thì `python -m ipguard resolve order_789`


if __name__ == "__main__":
    asyncio.run(main())
