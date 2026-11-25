"""Benchmark CHỈ ĐỌC trên trang đặt bàn thật: tải trang chủ + trang đặt bàn qua ipguard,
ghi tín hiệu (OK / challenge / CAPTCHA / chặn), chụp màn hình, đếm ô form.

KHÔNG điền form, KHÔNG gửi gì (luôn chạy dry_run). Mỗi trang 1 lượt, theo nhịp ipguard.
Chỉ dùng cho website riêng của nhà hàng, không dùng cho nền tảng cấm tự động hóa.

    python bench_sites.py sites.txt                 # đi thẳng bằng IP máy này
    python bench_sites.py sites.txt -c ipguard.toml # đi qua proxy trong cấu hình
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from urllib.parse import urlsplit

from ipguard import AntiBan, ProxyEndpoint, classify
from ipguard.adapters import _GEO, context_kwargs, guarded_goto, guarded_page
from ipguard.health import DEFAULT_GEO_URL, parse_geo, urllib_fetch

BLOCKLIST = ("pasgo.vn", "tablecheck.com", "opentable.", "thefork.", "resy.com",
             "pato.com.vn", "diningcity.")


async def _chrome(pw, s, profile_dir, headless):
    return await pw.chromium.launch_persistent_context(
        profile_dir, channel="chrome", headless=headless, **context_kwargs(s.proxy))


def read_sites(path: str) -> list[str]:
    out = []
    for line in open(path, encoding="utf-8"):
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        if any(b in line for b in BLOCKLIST):
            print(f"bỏ qua (nền tảng trung gian): {line}")
            continue
        out.append(line)
    return out


def site_flow(url: str, rec: dict, out_dir: str, headless: bool):
    u = urlsplit(url)
    home = f"{u.scheme}://{u.netloc}/"
    urls = [home] if url.rstrip("/") == home.rstrip("/") else [home, url]

    async def flow(s):
        from playwright.async_api import async_playwright
        rec["ip"], rec["engine"] = s.proxy.id, s.engine
        async with async_playwright() as pw:
            async with guarded_page(pw, s, profile_root=os.path.join(out_dir, "profiles"),
                                    launchers={"chrome": _chrome}, headless=headless) as (page, issues):
                def on_resp(resp):
                    try:
                        if resp.request.resource_type == "document" and resp.frame == page.main_frame:
                            h = resp.headers
                            rec["docs"].append({"url": resp.url[:120], "status": resp.status,
                                                "server": h.get("server", ""),
                                                "cf": bool(h.get("cf-ray"))})
                    except Exception:
                        pass
                page.on("response", on_resp)
                try:
                    for target in urls:
                        await guarded_goto(page, s, target, issues, wait_until="domcontentloaded",
                                           timeout=45_000)
                        await page.wait_for_timeout(2500)     # để challenge JS (nếu có) hiện ra
                        await s.human_pause()
                finally:
                    rec["title"] = (await page.title())[:80]
                    rec["final_url"] = page.url[:120]
                    shot = os.path.join(out_dir, f"{_slug(url)}.png")
                    await page.screenshot(path=shot)
                    rec["screenshot"] = shot
                    html = await page.content()
                    rec["rendered_signal"] = classify(200, {}, html).signal.value
                    rec["form"] = await page.evaluate("""() => ({
                        inputs: document.querySelectorAll('input:not([type=hidden]),select,textarea').length,
                        forms: document.forms.length,
                        recaptcha: !!document.querySelector('.g-recaptcha,iframe[src*="recaptcha"]'),
                        turnstile: !!document.querySelector('.cf-turnstile,iframe[src*="challenges.cloudflare"]'),
                        hcaptcha: !!document.querySelector('iframe[src*="hcaptcha"]')})""")
                s.mark_submitted()        # dry_run -> dừng ở đây, không bấm gì
    return flow


def _slug(url: str) -> str:
    return "".join(c if c.isalnum() else "_" for c in url.split("://", 1)[-1])[:60]


async def detect_country() -> tuple[str, str]:
    status, body = await urllib_fetch("direct", DEFAULT_GEO_URL, 15)
    return parse_geo(body) if status == 200 else ("", "")


async def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("sites")
    ap.add_argument("-c", "--config", help="ipguard.toml (proxy); bỏ trống = IP máy này")
    ap.add_argument("-o", "--out", default="bench_out")
    ap.add_argument("--show", action="store_true", help="hiện cửa sổ trình duyệt")
    a = ap.parse_args(argv)
    os.makedirs(a.out, exist_ok=True)
    sites = read_sites(a.sites)

    if a.config:
        ab = AntiBan.from_config(a.config, dry_run=True, engines=("chrome",))
        country = None
    else:
        ip, country = await detect_country()
        if country not in _GEO:
            print(f"IP máy {ip} ở {country or '?'}: chưa có timezone/locale mặc định, dùng UTC")
        print(f"Đi thẳng bằng IP máy này ({ip}, {country}).")
        ab = AntiBan([ProxyEndpoint("may-nay", "direct", country or "VN", "residential",
                                    added_at=time.time() - 30 * 86400)],
                     dry_run=True, engines=("chrome",),
                     state_path=os.path.join(a.out, "state.json"))

    results = []
    async with ab:
        for url in sites:
            rec = {"site": url, "docs": []}
            t0 = time.time()
            r = await ab.book(urlsplit(url).hostname, "bench", site_flow(url, rec, a.out, not a.show),
                              country=country)
            rec.update(outcome=r.outcome, detail=r.detail, log=r.log, seconds=round(time.time() - t0, 1))
            results.append(rec)
            sig = r.log[-1][2] if r.log else "-"
            print(f"{r.outcome:<12} {sig:<15} {url}  {r.detail[:70] if r.outcome != 'dry_run' else ''}")
        rep = await ab.report()

    with open(os.path.join(a.out, "results.json"), "w", encoding="utf-8") as f:
        json.dump({"results": results, "report": rep}, f, ensure_ascii=False, indent=2)
    print(f"\nChi tiết: {os.path.join(a.out, 'results.json')}")


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    asyncio.run(main(sys.argv[1:]))
