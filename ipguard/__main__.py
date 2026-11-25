"""CLI quản trị:

    python -m ipguard -c ipguard.toml report [--json]
    python -m ipguard -c ipguard.toml check
    python -m ipguard -c ipguard.toml reinstate <ip_id>
    python -m ipguard -c ipguard.toml resolve <request_id>
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time

from .antiban import AntiBan


def _ago(ts: float, now: float) -> str:
    s = max(0, int(now - ts))
    return f"{s // 3600}h{(s % 3600) // 60:02d}" if s >= 3600 else f"{s // 60}m{s % 60:02d}"


def format_report(r: dict) -> str:
    now = r["at"]
    lines = ["IP:"]
    lines.append(f"  {'id':<14}{'nước':<6}{'loại':<12}{'điểm':>5}  {'hôm nay':>7}  "
                 f"{'đang chạy':>9}  trạng thái")
    for ip in r["ips"]:
        status = ("LOẠI: " + ip["reason"]) if ip["retired"] else \
            ("CHẶN: " + ip["health"]) if ip["health"] else "ok"
        if ip["blocked_on"] and not ip["retired"]:
            status += f" (bị chặn ở {', '.join(ip['blocked_on'])})"
        lines.append(f"  {ip['ip']:<14}{ip['country']:<6}{ip['kind']:<12}{ip['score']:>5}  "
                     f"{ip['bookings_today']:>7}  {ip['active']:>9}  {status}")
    lines.append("")
    lines.append("Domain:")
    for dm, d in r["domains"].items():
        oc = ", ".join(f"{k}={v}" for k, v in sorted(d.get("outcomes", {}).items())) or "-"
        extra = f", tạm dừng {d['paused_s']}s" if d["paused_s"] else ""
        lines.append(f"  {dm}: cầu dao {d['breaker']}, {d['rpm']} lượt/phút{extra}, "
                     f"{d['active_sessions']} phiên | challenge {d.get('challenge_rate', 0):.0%}, "
                     f"captcha {d.get('captcha_rate', 0):.0%}, chặn {d.get('block_rate', 0):.0%}"
                     f" | {oc}")
    if r["pending_requests"]:
        lines.append("")
        lines.append("Đã submit, chưa rõ kết quả (kiểm tra rồi `resolve`): "
                     + ", ".join(r["pending_requests"]))
    if r["events"]:
        lines.append("")
        lines.append("Sự kiện gần đây:")
        for ev in r["events"][-15:]:
            rest = ", ".join(f"{k}={v}" for k, v in ev.items() if k not in ("ts", "kind"))
            lines.append(f"  {_ago(ev['ts'], now):>6} trước  {ev['kind']}  {rest}")
    return "\n".join(lines)


async def _main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="python -m ipguard")
    ap.add_argument("-c", "--config", default="ipguard.toml")
    sub = ap.add_subparsers(dest="cmd", required=True)
    rp = sub.add_parser("report", help="tình trạng IP, domain, sự kiện")
    rp.add_argument("--json", action="store_true")
    sub.add_parser("check", help="kiểm tra tất cả proxy ngay")
    p = sub.add_parser("reinstate", help="đưa lại IP đã bị loại")
    p.add_argument("ip_id")
    p = sub.add_parser("resolve", help="xác nhận lượt đã submit thực ra chưa được đặt")
    p.add_argument("request_id")
    a = ap.parse_args(argv)

    ab = AntiBan.from_config(a.config)
    if a.cmd == "report":
        r = await ab.report()
        print(json.dumps(r, ensure_ascii=False, indent=2) if a.json else format_report(r))
    elif a.cmd == "check":
        for res in await ab.check_proxies(force=True):
            print(f"{res.ip_id:<14} {'OK ' if res.ok and not res.issues else 'LỖI'} "
                  f"{res.exit_ip or '-':<16} {res.country or '-':<3} "
                  f"{'; '.join(res.issues) or res.error}")
    elif a.cmd == "reinstate":
        if a.ip_id not in ab.pool.proxies:
            print(f"không có IP {a.ip_id}", file=sys.stderr)
            return 2
        await ab.reinstate(a.ip_id)
        print(f"đã đưa lại {a.ip_id} (chạy lại warm-up)")
    elif a.cmd == "resolve":
        await ab.resolve(a.request_id)
        print(f"đã gỡ khóa {a.request_id}")
    return 0


def main() -> None:
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    raise SystemExit(asyncio.run(_main(sys.argv[1:])))


if __name__ == "__main__":
    main()
