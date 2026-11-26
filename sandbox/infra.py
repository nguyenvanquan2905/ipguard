"""Hạ tầng sandbox để test ipguard với agent trình duyệt — chạy hoàn toàn trên máy, khép kín.

Gồm 3 phần, đều là stdlib:

1. **Website đặt bàn giả lập** (1 HTTP server, nhiều "nhà hàng" theo Host `<kịch bản>.sandbox.test`).
   Mỗi kịch bản mô phỏng một phản ứng chống bot: Cloudflare challenge, DataDome CAPTCHA, chặn cứng,
   429, 503, chặn sau khi submit, cấm theo IP… Site ghi lại *sự thật* (ground truth): request nào,
   từ IP ra nào, form nào đã POST, timezone/ngôn ngữ trình duyệt báo về.
2. **Proxy giả lập** (mỗi cổng = 1 "IP ra" cố định + quốc gia). Proxy gắn header
   `X-Sandbox-Egress` để site biết request đi từ "IP" nào. Proxy CHỈ chuyển tiếp tới
   `*.sandbox.test`, mọi host khác bị từ chối: trình duyệt trong sandbox không ra được Internet.
3. **Dịch vụ tra IP** `http://geo.sandbox.test/json` (giống ipinfo.io) để HealthChecker của ipguard
   kiểm tra IP ra/quốc gia qua từng proxy.

    sb = Sandbox.start(); ...; sb.stop()
    python -m sandbox.infra          # chạy tay để xem bằng trình duyệt
"""
from __future__ import annotations

import asyncio
import html
import json
import socket
import threading
import time
import uuid
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional
from urllib.parse import parse_qs, urlsplit

SUFFIX = ".sandbox.test"
EGRESS_HEADER = "X-Sandbox-Egress"


# ======================================================================
# Proxy giả lập
# ======================================================================
@dataclass
class Egress:
    id: str
    ip: str
    country: str              # quốc gia mà "IP ra" này thực sự mang (geo service trả về)
    port: int = 0
    dead: bool = False        # không mở cổng: mô phỏng proxy chết


# Danh tính mặc định. px-vn-geo khai báo VN với ipguard nhưng ra bằng IP SG (lệch geo);
# px-vn-dead không có ai nghe ở cổng (proxy chết). HealthChecker phải loại cả hai.
DEFAULT_EGRESS = [
    Egress("px-vn-1", "203.0.113.11", "VN"),
    Egress("px-vn-2", "203.0.113.12", "VN"),
    Egress("px-vn-3", "203.0.113.13", "VN"),
    Egress("px-vn-4", "203.0.113.14", "VN"),
    Egress("px-vn-geo", "198.51.100.7", "SG"),
    Egress("px-vn-dead", "203.0.113.99", "VN", dead=True),
]


class _ProxyServer:
    """Proxy HTTP forward tối giản (absolute-form GET/POST). Không hỗ trợ CONNECT (HTTPS):
    trả 403 để trình duyệt rơi về http và để không có đường hầm nào ra ngoài."""

    def __init__(self, egress: Egress, site_port: int, log: list):
        self.e, self.site_port, self.log = egress, site_port, log
        self.server: Optional[asyncio.base_events.Server] = None

    async def start(self, loop_host="127.0.0.1"):
        self.server = await asyncio.start_server(self._client, loop_host, self.e.port)

    async def _client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            while True:
                head = await reader.readuntil(b"\r\n\r\n")
                lines = head.decode("latin-1").split("\r\n")
                method, target, version = lines[0].split(" ", 2)
                headers = [ln.split(":", 1) for ln in lines[1:] if ":" in ln]
                hmap = {k.strip().lower(): v.strip() for k, v in headers}
                body = b""
                if int(hmap.get("content-length", "0") or 0):
                    body = await reader.readexactly(int(hmap["content-length"]))
                if method == "CONNECT":
                    host = target.split(":")[0]
                    self.log.append({"ts": time.time(), "egress": self.e.id, "method": method,
                                     "host": host, "refused": True})
                    await self._reply(writer, 403, "sandbox: HTTPS/CONNECT không được phép")
                    return
                u = urlsplit(target)
                host = (u.hostname or hmap.get("host", "")).lower()
                if not host.endswith(SUFFIX):
                    self.log.append({"ts": time.time(), "egress": self.e.id, "method": method,
                                     "host": host, "refused": True})
                    await self._reply(writer, 403, f"sandbox: host {host} nằm ngoài sandbox")
                    return
                path = (u.path or "/") + (f"?{u.query}" if u.query else "")
                out = [f"{method} {path} HTTP/1.1", f"Host: {host}", "Connection: close"]
                for k, v in headers:
                    kl = k.strip().lower()
                    if kl in ("host", "connection", "proxy-connection", "keep-alive",
                              "proxy-authorization") or kl.startswith("x-sandbox-"):
                        continue
                    out.append(f"{k.strip()}: {v.strip()}")
                out.append(f"{EGRESS_HEADER}: {self.e.ip}|{self.e.country}|{self.e.id}")
                r2, w2 = await asyncio.open_connection("127.0.0.1", self.site_port)
                w2.write(("\r\n".join(out) + "\r\n\r\n").encode("latin-1") + body)
                await w2.drain()
                resp = await r2.read()
                w2.close()
                # trả nguyên response; site luôn gửi Connection: close -> đóng sau mỗi request
                writer.write(resp)
                await writer.drain()
                return
        except (asyncio.IncompleteReadError, ConnectionError, ValueError):
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass

    @staticmethod
    async def _reply(writer, code: int, text: str):
        data = text.encode("utf-8")
        writer.write(f"HTTP/1.1 {code} X\r\nContent-Type: text/plain; charset=utf-8\r\n"
                     f"Content-Length: {len(data)}\r\nConnection: close\r\n\r\n".encode() + data)
        await writer.drain()


class _LeakTrap:
    """Đích của HTTP_PROXY/HTTPS_PROXY trong process chạy agent: request nào tới đây là request
    KHÔNG đi qua trình duyệt/proxy của lease (vd. http_get() trong REPL của agent) -> ghi lại, từ chối."""

    def __init__(self, port: int, log: list):
        self.port, self.log = port, log
        self.server = None

    async def start(self):
        self.server = await asyncio.start_server(self._client, "127.0.0.1", self.port)

    async def _client(self, reader, writer):
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 10)
            line = head.decode("latin-1").split("\r\n")[0]
            self.log.append({"ts": time.time(), "request": line})
            await _ProxyServer._reply(writer, 403, "sandbox: request đi vòng qua ipguard")
        except Exception:
            pass
        finally:
            writer.close()


# ======================================================================
# Website đặt bàn giả lập
# ======================================================================
# Kịch bản: host "<tên>.sandbox.test". Hai biến thể form để agent LLM phải tự hiểu trang.
SCENARIOS = {
    "ok":           "Đặt bàn 2 bước (chọn giờ -> thông tin khách), thành công",
    "en":           "Form 1 trang, nhãn tiếng Anh, thành công",
    "cf":           "Mọi trang: Cloudflare challenge (403 + cf-ray)",
    "captcha":      "Mọi trang: DataDome CAPTCHA",
    "blocked":      "Mọi trang: chặn cứng 403 Access denied",
    "ratelimit":    "Mọi trang: 429 Retry-After: 5",
    "down":         "Mọi trang: 503 site lỗi (không phải anti-bot)",
    "ipban":        "Cấm IP ra ĐẦU TIÊN ghé thăm; IP khác vào bình thường",
    "midblock":     "Bước 1 OK, bước 2 (thông tin khách) bị chặn 403 — trước submit",
    "afterblock":   "Form OK, POST xác nhận bị chặn 403 — sau submit",
    "aftercaptcha": "Form OK, POST xác nhận ra CAPTCHA — sau submit",
    "walls":        "Chặn MỌI IP: dùng để test cầu dao domain",
}

_CSS = ("body{font-family:system-ui,sans-serif;max-width:560px;margin:32px auto;padding:0 16px}"
        "label{display:block;margin-top:12px}input,select{width:100%;padding:6px;font-size:15px}"
        "button{margin-top:18px;padding:10px 18px;font-size:15px}.note{color:#666}")

# Trình duyệt báo timezone/ngôn ngữ về site (site thật cũng thu như vậy để chấm điểm bot).
_BEACON = """<script>
fetch('/__beacon',{method:'POST',headers:{'Content-Type':'application/json'},
 body:JSON.stringify({tz:Intl.DateTimeFormat().resolvedOptions().timeZone,
 lang:navigator.language,wd:navigator.webdriver===true,path:location.pathname})}).catch(()=>{});
</script>"""


def _page(title: str, body: str) -> str:
    return (f"<!doctype html><html lang='vi'><head><meta charset='utf-8'><title>{title}</title>"
            f"<style>{_CSS}</style></head><body>{body}{_BEACON}</body></html>")


def _step1(name: str) -> str:
    return _page(f"Đặt bàn — {name}", f"""<h1>{name}</h1><h2>Đặt bàn — bước 1/2</h2>
<form method="get" action="/dat-ban/thong-tin">
<label for="party">Số khách</label><input id="party" name="party" type="number" min="1" max="20">
<label for="date">Ngày</label><input id="date" name="date" type="date">
<label for="time">Giờ</label><select id="time" name="time">
<option value="">-- chọn giờ --</option><option>18:00</option><option>18:30</option>
<option>19:00</option><option>19:30</option><option>20:00</option></select>
<button type="submit">Tiếp tục</button></form>""")


def _step2(name: str, q: dict, action: str) -> str:
    hidden = "".join(f"<input type='hidden' name='{k}' value='{html.escape(v)}'>"
                     for k, v in q.items())
    return _page(f"Thông tin khách — {name}", f"""<h1>{name}</h1><h2>Đặt bàn — bước 2/2</h2>
<p class="note">{html.escape(q.get('party', '?'))} khách, {html.escape(q.get('date', '?'))}
lúc {html.escape(q.get('time', '?'))}</p>
<form method="post" action="{action}">{hidden}
<label for="name">Họ tên</label><input id="name" name="name">
<label for="phone">Điện thoại</label><input id="phone" name="phone" type="tel">
<label for="note">Ghi chú</label><input id="note" name="note">
<button type="submit">Xác nhận đặt bàn</button></form>""")


def _english(name: str) -> str:
    return _page(f"Reservations — {name}", f"""<h1>{name}</h1><h2>Book a table</h2>
<form method="post" action="/reserve">
<label for="g">Guests</label><input id="g" name="party" type="number">
<label for="dt">Date</label><input id="dt" name="date" type="date">
<label for="tm">Time</label><select id="tm" name="time"><option value="">--</option>
<option>18:00</option><option>19:00</option><option>20:00</option></select>
<label for="fn">Full name</label><input id="fn" name="name">
<label for="tel">Phone number</label><input id="tel" name="phone">
<button type="submit">Confirm reservation</button></form>""")


CF_BODY = ("<!doctype html><html><head><title>Just a moment...</title></head><body>"
           "<h1>Checking your browser before accessing the site.</h1>"
           "<script src='/cdn-cgi/challenge-platform/h/b/orchestrate/jsch/v1'></script>"
           "</body></html>")
DD_BODY = ("<html><head><title>Verification</title></head><body>"
           "<script src='https://geo.captcha-delivery.com/captcha/?initialCid=x'></script>"
           "<p>Please verify you are a human</p></body></html>")
BLOCK_BODY = "<html><body><h1>Access denied</h1><p>You don't have permission.</p></body></html>"


@dataclass
class SiteState:
    requests: list = field(default_factory=list)      # mọi request tới site
    bookings: list = field(default_factory=list)      # mọi POST xác nhận (kể cả bị chặn)
    beacons: list = field(default_factory=list)       # timezone/ngôn ngữ trình duyệt báo về
    first_egress: dict = field(default_factory=dict)  # host -> IP ra đầu tiên (kịch bản ipban)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def reset(self):
        with self.lock:
            self.requests.clear(); self.bookings.clear(); self.beacons.clear()
            self.first_egress.clear()

    def snapshot(self, host: Optional[str] = None) -> dict:
        with self.lock:
            f = (lambda r: r.get("host") == host) if host else (lambda r: True)
            return {"requests": [r for r in self.requests if f(r)],
                    "bookings": [b for b in self.bookings if f(b)],
                    "beacons": [b for b in self.beacons if f(b)]}


def _make_handler(state: SiteState):
    class Site(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        # ---------- tiện ích ----------
        @property
        def host(self) -> str:
            return (self.headers.get("Host") or "").split(":")[0].lower()

        @property
        def egress(self) -> tuple[str, str, str]:
            raw = self.headers.get(EGRESS_HEADER)
            if not raw:
                return ("direct", "", "direct")
            ip, cc, pid = (raw.split("|") + ["", ""])[:3]
            return ip, cc, pid

        def _send(self, code: int, body: str, headers=(), ctype="text/html; charset=utf-8"):
            data = body.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Connection", "close")
            for k, v in headers:
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)
            self.close_connection = True
            rec = getattr(self, "_rec", None)
            if rec is not None:
                with state.lock:
                    rec["status"] = code

        def _record(self, method: str, body: str = ""):
            ip, cc, pid = self.egress
            rec = {"ts": time.time(), "host": self.host, "method": method, "path": self.path,
                   "egress_ip": ip, "egress_country": cc, "proxy_id": pid,
                   "accept_language": self.headers.get("Accept-Language", ""),
                   "user_agent": self.headers.get("User-Agent", ""),
                   "sec_ch_ua": self.headers.get("Sec-CH-UA", ""),
                   "dest": self.headers.get("Sec-Fetch-Dest", ""),   # chỉ có trên https
                   "accept": self.headers.get("Accept", ""), "status": None}
            # http không có Sec-Fetch-*: nhận diện lượt tải trang bằng Accept: text/html
            rec["document"] = (method == "GET" and "text/html" in rec["accept"]
                               and not self.path.startswith("/favicon"))
            with state.lock:
                state.requests.append(rec)
            self._rec = rec
            return rec

        def _scenario(self) -> str:
            h = self.host
            return h[: -len(SUFFIX)] if h.endswith(SUFFIX) else ""

        def _antibot(self, scn: str) -> bool:
            """True nếu đã trả lời bằng một phản ứng chống bot (áp cho mọi trang)."""
            if scn == "cf":
                self._send(403, CF_BODY, [("Server", "cloudflare"), ("cf-ray", "8a1b2c3d4e-SIN"),
                                          ("cf-mitigated", "challenge")])
            elif scn == "captcha":
                self._send(403, DD_BODY, [("x-datadome", "protected"), ("Server", "nginx")])
            elif scn in ("blocked", "walls"):
                self._send(403, BLOCK_BODY)
            elif scn == "ratelimit":
                self._send(429, "Too many requests", [("Retry-After", "5")], "text/plain")
            elif scn == "down":
                self._send(503, "<html><body><h1>Service Unavailable</h1>"
                                "<p>Hệ thống đang bảo trì.</p></body></html>")
            elif scn == "ipban":
                ip = self.egress[0]
                with state.lock:
                    first = state.first_egress.setdefault(self.host, ip)
                if ip == first:
                    self._send(403, BLOCK_BODY)
                else:
                    return False
            else:
                return False
            return True

        # ---------- GET ----------
        def do_GET(self):
            self._record("GET")
            h, scn = self.host, self._scenario()
            u = urlsplit(self.path)
            if h == "geo" + SUFFIX:                       # dịch vụ tra IP kiểu ipinfo.io
                ip, cc, _ = self.egress
                return self._send(200, json.dumps({"ip": ip, "country": cc, "org": "AS64500 Sandbox"}),
                                  ctype="application/json")
            if scn not in SCENARIOS:
                return self._send(404, _page("404", f"<h1>Không có nhà hàng {html.escape(h)}</h1>"))
            if u.path == "/favicon.ico":
                return self._send(404, "")
            if self._antibot(scn):
                return
            name = f"Nhà hàng Sandbox «{scn}»"
            if u.path in ("/", ""):
                return self._send(200, _page(name, f"<h1>{name}</h1><p>Món Việt, mở cửa 17h–22h."
                                                   f"</p><p><a href='/dat-ban'>Đặt bàn</a></p>"))
            if scn == "en":
                if u.path in ("/dat-ban", "/reserve"):
                    return self._send(200, _english(name))
            elif u.path == "/dat-ban":
                return self._send(200, _step1(name))
            elif u.path == "/dat-ban/thong-tin":
                if scn == "midblock":
                    return self._send(403, BLOCK_BODY)
                q = {k: v[0] for k, v in parse_qs(u.query).items()}
                if not all(q.get(k) for k in ("party", "date", "time")):
                    return self._send(200, _page(name, "<h1>Thiếu thông tin</h1><p>Vui lòng chọn "
                                                       "số khách, ngày và giờ. <a href='/dat-ban'>"
                                                       "Quay lại</a></p>"))
                return self._send(200, _step2(name, q, "/xac-nhan"))
            return self._send(404, _page("404", "<h1>Không tìm thấy trang</h1>"))

        # ---------- POST ----------
        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0) or 0)
            raw = self.rfile.read(n).decode("utf-8", "replace")
            self._record("POST")
            h, scn = self.host, self._scenario()
            if self.path == "/__beacon":
                try:
                    data = json.loads(raw)
                except ValueError:
                    data = {}
                ip, cc, pid = self.egress
                with state.lock:
                    state.beacons.append({"ts": time.time(), "host": h, "egress_country": cc,
                                          "proxy_id": pid, **data})
                return self._send(204, "")
            form = {k: v[0] for k, v in parse_qs(raw).items()}
            if scn not in SCENARIOS or self.path not in ("/xac-nhan", "/reserve"):
                return self._send(404, _page("404", "<h1>Không tìm thấy</h1>"))
            ip, cc, pid = self.egress
            rec = {"ts": time.time(), "host": h, "egress_ip": ip, "proxy_id": pid, "form": form}
            with state.lock:
                dup = any(b["host"] == h and b.get("accepted") and
                          b["form"].get("phone") == form.get("phone") and
                          b["form"].get("date") == form.get("date") for b in state.bookings)
                state.bookings.append(rec)
            if self._antibot(scn):
                return
            if scn == "afterblock":
                return self._send(403, BLOCK_BODY)
            if scn == "aftercaptcha":
                return self._send(403, DD_BODY, [("x-datadome", "protected")])
            missing = [k for k in ("party", "date", "time", "name", "phone") if not form.get(k)]
            if missing:
                return self._send(200, _page("Thiếu thông tin", "<h1>Thiếu thông tin</h1><p>Còn "
                                             f"thiếu: {', '.join(missing)}</p>"))
            ref = "SBX-" + uuid.uuid4().hex[:6].upper()
            rec.update(accepted=True, ref=ref, duplicate=dup)
            return self._send(200, _page("Thành công", f"<h1>Đặt bàn thành công</h1>"
                                         f"<p>Mã đặt bàn: <span class='booking-ref'>{ref}</span></p>"
                                         f"<p>{html.escape(form.get('name', ''))} — "
                                         f"{html.escape(form.get('party', ''))} khách, "
                                         f"{html.escape(form.get('date', ''))} "
                                         f"{html.escape(form.get('time', ''))}</p>"))
    return Site


# ======================================================================
# Ghép lại
# ======================================================================
def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Sandbox:
    def __init__(self, egress: list[Egress], site_port: int):
        self.egress = egress
        self.site_port = site_port
        self.state = SiteState()
        self.proxy_log: list = []
        self._httpd: Optional[ThreadingHTTPServer] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._threads: list[threading.Thread] = []
        self._proxies: list[_ProxyServer] = []
        self.leak_port = _free_port()
        self.leaks: list = []          # request đi vòng (không qua trình duyệt của lease)
        self._trap: Optional[_LeakTrap] = None

    @classmethod
    def start(cls, egress: Optional[list[Egress]] = None, site_port: int = 0,
              proxy_base_port: int = 0) -> "Sandbox":
        egress = [Egress(**vars(e)) for e in (egress or DEFAULT_EGRESS)]
        for i, e in enumerate(egress):
            e.port = (proxy_base_port + i) if proxy_base_port else _free_port()
        sb = cls(egress, site_port or _free_port())
        sb._httpd = ThreadingHTTPServer(("127.0.0.1", sb.site_port), _make_handler(sb.state))
        sb._httpd.daemon_threads = True
        t = threading.Thread(target=sb._httpd.serve_forever, daemon=True, name="sandbox-site")
        t.start()
        sb._threads.append(t)

        ready = threading.Event()

        def run_proxies():
            loop = asyncio.new_event_loop()
            sb._loop = loop
            asyncio.set_event_loop(loop)
            for e in egress:
                if not e.dead:
                    px = _ProxyServer(e, sb.site_port, sb.proxy_log)
                    loop.run_until_complete(px.start())
                    sb._proxies.append(px)
            sb._trap = _LeakTrap(sb.leak_port, sb.leaks)
            loop.run_until_complete(sb._trap.start())
            ready.set()
            loop.run_forever()

        t2 = threading.Thread(target=run_proxies, daemon=True, name="sandbox-proxies")
        t2.start()
        sb._threads.append(t2)
        ready.wait(10)
        return sb

    def stop(self):
        if self._httpd:
            self._httpd.shutdown()
            self._httpd.server_close()
        if self._loop:
            async def _close():
                for px in [*self._proxies, *([self._trap] if self._trap else [])]:
                    px.server.close()
                    await px.server.wait_closed()
            try:
                asyncio.run_coroutine_threadsafe(_close(), self._loop).result(5)
            except Exception:
                pass
            self._loop.call_soon_threadsafe(self._loop.stop)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.stop()

    # ---------- tiện ích ----------
    def proxy_url(self, egress_id: str) -> str:
        e = next(e for e in self.egress if e.id == egress_id)
        return f"http://127.0.0.1:{e.port}"

    def url(self, scenario: str, path: str = "/dat-ban") -> str:
        return f"http://{scenario}{SUFFIX}{path}"

    @staticmethod
    def domain(scenario: str) -> str:
        return f"{scenario}{SUFFIX}"

    @property
    def leak_proxy(self) -> str:
        return f"http://127.0.0.1:{self.leak_port}"

    @property
    def geo_url(self) -> str:
        return f"http://geo{SUFFIX}/json"


if __name__ == "__main__":
    sb = Sandbox.start(site_port=18080, proxy_base_port=18081)
    print(f"Site:   127.0.0.1:{sb.site_port} (chỉ vào được qua proxy, theo Host *.sandbox.test)")
    for e in sb.egress:
        print(f"Proxy {e.id:11s} {'(chết)' if e.dead else f'http://127.0.0.1:{e.port}'}"
              f"  -> IP ra {e.ip} ({e.country})")
    print("\nKịch bản:")
    for k, v in SCENARIOS.items():
        print(f"  http://{k}{SUFFIX}/dat-ban   {v}")
    print("\nVd: chrome --proxy-server=http://127.0.0.1:18081 http://ok.sandbox.test/dat-ban")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        sb.stop()
