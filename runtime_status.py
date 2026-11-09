#!/usr/bin/env python3
"""Read-only, dependency-free status page for a Linux container."""
from __future__ import annotations

import datetime as dt
import html
import ipaddress
import json
import math
import os
import re
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from shutil import disk_usage
from urllib.error import URLError
from urllib.request import Request, urlopen
from zoneinfo import ZoneInfo

CACHE_SECONDS = 5
_STARTED_AT = time.monotonic()
_CACHE_LOCK = threading.Lock()
_CACHE: dict[str, object] = {"at": 0.0, "data": None}

_MEMORY_USED_FILES = (
    "/sys/fs/cgroup/memory.current",
    "/sys/fs/cgroup/memory/memory.usage_in_bytes",
)
_MEMORY_LIMIT_FILES = (
    "/sys/fs/cgroup/memory.max",
    "/sys/fs/cgroup/memory/memory.limit_in_bytes",
)
SAFE_ENVIRONMENT_VARIABLES = (
    "SERVER_PORT",
    "PYTHONUNBUFFERED",
    "PYTHONDONTWRITEBYTECODE",
    "TZ",
)
_BOOLEAN_ENVIRONMENT_VALUES = {
    "PYTHONUNBUFFERED": {"1": True, "true": True, "yes": True, "on": True,
                         "0": False, "false": False, "no": False, "off": False, "": False},
    "PYTHONDONTWRITEBYTECODE": {"1": True, "true": True, "yes": True, "on": True,
                                "0": False, "false": False, "no": False, "off": False, "": False},
}
_PUBLIC_IP_URL = "https://api.ipify.org"


def read_text(path: str, limit: int = 128) -> str | None:
    """Read a small, fixed system file; return None when it is unavailable."""
    try:
        with open(path, "r", encoding="ascii", errors="replace") as stream:
            return stream.read(limit).strip()
    except (OSError, ValueError):
        return None


def get_hostname() -> str | None:
    """Return the system hostname, bounded to the conventional DNS name size."""
    try:
        value = socket.gethostname().strip()
    except OSError:
        return None
    return value[:255] or None


def get_local_ip() -> str | None:
    """Find the route-selected local address without sending a network packet."""
    targets = (
        (socket.AF_INET, ("198.51.100.1", 9)),
        (socket.AF_INET6, ("2001:db8::1", 9, 0, 0)),
    )
    for family, target in targets:
        try:
            with socket.socket(family, socket.SOCK_DGRAM) as sock:
                # UDP connect selects an interface/address; it does not transmit data.
                sock.connect(target)
                address = ipaddress.ip_address(sock.getsockname()[0])
                if not address.is_unspecified and not address.is_loopback:
                    return str(address)
        except (OSError, ValueError, IndexError):
            continue
    return None


def get_public_egress_ip() -> str | None:
    """Query a fixed HTTPS IP-echo endpoint; never send runtime or environment data."""
    request = Request(_PUBLIC_IP_URL, headers={"Accept": "text/plain"})
    try:
        with urlopen(request, timeout=2) as response:
            raw = response.read(65)
        if len(raw) > 64:
            return None
        return str(ipaddress.ip_address(raw.decode("ascii").strip()))
    except (OSError, URLError, ValueError, UnicodeError):
        return None


def collect_environment(environ=None) -> dict[str, object]:
    """Return a strict allowlist, normalizing values rather than copying arbitrary text."""
    source = os.environ if environ is None else environ
    result: dict[str, object] = {}

    raw_port = source.get("SERVER_PORT")
    if isinstance(raw_port, str) and re.fullmatch(r"[0-9]{1,5}", raw_port):
        port = int(raw_port)
        if 1 <= port <= 65535:
            result["SERVER_PORT"] = str(port)

    for name, accepted_values in _BOOLEAN_ENVIRONMENT_VALUES.items():
        raw_value = source.get(name)
        if isinstance(raw_value, str):
            normalized = accepted_values.get(raw_value.strip().lower())
            if normalized is not None:
                result[name] = normalized

    raw_timezone = source.get("TZ")
    if (isinstance(raw_timezone, str) and len(raw_timezone) <= 64
            and re.fullmatch(r"[A-Za-z0-9_+-]+(?:/[A-Za-z0-9_+-]+)*", raw_timezone)
            and all(part not in (".", "..") for part in raw_timezone.split("/"))):
        try:
            ZoneInfo(raw_timezone)
        except (KeyError, ValueError, OSError):
            pass
        else:
            result["TZ"] = raw_timezone
    return result


def _first_integer(paths: tuple[str, ...], *, allow_zero: bool) -> int | None:
    for path in paths:
        value = read_text(path)
        if not value or value == "max":
            continue
        try:
            number = int(value)
        except ValueError:
            continue
        if number < 0 or (number == 0 and not allow_zero):
            continue
        # Very large v1 sentinel values mean "unlimited", not a usable limit.
        if number >= 1 << 60:
            continue
        return number
    return None


def format_bytes(value: object) -> str:
    if isinstance(value, bool):
        return "不可用"
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError):
        return "不可用"
    if not math.isfinite(number) or number < 0:
        return "不可用"
    if number == 0:
        return "0 B"
    units = ("B", "KB", "MB", "GB", "TB")
    index = 0
    while number >= 1024 and index < len(units) - 1:
        number /= 1024
        index += 1
    if index and round(number, 2) >= 1024 and index < len(units) - 1:
        number /= 1024
        index += 1
    return f"{number:.2f} {units[index]}" if index else f"{number:.0f} B"


def percent(used: object, total: object) -> float | None:
    try:
        used_number, total_number = float(used), float(total)
    except (TypeError, ValueError, OverflowError):
        return None
    if (not math.isfinite(used_number) or not math.isfinite(total_number)
            or used_number < 0 or total_number <= 0):
        return None
    return round(min(100.0, used_number / total_number * 100), 1)


def collect_status() -> dict[str, object]:
    """Collect runtime metrics and explicitly approved, bounded environment details."""
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    uptime = max(0, int(time.monotonic() - _STARTED_AT))
    memory = {
        "used_bytes": _first_integer(_MEMORY_USED_FILES, allow_zero=True),
        "limit_bytes": _first_integer(_MEMORY_LIMIT_FILES, allow_zero=False),
    }
    try:
        usage = disk_usage("/")
        disk: dict[str, int | None] = {
            "used_bytes": int(usage.used),
            "available_bytes": int(usage.free),
            "total_bytes": int(usage.total),
        }
    except OSError:
        disk = {"used_bytes": None, "available_bytes": None, "total_bytes": None}

    return {
        "generated_at_utc": now.isoformat().replace("+00:00", "Z"),
        "service_uptime_seconds": uptime,
        "hostname": get_hostname(),
        "local_ip": get_local_ip(),
        "public_egress_ip": get_public_egress_ip(),
        "environment": collect_environment(),
        "memory": memory,
        "disk": disk,
    }


def status() -> dict[str, object]:
    with _CACHE_LOCK:
        now = time.monotonic()
        if _CACHE["data"] is None or now - float(_CACHE["at"]) >= CACHE_SECONDS:
            _CACHE["data"] = collect_status()
            _CACHE["at"] = now
        # The snapshot is composed of JSON-compatible primitives; round-trip to
        # prevent callers from mutating the shared cached dictionary.
        return json.loads(json.dumps(_CACHE["data"]))


def _metric(label: str, value: object) -> str:
    if value is None:
        shown = "不可用"
    elif isinstance(value, bool):
        shown = "是" if value else "否"
    else:
        shown = str(value)
    return (f'<div class="metric"><span>{html.escape(label)}</span>'
            f'<strong>{html.escape(shown)}</strong></div>')


def render_page(data: dict[str, object]) -> str:
    memory = data.get("memory") if isinstance(data.get("memory"), dict) else {}
    disk = data.get("disk") if isinstance(data.get("disk"), dict) else {}
    environment = data.get("environment") if isinstance(data.get("environment"), dict) else {}
    memory = memory or {}
    disk = disk or {}
    environment = environment or {}

    memory_pct = percent(memory.get("used_bytes"), memory.get("limit_bytes"))
    disk_pct = percent(disk.get("used_bytes"), disk.get("total_bytes"))
    mem_rate = f"{memory_pct:.1f}%" if memory_pct is not None else None
    disk_rate = f"{disk_pct:.1f}%" if disk_pct is not None else None

    memory_body = "".join((
        _metric("已用", format_bytes(memory.get("used_bytes"))),
        _metric("可见限制", format_bytes(memory.get("limit_bytes"))),
        _metric("使用率", mem_rate),
    ))
    disk_body = "".join((
        _metric("已用", format_bytes(disk.get("used_bytes"))),
        _metric("可用", format_bytes(disk.get("available_bytes"))),
        _metric("总量", format_bytes(disk.get("total_bytes"))),
        _metric("使用率", disk_rate),
    ))
    generated = data.get("generated_at_utc")
    uptime = data.get("service_uptime_seconds")
    try:
        uptime_text = f"{max(0, int(uptime))} 秒" if uptime is not None else None
    except (TypeError, ValueError, OverflowError):
        uptime_text = None
    overview = "".join((
        _metric("服务运行时间", uptime_text),
        _metric("快照时间（UTC）", generated),
    ))
    host_body = _metric("主机名", data.get("hostname"))
    network_body = "".join((
        _metric("本地 IP", data.get("local_ip")),
        _metric("公网出口 IP", data.get("public_egress_ip")),
    ))
    environment_labels = (
        ("SERVER_PORT", "服务端口"),
        ("PYTHONUNBUFFERED", "Python 无缓冲输出"),
        ("PYTHONDONTWRITEBYTECODE", "Python 不写入字节码"),
        ("TZ", "时区"),
    )
    environment_body = "".join(
        _metric(label, environment.get(key)) for key, label in environment_labels
    )

    return f'''<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark"><title>运行环境状态</title>
<style>
:root{{color-scheme:dark;background:#090d16;color:#e7edf8;font:16px system-ui,-apple-system,"Segoe UI",sans-serif}}
*{{box-sizing:border-box}}body{{max-width:900px;margin:auto;padding:clamp(1rem,4vw,2.5rem)}}
h1{{font-size:clamp(1.8rem,5vw,2.7rem);margin:.2rem 0;color:#fff}}
.intro{{color:#b4bfd1;line-height:1.6;margin-bottom:1.4rem}}
main{{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,280px),1fr));gap:1rem}}
section{{background:#111a29;border:1px solid #2a3951;border-radius:14px;padding:1.1rem}}
h2{{font-size:1.15rem;margin:0 0 .7rem;color:#a5c8ff}}
.metric{{display:flex;justify-content:space-between;gap:1rem;padding:.65rem 0;border-bottom:1px solid #263348;align-items:flex-start}}
.metric:last-child{{border:0}}.metric span{{color:#bac7da}}
.metric strong{{text-align:right;overflow-wrap:anywhere;color:#f4f7fc;font-weight:600}}
.foot{{margin-top:1.3rem;color:#b4bfd1;font-size:.92rem;line-height:1.6}}
a{{color:#9ac4ff}}
@media(max-width:430px){{.metric{{display:block}}.metric strong{{display:block;text-align:left;margin-top:.25rem}}}}
</style></head><body><header><h1>运行环境状态</h1>
<p class="intro">只读概览：显示资源用量、主机名、网络地址和经筛选的运行配置；不会读取或返回完整环境变量。</p></header>
<main><section><h2>服务</h2>{overview}</section>
<section><h2>主机</h2>{host_body}</section>
<section><h2>网络</h2>{network_body}</section>
<section><h2>安全筛选的环境配置</h2>{environment_body}</section>
<section><h2>内存</h2>{memory_body}</section>
<section><h2>磁盘</h2>{disk_body}</section></main>
<p class="foot">公网出口 IP 通过 HTTPS 向固定的 api.ipify.org 查询；只发送 IP 查询请求，不发送环境或运行配置。查询失败时显示“不可用”。容量使用 1024 进位（1 GB = 1024 MB）；磁盘容量仅表示当前根挂载视图，不代表独享配额。</p>
<p><a href="/api/status">查看 JSON 状态接口</a></p></body></html>'''


class Handler(BaseHTTPRequestHandler):
    server_version = "RuntimeStatus"
    sys_version = ""

    def log_message(self, fmt: str, *args: object) -> None:
        # Avoid writing client addresses and request data to logs.
        return

    def _respond(self, code: int, body: bytes, content_type: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            pass

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        if path == "/healthz":
            self._respond(200, b"ok\n", "text/plain; charset=utf-8")
            return
        if path not in ("/", "/api/status"):
            self._respond(404, b"not found\n", "text/plain; charset=utf-8")
            return
        try:
            data = status()
            if path == "/api/status":
                body = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
                content_type = "application/json; charset=utf-8"
            else:
                body = render_page(data).encode("utf-8")
                content_type = "text/html; charset=utf-8"
            self._respond(200, body, content_type)
        except Exception:
            self._respond(503, b'{"error":"status temporarily unavailable"}', "application/json; charset=utf-8")

    def do_POST(self) -> None:
        self._respond(405, b"method not allowed\n", "text/plain; charset=utf-8")


class LimitedHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 16

    def __init__(self, address: tuple[str, int], handler: type[BaseHTTPRequestHandler]):
        self._slots = threading.BoundedSemaphore(8)
        super().__init__(address, handler)

    def get_request(self):
        request, address = super().get_request()
        request.settimeout(5)
        return request, address

    def process_request(self, request, client_address) -> None:
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()


def main() -> None:
    try:
        port = int(os.environ.get("SERVER_PORT", "8000"))
    except (TypeError, ValueError):
        raise SystemExit("SERVER_PORT must be an integer from 1 to 65535")
    if not 1 <= port <= 65535:
        raise SystemExit("SERVER_PORT must be an integer from 1 to 65535")

    server = LimitedHTTPServer(("0.0.0.0", port), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
