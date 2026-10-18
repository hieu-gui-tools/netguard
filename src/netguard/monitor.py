"""Quét kết nối (psutil) và luồng giám sát nền."""
from __future__ import annotations

import logging
import socket
import time

import psutil
from PySide6.QtCore import QThread, Signal

from .engine import Engine
from .models import Connection
from .netutil import normalize_ip

log = logging.getLogger(__name__)

SKIP_STATES = {"TIME_WAIT"}


class Scanner:
    def __init__(self) -> None:
        self._proc_cache: dict[int, tuple[float, str, str]] = {}
        self._first_seen: dict[tuple, float] = {}
        self.listening: set[int] = set()

    def _proc(self, pid: int) -> tuple[str, str]:
        now = time.time()
        hit = self._proc_cache.get(pid)
        if hit and now - hit[0] < 30:
            return hit[1], hit[2]
        name, exe = "?", ""
        if pid:
            try:
                p = psutil.Process(pid)
                name = p.name()
                try:
                    exe = p.exe()
                except (psutil.AccessDenied, OSError):
                    exe = ""
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        else:
            name = "System"
        self._proc_cache[pid] = (now, name, exe)
        if len(self._proc_cache) > 2000:
            self._proc_cache = {k: v for k, v in self._proc_cache.items() if now - v[0] < 30}
        return name, exe

    def scan(self) -> list[Connection]:
        try:
            raw = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, OSError) as exc:
            log.warning("Không đọc được danh sách kết nối: %s", exc)
            return []
        listening = {c.laddr.port for c in raw if c.status == psutil.CONN_LISTEN and c.laddr}
        self.listening = listening
        now = time.time()
        out: list[Connection] = []
        keys = set()
        for c in raw:
            if not c.laddr or c.status in SKIP_STATES:
                continue
            proto = "TCP" if c.type == socket.SOCK_STREAM else "UDP"
            lip, lport = normalize_ip(c.laddr.ip), c.laddr.port
            if c.status == psutil.CONN_LISTEN:
                direction, rip, rport = "listen", "", 0
            elif c.raddr:
                rip, rport = normalize_ip(c.raddr.ip), c.raddr.port
                direction = "in" if lport in listening else "out"
            else:
                continue
            pid = c.pid or 0
            name, exe = self._proc(pid)
            conn = Connection(pid, name, exe, proto, lip, lport, rip, rport, c.status, direction)
            conn.first_seen = self._first_seen.get(conn.key, now)
            keys.add(conn.key)
            out.append(conn)
        self._first_seen = {k: self._first_seen.get(k, now) for k in keys}
        return out


class MonitorWorker(QThread):
    """Vòng lặp nền: sự kiện ETW được xử lý mỗi 100 ms, quét đầy đủ theo chu kỳ cài đặt."""
    scanned = Signal(list)
    alert = Signal(str, str)  # level, message
    error = Signal(str)

    def __init__(self, engine: Engine):
        super().__init__()
        self.engine = engine
        engine.on_alert = lambda level, msg: self.alert.emit(level, msg)

    def run(self) -> None:
        last_scan = 0.0
        while not self.isInterruptionRequested():
            now = time.time()
            try:
                self.engine.refresh_config(now)
                if now - last_scan >= self.engine.poll_interval:
                    last_scan = now
                    self.scanned.emit(self.engine.scan_tick(now))
                else:
                    self.engine.realtime_tick(now)
            except Exception as exc:
                log.exception("Lỗi khi quét")
                self.error.emit(str(exc))
            self.msleep(100)
        self.engine.stop()
