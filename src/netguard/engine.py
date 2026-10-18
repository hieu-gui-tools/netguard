"""Bộ máy giám sát (không phụ thuộc Qt): kết hợp quét định kỳ và sự kiện ETW thời gian thực."""
from __future__ import annotations

import logging
import threading
import time
from collections import deque
from typing import Callable

from .classifier import Classifier
from .feed import ThreatFeed
from .guard import Guard
from .models import Connection
from .netutil import is_loopback
from .realtime import EtwSource, RtEvent, swap16
from .storage import Storage

log = logging.getLogger(__name__)


class Engine:
    RT_KEEP = 15.0  # giữ kết nối ETW bao lâu để còn hiện trên bảng dù đã đóng trước lần quét kế tiếp

    def __init__(self, guard: Guard, classifier: Classifier, scanner, storage: Storage, feed: ThreatFeed,
                 etw: EtwSource | None = None, on_alert: Callable[[str, str], None] | None = None):
        self.guard, self.classifier, self.scanner = guard, classifier, scanner
        self.storage, self.feed, self.etw = storage, feed, etw
        self.on_alert = on_alert or (lambda level, msg: None)
        self.poll_interval = float(guard.setting("poll_interval"))
        self.last_feed_result: dict[str, str] = {}
        self.swap_ports = False
        self._cal_normal = self._cal_swapped = 0
        self._cal_seen: deque[tuple[int, str, int]] = deque(maxlen=500)
        self._rt: dict[tuple, tuple[float, Connection]] = {}
        self._logged: dict[tuple, float] = {}
        self._allow_dirty = True
        self._etw_wanted: bool | None = None
        self._last_cfg = 0.0
        self._last_prune = 0.0
        self._feed_busy = False
        self._feed_attempt = 0.0
        guard.on_change(self._on_guard)

    def _on_guard(self, what: str) -> None:
        if what == "allow":
            self._allow_dirty = True

    # ---- cấu hình & ETW
    def refresh_config(self, now: float, force: bool = False) -> None:
        if not force and now - self._last_cfg < 1.0:
            return
        self._last_cfg = now
        self.poll_interval = max(1.0, float(self.guard.setting("poll_interval")))
        self.classifier.danger_threshold = max(50, int(self.guard.setting("block_threshold")))
        if self.etw is not None:
            want = bool(self.guard.setting("use_etw"))
            if want != self._etw_wanted:
                self._etw_wanted = want
                if want:
                    self.etw.start()
                else:
                    self.etw.stop()
                    self.etw.status, self.etw.detail = "disabled", ""

    def stop(self) -> None:
        if self.etw is not None:
            self.etw.stop()

    # ---- sự kiện ETW (thời gian thực)
    def _conn_from_event(self, ev: RtEvent) -> Connection | None:
        if not ev.rip or is_loopback(ev.rip):
            return None
        rport = swap16(ev.rport) if self.swap_ports else ev.rport
        lport = swap16(ev.lport) if self.swap_ports else ev.lport
        listening = getattr(self.scanner, "listening", set())
        direction = "in" if ev.kind == "established" and lport in listening else "out"
        return Connection(ev.pid, ev.name, ev.exe, ev.proto, ev.lip, lport, ev.rip, rport, "ETW", direction,
                          first_seen=ev.ts)

    def realtime_tick(self, now: float) -> int:
        if self.etw is None:
            return 0
        n = 0
        for ev in self.etw.drain():
            self._cal_seen.append((ev.pid, ev.rip, ev.rport))
            c = self._conn_from_event(ev)
            if c is None:
                continue
            try:
                self._handle(c, now)
            except Exception:
                log.exception("Lỗi xử lý sự kiện ETW")
                continue
            self._rt[c.key] = (now, c)
            n += 1
        return n

    def _calibrate(self, pairs: set[tuple]) -> None:
        """Đối chiếu cổng trong sự kiện ETW với bảng kết nối thật để phát hiện sai thứ tự byte."""
        while self._cal_seen:
            pid, rip, rport = self._cal_seen.popleft()
            if (pid, rip, rport) in pairs:
                self._cal_normal += 1
            elif swap16(rport) != rport and (pid, rip, swap16(rport)) in pairs:
                self._cal_swapped += 1
        self.swap_ports = self._cal_swapped >= 5 and self._cal_swapped > self._cal_normal * 3

    # ---- quét định kỳ
    def scan_tick(self, now: float) -> list[Connection]:
        self.refresh_config(now, force=True)
        if self._allow_dirty:
            self.classifier.allow.load(self.storage.list_allow())
            self._allow_dirty = False
        self.realtime_tick(now)  # xử lý nốt sự kiện ETW đang chờ trước khi quét
        self.classifier.begin_scan(now)
        conns = self.scanner.scan()
        pairs = {(c.pid, c.remote_ip, c.remote_port) for c in conns if c.remote_ip}
        self._calibrate(pairs)
        for c in conns:
            self._handle(c, now)
        # kết nối ngắn mà ETW thấy nhưng lần quét đã bỏ lỡ → vẫn hiện trên bảng một lúc
        for key, (ts, c) in list(self._rt.items()):
            if now - ts > self.RT_KEEP:
                del self._rt[key]
            elif (c.pid, c.remote_ip, c.remote_port) not in pairs:
                c.blocked = self.guard.is_blocked(c)
                conns.append(c)
        if len(self._logged) > 5000:
            cutoff = now - 6 * 3600
            self._logged = {k: t for k, t in self._logged.items() if t > cutoff}
        self._housekeeping(now)
        return conns

    def _handle(self, c: Connection, now: float) -> None:
        self.classifier.classify(c)
        c.blocked = self.guard.is_blocked(c)
        if c.level == "DANGEROUS" and not c.blocked and c.direction != "listen":
            desc = self.guard.auto_block(c)
            if desc:
                c.blocked = True
                self.on_alert("DANGEROUS", f"{desc} — {c.process} → {c.remote_ip}:{c.remote_port}")
        if c.level in ("SUSPICIOUS", "DANGEROUS"):
            key = (c.exe or c.process, c.remote_ip, c.remote_port, c.direction)
            if key not in self._logged:
                self._logged[key] = now
                self.storage.add_event(c, c.blocked)
                if not (c.level == "DANGEROUS" and c.blocked):
                    target = f"{c.remote_ip}:{c.remote_port}" if c.remote_ip else f"cổng {c.local_port}"
                    self.on_alert(c.level, f"{c.process} → {target}: {'; '.join(c.reasons[:2])}")

    # ---- việc nền: dọn dữ liệu, cập nhật danh sách đe dọa
    def _housekeeping(self, now: float) -> None:
        if now - self._last_prune > 3600:
            self._last_prune = now
            self.storage.prune_events(int(self.guard.setting("event_retention_days")))
        hours = float(self.guard.setting("feed_refresh_hours"))
        if not self._feed_busy and now - self.feed.updated > hours * 3600 and now - self._feed_attempt > 1800:
            self.refresh_feed_async()

    def refresh_feed_async(self) -> None:
        if self._feed_busy:
            return
        self._feed_busy = True
        self._feed_attempt = time.time()

        def job() -> None:
            try:
                urls = [u.strip() for u in str(self.guard.setting("feed_urls")).splitlines() if u.strip()]
                self.last_feed_result = self.feed.update(urls)
            finally:
                self._feed_busy = False
                self.guard._notify("feed")

        threading.Thread(target=job, daemon=True, name="feed-update").start()
