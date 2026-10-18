"""Giám sát kết nối thời gian thực bằng ETW (nhà cung cấp Microsoft-Windows-Kernel-Network).

Phiên ETW chạy trong *tiến trình con* (netguard.etw_worker) và gửi sự kiện về dạng JSON từng dòng.
Lý do: mã ctypes của thư viện ETW nếu gặp sự cố (hoặc ngốn CPU) sẽ không làm sập ứng dụng chính;
tiến trình cha có thể giết và khởi động lại nó.
"""
from __future__ import annotations

import json
import logging
import os
import socket
import struct
import subprocess
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass

import psutil

from .netutil import normalize_ip

log = logging.getLogger(__name__)

KERNEL_NETWORK_GUID = "{7DD42A49-5329-4832-8DFD-43D979153A88}"
SESSION_NAME = "NetGuard-ETW"
# Mã sự kiện (đã đối chiếu với manifest trên Windows 11): 12/28 = thử kết nối TCP v4/v6,
# 15/31 = kết nối TCP đã thiết lập, 42/58 = UDP v4/v6 gửi dữ liệu. KHÔNG đăng ký 10/11 (mỗi gói tin).
WANTED = {
    12: ("connect", "TCP"), 28: ("connect", "TCP"),
    15: ("established", "TCP"), 31: ("established", "TCP"),
    42: ("send", "UDP"), 58: ("send", "UDP"),
}
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def swap16(p: int) -> int:
    return ((p & 0xFF) << 8) | ((p >> 8) & 0xFF)


def _to_int(v):
    if v is None:
        return None
    if isinstance(v, int):
        return v
    s = str(v).strip()
    for base in (10, 0):
        try:
            return int(s, base)
        except ValueError:
            continue
    return None


def _to_ip(v) -> str:
    if v is None:
        return ""
    if isinstance(v, int) or str(v).strip().isdigit():
        try:  # số nguyên thô: 4 byte theo thứ tự mạng đọc trên máy little-endian
            return socket.inet_ntoa(struct.pack("<I", int(v) & 0xFFFFFFFF))
        except (OSError, struct.error, ValueError):
            return ""
    return normalize_ip(str(v).strip())


def parse_event(event_id: int, data: dict) -> dict | None:
    """Chuẩn hóa một sự kiện Kernel-Network. Thứ tự trường: PID, size, daddr (đích), saddr (nguồn), dport, sport."""
    meta = WANTED.get(event_id)
    if not meta:
        return None
    d = {str(k).lower(): v for k, v in data.items()}
    pid = _to_int(d.get("pid"))
    if pid is None:
        pid = _to_int((data.get("EventHeader") or {}).get("ProcessId"))
    rip, lip = _to_ip(d.get("daddr")), _to_ip(d.get("saddr"))
    rport, lport = _to_int(d.get("dport")), _to_int(d.get("sport"))
    if not rip or rport is None or lport is None:
        return None
    return {"id": event_id, "kind": meta[0], "proto": meta[1], "pid": pid or 0,
            "lip": lip, "lport": lport, "rip": rip, "rport": rport}


@dataclass
class RtEvent:
    ts: float
    kind: str
    proto: str
    pid: int
    lip: str
    lport: int  # cổng thô, chưa hiệu chỉnh thứ tự byte
    rip: str
    rport: int
    name: str
    exe: str


class EtwSource:
    """Quản lý tiến trình con ETW, nhận sự kiện, khử trùng lặp và đưa vào hàng đợi."""

    def __init__(self, child_cmd: list[str] | None = None, platform_ok: bool | None = None,
                 kernel_filter: bool = True, event_filter: bool = True):
        self.status = "stopped"   # stopped|starting|running|needs-admin|missing-lib|unsupported|overload|error
        self.detail = ""
        self.total = 0
        self.kernel_filter = False
        self.counts: dict[int, int] = {}
        self.restarts = 0
        self.restart_delay = 2.0
        self.cpu_limit = 35.0
        self.watch_interval = 3.0
        self._child_cmd = child_cmd
        self._platform_ok = (sys.platform == "win32") if platform_ok is None else platform_ok
        self._want_kernel_filter = kernel_filter
        self._event_filter = event_filter
        self._q: deque[RtEvent] = deque(maxlen=5000)
        self._proc: subprocess.Popen | None = None
        self._stop = threading.Event()
        self._fatal = False
        self._seen: dict[tuple, float] = {}
        self._pc: dict[int, tuple[float, str, str]] = {}
        self._lock = threading.Lock()

    # ---- điều khiển
    def _set(self, status: str, detail: str = "") -> None:
        self.status, self.detail = status, detail

    def start(self) -> bool:
        if not self._platform_ok:
            self._set("unsupported", "ETW chỉ có trên Windows")
            return False
        if self.status in ("starting", "running"):
            return True
        self.restarts = 0
        self._fatal = False
        self._stop.clear()
        if self._child_cmd is None:
            self._cleanup_session()
        self._spawn()
        return True

    def _spawn(self) -> None:
        cmd = self._child_cmd or [sys.executable, "-m", "netguard.etw_worker"]
        if self._child_cmd is None:
            if not self._want_kernel_filter:
                cmd.append("--no-kernel-filter")
            if not self._event_filter:
                cmd.append("--no-event-filter")
        self._set("starting", "")
        try:
            proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    text=True, encoding="utf-8", errors="replace", bufsize=1,
                                    creationflags=_NO_WINDOW)
        except OSError as exc:
            self._set("error", f"Không khởi động được tiến trình ETW: {exc}")
            return
        self._proc = proc
        threading.Thread(target=self._read_loop, args=(proc,), daemon=True, name="etw-reader").start()
        threading.Thread(target=self._watchdog, args=(proc,), daemon=True, name="etw-watchdog").start()

    def stop(self) -> None:
        self._stop.set()
        proc, self._proc = self._proc, None
        if proc:
            try:
                proc.stdin.close()  # tiến trình con thoát khi stdin đóng → tự dừng phiên ETW
            except (OSError, ValueError):
                pass
            try:
                proc.wait(3)
            except subprocess.TimeoutExpired:
                proc.kill()
        if self._child_cmd is None and self._platform_ok:
            self._cleanup_session()
        if self.status not in ("needs-admin", "missing-lib", "unsupported", "overload"):
            self._set("stopped", "")

    @staticmethod
    def _cleanup_session() -> None:
        """Phiên ETW là tài nguyên toàn hệ thống và còn lại sau khi app bị kill → dọn phiên cũ theo tên."""
        try:
            subprocess.run(["logman", "stop", SESSION_NAME, "-ets"], capture_output=True, timeout=10,
                           creationflags=_NO_WINDOW)
        except (OSError, subprocess.TimeoutExpired):
            pass

    # ---- luồng đọc
    def _read_loop(self, proc: subprocess.Popen) -> None:
        tail: deque[str] = deque(maxlen=6)
        try:
            for line in proc.stdout:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except ValueError:
                    tail.append(line[:200])
                    continue
                if "status" in rec:
                    self._on_status(rec)
                else:
                    self._ingest(rec)
        except (OSError, ValueError):
            pass
        rc = proc.wait()
        if self._stop.is_set() or proc is not self._proc:
            return
        if self.status in ("needs-admin", "missing-lib", "overload", "unsupported") or self._fatal:
            return
        self._set("error", f"Tiến trình ETW dừng đột ngột (mã {rc}) {' | '.join(tail)}".strip())
        self._maybe_restart()

    def _on_status(self, rec: dict) -> None:
        st = rec.get("status")
        if st == "ready":
            self.kernel_filter = bool(rec.get("kernel_filter"))
            self._set("running", "")
        elif st == "warn":
            log.warning("ETW: %s", rec.get("msg"))
        elif st == "error":
            self._fatal = True
            if rec.get("kind") == "missing-lib":
                self._set("missing-lib", str(rec.get("msg", "")))
            elif rec.get("code") == 5:
                self._set("needs-admin", "Truy cập bị từ chối — cần quyền Administrator")
            else:
                self._set("error", f"{rec.get('msg', '')} (mã {rec.get('code')})")

    def _maybe_restart(self) -> None:
        if self._fatal or self._stop.is_set() or self.restarts >= 3:
            return
        self.restarts += 1
        if self.restarts >= 2:
            self._want_kernel_filter = False  # lần thử sau: bỏ lọc ở kernel, chỉ lọc ở Python
        threading.Timer(self.restart_delay, lambda: None if self._stop.is_set() else self._spawn()).start()

    def _watchdog(self, proc: subprocess.Popen) -> None:
        """Nếu tiến trình con ngốn CPU liên tục (bộ lọc không hiệu quả) thì tắt ETW, quay về quét định kỳ."""
        high = 0
        cache: dict[int, psutil.Process] = {}
        try:
            parent = psutil.Process(proc.pid)
            parent.cpu_percent(None)
            cache[proc.pid] = parent
        except psutil.Error:
            return

        while proc.poll() is None and not self._stop.is_set():
            time.sleep(self.watch_interval)
            try:
                current_pids = [proc.pid] + [c.pid for c in parent.children(recursive=True)]
                for pid in current_pids:
                    if pid not in cache:
                        try:
                            cp = psutil.Process(pid)
                            cp.cpu_percent(None)
                            cache[pid] = cp
                        except psutil.Error:
                            pass
                total_cpu = 0.0
                for pid in list(cache.keys()):
                    if pid not in current_pids:
                        cache.pop(pid, None)
                        continue
                    try:
                        total_cpu += cache[pid].cpu_percent(None)
                    except psutil.Error:
                        cache.pop(pid, None)
                high = high + 1 if total_cpu > self.cpu_limit else 0
            except psutil.Error:
                return
            if high >= 3:
                self._fatal = True
                self._set("overload", "Tiến trình ETW dùng quá nhiều CPU — đã tắt, ứng dụng quay về quét định kỳ")
                for cp in list(cache.values()):
                    try:
                        cp.kill()
                    except (psutil.Error, OSError):
                        pass
                try:
                    proc.kill()
                except OSError:
                    pass
                return

    # ---- xử lý sự kiện
    def _resolve(self, pid: int) -> tuple[str, str]:
        now = time.time()
        hit = self._pc.get(pid)
        if hit and now - hit[0] < 60:
            return hit[1], hit[2]
        name, exe = "?", ""
        try:
            p = psutil.Process(pid)
            name = p.name()
            try:
                exe = p.exe()
            except (psutil.AccessDenied, OSError):
                pass
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        if len(self._pc) > 2000:
            self._pc.clear()
        self._pc[pid] = (now, name, exe)
        return name, exe

    def _ingest(self, rec: dict) -> None:
        rid = rec.get("id")
        if rid is None:
            return
        self.counts[rid] = self.counts.get(rid, 0) + 1
        if rid not in WANTED or "rip" not in rec:
            return
        now = time.time()
        # 12 (thử kết nối) rồi 15 (đã thiết lập) cho cùng một kết nối → chỉ giữ một; UDP gửi liên tục → 30 giây
        key = (rec["pid"], rec["proto"], rec["rip"], rec["rport"], rec["lport"])
        ttl = 30 if rec["proto"] == "UDP" else 10
        with self._lock:
            if now - self._seen.get(key, 0) < ttl:
                return
            self._seen[key] = now
            if len(self._seen) > 5000:
                self._seen = {k: t for k, t in self._seen.items() if now - t < 30}
        name, exe = self._resolve(rec["pid"])
        self._q.append(RtEvent(now, rec["kind"], rec["proto"], rec["pid"], rec["lip"], rec["lport"],
                               rec["rip"], rec["rport"], name, exe))
        self.total += 1

    def drain(self) -> list[RtEvent]:
        out = []
        while True:
            try:
                out.append(self._q.popleft())
            except IndexError:
                return out


def run_self_test(seconds: int = 15) -> int:
    """Chẩn đoán ETW: chạy bằng `netguard --etw-test` trong terminal có quyền Administrator."""
    import urllib.request
    admin = False
    try:
        import ctypes
        admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        pass
    print(f"Quyền Administrator: {'CÓ' if admin else 'KHÔNG — ETW sẽ bị từ chối'}")
    src = EtwSource(event_filter=False)  # để thấy cả sự kiện không mong muốn → kiểm tra bộ lọc kernel
    src.start()
    t0 = time.time()
    while src.status == "starting" and time.time() - t0 < 10:
        time.sleep(0.2)
    print(f"Trạng thái ETW: {src.status} {src.detail}")
    if src.status != "running":
        src.stop()
        return 1
    print(f"Bộ lọc mã sự kiện ở phía kernel: {'đã bật' if src.kernel_filter else 'KHÔNG bật (dùng lọc Python)'}")

    def traffic() -> None:
        time.sleep(1)
        try:
            urllib.request.urlopen("https://example.com", timeout=8).read(200)
        except Exception as exc:
            print("  (kết nối thử tới example.com lỗi:", exc, ")")

    threading.Thread(target=traffic, daemon=True).start()
    child_cpu0 = psutil.Process(src._proc.pid).cpu_times()
    events: list[RtEvent] = []
    end = time.time() + seconds
    print(f"Đang thu sự kiện trong {seconds} giây (hãy mở vài trang web / ứng dụng)…")
    while time.time() < end:
        events += src.drain()
        time.sleep(0.2)
    events += src.drain()
    try:
        c = psutil.Process(src._proc.pid).cpu_times()
        cpu = (c.user + c.system) - (child_cpu0.user + child_cpu0.system)
    except psutil.Error:
        cpu = -1
    src.stop()

    print(f"\nSự kiện thô theo mã: {dict(sorted(src.counts.items()))}")
    leaked = {k: v for k, v in src.counts.items() if k not in WANTED}
    if leaked:
        print(f"  ⚠ Có sự kiện ngoài danh sách ({leaked}) → bộ lọc kernel KHÔNG có hiệu lực. "
              "Ứng dụng vẫn chạy được nhờ lọc ở Python và bộ giám sát CPU, nhưng hãy báo lại kết quả này.")
    else:
        print("  ✓ Không có sự kiện dữ liệu từng gói → bộ lọc hoạt động.")
    print(f"CPU của tiến trình ETW trong {seconds} giây: {cpu:.2f}s")
    print(f"Kết nối hữu ích sau khử trùng lặp: {len(events)}")
    mine = [e for e in events if e.pid == os.getpid() and e.rip]
    for e in events[:8]:
        print(f"  {e.kind:11} {e.proto} pid={e.pid:<6} {e.name:<22} {e.lip}:{e.lport} → {e.rip}:{e.rport}")
    verdict = "chưa xác định (không thấy kết nối thử của chính tiến trình này)"
    for e in mine:
        if e.rport == 443:
            verdict = "ĐÚNG (cổng 443 hiện đúng 443)"
        elif swap16(e.rport) == 443:
            verdict = f"NGƯỢC BYTE (443 hiện là {e.rport}) — NetGuard sẽ tự đảo lại khi chạy"
    print(f"Thứ tự byte của cổng: {verdict}")
    return 0 if events else 2
