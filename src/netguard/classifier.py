"""Phân loại kết nối bằng điểm rủi ro (0–100) kèm lý do giải thích được.

Hai nhóm bằng chứng được tách riêng để quyết định *chặn cái gì*:
  - ip_score   : địa chỉ đích đáng ngờ (danh sách đe dọa, cổng backdoor...) → chặn IP
  - proc_score : chương trình đáng ngờ (chạy từ thư mục tạm, đuôi kép, chữ ký lỗi) → chặn chương trình
"""
from __future__ import annotations

import ipaddress
import ntpath
import re
import time

from .feed import ThreatFeed
from .guard import is_system_path
from .models import Connection
from .netutil import is_loopback_only, is_public, normalize_ip
from .signatures import is_trusted_publisher, signer_name

DOUBLE_EXT = re.compile(
    r"\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|zip|rar|7z|mp3|mp4|html?)\.(exe|scr|com|bat|cmd|js|vbs|msi)$"
)

# (đoạn đường dẫn, điểm, nhãn) — kiểm tra theo thứ tự, lấy mục đầu tiên khớp
USER_DIRS = (
    ("\\$recycle.bin\\", 40, "Thùng rác"),
    ("\\users\\public\\", 40, "Public"),
    ("\\windows\\temp\\", 35, "Windows\\Temp"),
    ("\\appdata\\local\\temp\\", 30, "Temp"),
    ("\\downloads\\", 25, "Downloads"),
    ("\\documents\\", 20, "Documents"),
    ("\\desktop\\", 20, "Desktop"),
)

SUSPECT_PORTS = {
    4444: (35, "Metasploit/backdoor"), 1337: (25, "hacker/backdoor"), 31337: (40, "Back Orifice"),
    6666: (30, "IRC botnet"), 6667: (25, "IRC"), 6697: (20, "IRC"), 12345: (30, "NetBus"),
    54321: (30, "backdoor"), 9001: (25, "Tor"), 9050: (25, "Tor"), 9051: (25, "Tor"),
    1604: (35, "DarkComet"), 3333: (20, "đào coin"), 14444: (25, "đào coin"), 14433: (25, "đào coin"),
}

SENSITIVE_INBOUND = {
    23: "Telnet", 135: "RPC", 139: "NetBIOS", 445: "SMB", 3389: "RDP",
    5900: "VNC", 5985: "WinRM", 1433: "SQL Server", 3306: "MySQL",
}

LOLBINS = {
    "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe",
    "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "installutil.exe", "regasm.exe",
}


class AllowList:
    def __init__(self) -> None:
        self.procs: set[str] = set()
        self.paths: set[str] = set()
        self.ips: set[str] = set()
        self.nets: list = []

    def load(self, rows) -> None:
        procs, paths, ips, nets = set(), set(), set(), []
        for r in rows:
            kind, value = r["kind"], r["value"].strip()
            if kind == "process":
                (paths if ("\\" in value or "/" in value) else procs).add(value.lower())
            elif kind == "ip":
                ips.add(normalize_ip(value))
            elif kind == "cidr":
                try:
                    nets.append(ipaddress.ip_network(value, strict=False))
                except ValueError:
                    pass
        self.procs, self.paths, self.ips, self.nets = procs, paths, ips, nets

    def match(self, c: Connection) -> str | None:
        if c.process.lower() in self.procs:
            return f"Tiến trình {c.process} nằm trong danh sách tin cậy"
        if c.exe and c.exe.lower() in self.paths:
            return "Chương trình nằm trong danh sách tin cậy"
        if c.remote_ip:
            if c.remote_ip in self.ips:
                return "Địa chỉ đích nằm trong danh sách tin cậy"
            if self.nets:
                try:
                    addr = ipaddress.ip_address(c.remote_ip)
                except ValueError:
                    return None
                if any(addr.version == n.version and addr in n for n in self.nets):
                    return "Địa chỉ đích thuộc dải mạng tin cậy"
        return None


class Classifier:
    def __init__(self, allow: AllowList, feed: ThreatFeed, sigs, danger_threshold: int = 70):
        self.allow = allow
        self.feed = feed
        self.sigs = sigs
        self.danger_threshold = danger_threshold
        self._recent: dict[int, dict[str, float]] = {}

    def begin_scan(self, now: float | None = None) -> None:
        now = now or time.time()
        for pid in list(self._recent):
            d = {ip: t for ip, t in self._recent[pid].items() if now - t <= 30}
            if d:
                self._recent[pid] = d
            else:
                del self._recent[pid]

    def classify(self, c: Connection) -> None:
        c.reasons, c.tags = [], set()
        c.ip_score = c.proc_score = 0
        has_remote = bool(c.remote_ip)
        public = has_remote and is_public(c.remote_ip)

        why = self.allow.match(c)
        if why:
            c.level, c.score, c.reasons = "TRUSTED", 0, [why]
            return

        exe_l = c.exe.lower().replace("/", "\\") if c.exe else ""
        name_l = c.process.lower()
        sysdir = bool(exe_l) and is_system_path(exe_l)
        if sysdir:
            c.tags.add("sysdir")
        ip = proc = 0

        # ---- bằng chứng về chương trình
        base = ntpath.basename(exe_l) if exe_l else ""
        if DOUBLE_EXT.search(name_l) or (base and DOUBLE_EXT.search(base)):
            proc += 60
            c.tags.add("doubleext")
            c.reasons.append(f"Tên file có đuôi kép giả tài liệu ({base or name_l})")
        if exe_l and not sysdir:
            for marker, pts, label in USER_DIRS:
                if marker in exe_l:
                    proc += pts
                    c.tags.add("userdir")
                    c.reasons.append(f"Chạy từ thư mục {label}")
                    break
        if name_l in LOLBINS and public and c.direction == "out":
            proc += 40
            c.reasons.append(f"{c.process} (công cụ hệ thống hay bị lạm dụng) kết nối ra internet")

        trusted_pub = False
        if exe_l and not sysdir:
            sig = self.sigs.lookup(c.exe)
            if sig:
                status, subject = sig
                if status == "Valid":
                    if is_trusted_publisher(subject):
                        trusted_pub = True
                        proc = max(0, proc - 30)
                    else:
                        proc = max(0, proc - 10)
                elif status == "NotSigned" and public and c.direction == "out":
                    proc += 12
                    c.reasons.append("Chương trình chưa có chữ ký số")
                elif status == "HashMismatch":
                    proc += 60
                    c.reasons.append("Chữ ký số không khớp — file đã bị sửa")
                elif status == "NotTrusted":
                    proc += 25
                    c.reasons.append(f"Chữ ký số không được tin cậy ({signer_name(subject) or 'không rõ'})")

        if public and c.direction == "out" and not trusted_pub:
            seen = self._recent.setdefault(c.pid, {})
            seen[c.remote_ip] = time.time()
            if len(seen) > 80:
                proc += 35
                c.reasons.append(f"Kết nối tới {len(seen)} IP khác nhau trong 30 giây (giống quét mạng/botnet)")

        # ---- bằng chứng về địa chỉ đích
        if public:
            hit = self.feed.contains(c.remote_ip)
            if hit:
                ip += 90
                c.reasons.append(f"IP nằm trong danh sách đe dọa ({hit})")
            if c.direction == "out" and c.remote_port in SUSPECT_PORTS:
                pts, label = SUSPECT_PORTS[c.remote_port]
                ip += pts
                c.reasons.append(f"Cổng đích {c.remote_port} thường dùng cho {label}")
            if c.direction == "in" and c.local_port in SENSITIVE_INBOUND:
                ip += 45
                c.reasons.append(
                    f"Máy bên ngoài đang kết nối vào dịch vụ {SENSITIVE_INBOUND[c.local_port]} (cổng {c.local_port})"
                )

        c.ip_score, c.proc_score = min(100, ip), min(100, proc)
        total = min(100, ip + proc)
        c.score = total

        # ---- xếp mức
        if c.direction == "listen":
            if is_loopback_only(c.local_ip) and total < 30:
                c.level = "LOCAL"
                return
        elif not has_remote or not public:
            if total < self.danger_threshold:
                c.level, c.score = "LOCAL", 0
                c.reasons = []
                return
        if total >= self.danger_threshold:
            c.level = "DANGEROUS"
        elif total >= 30:
            c.level = "SUSPICIOUS"
        elif (trusted_pub or "sysdir" in c.tags) and ip == 0:
            c.level = "TRUSTED"
        else:
            c.level = "NORMAL"
