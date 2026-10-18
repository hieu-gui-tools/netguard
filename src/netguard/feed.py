"""Danh sách IP đe dọa (botnet C2, netblock bị chiếm...) tải từ nguồn công khai, lưu cục bộ."""
from __future__ import annotations

import ipaddress
import logging
import time
import urllib.request
from pathlib import Path

log = logging.getLogger(__name__)


def parse_feed(text: str):
    ips: set[str] = set()
    nets: list = []
    for line in text.splitlines():
        line = line.split("#")[0].split(";")[0].strip()
        if not line:
            continue
        token = line.split()[0]
        try:
            net = ipaddress.ip_network(token, strict=False)
        except ValueError:
            continue
        if net.num_addresses == 1:
            ips.add(str(net.network_address))
        else:
            nets.append(net)
    return ips, nets


class ThreatFeed:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.ips: set[str] = set()
        self.nets: list = []
        self.updated = 0.0
        self.load()

    def load(self) -> None:
        if not self.path.exists():
            return
        try:
            self.ips, self.nets = parse_feed(self.path.read_text("utf-8", errors="replace"))
            self.updated = self.path.stat().st_mtime
        except OSError:
            log.exception("Không đọc được feed")

    def __len__(self) -> int:
        return len(self.ips) + len(self.nets)

    def contains(self, ip: str) -> str | None:
        if ip in self.ips:
            return ip
        if self.nets:
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                return None
            for net in self.nets:
                if addr.version == net.version and addr in net:
                    return str(net)
        return None

    def update(self, urls: list[str], timeout: int = 20) -> dict[str, str]:
        """Tải lại toàn bộ nguồn. Nếu tất cả thất bại, giữ nguyên dữ liệu cũ."""
        results: dict[str, str] = {}
        merged: list[str] = []
        for url in urls:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "NetGuard/0.1"})
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    text = resp.read(5_000_000).decode("utf-8", errors="replace")
                ips, nets = parse_feed(text)
                if not ips and not nets:
                    raise ValueError("không có mục hợp lệ")
                merged.append(text)
                results[url] = f"OK ({len(ips) + len(nets)} mục)"
            except Exception as exc:  # mạng lỗi không được làm hỏng app
                results[url] = f"Lỗi: {exc}"
        if merged:
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text("\n".join(merged), "utf-8")
            tmp.replace(self.path)
            self.load()
            self.updated = time.time()
        return results
