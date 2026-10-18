from __future__ import annotations

import time
from dataclasses import dataclass, field

LEVEL_LABEL = {
    "LOCAL": "Nội bộ",
    "TRUSTED": "Tin cậy",
    "NORMAL": "Bình thường",
    "SUSPICIOUS": "Đáng ngờ",
    "DANGEROUS": "Nguy hiểm",
}
LEVEL_RANK = {"LOCAL": 0, "TRUSTED": 1, "NORMAL": 2, "SUSPICIOUS": 3, "DANGEROUS": 4}
DIR_LABEL = {"out": "Đi ra", "in": "Đi vào", "listen": "Lắng nghe"}


@dataclass
class Connection:
    pid: int
    process: str
    exe: str
    proto: str
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    status: str
    direction: str  # out | in | listen
    first_seen: float = field(default_factory=time.time)
    level: str = "NORMAL"
    score: int = 0
    ip_score: int = 0    # bằng chứng về địa chỉ đích (danh sách đe dọa, cổng lạ...)
    proc_score: int = 0  # bằng chứng về chương trình (thư mục lạ, đuôi kép, chữ ký...)
    reasons: list[str] = field(default_factory=list)
    tags: set[str] = field(default_factory=set)
    blocked: bool = False

    @property
    def key(self) -> tuple:
        return (self.pid, self.proto, self.local_ip, self.local_port, self.remote_ip, self.remote_port)
