"""Đường dẫn dữ liệu và cài đặt mặc định."""
from __future__ import annotations

import logging
import logging.handlers
import os
from pathlib import Path

APP_NAME = "NetGuard"
RULE_PREFIX = "NetGuard"

DEFAULT_SETTINGS: dict[str, object] = {
    "poll_interval": 2,            # giây giữa hai lần quét
    "auto_block": True,            # tự động chặn kết nối nguy hiểm
    "block_threshold": 70,         # điểm >= ngưỡng này là "Nguy hiểm"
    "max_auto_blocks_per_min": 8,  # cầu dao an toàn: vượt mức này sẽ tạm dừng tự chặn
    "event_retention_days": 14,
    "snapshot_keep": 30,           # số bản sao lưu tự động giữ lại
    "minimize_to_tray": True,
    "use_etw": True,               # giám sát thời gian thực bằng ETW (cần quyền Administrator)
    "feed_refresh_hours": 12,
    "feed_urls": (
        "https://feodotracker.abuse.ch/downloads/ipblocklist.txt\n"
        "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt"
    ),
}


def data_dir() -> Path:
    override = os.environ.get("NETGUARD_HOME")
    if override:
        base = Path(override)
    else:
        root = os.environ.get("LOCALAPPDATA") or str(Path.home() / ".local" / "share")
        base = Path(root) / APP_NAME
    base.mkdir(parents=True, exist_ok=True)
    return base


def backups_dir() -> Path:
    p = data_dir() / "backups"
    p.mkdir(parents=True, exist_ok=True)
    return p


def db_path() -> Path:
    return data_dir() / "netguard.db"


def setup_logging() -> None:
    handler = logging.handlers.RotatingFileHandler(
        data_dir() / "netguard.log", maxBytes=1_000_000, backupCount=3, encoding="utf-8"
    )
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    root = logging.getLogger()
    if not any(isinstance(h, logging.handlers.RotatingFileHandler) for h in root.handlers):
        root.addHandler(handler)
    root.setLevel(logging.INFO)
