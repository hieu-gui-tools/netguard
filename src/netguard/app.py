from __future__ import annotations

import os
import sys
from dataclasses import dataclass

from .classifier import AllowList, Classifier
from .config import backups_dir, data_dir, db_path, setup_logging
from .engine import Engine
from .feed import ThreatFeed
from .firewall import create_firewall
from .guard import Guard
from .monitor import Scanner
from .realtime import EtwSource
from .signatures import SignatureCache
from .storage import Storage


@dataclass
class AppContext:
    storage: Storage
    fw: object
    guard: Guard
    classifier: Classifier
    scanner: Scanner
    feed: ThreatFeed
    sigs: SignatureCache
    etw: EtwSource
    engine: Engine
    dry_run: bool


def build_context(dry_run: bool = False) -> AppContext:
    setup_logging()
    storage = Storage(db_path())
    fw = create_firewall(dry_run, data_dir() / "dryrun_rules.json")
    guard = Guard(storage, fw, backups_dir())
    feed = ThreatFeed(data_dir() / "threat_feed.txt")
    sigs = SignatureCache(storage)
    allow = AllowList()
    allow.load(storage.list_allow())
    classifier = Classifier(allow, feed, sigs, int(guard.setting("block_threshold")))
    scanner = Scanner()
    etw = EtwSource()
    engine = Engine(guard, classifier, scanner, storage, feed, etw)
    return AppContext(storage, fw, guard, classifier, scanner, feed, sigs, etw, engine,
                      dry_run or fw.name == "dry-run")


def relaunch_as_admin(dry_run: bool = False) -> bool:
    """Mở lại NetGuard với quyền Administrator (hiện hộp thoại UAC). Trả về True nếu đã yêu cầu thành công."""
    if sys.platform != "win32":
        return False
    import ctypes
    exe = sys.executable
    pyw = exe[:-10] + "pythonw.exe" if exe.lower().endswith("python.exe") else exe
    if not os.path.exists(pyw):
        pyw = exe
    params = "-m netguard --elevated" + (" --dry-run" if dry_run else "")
    return ctypes.windll.shell32.ShellExecuteW(None, "runas", pyw, params, os.getcwd(), 1) > 32
