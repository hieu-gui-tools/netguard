"""Lõi nghiệp vụ: chặn/bỏ chặn, nhật ký, hoàn tác, sao lưu & khôi phục, đối soát với Firewall."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import ntpath
import os
import threading
import time
from collections import deque
from typing import Callable

from .config import DEFAULT_SETTINGS, RULE_PREFIX
from .firewall import FirewallError
from .models import Connection
from .netutil import is_loopback, is_public, normalize_ip, parse
from .snapshots import SnapshotManager
from .storage import Storage

log = logging.getLogger(__name__)

# DNS công cộng phổ biến: không bao giờ tự động chặn (chặn nhầm sẽ làm mất mạng)
PROTECTED_IPS = {
    "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112",
    "208.67.222.222", "208.67.220.220",
}


class GuardError(RuntimeError):
    pass


def system_prefixes() -> tuple[str, ...]:
    vals = [os.environ.get(k, "") for k in ("SystemRoot", "ProgramFiles", "ProgramFiles(x86)", "ProgramW6432")]
    vals += [r"C:\Windows", r"C:\Program Files", r"C:\Program Files (x86)"]
    return tuple(sorted({v.lower().rstrip("\\") + "\\" for v in vals if v}))


def is_system_path(path: str) -> bool:
    return path.lower().replace("/", "\\").startswith(system_prefixes())


class Guard:
    def __init__(self, storage: Storage, firewall, backups_dir):
        self.storage = storage
        self.fw = firewall
        self.snapshots = SnapshotManager(backups_dir, storage)
        self._lock = threading.RLock()
        self._listeners: list[Callable[[str], None]] = []
        self._ips: set[str] = set()
        self._progs: set[str] = set()
        self._auto_times: deque[float] = deque()
        self.breaker_until = 0.0
        self._last_auto_snapshot = 0.0
        self.refresh_cache()

    # ---- thông báo thay đổi cho UI
    def on_change(self, fn: Callable[[str], None]) -> None:
        self._listeners.append(fn)

    def _notify(self, what: str) -> None:
        for fn in list(self._listeners):
            try:
                fn(what)
            except Exception:
                log.exception("listener lỗi")

    def refresh_cache(self) -> None:
        rows = self.storage.list_blocks(active_only=True)
        self._ips = {r["target"] for r in rows if r["kind"] == "ip"}
        self._progs = {r["target"].lower() for r in rows if r["kind"] == "program"}

    def is_blocked(self, c: Connection) -> bool:
        return (bool(c.remote_ip) and c.remote_ip in self._ips) or (bool(c.exe) and c.exe.lower() in self._progs)

    def _log(self, actor, action, target, detail, undo=None) -> int:
        return self.storage.add_journal(actor, action, target, detail, undo)

    def setting(self, key: str):
        return self.storage.get_setting(key, DEFAULT_SETTINGS[key])

    # ---- sao lưu tự động (không quá 1 lần / 30 phút)
    def maybe_auto_snapshot(self, label: str = "Tự động trước khi thay đổi") -> None:
        if time.time() - self._last_auto_snapshot > 1800:
            self.snapshot_now(label, "auto")

    def snapshot_now(self, label: str, kind: str = "manual"):
        path = self.snapshots.create(label, kind)
        if kind == "auto":
            self._last_auto_snapshot = time.time()
        self._notify("backups")
        return path

    # ---- cài đặt
    def set_settings(self, changes: dict, actor: str = "manual", undoable: bool = True) -> None:
        changes = {k: v for k, v in changes.items() if k in DEFAULT_SETTINGS}
        old = {k: self.setting(k) for k in changes}
        diff = {k: v for k, v in changes.items() if old[k] != v}
        if not diff:
            return
        with self._lock:
            self.storage.set_settings(diff)
            self._log(actor, "settings", ", ".join(diff),
                      "; ".join(f"{k}: {old[k]!r} → {v!r}" for k, v in diff.items() if k != "feed_urls"),
                      {"op": "settings", "values": {k: old[k] for k in diff}} if undoable else None)
        self._notify("settings")

    # ---- chặn / bỏ chặn
    def block_ip(self, ip: str, reason: str = "", source: str = "manual", process: str = "", score: int = 0) -> int:
        ip = normalize_ip(ip.strip())
        if parse(ip) is None:
            raise GuardError("Địa chỉ IP không hợp lệ")
        if is_loopback(ip):
            raise GuardError("Không thể chặn địa chỉ loopback hoặc 0.0.0.0")
        if source == "auto" and (not is_public(ip) or ip in PROTECTED_IPS):
            raise GuardError("Địa chỉ này được bảo vệ, không tự động chặn")
        return self._block("ip", ip, f"{RULE_PREFIX}-IP-{ip}", reason, source, process, score)

    def block_program(self, exe: str, reason: str = "", source: str = "manual", process: str = "", score: int = 0) -> int:
        exe = exe.strip()
        if not exe:
            raise GuardError("Không xác định được đường dẫn chương trình (có thể cần quyền Administrator)")
        if source == "auto" and is_system_path(exe):
            raise GuardError("Chương trình hệ thống được bảo vệ, không tự động chặn")
        tag = hashlib.sha1(exe.lower().encode("utf-8")).hexdigest()[:8]
        return self._block("program", exe, f"{RULE_PREFIX}-APP-{ntpath.basename(exe)}-{tag}",
                           reason, source, process, score)

    def _add_rule(self, kind: str, target: str, rule_name: str) -> None:
        try:
            if kind == "ip":
                self.fw.add_block_ip(rule_name, target)
            else:
                self.fw.add_block_program(rule_name, target)
        except FirewallError as exc:
            raise GuardError(str(exc)) from exc

    def _block(self, kind, target, rule_name, reason, source, process, score) -> int:
        with self._lock:
            existing = self.storage.get_block_by_name(rule_name)
            if existing and existing["active"]:
                return int(existing["id"])
            self.maybe_auto_snapshot()
            self._add_rule(kind, target, rule_name)
            try:
                bid = self.storage.upsert_block(kind, target, rule_name, reason, process, source, score)
            except Exception:
                try:
                    self.fw.delete_rule(rule_name)
                except FirewallError:
                    pass
                raise
            self._log(source, f"block_{kind}", target, reason or "", {"op": "unblock", "block_id": bid})
            self.refresh_cache()
        self._notify("blocks")
        return bid

    def unblock(self, block_id: int, actor: str = "manual", undoable: bool = True) -> None:
        with self._lock:
            row = self.storage.get_block(block_id)
            if not row or not row["active"]:
                raise GuardError("Mục chặn không tồn tại hoặc đã được gỡ")
            try:
                self.fw.delete_rule(row["rule_name"])
            except FirewallError as exc:
                raise GuardError(str(exc)) from exc
            self.storage.deactivate_block(block_id)
            self._log(actor, "unblock", row["target"], row["reason"] or "",
                      {"op": "reblock", "block_id": block_id} if undoable else None)
            self.refresh_cache()
        self._notify("blocks")

    # ---- danh sách tin cậy
    def allow_add(self, kind: str, value: str, note: str = "", actor: str = "manual", undoable: bool = True) -> int:
        value = value.strip()
        if kind == "ip":
            if parse(normalize_ip(value)) is None:
                raise GuardError("Địa chỉ IP không hợp lệ")
            value = normalize_ip(value)
        elif kind == "cidr":
            try:
                value = str(ipaddress.ip_network(value, strict=False))
            except ValueError as exc:
                raise GuardError("Dải mạng (CIDR) không hợp lệ") from exc
        elif kind != "process" or not value:
            raise GuardError("Giá trị không hợp lệ")
        with self._lock:
            aid = self.storage.add_allow(kind, value, note)
            if aid is None:
                raise GuardError("Mục này đã có trong danh sách tin cậy")
            self._log(actor, "allow_add", f"{kind}:{value}", note,
                      {"op": "allow_remove", "id": aid} if undoable else None)
        self._notify("allow")
        return aid

    def allow_remove(self, allow_id: int, actor: str = "manual", undoable: bool = True) -> None:
        with self._lock:
            row = self.storage.get_allow(allow_id)
            if not row:
                raise GuardError("Mục không tồn tại")
            self.storage.remove_allow(allow_id)
            self._log(actor, "allow_remove", f"{row['kind']}:{row['value']}", row["note"] or "",
                      {"op": "allow_add", "kind": row["kind"], "value": row["value"], "note": row["note"] or ""}
                      if undoable else None)
        self._notify("allow")

    # ---- hoàn tác một thay đổi trong nhật ký
    def undo(self, journal_id: int) -> None:
        entry = self.storage.get_journal(journal_id)
        if not entry:
            raise GuardError("Không tìm thấy mục nhật ký")
        if entry["undone"]:
            raise GuardError("Thay đổi này đã được hoàn tác")
        if not entry["undo"]:
            raise GuardError("Mục này không thể hoàn tác trực tiếp — hãy dùng 'Khôi phục' từ bản sao lưu")
        undo = json.loads(entry["undo"])
        op = undo["op"]
        if op == "unblock":
            self.unblock(undo["block_id"], actor="undo", undoable=False)
        elif op == "reblock":
            row = self.storage.get_block(undo["block_id"])
            if not row:
                raise GuardError("Mục chặn gốc không còn tồn tại")
            self._block(row["kind"], row["target"], row["rule_name"], row["reason"] or "",
                        "undo", row["process"] or "", row["score"])
        elif op == "allow_remove":
            self.allow_remove(undo["id"], actor="undo", undoable=False)
        elif op == "allow_add":
            self.allow_add(undo["kind"], undo["value"], undo.get("note", ""), actor="undo", undoable=False)
        elif op == "settings":
            self.set_settings(undo["values"], actor="undo", undoable=False)
        else:
            raise GuardError(f"Không hiểu thao tác hoàn tác: {op}")
        self.storage.mark_undone(journal_id)
        self._notify("journal")

    # ---- đối soát với Windows Firewall (tự chữa lành)
    def reconcile(self, fix: bool = True, remove_orphans: bool = False) -> dict:
        rows = {r["rule_name"]: r for r in self.storage.list_blocks(active_only=True)}
        try:
            present = self.fw.list_rules()
        except FirewallError as exc:
            return {"error": str(exc), "missing": [], "orphans": [], "fixed": [], "errors": []}
        missing = sorted(set(rows) - present)
        orphans = sorted(present - set(rows))
        fixed, errors = [], []
        if fix and self.fw.can_modify():
            for name in missing:
                r = rows[name]
                try:
                    self._add_rule(r["kind"], r["target"], name)
                    fixed.append(name)
                except GuardError as exc:
                    errors.append(f"{name}: {exc}")
            if remove_orphans:
                for name in orphans:
                    try:
                        self.fw.delete_rule(name)
                        fixed.append(f"-{name}")
                    except FirewallError as exc:
                        errors.append(f"{name}: {exc}")
            if fixed:
                self._log("system", "reconcile", f"{len(fixed)} rule", "; ".join(fixed)[:500], None)
        return {"missing": missing, "orphans": orphans, "fixed": fixed, "errors": errors, "error": None}

    # ---- khôi phục từ bản sao lưu
    def restore_snapshot(self, path) -> dict:
        snap = self.snapshots.load(path)
        with self._lock:
            self.snapshots.create("Tự động trước khi khôi phục", "pre-restore")
            desired = {b["rule_name"]: b for b in snap["blocks"]}
            active = {r["rule_name"]: r for r in self.storage.list_blocks(active_only=True)}
            removed = added = 0
            errors: list[str] = []
            for name, row in active.items():
                if name not in desired:
                    try:
                        self.unblock(row["id"], actor="restore", undoable=False)
                        removed += 1
                    except GuardError as exc:
                        errors.append(f"{name}: {exc}")
            for name, b in desired.items():
                if name not in active:
                    try:
                        self._block(b["kind"], b["target"], name, b.get("reason") or "", "restore",
                                    b.get("process") or "", int(b.get("score") or 0))
                        added += 1
                    except GuardError as exc:
                        errors.append(f"{name}: {exc}")
            self.storage.replace_allowlist(snap["allowlist"])
            settings = {k: v for k, v in snap["settings"].items() if k in DEFAULT_SETTINGS}
            self.storage.set_settings(settings)
            self._log("restore", "restore_snapshot", os.path.basename(str(path)),
                      f"gỡ {removed}, thêm {added}, lỗi {len(errors)}", None)
            self.refresh_cache()
        rec = self.reconcile(fix=True, remove_orphans=True)
        for kind in ("blocks", "allow", "settings", "journal", "backups"):
            self._notify(kind)
        return {"removed": removed, "added": added, "errors": errors + rec["errors"]}

    def emergency_clear(self) -> int:
        """Gỡ TOÀN BỘ rule NetGuard khỏi Firewall và tắt tự động chặn. Có bản sao lưu để khôi phục."""
        with self._lock:
            self.snapshots.create("Tự động trước khi gỡ toàn bộ rule", "pre-restore")
            active = self.storage.list_blocks(active_only=True)
            names = {r["rule_name"] for r in active}
            try:
                names |= self.fw.list_rules()
            except FirewallError:
                pass
            errors = []
            for name in names:
                try:
                    self.fw.delete_rule(name)
                except FirewallError as exc:
                    errors.append(str(exc))
            if errors and self.fw.can_modify():
                raise GuardError("Không gỡ được một số rule: " + "; ".join(errors[:3]))
            for r in active:
                self.storage.deactivate_block(r["id"])
            self._log("emergency", "emergency_clear", f"{len(names)} rule",
                      "Gỡ toàn bộ rule NetGuard, tắt tự động chặn", None)
            self.refresh_cache()
        self.set_settings({"auto_block": False}, actor="emergency", undoable=False)
        for kind in ("blocks", "journal", "backups"):
            self._notify(kind)
        return len(names)

    # ---- tự động chặn (có cầu dao an toàn)
    def auto_block(self, c: Connection) -> str | None:
        if not self.setting("auto_block") or not self.fw.can_modify():
            return None
        now = time.time()
        if now < self.breaker_until:
            return None
        while self._auto_times and now - self._auto_times[0] > 60:
            self._auto_times.popleft()
        if len(self._auto_times) >= int(self.setting("max_auto_blocks_per_min")):
            self.breaker_until = now + 300
            self._log("auto", "breaker", "", "Chặn quá nhiều mục trong 1 phút — tạm dừng tự động chặn 5 phút")
            self._notify("breaker")
            return None
        reason = "; ".join(c.reasons)[:500]
        try:
            if c.ip_score > 0 and is_public(c.remote_ip) and c.remote_ip not in PROTECTED_IPS:
                self.block_ip(c.remote_ip, reason, "auto", c.process, c.score)
                desc = f"Đã chặn IP {c.remote_ip}"
            elif "userdir" in c.tags and c.exe:
                self.block_program(c.exe, reason, "auto", c.process, c.score)
                desc = f"Đã chặn chương trình {c.process}"
            else:
                return None
        except GuardError as exc:
            log.warning("auto_block bỏ qua: %s", exc)
            return None
        self._auto_times.append(now)
        return desc
