"""Điều khiển Windows Firewall qua netsh/PowerShell. Mọi rule do app tạo đều có tiền tố NetGuard-."""
from __future__ import annotations

import json
import subprocess
import sys
import threading
from pathlib import Path

from .config import RULE_PREFIX

_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


class FirewallError(RuntimeError):
    pass


def _run(args: list[str], timeout: int = 60) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            args, capture_output=True, text=True, errors="replace",
            timeout=timeout, creationflags=_NO_WINDOW,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise FirewallError(str(exc)) from exc


class WindowsFirewall:
    name = "windows"

    def is_admin(self) -> bool:
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False

    def can_modify(self) -> bool:
        return self.is_admin()

    def _netsh(self, *args: str) -> None:
        if not self.can_modify():
            raise FirewallError("Cần chạy NetGuard với quyền Administrator để thay đổi Windows Firewall.")
        p = _run(["netsh", "advfirewall", *args])
        if p.returncode != 0:
            raise FirewallError((p.stdout + p.stderr).strip() or f"netsh lỗi (mã {p.returncode})")

    def _add(self, name: str, extra: list[str]) -> None:
        created = []
        try:
            for direction in ("out", "in"):
                self._netsh("firewall", "add", "rule", f"name={name}", f"dir={direction}",
                            "action=block", "enable=yes", "profile=any", "protocol=any", *extra)
                created.append(direction)
        except FirewallError:
            if created:  # không để lại rule dở dang
                try:
                    self._netsh("firewall", "delete", "rule", f"name={name}")
                except FirewallError:
                    pass
            raise

    def add_block_ip(self, name: str, ip: str) -> None:
        self._add(name, [f"remoteip={ip}"])

    def add_block_program(self, name: str, path: str) -> None:
        self._add(name, [f"program={path}"])

    def delete_rule(self, name: str) -> None:
        try:
            self._netsh("firewall", "delete", "rule", f"name={name}")
        except FirewallError:
            if name in self.list_rules():  # lỗi thật, không phải "rule không tồn tại"
                raise

    def list_rules(self) -> set[str]:
        script = (
            "[Console]::OutputEncoding=[Text.Encoding]::UTF8; "
            f"Get-NetFirewallRule -DisplayName '{RULE_PREFIX}-*' -ErrorAction SilentlyContinue | "
            "Select-Object -ExpandProperty DisplayName | ConvertTo-Json -Compress"
        )
        p = _run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script])
        out = (p.stdout or "").strip()
        if p.returncode != 0:
            raise FirewallError(p.stderr.strip() or "Không đọc được danh sách rule")
        if not out:
            return set()
        try:
            data = json.loads(out)
        except ValueError as exc:
            raise FirewallError(f"Kết quả PowerShell không hợp lệ: {out[:200]}") from exc
        return {data} if isinstance(data, str) else set(data)

    def export_policy(self, path: Path) -> None:
        self._netsh("export", str(path))

    def import_policy(self, path: Path) -> None:
        self._netsh("import", str(path))


class DryRunFirewall:
    """Giả lập firewall (dùng cho thử nghiệm / chạy ngoài Windows). Không đụng tới hệ thống."""
    name = "dry-run"

    def __init__(self, path: Path | None = None):
        self.path = Path(path) if path else None
        self._lock = threading.Lock()
        self.rules: dict[str, dict] = {}
        if self.path and self.path.exists():
            self.rules = json.loads(self.path.read_text("utf-8"))

    def _save(self) -> None:
        if self.path:
            self.path.write_text(json.dumps(self.rules), "utf-8")

    def is_admin(self) -> bool:
        return True

    def can_modify(self) -> bool:
        return True

    def add_block_ip(self, name: str, ip: str) -> None:
        with self._lock:
            self.rules[name] = {"remoteip": ip}
            self._save()

    def add_block_program(self, name: str, path: str) -> None:
        with self._lock:
            self.rules[name] = {"program": path}
            self._save()

    def delete_rule(self, name: str) -> None:
        with self._lock:
            self.rules.pop(name, None)
            self._save()

    def list_rules(self) -> set[str]:
        with self._lock:
            return {n for n in self.rules if n.startswith(RULE_PREFIX + "-")}

    def export_policy(self, path: Path) -> None:
        Path(path).write_text(json.dumps(self.rules), "utf-8")

    def import_policy(self, path: Path) -> None:
        with self._lock:
            self.rules = json.loads(Path(path).read_text("utf-8"))
            self._save()


def create_firewall(dry_run: bool = False, state_path: Path | None = None):
    if dry_run or sys.platform != "win32":
        return DryRunFirewall(state_path)
    return WindowsFirewall()
