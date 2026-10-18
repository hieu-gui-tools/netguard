"""Kiểm tra chữ ký số (Authenticode) của file thực thi, chạy nền và cache vào SQLite."""
from __future__ import annotations

import json
import logging
import os
import queue
import re
import subprocess
import sys
import threading

from .storage import Storage

log = logging.getLogger(__name__)
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

TRUSTED_PUBLISHERS = (
    "microsoft", "google", "nvidia", "intel", "realtek", "mozilla", "apple", "adobe", "amd",
    "advanced micro devices", "vng", "zalo", "telegram", "kingsoft", "cốc cốc", "coc coc",
    "oracle", "jetbrains", "github", "python software foundation", "anthropic", "notion labs",
    "dropbox", "zoom", "valve", "logitech", "dell", "hp inc", "lenovo", "asus", "tp-link",
)


def signer_name(subject: str) -> str:
    m = re.search(r"(?:^|,\s*)CN=([^,]+)", subject or "")
    if m:
        return m.group(1).strip().strip('"')
    m = re.search(r"O=([^,]+)", subject or "")
    return m.group(1).strip().strip('"') if m else ""


def is_trusted_publisher(subject: str) -> bool:
    s = (subject or "").lower()
    return any(p in s for p in TRUSTED_PUBLISHERS)


def check_signatures(paths: list[str]) -> list[tuple[str, str]]:
    """Trả về [(status, signer)] theo đúng thứ tự paths. status: Valid, NotSigned, HashMismatch, NotTrusted..."""
    script = (
        "[Console]::OutputEncoding=[Text.Encoding]::UTF8; "
        "$p = $env:NG_PATHS | ConvertFrom-Json; "
        "$r = foreach($f in $p){ $s = Get-AuthenticodeSignature -LiteralPath $f; "
        "[pscustomobject]@{status=[string]$s.Status; signer=[string]$s.SignerCertificate.Subject} }; "
        "ConvertTo-Json -InputObject @($r) -Compress"
    )
    env = dict(os.environ, NG_PATHS=json.dumps(paths))
    try:
        p = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=120, env=env, creationflags=_NO_WINDOW,
        )
        data = json.loads(p.stdout)
        if isinstance(data, dict):
            data = [data]
        if len(data) != len(paths):
            raise ValueError("số kết quả không khớp")
        return [(d.get("status") or "Unknown", d.get("signer") or "") for d in data]
    except Exception as exc:
        log.warning("Kiểm tra chữ ký lỗi: %s", exc)
        return [("Unknown", "")] * len(paths)


class SignatureCache:
    def __init__(self, storage: Storage | None, enabled: bool | None = None):
        self.storage = storage
        self.enabled = (sys.platform == "win32") if enabled is None else enabled
        self._mem: dict[str, tuple[str, str]] = {}
        self._pending: set[str] = set()
        self._q: queue.Queue[str] = queue.Queue()
        self._stop = threading.Event()
        if self.enabled:
            threading.Thread(target=self._run, daemon=True, name="signature-worker").start()

    def lookup(self, path: str) -> tuple[str, str] | None:
        """Trả về (status, signer) nếu đã biết; nếu chưa thì xếp hàng kiểm tra nền và trả về None."""
        if not path or not self.enabled:
            return None
        hit = self._mem.get(path)
        if hit:
            return hit
        try:
            mtime = os.stat(path).st_mtime
        except OSError:
            return None
        if self.storage:
            row = self.storage.get_sig(path)
            if row and abs(row["mtime"] - mtime) < 1:
                self._mem[path] = (row["status"], row["signer"] or "")
                return self._mem[path]
        if path not in self._pending:
            self._pending.add(path)
            self._q.put(path)
        return None

    def stop(self) -> None:
        self._stop.set()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                batch = [self._q.get(timeout=1)]
            except queue.Empty:
                continue
            while len(batch) < 20:
                try:
                    batch.append(self._q.get_nowait())
                except queue.Empty:
                    break
            for path, (status, signer) in zip(batch, check_signatures(batch)):
                self._mem[path] = (status, signer)
                self._pending.discard(path)
                if self.storage and status != "Unknown":
                    try:
                        self.storage.put_sig(path, os.stat(path).st_mtime, status, signer)
                    except OSError:
                        pass
