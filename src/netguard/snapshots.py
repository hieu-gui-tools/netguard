"""Bản sao lưu trạng thái (JSON) — dùng để khôi phục khi có sự cố."""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

from .config import DEFAULT_SETTINGS
from .storage import Storage

FORMAT = 1
KINDS = ("manual", "auto", "pre-restore")


class SnapshotError(RuntimeError):
    pass


class SnapshotManager:
    def __init__(self, directory: Path, storage: Storage):
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.storage = storage

    def create(self, label: str, kind: str = "manual", keep: int | None = None) -> Path:
        data = {
            "format": FORMAT,
            "created": time.time(),
            "label": label,
            "kind": kind,
            "blocks": [
                {k: r[k] for k in ("kind", "target", "rule_name", "reason", "process", "source", "score")}
                for r in self.storage.list_blocks(active_only=True)
            ],
            "allowlist": [
                {"kind": r["kind"], "value": r["value"], "note": r["note"] or ""}
                for r in self.storage.list_allow()
            ],
            "settings": {k: self.storage.get_setting(k, v) for k, v in DEFAULT_SETTINGS.items()},
        }
        stamp = time.strftime("%Y%m%d-%H%M%S")
        path = self.dir / f"snapshot-{stamp}-{kind}.json"
        n = 1
        while path.exists():
            n += 1
            path = self.dir / f"snapshot-{stamp}-{kind}-{n}.json"
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=1), "utf-8")
        os.replace(tmp, path)  # ghi nguyên tử: không bao giờ để lại file dở dang
        self.prune(keep if keep is not None else int(self.storage.get_setting("snapshot_keep", 30)))
        return path

    def load(self, path: Path) -> dict:
        try:
            data = json.loads(Path(path).read_text("utf-8"))
        except (OSError, ValueError) as exc:
            raise SnapshotError(f"Không đọc được bản sao lưu: {exc}") from exc
        if data.get("format") != FORMAT or not isinstance(data.get("blocks"), list):
            raise SnapshotError("Bản sao lưu không đúng định dạng")
        data.setdefault("allowlist", [])
        data.setdefault("settings", {})
        return data

    def list(self) -> list[dict]:
        out = []
        for p in sorted(self.dir.glob("snapshot-*.json"), reverse=True):
            try:
                d = self.load(p)
            except SnapshotError:
                continue
            out.append({"path": p, "created": d["created"], "label": d.get("label", ""),
                        "kind": d.get("kind", "manual"), "blocks": len(d["blocks"])})
        return out

    def latest(self) -> Path | None:
        items = self.list()
        return items[0]["path"] if items else None

    def delete(self, path: Path) -> None:
        Path(path).unlink(missing_ok=True)

    def prune(self, keep: int) -> None:
        auto = [i for i in self.list() if i["kind"] in ("auto", "pre-restore")]
        for item in auto[keep:]:  # list() đã sắp mới → cũ; bản thủ công không bao giờ bị xóa
            self.delete(item["path"])
