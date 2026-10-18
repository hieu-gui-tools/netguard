"""SQLite: nguồn dữ liệu duy nhất cho danh sách chặn, nhật ký thay đổi, danh sách tin cậy, cài đặt."""
from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Iterable

log = logging.getLogger(__name__)

SCHEMA = """
CREATE TABLE IF NOT EXISTS blocks(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,
    target TEXT NOT NULL,
    rule_name TEXT NOT NULL UNIQUE,
    reason TEXT, process TEXT,
    source TEXT NOT NULL,
    score INTEGER NOT NULL DEFAULT 0,
    created REAL NOT NULL,
    active INTEGER NOT NULL DEFAULT 1,
    removed REAL
);
CREATE TABLE IF NOT EXISTS journal(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL,
    target TEXT, detail TEXT, undo TEXT,
    undone INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS allowlist(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL, value TEXT NOT NULL, note TEXT, created REAL NOT NULL,
    UNIQUE(kind, value)
);
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS signatures(path TEXT PRIMARY KEY, mtime REAL, status TEXT, signer TEXT);
CREATE TABLE IF NOT EXISTS events(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL, level TEXT NOT NULL, score INTEGER, process TEXT, exe TEXT,
    direction TEXT, proto TEXT, remote_ip TEXT, remote_port INTEGER, reasons TEXT,
    blocked INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
"""


class Storage:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.lock = threading.RLock()
        self.recovered = False  # True nếu DB hỏng và đã được tạo lại
        self.conn = self._open()

    # ---- kết nối / tự phục hồi khi DB hỏng
    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        try:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            return conn
        except Exception:
            try:
                conn.close()
            except Exception:
                pass
            raise

    def _open(self) -> sqlite3.Connection:
        conn = None
        try:
            conn = self._connect()
            res = conn.execute("PRAGMA integrity_check").fetchone()
            if res[0] != "ok":
                raise sqlite3.DatabaseError(f"integrity_check: {res[0]}")
            conn.executescript(SCHEMA)
            return conn
        except sqlite3.DatabaseError as exc:
            log.error("Cơ sở dữ liệu hỏng (%s) — tạo lại", exc)
            if conn is not None:
                try:
                    conn.close()
                except sqlite3.Error:
                    pass
            stamp = time.strftime("%Y%m%d-%H%M%S")
            for suffix in ("", "-wal", "-shm"):
                f = Path(str(self.path) + suffix)
                if f.exists():
                    f.rename(f.with_name(f.name + f".corrupt-{stamp}"))
            self.recovered = True
            conn = self._connect()
            conn.executescript(SCHEMA)
            return conn

    def _q(self, sql: str, args: Iterable[Any] = ()) -> list[sqlite3.Row]:
        with self.lock:
            return self.conn.execute(sql, tuple(args)).fetchall()

    def _x(self, sql: str, args: Iterable[Any] = ()) -> sqlite3.Cursor:
        with self.lock:
            return self.conn.execute(sql, tuple(args))

    def close(self) -> None:
        with self.lock:
            self.conn.close()

    # ---- cài đặt
    def get_setting(self, key: str, default: Any = None) -> Any:
        rows = self._q("SELECT value FROM settings WHERE key=?", (key,))
        if not rows:
            return default
        try:
            return json.loads(rows[0]["value"])
        except ValueError:
            return default

    def set_settings(self, values: dict[str, Any]) -> None:
        with self.lock:
            for k, v in values.items():
                self.conn.execute(
                    "INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)", (k, json.dumps(v))
                )

    # ---- danh sách chặn
    def upsert_block(self, kind, target, rule_name, reason, process, source, score) -> int:
        now = time.time()
        with self.lock:
            row = self.conn.execute("SELECT id FROM blocks WHERE rule_name=?", (rule_name,)).fetchone()
            if row:
                self.conn.execute(
                    "UPDATE blocks SET kind=?,target=?,reason=?,process=?,source=?,score=?,"
                    "created=?,active=1,removed=NULL WHERE id=?",
                    (kind, target, reason, process, source, score, now, row["id"]),
                )
                return row["id"]
            cur = self.conn.execute(
                "INSERT INTO blocks(kind,target,rule_name,reason,process,source,score,created) "
                "VALUES(?,?,?,?,?,?,?,?)",
                (kind, target, rule_name, reason, process, source, score, now),
            )
            return int(cur.lastrowid)

    def get_block(self, block_id: int):
        rows = self._q("SELECT * FROM blocks WHERE id=?", (block_id,))
        return rows[0] if rows else None

    def get_block_by_name(self, rule_name: str):
        rows = self._q("SELECT * FROM blocks WHERE rule_name=?", (rule_name,))
        return rows[0] if rows else None

    def list_blocks(self, active_only: bool = True):
        sql = "SELECT * FROM blocks" + (" WHERE active=1" if active_only else "") + " ORDER BY created DESC"
        return self._q(sql)

    def deactivate_block(self, block_id: int) -> None:
        self._x("UPDATE blocks SET active=0, removed=? WHERE id=?", (time.time(), block_id))

    # ---- nhật ký thay đổi
    def add_journal(self, actor, action, target, detail, undo: dict | None) -> int:
        cur = self._x(
            "INSERT INTO journal(ts,actor,action,target,detail,undo) VALUES(?,?,?,?,?,?)",
            (time.time(), actor, action, target, detail, json.dumps(undo) if undo else None),
        )
        return int(cur.lastrowid)

    def list_journal(self, limit: int = 1000):
        return self._q("SELECT * FROM journal ORDER BY id DESC LIMIT ?", (limit,))

    def get_journal(self, journal_id: int):
        rows = self._q("SELECT * FROM journal WHERE id=?", (journal_id,))
        return rows[0] if rows else None

    def mark_undone(self, journal_id: int) -> None:
        self._x("UPDATE journal SET undone=1 WHERE id=?", (journal_id,))

    # ---- danh sách tin cậy
    def add_allow(self, kind: str, value: str, note: str = "") -> int | None:
        try:
            cur = self._x(
                "INSERT INTO allowlist(kind,value,note,created) VALUES(?,?,?,?)",
                (kind, value, note, time.time()),
            )
            return int(cur.lastrowid)
        except sqlite3.IntegrityError:
            return None

    def get_allow(self, allow_id: int):
        rows = self._q("SELECT * FROM allowlist WHERE id=?", (allow_id,))
        return rows[0] if rows else None

    def remove_allow(self, allow_id: int) -> None:
        self._x("DELETE FROM allowlist WHERE id=?", (allow_id,))

    def list_allow(self):
        return self._q("SELECT * FROM allowlist ORDER BY id")

    def replace_allowlist(self, items: list[dict]) -> None:
        with self.lock:
            self.conn.execute("BEGIN")
            try:
                self.conn.execute("DELETE FROM allowlist")
                for it in items:
                    self.conn.execute(
                        "INSERT OR IGNORE INTO allowlist(kind,value,note,created) VALUES(?,?,?,?)",
                        (it["kind"], it["value"], it.get("note", ""), time.time()),
                    )
                self.conn.execute("COMMIT")
            except Exception:
                self.conn.execute("ROLLBACK")
                raise

    # ---- cảnh báo
    def add_event(self, c, blocked: bool) -> None:
        self._x(
            "INSERT INTO events(ts,level,score,process,exe,direction,proto,remote_ip,remote_port,reasons,blocked)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (time.time(), c.level, c.score, c.process, c.exe, c.direction, c.proto,
             c.remote_ip, c.remote_port, "; ".join(c.reasons), int(blocked)),
        )

    def recent_events(self, limit: int = 100):
        return self._q("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,))

    def prune_events(self, days: int) -> None:
        self._x("DELETE FROM events WHERE ts < ?", (time.time() - days * 86400,))

    # ---- chữ ký số (cache)
    def get_sig(self, path: str):
        rows = self._q("SELECT * FROM signatures WHERE path=?", (path,))
        return rows[0] if rows else None

    def put_sig(self, path: str, mtime: float, status: str, signer: str) -> None:
        self._x(
            "INSERT OR REPLACE INTO signatures(path,mtime,status,signer) VALUES(?,?,?,?)",
            (path, mtime, status, signer),
        )
