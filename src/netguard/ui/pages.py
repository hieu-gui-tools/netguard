"""Các trang giao diện. Mỗi trang giữ tham chiếu tới cửa sổ chính (win) để gọi hành động."""
from __future__ import annotations

import os

from PySide6.QtCore import Qt, QTimer, QUrl
from PySide6.QtGui import QDesktopServices, QGuiApplication
from PySide6.QtWidgets import (QCheckBox, QComboBox, QFormLayout, QFrame, QGridLayout, QHBoxLayout, QInputDialog,
                               QLabel, QLineEdit, QMenu, QPlainTextEdit, QPushButton, QSpinBox, QTableView,
                               QVBoxLayout, QWidget, QFileDialog, QAbstractItemView)

from ..models import DIR_LABEL, LEVEL_LABEL, Connection
from ..netutil import fmt_addr
from .theme import LEVEL_COLOR
from .widgets import (COL_WIDTHS, Card, ConnFilter, ConnModel, confirm, fill_table, fmt_ts, make_table,
                      selected_id)


def page_title(text: str, sub: str = "") -> QWidget:
    w = QWidget()
    lay = QVBoxLayout(w)
    lay.setContentsMargins(0, 0, 0, 0)
    lay.setSpacing(2)
    t = QLabel(text)
    t.setObjectName("title")
    lay.addWidget(t)
    if sub:
        s = QLabel(sub)
        s.setObjectName("muted")
        s.setWordWrap(True)
        lay.addWidget(s)
    return w


def button(text: str, kind: str = "", slot=None) -> QPushButton:
    b = QPushButton(text)
    if kind:
        b.setObjectName(kind)
    if slot:
        b.clicked.connect(slot)
    return b


class BasePage(QWidget):
    def __init__(self, win):
        super().__init__()
        self.win = win
        self.root = QVBoxLayout(self)
        self.root.setContentsMargins(24, 20, 24, 16)
        self.root.setSpacing(12)


# ───────────────────────── Tổng quan
class DashboardPage(BasePage):
    def __init__(self, win):
        super().__init__(win)
        self.root.addWidget(page_title("Tổng quan", "Tình trạng kết nối mạng của máy tính theo thời gian thực."))
        row = QHBoxLayout()
        self.c_total = Card("Kết nối đang theo dõi")
        self.c_danger = Card("Nguy hiểm", LEVEL_COLOR["DANGEROUS"])
        self.c_susp = Card("Đáng ngờ", LEVEL_COLOR["SUSPICIOUS"])
        self.c_ok = Card("Bình thường / tin cậy", LEVEL_COLOR["TRUSTED"])
        self.c_blocked = Card("Mục đang bị chặn")
        for c in (self.c_total, self.c_danger, self.c_susp, self.c_ok, self.c_blocked):
            row.addWidget(c)
        self.root.addLayout(row)

        box = QFrame()
        box.setObjectName("card")
        g = QGridLayout(box)
        g.setContentsMargins(16, 12, 16, 12)
        g.setHorizontalSpacing(16)
        self.admin_lbl = QLabel()
        self.btn_admin = button("Chạy lại với quyền Administrator", "primary", win.restart_as_admin)
        self.auto_cb = QCheckBox("Tự động chặn kết nối nguy hiểm")
        self.auto_cb.toggled.connect(win.toggle_auto_block)
        self.breaker_lbl = QLabel()
        self.feed_lbl = QLabel()
        self.feed_lbl.setObjectName("muted")
        self.btn_feed = button("Cập nhật danh sách đe dọa", "", win.update_feed)
        g.addWidget(QLabel("Quyền hệ thống"), 0, 0)
        g.addWidget(self.admin_lbl, 0, 1)
        g.addWidget(self.btn_admin, 0, 2)
        g.addWidget(QLabel("Chặn tự động"), 1, 0)
        g.addWidget(self.auto_cb, 1, 1)
        g.addWidget(self.breaker_lbl, 1, 2)
        g.addWidget(QLabel("Danh sách đe dọa"), 2, 0)
        g.addWidget(self.feed_lbl, 2, 1)
        g.addWidget(self.btn_feed, 2, 2)
        self.etw_lbl = QLabel()
        g.addWidget(QLabel("Thời gian thực (ETW)"), 3, 0)
        g.addWidget(self.etw_lbl, 3, 1, 1, 2)
        g.setColumnStretch(1, 1)
        self.root.addWidget(box)

        lbl = QLabel("Cảnh báo gần đây")
        lbl.setObjectName("title")
        lbl.setStyleSheet("font-size:15px;")
        self.root.addWidget(lbl)
        self.alerts = make_table(["Thời gian", "Mức độ", "Tiến trình", "Đích", "Lý do", "Đã chặn"],
                                 [120, 100, 160, 200, 520, 70])
        self.root.addWidget(self.alerts, 1)
        self.refresh()
        self._etw_timer = QTimer(self)
        self._etw_timer.timeout.connect(self.refresh_etw)
        self._etw_timer.start(2000)

    def refresh_etw(self) -> None:
        etw = self.win.ctx.etw
        interval = int(self.win.guard.setting("poll_interval"))
        text, style = {
            "running": (f"Đang chạy — bắt kết nối ngay khi mở · {etw.total:,} sự kiện", "ok"),
            "starting": ("Đang khởi động…", "muted"),
            "disabled": (f"Đã tắt trong Cài đặt — quét định kỳ mỗi {interval} giây", "muted"),
            "needs-admin": (f"Chưa bật: cần quyền Administrator — đang quét định kỳ mỗi {interval} giây", "warn"),
            "missing-lib": ("Chưa bật: thiếu thư viện pywintrace (chạy: uv sync)", "warn"),
            "unsupported": ("Không hỗ trợ trên hệ điều hành này — quét định kỳ", "muted"),
            "overload": ("Đã tự tắt vì dùng quá nhiều CPU — đang quét định kỳ", "warn"),
            "error": (f"Lỗi ETW — đang quét định kỳ. {etw.detail}"[:160], "warn"),
            "stopped": (f"Chưa chạy — quét định kỳ mỗi {interval} giây", "muted"),
        }.get(etw.status, (etw.status, "muted"))
        self.etw_lbl.setText(text)
        self.etw_lbl.setObjectName(style)
        self.etw_lbl.style().unpolish(self.etw_lbl)
        self.etw_lbl.style().polish(self.etw_lbl)

    def update_stats(self, conns: list[Connection]) -> None:
        live = [c for c in conns if c.level != "LOCAL"]
        self.c_total.set(len(live))
        self.c_danger.set(sum(c.level == "DANGEROUS" for c in live))
        self.c_susp.set(sum(c.level == "SUSPICIOUS" for c in live))
        self.c_ok.set(sum(c.level in ("NORMAL", "TRUSTED") for c in live))

    def refresh(self) -> None:
        g = self.win.guard
        self.c_blocked.set(len(self.win.storage.list_blocks(active_only=True)))
        if self.win.ctx.dry_run:
            self.admin_lbl.setText("Chế độ thử nghiệm — không thay đổi Windows Firewall")
            self.admin_lbl.setObjectName("warn")
            self.btn_admin.setVisible(False)
        elif self.win.fw.is_admin():
            self.admin_lbl.setText("Đã có quyền Administrator")
            self.admin_lbl.setObjectName("ok")
            self.btn_admin.setVisible(False)
        else:
            self.admin_lbl.setText("Chưa có quyền Administrator — chỉ giám sát, chưa thể chặn")
            self.admin_lbl.setObjectName("warn")
            self.btn_admin.setVisible(True)
        self.admin_lbl.style().unpolish(self.admin_lbl)
        self.admin_lbl.style().polish(self.admin_lbl)
        self.auto_cb.blockSignals(True)
        self.auto_cb.setChecked(bool(g.setting("auto_block")))
        self.auto_cb.blockSignals(False)
        import time
        if time.time() < g.breaker_until:
            self.breaker_lbl.setText(f"Cầu dao đang ngắt đến {fmt_ts(g.breaker_until)}")
            self.breaker_lbl.setObjectName("warn")
        else:
            self.breaker_lbl.setText("")
        f = self.win.ctx.feed
        self.feed_lbl.setText(f"{len(f):,} mục · cập nhật {fmt_ts(f.updated)}" if len(f) else "Chưa tải — bấm Cập nhật")
        self.refresh_etw()
        ev = self.win.storage.recent_events(100)
        fill_table(
            self.alerts,
            [[fmt_ts(e["ts"]), LEVEL_LABEL.get(e["level"], e["level"]), e["process"],
              fmt_addr(e["remote_ip"], e["remote_port"]) if e["remote_ip"] else "—", e["reasons"],
              "Có" if e["blocked"] else ""] for e in ev],
            [e["id"] for e in ev], [LEVEL_COLOR.get(e["level"]) for e in ev],
        )


# ───────────────────────── Kết nối
class ConnectionsPage(BasePage):
    def __init__(self, win):
        super().__init__(win)
        self.root.addWidget(page_title("Kết nối", "Chuột phải vào một dòng để chặn hoặc đánh dấu tin cậy."))
        bar = QHBoxLayout()
        self.level = QComboBox()
        for text, key in [("Tất cả mức độ", "ALL"), ("Rủi ro (đáng ngờ + nguy hiểm)", "RISK"),
                          ("Nguy hiểm", "DANGEROUS"), ("Đáng ngờ", "SUSPICIOUS"), ("Bình thường", "NORMAL"),
                          ("Tin cậy", "TRUSTED")]:
            self.level.addItem(text, key)
        self.direction = QComboBox()
        for text, key in [("Mọi hướng", "ALL"), ("Đi ra", "out"), ("Đi vào", "in"), ("Lắng nghe", "listen")]:
            self.direction.addItem(text, key)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Tìm theo tiến trình, IP, cổng, PID…")
        self.hide_local = QCheckBox("Ẩn kết nối nội bộ")
        self.hide_local.setChecked(True)
        self.pause = QCheckBox("Tạm dừng cập nhật")
        self.count = QLabel("")
        self.count.setObjectName("muted")
        for w in (self.level, self.direction):
            bar.addWidget(w)
        bar.addWidget(self.search, 1)
        for w in (self.hide_local, self.pause, self.count):
            bar.addWidget(w)
        self.root.addLayout(bar)

        self.model = ConnModel()
        self.proxy = ConnFilter()
        self.proxy.setSourceModel(self.model)
        self.view = QTableView()
        self.view.setModel(self.proxy)
        self.view.setSortingEnabled(True)
        self.view.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.view.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.view.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.view.verticalHeader().setVisible(False)
        self.view.verticalHeader().setDefaultSectionSize(28)
        self.view.setAlternatingRowColors(True)
        self.view.setShowGrid(False)
        self.view.horizontalHeader().setStretchLastSection(True)
        for i, w in enumerate(COL_WIDTHS):
            self.view.setColumnWidth(i, w)
        self.view.sortByColumn(0, Qt.SortOrder.DescendingOrder)
        self.view.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.view.customContextMenuRequested.connect(self.menu)
        self.root.addWidget(self.view, 1)

        self.level.currentIndexChanged.connect(self._filters)
        self.direction.currentIndexChanged.connect(self._filters)
        self.search.textChanged.connect(self._filters)
        self.hide_local.toggled.connect(self._filters)

    def _filters(self) -> None:
        self.proxy.level = self.level.currentData()
        self.proxy.direction = self.direction.currentData()
        self.proxy.text = self.search.text().strip().lower()
        self.proxy.hide_local = self.hide_local.isChecked()
        self.proxy.invalidate()
        self._count()

    def _count(self) -> None:
        self.count.setText(f"{self.proxy.rowCount()} / {len(self.model.rows)}")

    def current(self) -> Connection | None:
        idx = self.view.currentIndex()
        if not idx.isValid():
            return None
        return self.model.rows[self.proxy.mapToSource(idx).row()]

    def refresh(self, conns: list[Connection]) -> None:
        if self.pause.isChecked():
            return
        cur = self.current()
        key = cur.key if cur else None
        scroll = self.view.verticalScrollBar().value()
        self.model.set_rows(conns)
        if key:
            for r in range(self.proxy.rowCount()):
                src = self.proxy.mapToSource(self.proxy.index(r, 0)).row()
                if self.model.rows[src].key == key:
                    self.view.selectRow(r)
                    break
        self.view.verticalScrollBar().setValue(scroll)
        self._count()

    def menu(self, pos) -> None:
        c = self.current()
        if not c:
            return
        m = QMenu(self)
        a_ip = m.addAction(f"Chặn IP {c.remote_ip}")
        a_ip.setEnabled(bool(c.remote_ip) and not c.blocked)
        a_prog = m.addAction(f"Chặn chương trình {c.process}")
        a_prog.setEnabled(bool(c.exe))
        m.addSeparator()
        a_tp = m.addAction(f"Tin cậy tiến trình {c.process}")
        a_ti = m.addAction(f"Tin cậy IP {c.remote_ip}")
        a_ti.setEnabled(bool(c.remote_ip))
        m.addSeparator()
        a_open = m.addAction("Mở thư mục chứa file")
        a_open.setEnabled(bool(c.exe))
        a_copy = m.addAction("Sao chép IP đích")
        a_copy.setEnabled(bool(c.remote_ip))
        chosen = m.exec(self.view.viewport().mapToGlobal(pos))
        w = self.win
        if chosen is a_ip:
            w.act_block_ip(c)
        elif chosen is a_prog:
            w.act_block_program(c)
        elif chosen is a_tp:
            w.act_allow("process", c.process, f"từ kết nối {c.remote_ip}")
        elif chosen is a_ti:
            w.act_allow("ip", c.remote_ip, f"từ tiến trình {c.process}")
        elif chosen is a_open:
            QDesktopServices.openUrl(QUrl.fromLocalFile(os.path.dirname(c.exe)))
        elif chosen is a_copy:
            QGuiApplication.clipboard().setText(c.remote_ip)


# ───────────────────────── Danh sách chặn
class BlocksPage(BasePage):
    def __init__(self, win):
        super().__init__(win)
        self.root.addWidget(page_title(
            "Danh sách chặn",
            "Mỗi mục là một rule trong Windows Firewall (tên bắt đầu bằng NetGuard-). Bỏ chặn có hiệu lực ngay."))
        bar = QHBoxLayout()
        bar.addWidget(button("Bỏ chặn mục đã chọn", "primary", self.unblock))
        bar.addWidget(button("Chặn IP thủ công…", "", self.add_ip))
        bar.addWidget(button("Đối soát với Firewall", "", win.sync_firewall))
        bar.addStretch(1)
        self.show_removed = QCheckBox("Hiện cả mục đã gỡ")
        self.show_removed.toggled.connect(self.refresh)
        bar.addWidget(self.show_removed)
        self.root.addLayout(bar)
        self.table = make_table(["Loại", "Đối tượng", "Nguồn", "Điểm", "Thời gian", "Trạng thái", "Lý do"],
                                [110, 330, 90, 60, 120, 100, 400])
        self.root.addWidget(self.table, 1)
        self.refresh()

    def refresh(self) -> None:
        rows = self.win.storage.list_blocks(active_only=not self.show_removed.isChecked())
        src = {"auto": "Tự động", "manual": "Thủ công", "restore": "Khôi phục", "undo": "Hoàn tác"}
        fill_table(
            self.table,
            [["IP" if r["kind"] == "ip" else "Chương trình", r["target"], src.get(r["source"], r["source"]),
              r["score"] or "", fmt_ts(r["created"]), "Đang chặn" if r["active"] else "Đã gỡ",
              r["reason"] or ""] for r in rows],
            [r["id"] for r in rows], [None if r["active"] else "#64748b" for r in rows],
        )

    def unblock(self) -> None:
        bid = selected_id(self.table)
        if bid is None:
            return
        row = self.win.storage.get_block(bid)
        if row and row["active"]:
            self.win.run(self.win.guard.unblock, bid, ok=f"Đã bỏ chặn {row['target']}")

    def add_ip(self) -> None:
        text, ok = QInputDialog.getText(self, "Chặn IP", "Nhập địa chỉ IP cần chặn:")
        if ok and text.strip():
            self.win.run(self.win.guard.block_ip, text.strip(), "Thêm thủ công", ok=f"Đã chặn {text.strip()}")


# ───────────────────────── Nhật ký thay đổi
ACTION = {
    "block_ip": "Chặn IP", "block_program": "Chặn chương trình", "unblock": "Bỏ chặn",
    "allow_add": "Thêm tin cậy", "allow_remove": "Gỡ tin cậy", "settings": "Đổi cài đặt",
    "restore_snapshot": "Khôi phục sao lưu", "reconcile": "Đồng bộ Firewall", "breaker": "Cầu dao an toàn",
    "emergency_clear": "Gỡ khẩn cấp",
}
ACTOR = {"auto": "Tự động", "manual": "Thủ công", "undo": "Hoàn tác", "restore": "Khôi phục",
         "system": "Hệ thống", "emergency": "Khẩn cấp"}


class JournalPage(BasePage):
    def __init__(self, win):
        super().__init__(win)
        self.root.addWidget(page_title(
            "Nhật ký thay đổi", "Mọi thay đổi đều được ghi lại. Chọn một dòng để hoàn tác riêng thay đổi đó."))
        bar = QHBoxLayout()
        bar.addWidget(button("Hoàn tác thay đổi đã chọn", "primary", self.undo))
        bar.addStretch(1)
        self.root.addLayout(bar)
        self.table = make_table(["Thời gian", "Nguồn", "Hành động", "Đối tượng", "Trạng thái", "Chi tiết"],
                                [120, 90, 160, 280, 120, 500])
        self.root.addWidget(self.table, 1)
        self.refresh()

    def refresh(self) -> None:
        rows = self.win.storage.list_journal(1000)
        fill_table(
            self.table,
            [[fmt_ts(r["ts"]), ACTOR.get(r["actor"], r["actor"]), ACTION.get(r["action"], r["action"]),
              r["target"], "Đã hoàn tác" if r["undone"] else ("Có thể hoàn tác" if r["undo"] else "—"),
              r["detail"] or ""] for r in rows],
            [r["id"] for r in rows], ["#64748b" if r["undone"] else None for r in rows],
        )

    def undo(self) -> None:
        jid = selected_id(self.table)
        if jid is not None and confirm(self, "Hoàn tác", "Hoàn tác thay đổi đã chọn?"):
            self.win.run(self.win.guard.undo, jid, ok="Đã hoàn tác")


# ───────────────────────── Sao lưu & khôi phục
class BackupsPage(BasePage):
    def __init__(self, win):
        super().__init__(win)
        self.root.addWidget(page_title(
            "Sao lưu & khôi phục",
            "NetGuard tự sao lưu khi khởi động và trước mỗi lần khôi phục. Khôi phục luôn tạo thêm một bản "
            "‘trước khi khôi phục’ để có thể quay lại."))
        bar = QHBoxLayout()
        bar.addWidget(button("Tạo bản sao lưu", "primary", self.create))
        bar.addWidget(button("Khôi phục bản đã chọn", "", self.restore))
        bar.addWidget(button("Xóa bản đã chọn", "", self.delete))
        bar.addWidget(button("Mở thư mục", "", lambda: QDesktopServices.openUrl(
            QUrl.fromLocalFile(str(win.guard.snapshots.dir)))))
        bar.addStretch(1)
        self.root.addLayout(bar)
        self.table = make_table(["Thời gian", "Loại", "Nhãn", "Mục đang chặn", "Tệp"], [130, 110, 340, 120, 400])
        self.root.addWidget(self.table, 1)

        box = QFrame()
        box.setObjectName("card")
        lay = QVBoxLayout(box)
        lay.setContentsMargins(16, 12, 16, 12)
        t = QLabel("Chính sách Windows Firewall (toàn bộ máy)")
        t.setStyleSheet("font-weight:600;")
        d = QLabel("Bản gốc được xuất tự động trong lần chạy đầu tiên có quyền Administrator "
                   "(backups\\firewall-original.wfw). Nhập lại sẽ thay thế TOÀN BỘ chính sách Firewall hiện tại.")
        d.setObjectName("muted")
        d.setWordWrap(True)
        row = QHBoxLayout()
        row.addWidget(button("Xuất chính sách…", "", self.export_fw))
        row.addWidget(button("Nhập chính sách…", "", self.import_fw))
        row.addStretch(1)
        row.addWidget(button("Gỡ toàn bộ rule NetGuard (khẩn cấp)", "danger", self.emergency))
        lay.addWidget(t)
        lay.addWidget(d)
        lay.addLayout(row)
        self.root.addWidget(box)
        self.refresh()

    def refresh(self) -> None:
        items = self.win.guard.snapshots.list()
        kinds = {"manual": "Thủ công", "auto": "Tự động", "pre-restore": "Trước khi khôi phục"}
        fill_table(
            self.table,
            [[fmt_ts(i["created"]), kinds.get(i["kind"], i["kind"]), i["label"], i["blocks"], i["path"].name]
             for i in items],
            [str(i["path"]) for i in items],
        )

    def create(self) -> None:
        label, ok = QInputDialog.getText(self, "Tạo bản sao lưu", "Ghi chú cho bản sao lưu:", text="Thủ công")
        if ok:
            self.win.run(self.win.guard.snapshot_now, label.strip() or "Thủ công", "manual", ok="Đã tạo bản sao lưu")

    def restore(self) -> None:
        path = selected_id(self.table)
        if path and confirm(self, "Khôi phục",
                            "Khôi phục danh sách chặn, danh sách tin cậy và cài đặt về thời điểm của bản sao lưu?\n"
                            "Một bản sao lưu của trạng thái hiện tại sẽ được tạo trước."):
            r = self.win.run(self.win.guard.restore_snapshot, path)
            if r:
                msg = f"Khôi phục xong: gỡ {r[1]['removed']}, thêm {r[1]['added']}."
                if r[1]["errors"]:
                    msg += f" Có {len(r[1]['errors'])} lỗi: {r[1]['errors'][0]}"
                self.win.show_info(msg)

    def delete(self) -> None:
        path = selected_id(self.table)
        if path and confirm(self, "Xóa", "Xóa bản sao lưu này?"):
            from pathlib import Path
            self.win.guard.snapshots.delete(Path(path))
            self.refresh()

    def export_fw(self) -> None:
        p, _ = QFileDialog.getSaveFileName(self, "Xuất chính sách Firewall", "firewall.wfw", "Windows Firewall (*.wfw)")
        if p:
            from pathlib import Path
            self.win.run(self.win.fw.export_policy, Path(p), ok="Đã xuất chính sách Firewall")

    def import_fw(self) -> None:
        p, _ = QFileDialog.getOpenFileName(self, "Nhập chính sách Firewall", "", "Windows Firewall (*.wfw)")
        if p and confirm(self, "Nhập chính sách",
                         "Thay thế TOÀN BỘ chính sách Windows Firewall hiện tại bằng tệp này?\n"
                         "Hãy chắc chắn bạn tin tưởng tệp."):
            from pathlib import Path
            if self.win.run(self.win.fw.import_policy, Path(p), ok="Đã nhập chính sách Firewall"):
                self.win.run(self.win.guard.reconcile, True, False)

    def emergency(self) -> None:
        if confirm(self, "Gỡ khẩn cấp",
                   "Gỡ TOÀN BỘ rule NetGuard khỏi Windows Firewall và tắt tự động chặn?\n"
                   "Bản sao lưu được tạo trước nên bạn vẫn khôi phục lại được."):
            r = self.win.run(self.win.guard.emergency_clear)
            if r:
                self.win.show_info(f"Đã gỡ {r[1]} rule và tắt tự động chặn.")


# ───────────────────────── Danh sách tin cậy
class AllowPage(BasePage):
    def __init__(self, win):
        super().__init__(win)
        self.root.addWidget(page_title(
            "Danh sách tin cậy", "Mục trong danh sách này không bao giờ bị đánh dấu hay tự động chặn."))
        form = QHBoxLayout()
        self.kind = QComboBox()
        for text, key in [("Tiến trình", "process"), ("Địa chỉ IP", "ip"), ("Dải mạng (CIDR)", "cidr")]:
            self.kind.addItem(text, key)
        self.value = QLineEdit()
        self.value.setPlaceholderText("Tên tiến trình (chrome.exe), đường dẫn đầy đủ, IP hoặc 10.0.0.0/8")
        self.note = QLineEdit()
        self.note.setPlaceholderText("Ghi chú (tùy chọn)")
        form.addWidget(self.kind)
        form.addWidget(self.value, 2)
        form.addWidget(self.note, 1)
        form.addWidget(button("Thêm", "primary", self.add))
        self.root.addLayout(form)
        bar = QHBoxLayout()
        bar.addWidget(button("Gỡ mục đã chọn", "", self.remove))
        bar.addStretch(1)
        self.root.addLayout(bar)
        self.table = make_table(["Loại", "Giá trị", "Ghi chú", "Thêm lúc"], [130, 460, 300, 130])
        self.root.addWidget(self.table, 1)
        self.refresh()

    def refresh(self) -> None:
        rows = self.win.storage.list_allow()
        names = {"process": "Tiến trình", "ip": "Địa chỉ IP", "cidr": "Dải mạng"}
        fill_table(self.table, [[names.get(r["kind"], r["kind"]), r["value"], r["note"] or "", fmt_ts(r["created"])]
                                for r in rows], [r["id"] for r in rows])

    def add(self) -> None:
        if self.value.text().strip() and self.win.run(
                self.win.guard.allow_add, self.kind.currentData(), self.value.text(), self.note.text()):
            self.value.clear()
            self.note.clear()

    def remove(self) -> None:
        aid = selected_id(self.table)
        if aid is not None:
            self.win.run(self.win.guard.allow_remove, aid)


# ───────────────────────── Cài đặt
class SettingsPage(BasePage):
    def __init__(self, win):
        super().__init__(win)
        self.root.addWidget(page_title("Cài đặt", "Thay đổi cài đặt cũng được ghi vào nhật ký và hoàn tác được."))
        form = QFormLayout()
        form.setHorizontalSpacing(24)
        form.setVerticalSpacing(10)
        self.poll = self._spin(1, 30)
        self.threshold = self._spin(50, 100)
        self.max_auto = self._spin(1, 50)
        self.retention = self._spin(1, 365)
        self.keep = self._spin(5, 200)
        self.feed_hours = self._spin(1, 168)
        self.auto = QCheckBox("Tự động chặn kết nối nguy hiểm")
        self.tray = QCheckBox("Thu nhỏ xuống khay hệ thống khi đóng cửa sổ")
        self.use_etw = QCheckBox("Giám sát thời gian thực bằng ETW (cần quyền Administrator)")
        self.feed_urls = QPlainTextEdit()
        self.feed_urls.setFixedHeight(80)
        form.addRow("Chu kỳ quét (giây)", self.poll)
        form.addRow("Ngưỡng ‘Nguy hiểm’ (điểm)", self.threshold)
        form.addRow("Giới hạn tự chặn / phút", self.max_auto)
        form.addRow("Lưu cảnh báo (ngày)", self.retention)
        form.addRow("Số bản sao lưu tự động giữ lại", self.keep)
        form.addRow("Làm mới danh sách đe dọa (giờ)", self.feed_hours)
        form.addRow("Nguồn danh sách đe dọa (mỗi dòng một URL)", self.feed_urls)
        form.addRow("", self.auto)
        form.addRow("", self.use_etw)
        form.addRow("", self.tray)
        self.root.addLayout(form)
        bar = QHBoxLayout()
        bar.addWidget(button("Lưu cài đặt", "primary", self.save))
        bar.addWidget(button("Đặt lại về mặc định", "", self.reset))
        bar.addStretch(1)
        self.root.addLayout(bar)
        self.root.addStretch(1)
        self.load()

    @staticmethod
    def _spin(lo: int, hi: int) -> QSpinBox:
        s = QSpinBox()
        s.setRange(lo, hi)
        s.setMaximumWidth(120)
        return s

    def load(self) -> None:
        g = self.win.guard
        self.poll.setValue(int(g.setting("poll_interval")))
        self.threshold.setValue(int(g.setting("block_threshold")))
        self.max_auto.setValue(int(g.setting("max_auto_blocks_per_min")))
        self.retention.setValue(int(g.setting("event_retention_days")))
        self.keep.setValue(int(g.setting("snapshot_keep")))
        self.feed_hours.setValue(int(g.setting("feed_refresh_hours")))
        self.auto.setChecked(bool(g.setting("auto_block")))
        self.tray.setChecked(bool(g.setting("minimize_to_tray")))
        self.use_etw.setChecked(bool(g.setting("use_etw")))
        self.feed_urls.setPlainText(str(g.setting("feed_urls")))

    def values(self) -> dict:
        return {
            "poll_interval": self.poll.value(), "block_threshold": self.threshold.value(),
            "max_auto_blocks_per_min": self.max_auto.value(), "event_retention_days": self.retention.value(),
            "snapshot_keep": self.keep.value(), "feed_refresh_hours": self.feed_hours.value(),
            "auto_block": self.auto.isChecked(), "minimize_to_tray": self.tray.isChecked(),
            "use_etw": self.use_etw.isChecked(),
            "feed_urls": self.feed_urls.toPlainText().strip(),
        }

    def save(self) -> None:
        self.win.run(self.win.guard.set_settings, self.values(), ok="Đã lưu cài đặt")

    def reset(self) -> None:
        from ..config import DEFAULT_SETTINGS
        if confirm(self, "Đặt lại", "Đặt toàn bộ cài đặt về mặc định?"):
            self.win.run(self.win.guard.set_settings, dict(DEFAULT_SETTINGS), ok="Đã đặt lại cài đặt")
