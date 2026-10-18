from __future__ import annotations

import logging
import threading
import time

from PySide6.QtCore import QObject, QTimer, Signal
from PySide6.QtGui import QAction
from PySide6.QtWidgets import (QApplication, QHBoxLayout, QLabel, QListWidget, QMainWindow, QMenu, QMessageBox,
                               QStackedWidget, QSystemTrayIcon, QVBoxLayout, QWidget)

from ..app import AppContext, relaunch_as_admin
from ..guard import GuardError
from ..models import Connection
from ..monitor import MonitorWorker
from ..snapshots import SnapshotError
from .pages import (AllowPage, BackupsPage, BlocksPage, ConnectionsPage, DashboardPage, JournalPage,
                    SettingsPage)
from .theme import app_icon
from .widgets import confirm

log = logging.getLogger(__name__)


class Bridge(QObject):
    """Chuyển sự kiện từ luồng nền về luồng giao diện."""
    changed = Signal(str)
    info = Signal(str)


class MainWindow(QMainWindow):
    def __init__(self, ctx: AppContext):
        super().__init__()
        self.ctx = ctx
        self.guard, self.storage, self.fw = ctx.guard, ctx.storage, ctx.fw
        self._really_quit = False
        self._tray_hint_shown = False
        self.setWindowTitle("NetGuard" + ("  [thử nghiệm]" if ctx.dry_run else ""))
        self.setWindowIcon(app_icon())
        self.resize(1280, 800)

        self.bridge = Bridge()
        self.guard.on_change(self.bridge.changed.emit)
        self.bridge.changed.connect(self.on_changed)
        self.bridge.info.connect(self.show_info)

        # ---- bố cục: thanh bên + các trang
        root = QWidget()
        root.setObjectName("root")
        h = QHBoxLayout(root)
        h.setContentsMargins(0, 0, 0, 0)
        h.setSpacing(0)
        side = QWidget()
        side.setObjectName("sidebar")
        side.setFixedWidth(220)
        sv = QVBoxLayout(side)
        sv.setContentsMargins(0, 0, 0, 10)
        brand = QLabel("NetGuard")
        brand.setObjectName("brand")
        sub = QLabel("Giám sát kết nối mạng")
        sub.setObjectName("brandSub")
        self.nav = QListWidget()
        self.nav.setObjectName("nav")
        sv.addWidget(brand)
        sv.addWidget(sub)
        sv.addWidget(self.nav, 1)
        self.stack = QStackedWidget()
        h.addWidget(side)
        h.addWidget(self.stack, 1)
        self.setCentralWidget(root)

        self.dashboard = DashboardPage(self)
        self.conn_page = ConnectionsPage(self)
        self.blocks_page = BlocksPage(self)
        self.journal_page = JournalPage(self)
        self.backups_page = BackupsPage(self)
        self.allow_page = AllowPage(self)
        self.settings_page = SettingsPage(self)
        for name, page in [("Tổng quan", self.dashboard), ("Kết nối", self.conn_page),
                           ("Danh sách chặn", self.blocks_page), ("Nhật ký thay đổi", self.journal_page),
                           ("Sao lưu & khôi phục", self.backups_page), ("Danh sách tin cậy", self.allow_page),
                           ("Cài đặt", self.settings_page)]:
            self.nav.addItem(name)
            self.stack.addWidget(page)
        self.nav.currentRowChanged.connect(self.stack.setCurrentIndex)
        self.nav.setCurrentRow(0)

        self.status_lbl = QLabel("Đang quét…")
        self.statusBar().addPermanentWidget(self.status_lbl)

        self._setup_tray()

        self.worker = MonitorWorker(ctx.engine)
        self.worker.scanned.connect(self.on_scanned)
        self.worker.alert.connect(self.on_alert)
        self.worker.error.connect(lambda m: self.statusBar().showMessage(f"Lỗi quét: {m}", 8000))
        self.worker.start()
        QTimer.singleShot(400, self._start_startup_tasks)

    # ───────── khay hệ thống
    def _setup_tray(self) -> None:
        self.tray = None
        if not QSystemTrayIcon.isSystemTrayAvailable():
            return
        self.tray = QSystemTrayIcon(app_icon(), self)
        menu = QMenu()
        act_open = QAction("Mở NetGuard", self)
        act_open.triggered.connect(self.show_normal)
        act_quit = QAction("Thoát", self)
        act_quit.triggered.connect(self.quit_app)
        menu.addAction(act_open)
        menu.addSeparator()
        menu.addAction(act_quit)
        self.tray.setContextMenu(menu)
        self.tray.activated.connect(lambda r: self.show_normal() if r == QSystemTrayIcon.ActivationReason.Trigger else None)
        self.tray.setToolTip("NetGuard đang giám sát")
        self.tray.show()

    def show_normal(self) -> None:
        self.showNormal()
        self.raise_()
        self.activateWindow()

    def quit_app(self) -> None:
        self._really_quit = True
        self.close()

    def closeEvent(self, event) -> None:
        if (not self._really_quit and self.tray and self.tray.isVisible()
                and self.guard.setting("minimize_to_tray")):
            self.hide()
            if not self._tray_hint_shown:
                self.tray.showMessage("NetGuard", "Vẫn đang giám sát ở chế độ nền. Chuột phải biểu tượng để thoát.",
                                      QSystemTrayIcon.MessageIcon.Information, 4000)
                self._tray_hint_shown = True
            event.ignore()
            return
        self.worker.requestInterruption()
        self.worker.wait(5000)
        self.ctx.engine.stop()
        self.ctx.sigs.stop()
        if self.tray:
            self.tray.hide()
        event.accept()
        QApplication.quit()

    # ───────── tác vụ khi khởi động (chạy nền để không đơ giao diện)
    def _start_startup_tasks(self) -> None:
        threading.Thread(target=self._startup_tasks, daemon=True, name="startup").start()

    def _startup_tasks(self) -> None:
        try:
            snaps = self.guard.snapshots
            if self.storage.recovered:
                latest = snaps.latest()
                if latest:
                    r = self.guard.restore_snapshot(latest)
                    self.bridge.info.emit(
                        f"Cơ sở dữ liệu bị hỏng — đã tự khôi phục từ bản sao lưu gần nhất (thêm {r['added']} mục).")
                else:
                    self.bridge.info.emit("Cơ sở dữ liệu bị hỏng và được tạo lại (chưa có bản sao lưu).")
            self.guard.snapshot_now("Khi khởi động", "auto")
            if self.fw.name == "windows" and self.fw.can_modify():
                baseline = snaps.dir / "firewall-original.wfw"
                if not baseline.exists():
                    self.fw.export_policy(baseline)
                rep = self.guard.reconcile(fix=True)
                if rep.get("fixed"):
                    self.bridge.info.emit(f"Đã tự sửa {len(rep['fixed'])} rule Firewall bị thiếu.")
                elif rep.get("orphans"):
                    self.bridge.info.emit(f"Có {len(rep['orphans'])} rule NetGuard lạ trong Firewall "
                                          "(xem Danh sách chặn → Đối soát).")
        except Exception as exc:
            log.exception("Lỗi khi khởi động")
            self.bridge.info.emit(f"Lỗi khi khởi động: {exc}")

    # ───────── cập nhật giao diện
    def show_info(self, msg: str) -> None:
        self.statusBar().showMessage(msg, 12000)

    def on_scanned(self, conns: list[Connection]) -> None:
        self.dashboard.update_stats(conns)
        self.conn_page.refresh(conns)
        self.status_lbl.setText(f"Quét lúc {time.strftime('%H:%M:%S')} · {len(conns)} kết nối")

    def on_alert(self, level: str, msg: str) -> None:
        self.dashboard.refresh()
        self.show_info(msg)
        if level == "DANGEROUS" and self.tray:
            self.tray.showMessage("NetGuard — kết nối nguy hiểm", msg, QSystemTrayIcon.MessageIcon.Critical, 9000)

    def on_changed(self, what: str) -> None:
        self.blocks_page.refresh()
        self.journal_page.refresh()
        self.backups_page.refresh()
        self.allow_page.refresh()
        self.dashboard.refresh()
        if what == "settings":
            self.settings_page.load()
        elif what == "breaker":
            msg = "Cầu dao an toàn: đã chặn quá nhiều mục trong 1 phút nên tạm dừng tự động chặn 5 phút."
            self.show_info(msg)
            if self.tray:
                self.tray.showMessage("NetGuard", msg, QSystemTrayIcon.MessageIcon.Warning, 8000)
        elif what == "feed":
            res = self.ctx.engine.last_feed_result
            if res:
                self.show_info("Danh sách đe dọa: " + " | ".join(f"{u.split('/')[2]}: {r}" for u, r in res.items()))

    # ───────── hành động (có xử lý lỗi thống nhất)
    def run(self, fn, *args, ok: str | None = None):
        """Gọi một hành động; trả về (True, kết quả) hoặc None nếu lỗi (đã báo cho người dùng)."""
        try:
            result = fn(*args)
        except (GuardError, SnapshotError) as exc:
            QMessageBox.warning(self, "NetGuard", str(exc))
            return None
        except Exception as exc:
            log.exception("Lỗi hành động")
            QMessageBox.critical(self, "NetGuard", f"Lỗi không mong muốn: {exc}")
            return None
        if ok:
            self.show_info(ok)
        return (True, result)

    def act_block_ip(self, c: Connection) -> None:
        if confirm(self, "Chặn IP", f"Chặn mọi kết nối đi và đến {c.remote_ip}?\nBạn có thể bỏ chặn bất cứ lúc nào."):
            self.run(self.guard.block_ip, c.remote_ip, "; ".join(c.reasons) or "Chặn thủ công", "manual",
                     c.process, c.score, ok=f"Đã chặn {c.remote_ip}")

    def act_block_program(self, c: Connection) -> None:
        if confirm(self, "Chặn chương trình",
                   f"Chặn toàn bộ kết nối mạng của\n{c.exe}\n\nChương trình sẽ mất mạng cho tới khi bạn bỏ chặn."):
            self.run(self.guard.block_program, c.exe, "; ".join(c.reasons) or "Chặn thủ công", "manual",
                     c.process, c.score, ok=f"Đã chặn {c.process}")

    def act_allow(self, kind: str, value: str, note: str) -> None:
        self.run(self.guard.allow_add, kind, value, note, ok=f"Đã thêm {value} vào danh sách tin cậy")

    def toggle_auto_block(self, on: bool) -> None:
        self.run(self.guard.set_settings, {"auto_block": on})

    def update_feed(self) -> None:
        self.show_info("Đang tải danh sách đe dọa…")
        self.ctx.engine.refresh_feed_async()

    def sync_firewall(self) -> None:
        QApplication.setOverrideCursor(Qt_wait())
        try:
            r = self.run(self.guard.reconcile, True, False)
        finally:
            QApplication.restoreOverrideCursor()
        if not r:
            return
        rep = r[1]
        if rep.get("error"):
            QMessageBox.warning(self, "Đối soát", rep["error"])
            return
        msg = f"Thiếu trong Firewall: {len(rep['missing'])} · đã sửa: {len([f for f in rep['fixed'] if not f.startswith('-')])}"
        msg += f"\nRule NetGuard lạ (không có trong danh sách): {len(rep['orphans'])}"
        if rep["errors"]:
            msg += "\nLỗi: " + "; ".join(rep["errors"][:3])
        QMessageBox.information(self, "Đối soát với Firewall", msg)
        if rep["orphans"] and confirm(self, "Rule lạ", "Gỡ các rule NetGuard lạ khỏi Firewall?\n" + "\n".join(rep["orphans"][:8])):
            self.run(self.guard.reconcile, True, True, ok="Đã gỡ rule lạ")

    def restart_as_admin(self) -> None:
        if relaunch_as_admin(self.ctx.dry_run):
            self.quit_app()
        else:
            QMessageBox.warning(self, "NetGuard", "Không thể yêu cầu quyền Administrator.")


def Qt_wait():
    from PySide6.QtCore import Qt
    return Qt.CursorShape.WaitCursor
