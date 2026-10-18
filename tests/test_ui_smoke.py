import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6.QtWidgets")

from PySide6.QtWidgets import QApplication, QMessageBox  # noqa: E402

from conftest import mkconn  # noqa: E402


@pytest.fixture
def window(tmp_path, monkeypatch):
    monkeypatch.setenv("NETGUARD_HOME", str(tmp_path))
    from netguard.app import build_context
    from netguard.ui.main_window import MainWindow
    from netguard.ui.theme import QSS
    app = QApplication.instance() or QApplication([])
    app.setStyleSheet(QSS)
    # không bao giờ hiện hộp thoại thật trong test
    monkeypatch.setattr(QMessageBox, "question", staticmethod(lambda *a, **k: QMessageBox.StandardButton.Yes))
    monkeypatch.setattr(QMessageBox, "warning", staticmethod(lambda *a, **k: None))
    monkeypatch.setattr(QMessageBox, "information", staticmethod(lambda *a, **k: None))
    ctx = build_context(dry_run=True)
    w = MainWindow(ctx)
    w._really_quit = True
    yield w, app
    w.close()


def pump(app, n=5):
    for _ in range(n):
        app.processEvents()


def test_window_builds_and_shows_connections(window):
    w, app = window
    w.show()
    pump(app)
    conns = [
        mkconn(process="chrome.exe", remote_ip="142.250.1.1"),
        mkconn(process="telegram.pdf.exe", exe=r"C:\Users\x\Documents\telegram.pdf.exe", remote_ip="45.9.9.9"),
        mkconn(process="svchost.exe", remote_ip="192.168.1.1"),
    ]
    for c in conns:
        w.ctx.classifier.classify(c)
    w.on_scanned(conns)
    pump(app)
    page = w.conn_page
    assert page.model.rowCount() == 3 and page.proxy.rowCount() == 2  # ẩn kết nối nội bộ
    # sắp xếp: mức nguy hiểm nằm đầu bảng
    first = page.model.rows[page.proxy.mapToSource(page.proxy.index(0, 0)).row()]
    assert first.process == "telegram.pdf.exe" and first.level == "DANGEROUS"
    page.search.setText("chrome")
    assert page.proxy.rowCount() == 1
    page.search.setText("")
    assert w.dashboard.c_danger.value.text() == "1"


def test_block_and_undo_via_window(window):
    w, app = window
    c = mkconn(remote_ip="185.220.101.9")
    w.act_block_ip(c)
    pump(app)
    assert "NetGuard-IP-185.220.101.9" in w.fw.list_rules()
    assert w.blocks_page.table.rowCount() == 1
    assert w.journal_page.table.rowCount() >= 1
    # chọn dòng nhật ký mới nhất → hoàn tác
    w.journal_page.table.selectRow(0)
    w.journal_page.undo()
    pump(app)
    assert not w.fw.list_rules() and w.blocks_page.table.rowCount() == 0


def test_all_pages_render_after_changes(window):
    w, app = window
    w.guard.allow_add("process", "x.exe", "t")
    w.guard.snapshot_now("t")
    w.settings_page.threshold.setValue(80)
    w.settings_page.save()
    pump(app)
    assert w.guard.setting("block_threshold") == 80
    for i in range(w.stack.count()):
        w.nav.setCurrentRow(i)
        pump(app, 2)
    assert w.allow_page.table.rowCount() == 1
    assert w.backups_page.table.rowCount() >= 1
