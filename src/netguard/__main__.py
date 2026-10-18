from __future__ import annotations

import argparse
import sys


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="netguard", description="Giám sát & chặn kết nối nguy hiểm")
    parser.add_argument("--dry-run", action="store_true", help="Không chạm vào Windows Firewall (thử nghiệm)")
    parser.add_argument("--elevated", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--etw-test", action="store_true", help="Chẩn đoán ETW (chạy trong terminal Administrator)")
    parser.add_argument("--etw-seconds", type=int, default=15, help="Thời gian thu của --etw-test")
    args, qt_args = parser.parse_known_args(argv)

    if args.etw_test:
        from .realtime import run_self_test
        return run_self_test(args.etw_seconds)

    from PySide6.QtCore import QLockFile
    from PySide6.QtWidgets import QApplication, QMessageBox

    from .app import build_context
    from .config import data_dir
    from .ui.main_window import MainWindow
    from .ui.theme import QSS, app_icon

    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("netguard.security.firewall.0.1.0")
        except Exception:
            pass

    app = QApplication([sys.argv[0], *qt_args])
    app.setApplicationName("NetGuard")
    app.setStyle("Fusion")
    app.setStyleSheet(QSS)
    app.setWindowIcon(app_icon())
    app.setQuitOnLastWindowClosed(False)

    lock = QLockFile(str(data_dir() / "netguard.lock"))
    if not lock.tryLock(10000 if args.elevated else 300):
        QMessageBox.information(None, "NetGuard", "NetGuard đang chạy rồi (kiểm tra khay hệ thống).")
        return 0

    window = MainWindow(build_context(args.dry_run))
    window.show()
    code = app.exec()
    lock.unlock()
    return code


if __name__ == "__main__":
    sys.exit(main())
