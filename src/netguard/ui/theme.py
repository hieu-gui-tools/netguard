from __future__ import annotations

from PySide6.QtCore import QPointF, Qt
from PySide6.QtGui import QColor, QIcon, QPainter, QPainterPath, QPixmap

LEVEL_COLOR = {
    "DANGEROUS": "#f87171", "SUSPICIOUS": "#fbbf24", "NORMAL": "#e2e8f0",
    "TRUSTED": "#4ade80", "LOCAL": "#94a3b8",
}

QSS = """
* { font-family: 'Segoe UI', 'Inter', sans-serif; font-size: 13px; }
QMainWindow, QWidget#root, QStackedWidget { background: #0f172a; }
QWidget { color: #e2e8f0; }
QWidget#sidebar { background: #0b1220; border-right: 1px solid #1e293b; }
QLabel#brand { font-size: 17px; font-weight: 700; color: #f8fafc; padding: 18px 20px 2px 20px; }
QLabel#brandSub { color: #64748b; padding: 0 20px 14px 20px; }
QListWidget#nav { background: transparent; border: none; outline: none; }
QListWidget#nav::item { padding: 10px 14px; border-radius: 6px; margin: 1px 10px; color: #94a3b8; }
QListWidget#nav::item:selected { background: #1e3a8a; color: #ffffff; }
QListWidget#nav::item:hover:!selected { background: #151f35; }
QLabel#title { font-size: 20px; font-weight: 600; color: #f8fafc; }
QLabel#muted { color: #94a3b8; }
QLabel#ok { color: #4ade80; font-weight: 600; }
QLabel#warn { color: #fbbf24; font-weight: 600; }
QFrame#card { background: #111c33; border: 1px solid #1e293b; border-radius: 8px; }
QLabel#cardValue { font-size: 26px; font-weight: 700; }
QPushButton { background: #1e293b; border: 1px solid #334155; border-radius: 6px; padding: 7px 14px; }
QPushButton:hover { background: #27374f; }
QPushButton:disabled { color: #64748b; background: #151f35; }
QPushButton#primary { background: #2563eb; border-color: #2563eb; color: #ffffff; }
QPushButton#primary:hover { background: #1d4ed8; }
QPushButton#danger { background: #991b1b; border-color: #991b1b; color: #ffffff; }
QPushButton#danger:hover { background: #7f1d1d; }
QLineEdit, QComboBox, QSpinBox, QPlainTextEdit { background: #0b1220; border: 1px solid #334155;
    border-radius: 6px; padding: 6px 10px; selection-background-color: #2563eb; }
QLineEdit:focus, QComboBox:focus, QSpinBox:focus, QPlainTextEdit:focus { border-color: #3b82f6; }
QComboBox QAbstractItemView { background: #0b1220; border: 1px solid #334155; selection-background-color: #1e3a8a; }
QTableView, QTableWidget { background: #0b1220; alternate-background-color: #0e1628; border: 1px solid #1e293b;
    border-radius: 6px; gridline-color: transparent; selection-background-color: #1e3a8a; selection-color: #ffffff; }
QTableView::item, QTableWidget::item { padding: 4px 8px; }
QHeaderView::section { background: #111c33; color: #94a3b8; border: none; border-bottom: 1px solid #1e293b;
    padding: 8px 10px; font-weight: 600; }
QScrollBar:vertical { background: transparent; width: 10px; margin: 0; }
QScrollBar::handle:vertical { background: #334155; border-radius: 5px; min-height: 30px; }
QScrollBar:horizontal { background: transparent; height: 10px; margin: 0; }
QScrollBar::handle:horizontal { background: #334155; border-radius: 5px; min-width: 30px; }
QScrollBar::add-line, QScrollBar::sub-line { height: 0; width: 0; }
QCheckBox { spacing: 8px; }
QMenu { background: #111c33; border: 1px solid #334155; padding: 4px; }
QMenu::item { padding: 6px 20px; border-radius: 4px; }
QMenu::item:selected { background: #1e3a8a; }
QMenu::separator { height: 1px; background: #334155; margin: 4px 8px; }
QToolTip { background: #111c33; color: #e2e8f0; border: 1px solid #334155; padding: 4px; }
QStatusBar { background: #0b1220; color: #94a3b8; border-top: 1px solid #1e293b; }
QMessageBox { background: #0f172a; }
"""


def app_icon() -> QIcon:
    """Biểu tượng khiên từ file .ico hoặc vẽ bằng code nếu chưa có file."""
    from pathlib import Path
    for candidate in [
        Path(__file__).resolve().parent / "netguard.ico",
        Path(__file__).resolve().parent.parent.parent.parent / "assets" / "netguard.ico",
        Path.cwd() / "assets" / "netguard.ico",
    ]:
        if candidate.is_file():
            ico = QIcon(str(candidate))
            if not ico.isNull():
                return ico

    pm = QPixmap(64, 64)
    pm.fill(Qt.GlobalColor.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    path = QPainterPath()
    path.moveTo(QPointF(32, 4))
    path.lineTo(QPointF(56, 13))
    path.lineTo(QPointF(56, 32))
    path.cubicTo(QPointF(56, 46), QPointF(46, 56), QPointF(32, 61))
    path.cubicTo(QPointF(18, 56), QPointF(8, 46), QPointF(8, 32))
    path.lineTo(QPointF(8, 13))
    path.closeSubpath()
    p.fillPath(path, QColor("#2563eb"))
    p.setPen(QColor("#f8fafc"))
    p.setBrush(Qt.BrushStyle.NoBrush)
    pen = p.pen()
    pen.setWidth(5)
    pen.setCapStyle(Qt.PenCapStyle.RoundCap)
    pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
    p.setPen(pen)
    p.drawPolyline([QPointF(21, 33), QPointF(29, 41), QPointF(44, 24)])
    p.end()
    return QIcon(pm)
