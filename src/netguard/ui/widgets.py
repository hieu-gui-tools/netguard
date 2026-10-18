"""Thành phần giao diện dùng chung: model bảng kết nối, bộ lọc, thẻ số liệu, hàm tiện ích bảng."""
from __future__ import annotations

import time

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QSortFilterProxyModel, Qt
from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import (QAbstractItemView, QFrame, QLabel, QMessageBox, QTableWidget,
                               QTableWidgetItem, QVBoxLayout)

from ..models import DIR_LABEL, LEVEL_LABEL, LEVEL_RANK, Connection
from ..netutil import fmt_addr
from .theme import LEVEL_COLOR

UR = Qt.ItemDataRole


def fmt_ts(ts: float | None) -> str:
    return time.strftime("%d/%m %H:%M:%S", time.localtime(ts)) if ts else "—"


def confirm(parent, title: str, text: str) -> bool:
    box = QMessageBox.StandardButton
    return QMessageBox.question(parent, title, text, box.Yes | box.No, box.No) == box.Yes


def make_table(headers: list[str], widths: list[int] | None = None) -> QTableWidget:
    t = QTableWidget(0, len(headers))
    t.setHorizontalHeaderLabels(headers)
    t.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    t.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
    t.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    t.verticalHeader().setVisible(False)
    t.verticalHeader().setDefaultSectionSize(30)
    t.setAlternatingRowColors(True)
    t.setShowGrid(False)
    t.setWordWrap(False)
    t.horizontalHeader().setStretchLastSection(True)
    for i, w in enumerate(widths or []):
        t.setColumnWidth(i, w)
    return t


def fill_table(t: QTableWidget, rows: list[list], ids: list | None = None, colors: list | None = None) -> None:
    keep = selected_id(t)
    t.setRowCount(len(rows))
    for r, row in enumerate(rows):
        for c, val in enumerate(row):
            item = QTableWidgetItem("" if val is None else str(val))
            if c == 0 and ids is not None:
                item.setData(UR.UserRole, ids[r])
            if colors and colors[r]:
                item.setForeground(QBrush(QColor(colors[r])))
            t.setItem(r, c, item)
    if keep is not None and ids is not None and keep in ids:
        t.selectRow(ids.index(keep))


def selected_id(t: QTableWidget):
    row = t.currentRow()
    item = t.item(row, 0) if row >= 0 else None
    return item.data(UR.UserRole) if item else None


class Card(QFrame):
    def __init__(self, caption: str, color: str = "#e2e8f0"):
        super().__init__()
        self.setObjectName("card")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 12, 16, 12)
        lay.setSpacing(2)
        self.value = QLabel("0")
        self.value.setObjectName("cardValue")
        self.value.setStyleSheet(f"color:{color};")
        cap = QLabel(caption)
        cap.setObjectName("muted")
        lay.addWidget(self.value)
        lay.addWidget(cap)

    def set(self, n) -> None:
        self.value.setText(str(n))


COLS = ["Mức độ", "Tiến trình", "PID", "Hướng", "Giao thức", "Cục bộ", "Từ xa", "Trạng thái", "Điểm", "Lý do"]
COL_WIDTHS = [130, 170, 60, 80, 80, 170, 200, 110, 55, 400]


class ConnModel(QAbstractTableModel):
    def __init__(self) -> None:
        super().__init__()
        self.rows: list[Connection] = []

    def set_rows(self, rows: list[Connection]) -> None:
        self.beginResetModel()
        self.rows = rows
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(COLS)

    def headerData(self, section, orientation, role=UR.DisplayRole):
        if role == UR.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return COLS[section]
        return None

    @staticmethod
    def _display(c: Connection, col: int) -> str:
        if col == 0:
            return LEVEL_LABEL[c.level] + (" · Đã chặn" if c.blocked else "")
        return (
            c.process, str(c.pid), DIR_LABEL.get(c.direction, c.direction), c.proto,
            fmt_addr(c.local_ip, c.local_port), fmt_addr(c.remote_ip, c.remote_port), c.status,
            str(c.score), "; ".join(c.reasons),
        )[col - 1]

    def data(self, index, role=UR.DisplayRole):
        if not index.isValid():
            return None
        c = self.rows[index.row()]
        col = index.column()
        if role == UR.DisplayRole:
            return self._display(c, col)
        if role == UR.UserRole:  # khóa sắp xếp
            if col == 0:
                return LEVEL_RANK[c.level] * 1000 + c.score
            if col in (2, 8):
                return int(self._display(c, col))
            return self._display(c, col).lower()
        if role == UR.ForegroundRole and col == 0:
            return QBrush(QColor(LEVEL_COLOR[c.level]))
        if role == UR.BackgroundRole:
            if c.level == "DANGEROUS":
                return QBrush(QColor(239, 68, 68, 38))
            if c.level == "SUSPICIOUS":
                return QBrush(QColor(245, 158, 11, 28))
        if role == UR.ToolTipRole:
            tip = [f"{c.process} (PID {c.pid})"]
            if c.exe:
                tip.append(c.exe)
            tip += [f"• {r}" for r in c.reasons]
            return "\n".join(tip)
        return None


class ConnFilter(QSortFilterProxyModel):
    def __init__(self) -> None:
        super().__init__()
        self.level = "ALL"
        self.direction = "ALL"
        self.text = ""
        self.hide_local = True
        self.setSortRole(UR.UserRole)
        self.setDynamicSortFilter(True)

    def filterAcceptsRow(self, row, parent) -> bool:
        c = self.sourceModel().rows[row]
        if self.hide_local and c.level == "LOCAL":
            return False
        if self.level == "RISK" and c.level not in ("SUSPICIOUS", "DANGEROUS"):
            return False
        if self.level not in ("ALL", "RISK") and c.level != self.level:
            return False
        if self.direction != "ALL" and c.direction != self.direction:
            return False
        if self.text:
            hay = f"{c.process} {c.exe} {c.remote_ip} {c.remote_port} {c.local_port} {c.pid}".lower()
            if self.text not in hay:
                return False
        return True
