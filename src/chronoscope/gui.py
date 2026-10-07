"""Desktop timeline viewer built on Qt (PySide6, the optional ``gui`` extra).

Opens a case read-only and lists its events in timeline order. Rows are loaded in batches as
you scroll, so large cases open instantly. Filters cover text, artifact, evidence, time range,
timestomp flags and deleted entries.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QPersistentModelIndex, Qt
from PySide6.QtGui import QAction, QColor, QFontDatabase, QKeySequence, QPalette
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QGridLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QStyle,
    QStyledItemDelegate,
    QStyleOptionViewItem,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from chronoscope import __version__
from chronoscope.case import CaseError, StoredEvent
from chronoscope.timeutil import parse_iso
from chronoscope.viewer import Filters, TimelineReader, is_deleted, is_flagged

BATCH_SIZE = 500
ALL = "(all)"
COLUMNS = (
    ("Time (UTC)", "datetime"),
    ("Description", "timestamp_desc"),
    ("Artifact", "artifact"),
    ("Evidence", "evidence_label"),
    ("Message", "message"),
)
FLAGGED_COLOR = QColor("#d32f2f")
DELETED_COLOR = QColor("#8a8a8a")
_Index = QModelIndex | QPersistentModelIndex


class EventTableModel(QAbstractTableModel):
    """Events matching the current filters, fetched lazily in timeline order."""

    def __init__(self) -> None:
        super().__init__()
        self.reader: TimelineReader | None = None
        self.filters = Filters()
        self.total = 0
        self.events: list[StoredEvent] = []
        self.marks: list[str] = []  # "flagged", "deleted" or "" per loaded row

    def set_query(self, reader: TimelineReader | None, filters: Filters) -> None:
        self.beginResetModel()
        self.reader, self.filters = reader, filters
        self.total = reader.count(filters) if reader else 0
        self.events, self.marks = [], []
        self.endResetModel()
        if self.canFetchMore(QModelIndex()):
            self.fetchMore(QModelIndex())

    def event(self, row: int) -> StoredEvent:
        return self.events[row]

    def rowCount(self, parent: _Index = QModelIndex()) -> int:  # noqa: B008
        return 0 if parent.isValid() else len(self.events)

    def columnCount(self, parent: _Index = QModelIndex()) -> int:  # noqa: B008
        return 0 if parent.isValid() else len(COLUMNS)

    def canFetchMore(self, parent: _Index) -> bool:
        return not parent.isValid() and len(self.events) < self.total

    def fetchMore(self, parent: _Index) -> None:
        if self.reader is None or parent.isValid():
            return
        batch = self.reader.page(self.filters, len(self.events), BATCH_SIZE)
        if not batch:
            self.total = len(self.events)  # the case changed underneath us; stop fetching
            return
        first = len(self.events)
        self.beginInsertRows(QModelIndex(), first, first + len(batch) - 1)
        self.events.extend(batch)
        self.marks.extend(
            "flagged" if is_flagged(ev) else "deleted" if is_deleted(ev) else "" for ev in batch
        )
        self.endInsertRows()

    def data(self, index: _Index, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid():
            return None
        ev = self.events[index.row()]
        if role in (Qt.ItemDataRole.DisplayRole, Qt.ItemDataRole.ToolTipRole):
            return getattr(ev, COLUMNS[index.column()][1])
        if role == Qt.ItemDataRole.ForegroundRole:
            mark = self.marks[index.row()]
            if mark == "flagged":
                return FLAGGED_COLOR
            if mark == "deleted":
                return DELETED_COLOR
        return None

    def headerData(
        self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole
    ) -> Any:
        if role != Qt.ItemDataRole.DisplayRole:
            return None
        if orientation == Qt.Orientation.Horizontal:
            return COLUMNS[section][0]
        return section + 1


class MarkedRowDelegate(QStyledItemDelegate):
    """Keeps selected rows readable: the highlight text color wins over red or grey marks."""

    def initStyleOption(self, option: QStyleOptionViewItem, index: _Index) -> None:
        super().initStyleOption(option, index)
        if option.state & QStyle.StateFlag.State_Selected:
            highlighted = option.palette.brush(QPalette.ColorRole.HighlightedText)
            option.palette.setBrush(QPalette.ColorRole.Text, highlighted)


def describe(ev: StoredEvent) -> str:
    """The text shown in the details pane for one event."""
    attributes = json.dumps(json.loads(ev.attributes), indent=2, ensure_ascii=False)
    return "\n".join(
        [
            f"Time (UTC):   {ev.datetime}",
            f"Description:  {ev.timestamp_desc}",
            f"Source:       {ev.source}",
            f"Artifact:     {ev.artifact}",
            f"Evidence:     {ev.evidence_label} (#{ev.evidence_id})",
            f"Path:         {ev.path}",
            f"Message:      {ev.message}",
            f"Fingerprint:  {ev.fingerprint}",
            "",
            "Attributes:",
            attributes,
        ]
    )


class MainWindow(QMainWindow):
    def __init__(self, case_dir: Path | None = None) -> None:
        super().__init__()
        self.reader: TimelineReader | None = None
        self.model = EventTableModel()
        self.setWindowTitle(f"Chronoscope {__version__}")
        self.resize(1280, 800)
        self._build_menu()
        central = QWidget()
        layout = QVBoxLayout(central)
        layout.addLayout(self._build_filters())
        layout.addWidget(self._build_body(), 1)
        self.setCentralWidget(central)
        self._set_filters_enabled(False)
        self.statusBar().showMessage("Open a case with File > Open case... (Ctrl+O)")
        if case_dir is not None:
            self.open_case(case_dir)

    # -- layout ------------------------------------------------------------------------

    def _build_menu(self) -> None:
        menu = self.menuBar().addMenu("&File")
        open_action = QAction("&Open case...", self)
        open_action.setShortcut(QKeySequence.StandardKey.Open)
        open_action.triggered.connect(self.choose_case)
        menu.addAction(open_action)
        menu.addSeparator()
        quit_action = QAction("&Quit", self)
        quit_action.setShortcut(QKeySequence.StandardKey.Quit)
        quit_action.triggered.connect(self.close)
        menu.addAction(quit_action)

    def _build_filters(self) -> QGridLayout:
        grid = QGridLayout()
        self.search = QLineEdit(placeholderText="Message, path or description")
        self.artifact = QComboBox()
        self.evidence = QComboBox()
        self.start = QLineEdit(placeholderText="e.g. 2024-03-01T00:00:00Z")
        self.end = QLineEdit(placeholderText="e.g. 2024-03-02T00:00:00Z")
        self.flagged = QCheckBox("Possible timestomp")
        self.deleted = QCheckBox("Deleted only")
        self.apply_button = QPushButton("Apply")
        self.reset_button = QPushButton("Reset")

        grid.addWidget(QLabel("Search"), 0, 0)
        grid.addWidget(self.search, 0, 1)
        grid.addWidget(QLabel("Artifact"), 0, 2)
        grid.addWidget(self.artifact, 0, 3)
        grid.addWidget(QLabel("Evidence"), 0, 4)
        grid.addWidget(self.evidence, 0, 5)
        grid.addWidget(self.flagged, 0, 6)
        grid.addWidget(QLabel("From"), 1, 0)
        grid.addWidget(self.start, 1, 1)
        grid.addWidget(QLabel("To"), 1, 2)
        grid.addWidget(self.end, 1, 3, 1, 3)
        grid.addWidget(self.deleted, 1, 6)
        grid.addWidget(self.apply_button, 0, 7)
        grid.addWidget(self.reset_button, 1, 7)
        grid.setColumnStretch(1, 2)
        grid.setColumnStretch(3, 1)
        grid.setColumnStretch(5, 1)

        for edit in (self.search, self.start, self.end):
            edit.returnPressed.connect(self.apply_filters)
        for box in (self.artifact, self.evidence):
            box.activated.connect(self.apply_filters)
        for check in (self.flagged, self.deleted):
            check.toggled.connect(self.apply_filters)
        self.apply_button.clicked.connect(self.apply_filters)
        self.reset_button.clicked.connect(self.reset_filters)
        return grid

    def _build_body(self) -> QSplitter:
        self.table = QTableView()
        self.table.setModel(self.model)
        self.table.setItemDelegate(MarkedRowDelegate(self.table))
        self.table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableView.SelectionMode.SingleSelection)
        self.table.setAlternatingRowColors(True)
        self.table.setWordWrap(False)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(self.fontMetrics().height() + 8)
        header = self.table.horizontalHeader()
        header.setStretchLastSection(True)
        for col, sample in enumerate(
            ("0000-00-00T00:00:00.000000Z", "Content Modification Time", "chromium_history", "")
        ):
            if sample:
                width = self.fontMetrics().horizontalAdvance(sample) + 24
                header.resizeSection(col, width)
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.table.selectionModel().currentRowChanged.connect(self.show_details)

        self.details = QPlainTextEdit(readOnly=True)
        self.details.setFont(QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont))
        self.details.setPlaceholderText("Select an event to see all of its fields.")

        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.addWidget(self.table)
        splitter.addWidget(self.details)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 1)
        return splitter

    def _set_filters_enabled(self, enabled: bool) -> None:
        for widget in (
            self.search,
            self.artifact,
            self.evidence,
            self.start,
            self.end,
            self.flagged,
            self.deleted,
            self.apply_button,
            self.reset_button,
        ):
            widget.setEnabled(enabled)

    # -- actions -----------------------------------------------------------------------

    def choose_case(self) -> None:
        directory = QFileDialog.getExistingDirectory(self, "Open Chronoscope case")
        if directory:
            self.open_case(Path(directory))

    def open_case(self, case_dir: Path) -> bool:
        try:
            reader = TimelineReader(case_dir)
        except (CaseError, OSError, ValueError) as exc:
            QMessageBox.critical(self, "Cannot open case", str(exc))
            return False
        if self.reader is not None:
            self.reader.close()
        self.reader = reader
        name = reader.meta.get("name", case_dir.name)
        self.setWindowTitle(f"Chronoscope {__version__} - {name} (read-only)")
        for box, column in ((self.artifact, "artifact"), (self.evidence, "evidence_label")):
            box.clear()
            box.addItems([ALL, *reader.distinct(column)])
        self._set_filters_enabled(True)
        self.reset_filters()
        return True

    def reset_filters(self) -> None:
        widgets = (self.search, self.start, self.end, self.flagged, self.deleted)
        for widget in widgets:
            widget.blockSignals(True)
        self.search.clear()
        self.start.clear()
        self.end.clear()
        self.flagged.setChecked(False)
        self.deleted.setChecked(False)
        self.artifact.setCurrentIndex(0)
        self.evidence.setCurrentIndex(0)
        for widget in widgets:
            widget.blockSignals(False)
        self.apply_filters()

    def read_filters(self) -> Filters | None:
        times = {}
        for key, edit in (("start", self.start), ("end", self.end)):
            text = edit.text().strip()
            try:
                times[key] = parse_iso(text) if text else None
            except ValueError as exc:
                QMessageBox.warning(
                    self,
                    "Invalid time",
                    f"{key.title()}: {exc}\n\nUse ISO 8601 with an offset, "
                    "e.g. 2024-03-01T00:00:00Z",
                )
                edit.setFocus()
                return None
        artifact, evidence = self.artifact.currentText(), self.evidence.currentText()
        return Filters(
            text=self.search.text().strip(),
            artifact="" if artifact == ALL else artifact,
            evidence="" if evidence == ALL else evidence,
            start=times["start"],
            end=times["end"],
            flagged_only=self.flagged.isChecked(),
            deleted_only=self.deleted.isChecked(),
        )

    def apply_filters(self) -> None:
        if self.reader is None:
            return
        filters = self.read_filters()
        if filters is None:
            return
        self.model.set_query(self.reader, filters)
        self.details.clear()
        total = self.model.total
        self.statusBar().showMessage(
            f"{total:,} event(s) match" if total else "No events match the filters"
        )

    def show_details(self, current: QModelIndex, _previous: QModelIndex | None = None) -> None:
        if current.isValid():
            self.details.setPlainText(describe(self.model.event(current.row())))
        else:
            self.details.clear()

    def closeEvent(self, event: Any) -> None:
        self.model.set_query(None, Filters())
        if self.reader is not None:
            self.reader.close()
            self.reader = None
        super().closeEvent(event)


def run(case_dir: Path | None = None) -> int:
    app = QApplication.instance() or QApplication(sys.argv[:1])
    app.setApplicationName("Chronoscope")
    window = MainWindow(case_dir)
    window.show()
    return app.exec()
