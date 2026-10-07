"""Desktop timeline viewer built on Qt (PySide6, the optional ``gui`` extra).

Browses a case's timeline through a read-only connection. Rows are loaded in batches as you
scroll, so large cases open instantly. Filters cover text, artifact, evidence, time range,
timestomp flags and deleted entries. Ingest and export (``chronoscope.gui_tasks``) run in the
background through the same code paths, hashing and audit log as the CLI.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Callable
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
    QProgressBar,
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
from chronoscope.export import ExportResult
from chronoscope.gui_tasks import (
    ExportDialog,
    ExportRequest,
    IngestDialog,
    IngestRequest,
    Job,
    default_operator,
    describe_ingest,
    run_export,
    run_ingest,
)
from chronoscope.ingest import IngestResult
from chronoscope.parsers import discover
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
        self.paused = False  # no reads while a background job writes to the case

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
        return not self.paused and not parent.isValid() and len(self.events) < self.total

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
        self.case_dir: Path | None = None
        self.operator = default_operator()
        self.job: Job | None = None
        self.model = EventTableModel()
        self.setWindowTitle(f"Chronoscope {__version__}")
        self.resize(1280, 800)
        self._build_menu()
        central = QWidget()
        layout = QVBoxLayout(central)
        layout.addLayout(self._build_filters())
        layout.addWidget(self._build_body(), 1)
        self.setCentralWidget(central)
        self.progress = QProgressBar(maximumWidth=160)
        self.progress.setRange(0, 0)  # indeterminate: ingest has no reliable total
        self.progress.hide()
        self.statusBar().addPermanentWidget(self.progress)
        self._set_filters_enabled(False)
        self._set_case_actions_enabled(False)
        self.statusBar().showMessage("Open a case with File > Open case... (Ctrl+O)")
        if case_dir is not None:
            self.open_case(case_dir)

    # -- layout ------------------------------------------------------------------------

    def _action(self, text: str, shortcut: Any, slot: Callable[[], None]) -> QAction:
        action = QAction(text, self)
        action.setShortcut(shortcut)
        action.triggered.connect(slot)
        return action

    def _build_menu(self) -> None:
        self.open_action = self._action(
            "&Open case...", QKeySequence.StandardKey.Open, self.choose_case
        )
        self.ingest_action = self._action("&Ingest evidence...", "Ctrl+I", self.ingest_evidence)
        self.export_action = self._action("&Export timeline...", "Ctrl+E", self.export_timeline)
        menu = self.menuBar().addMenu("&File")
        menu.addAction(self.open_action)
        menu.addSeparator()
        menu.addAction(self.ingest_action)
        menu.addAction(self.export_action)
        menu.addSeparator()
        quit_action = QAction("&Quit", self)
        quit_action.setShortcut(QKeySequence.StandardKey.Quit)
        quit_action.triggered.connect(self.close)
        menu.addAction(quit_action)
        toolbar = self.addToolBar("Case")
        toolbar.setMovable(False)
        for action in (self.open_action, self.ingest_action, self.export_action):
            toolbar.addAction(action)

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

    def _set_case_actions_enabled(self, enabled: bool) -> None:
        has_case = self.case_dir is not None
        self.ingest_action.setEnabled(enabled and has_case)
        self.export_action.setEnabled(enabled and has_case)
        self.open_action.setEnabled(enabled or not has_case)

    def report(self, icon: QMessageBox.Icon, title: str, text: str, details: str = "") -> None:
        """Show an outcome to the user (a separate method so tests can capture it)."""
        box = QMessageBox(icon, title, text, parent=self)
        if details:
            box.setDetailedText(details)
        box.exec()

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
        self.case_dir = case_dir
        name = reader.meta.get("name", case_dir.name)
        self.setWindowTitle(f"Chronoscope {__version__} - {name}")
        self.refresh_choices()
        self._set_filters_enabled(True)
        self._set_case_actions_enabled(True)
        self.reset_filters()
        return True

    def refresh_choices(self) -> None:
        """Reload the artifact and evidence lists, keeping the current selections."""
        assert self.reader is not None
        for box, column in ((self.artifact, "artifact"), (self.evidence, "evidence_label")):
            current = box.currentText() or ALL
            box.clear()
            box.addItems([ALL, *self.reader.distinct(column)])
            box.setCurrentIndex(max(0, box.findText(current)))

    def ingest_evidence(self) -> None:
        if self.case_dir is None or self.job is not None:
            return
        dialog = IngestDialog(self, discover(), self.operator)
        if dialog.exec():
            self.start_ingest(dialog.request)

    def export_timeline(self) -> None:
        if self.case_dir is None or self.job is not None:
            return
        dialog = ExportDialog(self, self.operator, self.start.text(), self.end.text())
        if dialog.exec():
            self.start_export(dialog.request)

    def start_ingest(self, request: IngestRequest) -> None:
        assert self.case_dir is not None
        self.operator = request.operator
        case_dir = self.case_dir
        self._start_job(
            f"Ingesting {request.evidence}...",
            lambda: run_ingest(case_dir, request),
            self._ingest_done,
            "Ingest failed",
            "The ingest was rolled back, so nothing was added to the case. "
            "The audit log records the failure.",
        )

    def start_export(self, request: ExportRequest) -> None:
        assert self.case_dir is not None
        self.operator = request.operator
        case_dir = self.case_dir
        self._start_job(
            f"Exporting to {request.output}...",
            lambda: run_export(case_dir, request),
            self._export_done,
            "Export failed",
            "The output file may be incomplete. The export was not recorded in the audit log.",
        )

    def _start_job(
        self,
        message: str,
        fn: Callable[[], Any],
        on_success: Callable[[Any], None],
        failure_title: str,
        failure_note: str,
    ) -> None:
        job = self.job = Job(fn, self)
        job.finished.connect(
            lambda: self._job_finished(job, on_success, failure_title, failure_note)
        )
        self.model.paused = True
        self._set_filters_enabled(False)
        self._set_case_actions_enabled(False)
        self.progress.show()
        self.statusBar().showMessage(message)
        job.start()

    def _job_finished(
        self,
        job: Job,
        on_success: Callable[[Any], None],
        failure_title: str,
        failure_note: str,
    ) -> None:
        job.deleteLater()
        self.job = None
        self.progress.hide()
        self.model.paused = False
        self._set_filters_enabled(True)
        self._set_case_actions_enabled(True)
        self.refresh_choices()
        self.apply_filters()  # show new events before the summary appears
        if job.error is not None:
            self.report(QMessageBox.Icon.Critical, failure_title, f"{job.error}\n\n{failure_note}")
        else:
            on_success(job.result)

    def _ingest_done(self, result: IngestResult) -> None:
        text, details = describe_ingest(result)
        icon = QMessageBox.Icon.Warning if result.errors else QMessageBox.Icon.Information
        self.report(icon, "Ingest complete", text, details)

    def _export_done(self, result: ExportResult) -> None:
        self.report(
            QMessageBox.Icon.Information,
            "Export complete",
            f"Wrote {result.events:,} event(s) to {result.output}\n\nSHA-256 {result.sha256}",
        )

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
        if self.job is not None:
            self.report(
                QMessageBox.Icon.Information,
                "Please wait",
                "An ingest or export is still running. Close the window when it finishes.",
            )
            event.ignore()
            return
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
