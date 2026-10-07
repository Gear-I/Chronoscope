"""Ingest and export from the desktop GUI: the dialogs and the background job runner.

Both operations run on a worker thread with their own read-write ``Case`` (SQLite connections
are bound to the thread that opened them), so the window stays responsive. They go through
the same ``ingest()`` and ``export_timeline()`` functions as the CLI, so hashing, transactions
and audit-log entries are identical.
"""

from __future__ import annotations

import getpass
import os
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from PySide6.QtCore import Qt, QThread
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from chronoscope.case import Case
from chronoscope.export import FORMATS, ExportResult, export_timeline
from chronoscope.ingest import WRITABLE_WARNING, IngestResult, ingest
from chronoscope.parsers import Registry
from chronoscope.timeutil import parse_iso

TIME_HINT = "ISO 8601 with an offset, e.g. 2024-03-01T00:00:00Z"
ERROR_STYLE = "color: #d32f2f"


def default_operator() -> str:
    """Same default as the CLI: ``CHRONOSCOPE_OPERATOR``, else the OS user name."""
    return os.environ.get("CHRONOSCOPE_OPERATOR") or getpass.getuser()


@dataclass(frozen=True)
class IngestRequest:
    evidence: Path
    label: str | None
    parsers: list[str] | None  # None means auto-detect
    operator: str


@dataclass(frozen=True)
class ExportRequest:
    output: Path
    fmt: str
    start: datetime | None
    end: datetime | None
    excel_safe: bool
    operator: str


def run_ingest(case_dir: Path, request: IngestRequest) -> IngestResult:
    with Case.open(case_dir, request.operator) as case:
        return ingest(case, request.evidence, label=request.label, parser_names=request.parsers)


def run_export(case_dir: Path, request: ExportRequest) -> ExportResult:
    with Case.open(case_dir, request.operator) as case:
        return export_timeline(
            case, request.output, request.fmt, request.start, request.end, request.excel_safe
        )


def describe_ingest(result: IngestResult) -> tuple[str, str]:
    """(summary, details) for the dialog shown when an ingest finishes."""
    lines = [
        f"Evidence #{result.evidence_id} [{result.label}]: {result.items_seen:,} item(s), "
        f"{result.hashed_files:,} file(s) hashed.",
        f"{result.inserted:,} new event(s), {result.duplicates:,} duplicate(s).",
    ]
    for name, count in sorted(result.per_parser.items()):
        lines.append(f"    {name}: {count:,}")
    if WRITABLE_WARNING in result.warnings:
        lines += ["", f"Warning: {WRITABLE_WARNING}"]
    if result.errors:
        lines += ["", f"{len(result.errors)} error(s); see details."]
    if result.warnings:
        lines.append(f"{len(result.warnings)} warning(s) recorded in the audit log.")
    details = [f"ERROR: {e}" for e in result.errors] + [f"warning: {w}" for w in result.warnings]
    return "\n".join(lines), "\n".join(details)


class Job(QThread):
    """Runs one callable on a worker thread. Read ``result``/``error`` once ``finished``."""

    def __init__(self, fn: Callable[[], Any], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.fn = fn
        self.result: Any = None
        self.error: str | None = None

    def run(self) -> None:
        try:
            self.result = self.fn()
        except Exception as exc:  # shown to the user by the window
            self.error = f"{type(exc).__name__}: {exc}"


def _path_row(edit: QLineEdit, *buttons: QPushButton) -> QWidget:
    row = QWidget()
    layout = QHBoxLayout(row)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.addWidget(edit, 1)
    for button in buttons:
        layout.addWidget(button)
    return row


class _RequestDialog(QDialog):
    def __init__(self, parent: QWidget | None, title: str, ok_text: str) -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setMinimumWidth(560)
        self.form = QFormLayout()
        self.error = QLabel()
        self.error.setStyleSheet(ERROR_STYLE)
        self.error.setWordWrap(True)
        self.error.hide()
        self.buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        self.buttons.button(QDialogButtonBox.StandardButton.Ok).setText(ok_text)
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        layout = QVBoxLayout(self)
        layout.addLayout(self.form)
        layout.addWidget(self.error)
        layout.addWidget(self.buttons)
        self.request: Any = None

    def fail(self, message: str) -> None:
        self.error.setText(message)
        self.error.show()

    def build_request(self) -> Any:
        """Return the request, or call ``fail()`` and return None."""
        raise NotImplementedError

    def confirm(self, request: Any) -> bool:
        """Last chance to ask the user before accepting a valid request."""
        return True

    def accept(self) -> None:
        request = self.build_request()
        if request is None or not self.confirm(request):
            return
        self.request = request
        super().accept()


class IngestDialog(_RequestDialog):
    def __init__(self, parent: QWidget | None, registry: Registry, operator: str) -> None:
        super().__init__(parent, "Ingest evidence", "Ingest")
        self.evidence = QLineEdit(placeholderText="A file or a directory")
        file_button = QPushButton("File...")
        folder_button = QPushButton("Folder...")
        file_button.clicked.connect(self._choose_file)
        folder_button.clicked.connect(self._choose_folder)
        self.label = QLineEdit(placeholderText="Default: the evidence name (e.g. a host name)")
        self.auto = QCheckBox("Auto-detect parsers")
        self.auto.setChecked(True)
        self.parsers = QListWidget()
        self.parsers.setMaximumHeight(170)
        for name, parser in sorted(registry.parsers.items()):
            item = QListWidgetItem(f"{name} - {parser.description}")
            item.setData(Qt.ItemDataRole.UserRole, name)
            item.setToolTip(parser.description)
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            item.setCheckState(Qt.CheckState.Unchecked)
            self.parsers.addItem(item)
        for name, reason in sorted(registry.unavailable.items()):
            item = QListWidgetItem(f"{name} - unavailable")
            item.setToolTip(reason)
            item.setFlags(Qt.ItemFlag.NoItemFlags)
            self.parsers.addItem(item)
        self.parsers.setEnabled(False)
        self.auto.toggled.connect(lambda on: self.parsers.setEnabled(not on))
        self.operator = QLineEdit(operator)
        note = QLabel(
            "Ingest from a read-only mount, a write blocker or a verified copy. "
            "Reading evidence on a writable volume can update last-access times."
        )
        note.setWordWrap(True)

        self.form.addRow("Evidence", _path_row(self.evidence, file_button, folder_button))
        self.form.addRow("Label", self.label)
        self.form.addRow("Parsers", self.auto)
        self.form.addRow("", self.parsers)
        self.form.addRow("Operator", self.operator)
        self.form.addRow(note)

    def _choose_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Choose evidence file")
        if path:
            self.evidence.setText(path)

    def _choose_folder(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "Choose evidence folder")
        if path:
            self.evidence.setText(path)

    def checked_parsers(self) -> list[str]:
        names = []
        for row in range(self.parsers.count()):
            item = self.parsers.item(row)
            if item.checkState() == Qt.CheckState.Checked:
                names.append(item.data(Qt.ItemDataRole.UserRole))
        return names

    def build_request(self) -> IngestRequest | None:
        text = self.evidence.text().strip()
        if not text:
            self.fail("Choose the evidence file or folder to ingest.")
            return None
        evidence = Path(text)
        if not evidence.exists():
            self.fail(f"Evidence not found: {evidence}")
            return None
        parsers = None
        if not self.auto.isChecked():
            parsers = self.checked_parsers()
            if not parsers:
                self.fail("Tick at least one parser, or turn auto-detect back on.")
                return None
        operator = self.operator.text().strip()
        if not operator:
            self.fail("Enter the operator name recorded in the audit log.")
            return None
        return IngestRequest(evidence, self.label.text().strip() or None, parsers, operator)


class ExportDialog(_RequestDialog):
    def __init__(
        self, parent: QWidget | None, operator: str, start: str = "", end: str = ""
    ) -> None:
        super().__init__(parent, "Export timeline", "Export")
        self.output = QLineEdit(placeholderText="timeline.csv")
        browse = QPushButton("Browse...")
        browse.clicked.connect(self._choose_output)
        self.fmt = QComboBox()
        self.fmt.addItems(FORMATS)
        self.start = QLineEdit(start, placeholderText="Optional. " + TIME_HINT)
        self.end = QLineEdit(end, placeholderText="Optional. " + TIME_HINT)
        self.excel_safe = QCheckBox("Neutralise spreadsheet formulas (alters data; audited)")
        self.fmt.currentTextChanged.connect(self._format_changed)
        self.operator = QLineEdit(operator)
        note = QLabel(
            "Exports the whole timeline, optionally limited to a time range, exactly like "
            "'chronoscope export'. The file's SHA-256 is recorded in the audit log."
        )
        note.setWordWrap(True)

        self.form.addRow("Output file", _path_row(self.output, browse))
        self.form.addRow("Format", self.fmt)
        self.form.addRow("From", self.start)
        self.form.addRow("To", self.end)
        self.form.addRow("", self.excel_safe)
        self.form.addRow("Operator", self.operator)
        self.form.addRow(note)
        self._overwrite_ok: Path | None = None

    def _format_changed(self, fmt: str) -> None:
        self.excel_safe.setEnabled(fmt == "csv")
        if fmt != "csv":
            self.excel_safe.setChecked(False)

    def _choose_output(self) -> None:
        fmt = self.fmt.currentText()
        path, _ = QFileDialog.getSaveFileName(
            self, "Export timeline", f"timeline.{fmt}", f"{fmt.upper()} (*.{fmt});;All files (*)"
        )
        if path:  # the save dialog has already asked about overwriting
            self.output.setText(path)
            self._overwrite_ok = Path(path)

    def build_request(self) -> ExportRequest | None:
        text = self.output.text().strip()
        if not text:
            self.fail("Choose the output file.")
            return None
        output = Path(text)
        if not output.parent.is_dir():
            self.fail(f"Folder does not exist: {output.parent}")
            return None
        if output.is_dir():
            self.fail(f"{output} is a folder; choose a file name.")
            return None
        times: dict[str, datetime | None] = {}
        for key, edit in (("From", self.start), ("To", self.end)):
            value = edit.text().strip()
            try:
                times[key] = parse_iso(value) if value else None
            except ValueError as exc:
                self.fail(f"{key}: {exc}. Use {TIME_HINT}.")
                return None
        operator = self.operator.text().strip()
        if not operator:
            self.fail("Enter the operator name recorded in the audit log.")
            return None
        return ExportRequest(
            output,
            self.fmt.currentText(),
            times["From"],
            times["To"],
            self.excel_safe.isChecked(),
            operator,
        )

    def confirm(self, request: ExportRequest) -> bool:
        if not request.output.exists() or self._overwrite_ok == request.output:
            return True
        answer = QMessageBox.question(
            self, "Overwrite file?", f"{request.output} exists. Overwrite it?"
        )
        return answer == QMessageBox.StandardButton.Yes
