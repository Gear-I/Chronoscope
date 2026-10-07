"""Qt viewer tests. They run headless on Qt's offscreen platform."""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
QtWidgets = pytest.importorskip("PySide6.QtWidgets", exc_type=ImportError)

from chronoscope import gui  # noqa: E402
from chronoscope.viewer import Filters, TimelineReader  # noqa: E402

from .test_viewer import populated  # noqa: E402, F401  (fixture)


@pytest.fixture(scope="module")
def qapp():
    return QtWidgets.QApplication.instance() or QtWidgets.QApplication([])


def _messages(model):
    return [model.event(r).message for r in range(model.rowCount())]


def test_model_fetches_lazily_in_batches(populated, monkeypatch):  # noqa: F811
    monkeypatch.setattr(gui, "BATCH_SIZE", 2)
    with TimelineReader(populated) as reader:
        model = gui.EventTableModel()
        model.set_query(reader, Filters())
        assert model.total == 5
        assert model.rowCount() == 2
        while model.canFetchMore(gui.QModelIndex()):
            model.fetchMore(gui.QModelIndex())
        assert _messages(model) == [
            "other.txt",
            "plain.txt",
            "gone.exe",
            "stomped.dll",
            "100%_done_a.txt",
        ]
        assert model.data(model.index(3, 0)) == "2024-03-01T11:00:00.000000Z"
        assert model.data(model.index(3, 4)) == "stomped.dll"
        fg = gui.Qt.ItemDataRole.ForegroundRole
        assert model.data(model.index(3, 0), fg) == gui.FLAGGED_COLOR
        assert model.data(model.index(2, 0), fg) == gui.DELETED_COLOR
        assert model.data(model.index(1, 0), fg) is None
        model.set_query(None, Filters())


def test_window_filters_and_details(qapp, populated):  # noqa: F811
    window = gui.MainWindow(populated)
    try:
        assert "TEST-001" in window.windowTitle()
        assert window.model.total == 5
        assert [window.artifact.itemText(i) for i in range(window.artifact.count())] == [
            "(all)",
            "bodyfile",
            "mft",
        ]

        window.table.selectRow(3)
        details = window.details.toPlainText()
        assert "Path:         /Users/stomped.dll" in details
        assert '"si_created_before_fn": true' in details

        window.flagged.setChecked(True)  # toggling applies immediately
        assert _messages(window.model) == ["stomped.dll"]
        assert window.details.toPlainText() == ""

        window.reset_filters()
        assert window.model.total == 5
        window.search.setText("gone")
        window.evidence.setCurrentText("WS01")
        window.apply_filters()
        assert _messages(window.model) == ["gone.exe"]
        assert window.statusBar().currentMessage() == "1 event(s) match"
    finally:
        window.close()


def test_invalid_time_is_rejected(qapp, populated, monkeypatch):  # noqa: F811
    warnings = []
    monkeypatch.setattr(gui.QMessageBox, "warning", lambda *a: warnings.append(a[2]))
    window = gui.MainWindow(populated)
    try:
        window.start.setText("2024-03-01 10:00")  # no offset
        window.apply_filters()
        assert warnings and "no UTC offset" in warnings[0]
        assert window.model.total == 5  # previous results kept
    finally:
        window.close()


def test_bad_case_directory(qapp, tmp_path, monkeypatch):
    errors = []
    monkeypatch.setattr(gui.QMessageBox, "critical", lambda *a: errors.append(a[2]))
    window = gui.MainWindow()
    try:
        assert not window.open_case(tmp_path)
        assert errors and "not a Chronoscope case directory" in errors[0]
        assert not window.search.isEnabled()
    finally:
        window.close()


def test_logo_resources_and_welcome_page(qapp, populated):  # noqa: F811
    logo, icon = gui.pixmap("logo.png"), gui.pixmap("icon.png")
    assert (logo.width(), logo.height()) == (640, 469)
    assert (icon.width(), icon.height()) == (256, 256)
    assert not gui.app_icon().isNull()

    window = gui.MainWindow()
    try:
        assert window.pages.currentIndex() == 0  # welcome page with the logo
        assert not window.welcome_logo.pixmap().isNull()
        assert not window.windowIcon().isNull()
        assert window.open_case(populated)
        assert window.pages.currentIndex() == 1
    finally:
        window.close()
