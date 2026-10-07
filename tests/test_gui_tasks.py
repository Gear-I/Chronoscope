"""Ingest and export from the Qt GUI. Runs headless on Qt's offscreen platform."""

from __future__ import annotations

import gc
import os
import time

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
QtWidgets = pytest.importorskip("PySide6.QtWidgets", exc_type=ImportError)

from chronoscope import gui, gui_tasks  # noqa: E402
from chronoscope.case import Case  # noqa: E402
from chronoscope.hashing import hash_file  # noqa: E402
from chronoscope.parsers import discover  # noqa: E402

from .test_mft import build_mft  # noqa: E402
from .test_viewer import populated  # noqa: E402, F401  (fixture)

MFT_EVENTS = 68  # every timestamp in the synthetic $MFT from test_mft


@pytest.fixture(scope="module")
def qapp():
    return QtWidgets.QApplication.instance() or QtWidgets.QApplication([])


@pytest.fixture
def window(qapp, populated):  # noqa: F811
    win = gui.MainWindow(populated)
    # No reference back to ``win``: a cycle would leave the window to the cyclic GC.
    reports: list[tuple[str, str, str]] = []
    win.reports = reports
    win.report = lambda icon, title, text, details="": reports.append((title, text, details))
    yield win
    win.close()


def _wait(qapp, window, timeout=30.0):
    deadline = time.monotonic() + timeout
    while window.job is not None:
        assert time.monotonic() < deadline, "background job did not finish"
        qapp.processEvents()
        time.sleep(0.01)
    qapp.processEvents()


def _audit(case_dir):
    with Case.open(case_dir, "reader") as case:
        return list(case.audit.entries())


@pytest.fixture
def mft_evidence(tmp_path):
    folder = tmp_path / "evidence"
    folder.mkdir()
    (folder / "$MFT").write_bytes(build_mft())
    return folder / "$MFT"


def test_actions_follow_case_state(qapp, tmp_path):
    win = gui.MainWindow()
    try:
        assert not win.ingest_action.isEnabled()
        assert not win.export_action.isEnabled()
        assert win.open_action.isEnabled()
    finally:
        win.close()


def test_ingest_from_window(qapp, window, populated, mft_evidence):  # noqa: F811
    assert window.ingest_action.isEnabled()
    request = gui_tasks.IngestRequest(mft_evidence, "WS99", ["mft"], "gui-tester")
    window.start_ingest(request)
    assert not window.ingest_action.isEnabled()  # no second job while one runs
    assert not gc.isenabled()  # only the GUI-thread timer collects during a job
    _wait(qapp, window)

    [(title, text, _details)] = window.reports
    assert title == "Ingest complete"
    assert f"{MFT_EVENTS} new event(s), 0 duplicate(s)" in text
    assert "mft: 68" in text
    assert window.model.total == 5 + MFT_EVENTS
    assert "WS99" in [window.evidence.itemText(i) for i in range(window.evidence.count())]
    assert window.ingest_action.isEnabled()
    assert window.operator == "gui-tester"
    assert gc.isenabled()  # automatic collection is back on after the job

    audit = _audit(populated)
    assert [e["action"] for e in audit[-2:]] == ["ingest.start", "ingest.complete"]
    assert {e["operator"] for e in audit[-2:]} == {"gui-tester"}
    assert audit[-1]["details"]["inserted"] == MFT_EVENTS


def test_failed_ingest_is_reported_and_rolled_back(qapp, window, populated, mft_evidence):  # noqa: F811
    window.start_ingest(gui_tasks.IngestRequest(mft_evidence, None, ["no_such"], "gui-tester"))
    _wait(qapp, window)
    [(title, text, _)] = window.reports
    assert title == "Ingest failed"
    assert "no_such: unknown parser" in text
    assert window.model.total == 5


def test_export_from_window(qapp, window, populated, tmp_path):  # noqa: F811
    out = tmp_path / "timeline.csv"
    window.start_export(gui_tasks.ExportRequest(out, "csv", None, None, True, "gui-tester"))
    _wait(qapp, window)

    [(title, text, _)] = window.reports
    digest = hash_file(out).sha256
    assert title == "Export complete"
    assert f"Wrote 5 event(s) to {out}" in text
    assert digest in text
    assert len(out.read_text(encoding="utf-8").splitlines()) == 6  # header + 5 events

    entry = _audit(populated)[-1]
    assert entry["action"] == "export"
    assert entry["operator"] == "gui-tester"
    assert entry["details"]["sha256"] == digest
    assert entry["details"]["excel_safe"] is True


def test_close_is_refused_while_a_job_runs(window):
    window.job = object()  # stand-in for a running job
    try:
        window.show()
        assert not window.close()
        assert window.reports[0][0] == "Please wait"
    finally:
        window.job = None


def test_ingest_dialog_validation(qapp, mft_evidence):
    dialog = gui_tasks.IngestDialog(None, discover(), "examiner")
    dialog.accept()
    assert dialog.request is None
    assert "Choose the evidence" in dialog.error.text()

    dialog.evidence.setText(str(mft_evidence.parent / "missing"))
    dialog.accept()
    assert "Evidence not found" in dialog.error.text()

    dialog.evidence.setText(str(mft_evidence))
    dialog.auto.setChecked(False)
    assert dialog.parsers.isEnabled()
    dialog.accept()
    assert "Tick at least one parser" in dialog.error.text()

    for row in range(dialog.parsers.count()):
        item = dialog.parsers.item(row)
        if item.data(gui_tasks.Qt.ItemDataRole.UserRole) == "mft":
            item.setCheckState(gui_tasks.Qt.CheckState.Checked)
    dialog.label.setText("  WS01 ")
    dialog.accept()
    assert dialog.request == gui_tasks.IngestRequest(mft_evidence, "WS01", ["mft"], "examiner")


def test_export_dialog_validation(qapp, tmp_path, monkeypatch):
    dialog = gui_tasks.ExportDialog(None, "examiner", start="2024-03-01 00:00")
    dialog.output.setText(str(tmp_path / "out.jsonl"))
    dialog.fmt.setCurrentText("jsonl")
    assert not dialog.excel_safe.isEnabled()
    dialog.accept()
    assert dialog.request is None
    assert "From:" in dialog.error.text() and "offset" in dialog.error.text()

    dialog.start.setText("2024-03-01T00:00:00Z")
    existing = tmp_path / "out.jsonl"
    existing.write_text("old", encoding="utf-8")
    answers = [QtWidgets.QMessageBox.StandardButton.No, QtWidgets.QMessageBox.StandardButton.Yes]
    monkeypatch.setattr(gui_tasks.QMessageBox, "question", lambda *a: answers.pop(0))
    dialog.accept()
    assert dialog.request is None  # declined to overwrite
    dialog.accept()
    assert dialog.request is not None
    assert dialog.request.fmt == "jsonl"
    assert dialog.request.start.isoformat() == "2024-03-01T00:00:00+00:00"
    assert dialog.request.end is None
