from __future__ import annotations

from datetime import datetime, timezone

import pytest

from chronoscope.case import CaseError
from chronoscope.event import TimelineEvent
from chronoscope.hashing import hash_file
from chronoscope.viewer import Filters, TimelineReader, is_deleted, is_flagged


def _event(hour: int, message: str, artifact: str = "mft", **attrs) -> TimelineEvent:
    return TimelineEvent(
        timestamp=datetime(2024, 3, 1, hour, tzinfo=timezone.utc),
        timestamp_desc="SI Created",
        source="MFT",
        artifact=artifact,
        message=message,
        path=f"/Users/{message}",
        attributes=attrs,
    )


@pytest.fixture
def populated(case):
    with case.transaction():
        ws = case.add_evidence("WS01", case.directory, "file")
        case.add_events(
            ws,
            "WS01",
            [
                _event(9, "plain.txt", deleted=False),
                _event(10, "gone.exe", deleted=True),
                _event(11, "stomped.dll", si_created_before_fn=True, si_zero_fraction=False),
                _event(12, "100%_done_a.txt", artifact="bodyfile"),
            ],
        )
        lt = case.add_evidence("LT02", case.directory, "file")
        case.add_events(lt, "LT02", [_event(8, "other.txt", artifact="bodyfile")])
    return case.directory


def _messages(reader, filters=None, offset=0, limit=100):
    return [e.message for e in reader.page(filters or Filters(), offset, limit)]


def test_reader_is_read_only(populated):
    db = populated / "case.db"
    before = hash_file(db).sha256
    with TimelineReader(populated) as reader:
        assert reader.meta["name"] == "TEST-001"
        assert reader.count(Filters()) == 5
        with pytest.raises(Exception, match="readonly"):
            reader.db.execute("DELETE FROM events")
    assert hash_file(db).sha256 == before


def test_order_paging_and_distinct(populated):
    with TimelineReader(populated) as reader:
        assert _messages(reader) == [
            "other.txt",
            "plain.txt",
            "gone.exe",
            "stomped.dll",
            "100%_done_a.txt",
        ]
        assert _messages(reader, offset=1, limit=2) == ["plain.txt", "gone.exe"]
        assert reader.distinct("artifact") == ["bodyfile", "mft"]
        assert reader.distinct("evidence_label") == ["LT02", "WS01"]
        with pytest.raises(ValueError):
            reader.distinct("message; DROP TABLE events")


def test_filters(populated):
    with TimelineReader(populated) as reader:
        assert _messages(reader, Filters(artifact="bodyfile", evidence="WS01")) == [
            "100%_done_a.txt"
        ]
        assert _messages(reader, Filters(text="STOMPED")) == ["stomped.dll"]
        # % and _ are matched literally, not as wildcards.
        assert _messages(reader, Filters(text="0%_d")) == ["100%_done_a.txt"]
        assert _messages(reader, Filters(text="%")) == ["100%_done_a.txt"]
        assert _messages(reader, Filters(flagged_only=True)) == ["stomped.dll"]
        assert _messages(reader, Filters(deleted_only=True)) == ["gone.exe"]
        window = Filters(
            start=datetime(2024, 3, 1, 9, tzinfo=timezone.utc),
            end=datetime(2024, 3, 1, 10, tzinfo=timezone.utc),
        )
        assert _messages(reader, window) == ["plain.txt", "gone.exe"]
        assert reader.count(window) == 2


def test_row_flags(populated):
    with TimelineReader(populated) as reader:
        events = {e.message: e for e in reader.page(Filters(), 0, 100)}
    assert is_flagged(events["stomped.dll"])
    assert not is_flagged(events["gone.exe"])
    assert is_deleted(events["gone.exe"])
    assert not is_deleted(events["plain.txt"])


def test_not_a_case(tmp_path):
    with pytest.raises(CaseError):
        TimelineReader(tmp_path)


def test_gui_smoke(populated):
    tk = pytest.importorskip("tkinter")
    from chronoscope import gui

    try:
        root = tk.Tk()
    except tk.TclError as exc:  # headless CI
        pytest.skip(f"no display: {exc}")
    root.withdraw()
    try:
        app = gui.TimelineApp(root, populated)
        assert len(app.tree.get_children()) == 5
        assert app.status_var.get() == "Events 1-5 of 5"
        assert app.tree.item("3", "tags") == ("flagged",)
        assert app.tree.item("2", "tags") == ("deleted",)

        app.tree.selection_set("3")
        app.show_details()
        details = app.details.get("1.0", "end")
        assert '"si_created_before_fn": true' in details

        app.flagged_var.set(True)
        app.apply_filters()
        assert [app.rows[i].message for i in app.tree.get_children()] == ["stomped.dll"]

        app.reset_filters()
        app.artifact_var.set("bodyfile")
        app.apply_filters()
        assert app.total == 2
    finally:
        root.destroy()
