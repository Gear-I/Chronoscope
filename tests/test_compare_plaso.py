"""tools/compare_plaso.py against plaso-style events written from the test data's known values.

The plaso rows mirror what ``psort.py -o json_line`` writes, built from the constants that
generated the synthetic browser databases and $MFT, not from Chronoscope's output.
"""

from __future__ import annotations

import csv
import importlib.util
import json
import sys
from datetime import datetime
from pathlib import Path

import pytest

from chronoscope.export import export_timeline
from chronoscope.ingest import ingest
from chronoscope.timeutil import to_unix_us

from .conftest import DOWNLOAD_START, VISIT_IN_DB, VISIT_IN_WAL, prtime, webkit
from .test_mft import (
    DEL_C,
    DOC_A,
    DOC_C,
    DOC_E,
    DOC_M,
    LONG_NAME,
    ROOT_T,
    STOMP_FN,
    STOMP_SI,
    USERS_T,
    build_mft,
    ft,
)

_spec = importlib.util.spec_from_file_location(
    "compare_plaso", Path(__file__).parents[1] / "tools" / "compare_plaso.py"
)
cmp = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = cmp  # dataclasses look the module up
_spec.loader.exec_module(cmp)

COMPARED = ["chromium_history", "firefox_history", "mft"]
MFT_DESCS = (
    "Creation Time",
    "Content Modification Time",
    "Metadata Modification Time",
    "Last Access Time",
)


def _event(data_type: str, desc: str, dt: datetime, date_time: dict, **values) -> dict:
    return {
        "__container_type__": "event",
        "__type__": "AttributeContainer",
        "data_type": data_type,
        "timestamp_desc": desc,
        "timestamp": to_unix_us(dt),
        "date_time": {"__type__": "DateTimeValues", **date_time},
        **values,
    }


def _webkit(data_type, desc, dt, **values):
    stamp = {"__class_name__": "WebKitTime", "timestamp": webkit(dt)}
    return _event(data_type, desc, dt, stamp, **values)


def _posix_us(data_type, desc, dt, **values):
    stamp = {"__class_name__": "PosixTimeInMicroseconds", "timestamp": prtime(dt)}
    return _event(data_type, desc, dt, stamp, **values)


def _mft(entry, seq, attribute, times, parent=None, parent_seq=0, name=None):
    rows = []
    for desc, (dt, extra) in zip(MFT_DESCS, times, strict=True):
        values = {"attribute_type": attribute, "file_reference": entry | (seq << 48)}
        if attribute == 0x30:
            values.update(parent_file_reference=parent | (parent_seq << 48), name=name)
        stamp = {"__class_name__": "Filetime", "timestamp": ft(dt, extra)}
        rows.append(_event("fs:stat:ntfs", desc, dt, stamp, **values))
    return rows


def _same(dt, extra=0):
    return [(dt, extra)] * 4


def truth() -> list[dict]:
    """What psort -o json_line reports for the test browser profiles and synthetic $MFT."""
    rows = [
        _webkit(
            "chrome:history:page_visited",
            "Last Visited Time",
            VISIT_IN_DB,
            url="https://example.com/",
        ),
        _webkit(
            "chrome:history:page_visited",
            "Last Visited Time",
            VISIT_IN_WAL,
            url="https://evil.test/=HYPERLINK(1)",
        ),
        _webkit(
            "chrome:history:file_downloaded",
            "Start Time",
            DOWNLOAD_START,
            full_path="C:\\Users\\a\\payload.exe",
            url="https://cdn.test/payload",
        ),
        _posix_us(
            "firefox:places:page_visited",
            "Last Visited Time",
            VISIT_IN_DB,
            url="https://mozilla.org/",
        ),
        _posix_us(
            "firefox:places:page_visited",
            "Last Visited Time",
            VISIT_IN_WAL,
            url="https://mozilla.org/",
        ),
        _posix_us("firefox:places:bookmark", "Added Time", VISIT_IN_DB, url="https://mozilla.org/"),
        # plaso also reports the modification time, here equal to the added time
        _posix_us(
            "firefox:places:bookmark",
            "Content Modification Time",
            VISIT_IN_DB,
            url="https://mozilla.org/",
        ),
        # a parser Chronoscope does not have
        _event("windows:registry:key_value", "Content Modification Time", ROOT_T, {}),
    ]
    doc_si = [(DOC_C, 7), (DOC_M, 3), (DOC_E, 0), (DOC_A, 9)]
    for entry, seq, si, fn, parent, pseq, names in (
        (0, 1, _same(ROOT_T), _same(ROOT_T), 5, 5, ["$MFT"]),
        (5, 5, _same(ROOT_T), _same(ROOT_T), 5, 5, ["."]),
        (6, 2, _same(USERS_T), _same(USERS_T), 5, 5, ["Users"]),
        (7, 4, doc_si, _same(DOC_C, 7), 6, 2, ["PROPOS~1.DOC", "proposal.docx"]),
        (8, 3, _same(DEL_C), _same(DEL_C), 6, 2, ["evil.exe"]),
        (9, 1, _same(STOMP_SI), _same(STOMP_FN, 5), 6, 2, ["stomped.dll"]),
        (11, 1, _same(DOC_C), _same(DOC_C), 6, 2, [LONG_NAME]),
        (12, 2, _same(DEL_C), _same(DEL_C), 12, 7, ["orphan.txt"]),
    ):
        rows += _mft(entry, seq, 0x10, si)
        for name in names:
            rows += _mft(entry, seq, 0x30, fn, parent, pseq, name)
    return rows


def _write(path: Path, rows) -> Path:
    with open(path, "w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, sort_keys=True) + "\n")
    return path


@pytest.fixture
def export(case, evidence_dir, tmp_path) -> Path:
    mft = tmp_path / "mft" / "$MFT"
    mft.parent.mkdir()
    mft.write_bytes(build_mft())
    ingest(case, evidence_dir, label="WS01")
    ingest(case, mft, label="WS01", parser_names=["mft"])
    out = tmp_path / "timeline.jsonl"
    export_timeline(case, out, "jsonl")
    return out


def _run(export, rows, tmp_path, artifacts=COMPARED):
    ours = cmp.load_chronoscope(export, None, set(artifacts))
    theirs, skipped = cmp.load_plaso(_write(tmp_path / "plaso.jsonl", rows), set(artifacts), "")
    report = cmp.compare(ours, theirs)
    report.not_compared = skipped
    return report


def _found(report):
    return {(d.category, d.artifact, d.key, d.desc) for d in report.differences}


def test_agrees_with_ground_truth(export, tmp_path):
    report = _run(export, truth(), tmp_path)
    assert report.differences == []
    assert {a: (s.chronoscope, s.plaso, s.matched) for a, s in report.stats.items()} == {
        "chromium_history": (3, 3, 3),
        "firefox_history": (3, 3, 3),
        "mft": (68, 68, 68),
    }
    assert report.not_compared == {
        "windows:registry:key_value: Content Modification Time": 1,
        "firefox:places:bookmark: modification time equal to added time": 1,
    }


def test_detects_injected_differences(export, tmp_path):
    rows = truth()
    visit = rows[0]  # example.com: one microsecond later
    visit["date_time"]["timestamp"] += 1
    visit["timestamp"] += 1
    fn = next(
        r for r in rows if r.get("name") == "evil.exe" and r["timestamp_desc"] == "Last Access Time"
    )
    fn["date_time"]["timestamp"] += 1  # a single 100 ns tick
    rows = [
        r
        for r in rows
        if not (r.get("name") == "stomped.dll" and r["timestamp_desc"] == "Creation Time")
    ]
    rows.append(
        _webkit(
            "chrome:history:page_visited",
            "Last Visited Time",
            VISIT_IN_DB,
            url="https://extra.test/",
        )
    )

    found = _found(_run(export, rows, tmp_path))
    assert found == {
        ("time differs", "chromium_history", "visit | https://example.com/", "visit"),
        ("time differs", "mft", "8 | 3 | FN | 6 | evil.exe", "Accessed"),
        ("only in chronoscope", "mft", "9 | 1 | FN | 6 | stomped.dll", "Created"),
        ("only in plaso", "chromium_history", "visit | https://extra.test/", "visit"),
    }


def test_coarser_precision_wins():
    stamp = cmp.Stamp(1_000_000_123, cmp.NS)
    coarse = cmp.Stamp(1_000_000_000, cmp.US)
    a = [cmp.Event("filesystem", ("x",), "mtime", stamp)]
    b = [cmp.Event("filesystem", ("x",), "mtime", coarse)]
    assert cmp.compare(a, b).differences == []
    b = [cmp.Event("filesystem", ("x",), "mtime", cmp.Stamp(1_000_001_000, cmp.US))]
    assert len(cmp.compare(a, b).differences) == 1


def test_plaso_time_classes():
    assert cmp.plaso_stamp(
        {"date_time": {"__class_name__": "PosixTime", "timestamp": 5}}
    ) == cmp.Stamp(5 * cmp.SECOND, cmp.SECOND)
    assert cmp.plaso_stamp(
        {"date_time": {"__class_name__": "Filetime", "timestamp": cmp.FILETIME_UNIX_OFFSET + 7}}
    ) == cmp.Stamp(700, 100)
    # local-time or unknown classes fall back to plaso's UTC microsecond timestamp
    local = {"date_time": {"__class_name__": "Filetime", "timestamp": 1, "is_local_time": True}}
    assert cmp.plaso_stamp({**local, "timestamp": 42}) == cmp.Stamp(42_000, cmp.US)
    assert cmp.plaso_stamp(
        {"date_time": {"__class_name__": "TimeElements"}, "timestamp": 9}
    ) == cmp.Stamp(9_000, cmp.US)


def test_evtx_and_filesystem_mapping():
    ours = cmp.our_event(
        {
            "artifact": "evtx",
            "timestamp_desc": "Event Logged",
            "timestamp": 10,
            "path": "Windows/System32/winevt/Logs/Security.evtx",
            "attributes": {"record_number": "42"},
        }
    )
    theirs = cmp.plaso_event(
        {
            "data_type": "windows:evtx:record",
            "timestamp_desc": "Creation Time",
            "timestamp": 10,
            "filename": "\\Windows\\System32\\winevt\\Logs\\SECURITY.EVTX",
            "record_number": 42,
        },
        "",
    )
    assert ours.key == theirs.key == ("security.evtx", 42)
    written = {"data_type": "windows:evtx:record", "timestamp_desc": "Content Modification Time"}
    assert cmp.plaso_event(written, "") is None

    fs = cmp.plaso_event(
        {
            "data_type": "fs:stat",
            "timestamp_desc": "Metadata Modification Time",
            "timestamp": 1,
            "filename": "/mnt/ws01/Users/a/notes.txt",
        },
        "/mnt/ws01",
    )
    assert fs.key == ("Users/a/notes.txt",) and fs.desc == "ctime"
    assert cmp.file_path("\\mnt\\ws01", "/mnt/ws01") == ""


def test_command_line(export, tmp_path, capsys):
    plaso = _write(tmp_path / "p.jsonl", truth())
    args = [str(export), str(plaso)] + [f"--artifact={a}" for a in COMPARED]
    assert cmp.main(args) == 0
    out = capsys.readouterr().out
    assert "mft" in out and "Differences: 0" in out

    rows = truth()[1:]  # drop the example.com visit
    diffs = tmp_path / "diffs.csv"
    _write(plaso, rows)
    assert cmp.main([*args, "--out", str(diffs)]) == 1
    capsys.readouterr()
    with open(diffs, encoding="utf-8", newline="") as fh:
        [row] = list(csv.DictReader(fh))
    assert row["category"] == "only in chronoscope"
    assert row["chronoscope"] == "2024-03-01T09:30:00.000000000Z"

    bad = tmp_path / "bad.jsonl"
    bad.write_text("not json\n", encoding="utf-8")
    assert cmp.main([str(export), str(bad)]) == 2
    assert "not JSON Lines" in capsys.readouterr().err
