"""tools/compare_mftecmd.py against MFTECmd-style rows written from the known test volume.

The expected rows are built from the constants in test_mft (the ground truth of the synthetic
$MFT), not from Chronoscope's output, so the comparison is not circular.
"""

from __future__ import annotations

import csv
import importlib.util
import sys
from pathlib import Path

import pytest

from chronoscope.export import export_timeline
from chronoscope.ingest import ingest

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
    "compare_mftecmd", Path(__file__).parents[1] / "tools" / "compare_mftecmd.py"
)
cmp = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = cmp  # dataclasses look the module up
_spec.loader.exec_module(cmp)

COLUMNS = [
    "EntryNumber",
    "SequenceNumber",
    "InUse",
    "ParentEntryNumber",
    "ParentSequenceNumber",
    "ParentPath",
    "FileName",
    "Extension",
    "FileSize",
    "ReferenceCount",
    "ReparseTarget",
    "IsDirectory",
    "HasAds",
    "IsAds",
    "SI<FN",
    "uSecZeros",
    "Copied",
    "SiFlags",
    "NameType",
    "Created0x10",
    "Created0x30",
    "LastModified0x10",
    "LastModified0x30",
    "LastRecordChange0x10",
    "LastRecordChange0x30",
    "LastAccess0x10",
    "LastAccess0x30",
]
STEMS = ("Created", "LastModified", "LastRecordChange", "LastAccess")


def _times(dt, extra=0):
    return (ft(dt, extra),) * 4


def truth() -> list[dict[str, str]]:
    """What MFTECmd --at reports for the synthetic volume (DOS names omitted, its default)."""
    users = ".\\Users"
    spec = [
        # entry, seq, in_use, parent, parent_path, name, size, is_dir, si, fn, si<fn, usec0
        (0, 1, True, 5, ".", "$MFT", 0, False, _times(ROOT_T), _times(ROOT_T), False, False),
        (5, 5, True, 5, ".", ".", 0, True, _times(ROOT_T), _times(ROOT_T), False, False),
        (6, 2, True, 5, ".", "Users", 0, True, _times(USERS_T), _times(USERS_T), False, False),
        (
            *(7, 4, True, 6, users, "proposal.docx", 300, False),
            (ft(DOC_C, 7), ft(DOC_M, 3), ft(DOC_E), ft(DOC_A, 9)),
            _times(DOC_C, 7),
            *(False, False),
        ),
        (
            8,
            3,
            False,
            6,
            users,
            "evil.exe",
            4096,
            False,
            _times(DEL_C),
            _times(DEL_C),
            False,
            False,
        ),
        (
            *(9, 1, True, 6, users, "stomped.dll", 16, False),
            *(_times(STOMP_SI), _times(STOMP_FN, 5), True, True),
        ),
        (11, 1, True, 6, users, LONG_NAME, 0, False, _times(DOC_C), _times(DOC_C), False, False),
        (
            *(12, 2, False, 12, "PathUnknown\\Directory with ID 0x0000000C-00000007"),
            *("orphan.txt", 0, False, _times(DEL_C), _times(DEL_C), False, False),
        ),
    ]
    rows = []
    for entry, seq, in_use, parent, ppath, name, size, is_dir, si, fn, stomp, usec in spec:
        row = dict.fromkeys(COLUMNS, "")
        row.update(
            EntryNumber=str(entry),
            SequenceNumber=str(seq),
            InUse=str(in_use),
            ParentEntryNumber=str(parent),
            ParentPath=ppath,
            FileName=name,
            FileSize=str(size),
            IsDirectory=str(is_dir),
            IsAds="False",
            **{"SI<FN": str(stomp)},
            uSecZeros=str(usec),
            NameType="Windows",
        )
        for stem, s, f in zip(STEMS, si, fn, strict=True):
            row[f"{stem}0x10"] = cmp.format_ticks(s)
            row[f"{stem}0x30"] = cmp.format_ticks(f)
        rows.append(row)
    return rows


def _write_csv(path: Path, rows) -> Path:
    with open(path, "w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    return path


@pytest.fixture
def export(case, tmp_path) -> Path:
    mft = tmp_path / "evidence" / "$MFT"
    mft.parent.mkdir()
    mft.write_bytes(build_mft())
    ingest(case, mft, label="WS01", parser_names=["mft"])
    out = tmp_path / "timeline.jsonl"
    export_timeline(case, out, "jsonl")
    return out


def _run(export, rows, tmp_path, include_dos=False):
    ours = cmp.load_chronoscope(export, None)
    theirs = cmp.load_mftecmd(_write_csv(tmp_path / "mftecmd.csv", rows), include_dos)
    return cmp.compare(ours, theirs, include_dos)


def _found(report):
    return {(d.category, d.entry, d.field) for d in report.differences}


def test_matches_ground_truth_except_the_orphan_path(export, tmp_path):
    report = _run(export, truth(), tmp_path)
    assert report.matched_rows == 8
    # Chronoscope and MFTECmd name orphans differently; everything else agrees exactly.
    assert _found(report) == {("orphan path", 12, "path")}
    assert report.inferred_fn_rows == 0
    assert report.flags["si_zero_fraction=True / uSecZeros=True"] == 1


def test_blank_fn_columns_without_at_are_treated_as_equal_to_si(export, tmp_path):
    rows = truth()
    for row in rows:
        for stem in STEMS:
            if row[f"{stem}0x30"] == row[f"{stem}0x10"]:
                row[f"{stem}0x30"] = ""
    report = _run(export, rows, tmp_path)
    assert _found(report) == {("orphan path", 12, "path")}
    assert report.inferred_fn_rows == 7  # every row except the timestomped one


def test_detects_injected_differences(export, tmp_path):
    rows = truth()
    by_entry = {int(r["EntryNumber"]): r for r in rows}
    by_entry[7]["LastModified0x10"] = cmp.format_ticks(ft(DOC_M, 4))  # one 100 ns tick off
    by_entry[8]["InUse"] = "True"
    by_entry[11]["FileSize"] = "1"
    by_entry[6]["ParentPath"] = ".\\Elsewhere"
    by_entry[9]["SI<FN"] = "False"
    rows.remove(by_entry[0])
    extra = dict(by_entry[11], EntryNumber="99", FileName="ghost.txt")
    rows.append(extra)

    found = _found(_run(export, rows, tmp_path))
    assert found == {
        ("timestamp", 7, "SI Modified"),
        ("value", 8, "in_use"),
        ("value", 11, "size"),
        ("path", 6, "path"),
        ("timestomp flag", 9, "SI<FN"),
        ("missing in mftecmd", 0, "row"),
        ("missing in chronoscope", 99, "row"),
        ("orphan path", 12, "path"),
    }


def test_compares_at_the_precision_mftecmd_printed(export, tmp_path):
    rows = truth()
    for row in rows:
        for column in COLUMNS:
            if column.endswith(("0x10", "0x30")) and row[column]:
                row[column] = row[column][:-4]  # --dt "yyyy-MM-dd HH:mm:ss.fff"
    assert _found(_run(export, rows, tmp_path)) == {("orphan path", 12, "path")}


def test_dos_names_are_compared_on_request(export, tmp_path):
    rows = truth()
    dos = dict(rows[3], FileName="PROPOS~1.DOC", NameType="Dos")
    dos.update({f"{s}0x30": cmp.format_ticks(ft(DOC_C, 7)) for s in STEMS})
    rows.append(dos)
    assert _found(_run(export, rows, tmp_path)) == {("orphan path", 12, "path")}
    report = _run(export, rows, tmp_path, include_dos=True)
    assert report.matched_rows == 9
    assert _found(report) == {("orphan path", 12, "path")}


def test_command_line(export, tmp_path, capsys):
    mftecmd = _write_csv(tmp_path / "m.csv", truth())
    diffs = tmp_path / "diffs.csv"
    assert cmp.main([str(export), str(mftecmd), "--out", str(diffs)]) == 1
    out = capsys.readouterr().out
    assert "Matched rows:        8" in out
    assert "orphan path" in out
    with open(diffs, encoding="utf-8", newline="") as fh:
        [row] = list(csv.DictReader(fh))
    assert row["chronoscope"] == ".\\$OrphanFiles\\orphan.txt"

    bad = tmp_path / "bad.csv"
    bad.write_text("EntryNumber,FileName\n1,a\n", encoding="utf-8")
    assert cmp.main([str(export), str(bad)]) == 2
    assert "missing" in capsys.readouterr().err


def test_timestamp_parsing():
    stamp = cmp.parse_mftecmd_time("2024-03-01 09:15:30.2500007")
    assert stamp == cmp.Stamp(ft(DOC_C, 7), 7)
    assert cmp.parse_mftecmd_time("2024-03-01T09:15:30.250Z").digits == 3
    assert cmp.parse_mftecmd_time("") is None
    with pytest.raises(cmp.InputError):
        cmp.parse_mftecmd_time("03/01/2024 09:15")
