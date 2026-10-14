from __future__ import annotations

import struct
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import pytest
from click.testing import CliRunner

from chronoscope.cli import main
from chronoscope.containers import CREATED, MODIFIED, UT_CTIME, ufd_targets
from chronoscope.containers import zip_member_times as member_times
from chronoscope.hashing import hash_file
from chronoscope.ingest import NO_ARTIFACT_NOTE, ingest
from chronoscope.parsers import ParseContext, discover
from chronoscope.parsers.archive import UfedParser

from .conftest import DOWNLOAD_START, VISIT_IN_DB, VISIT_IN_WAL, make_chrome_history
from .test_mft import build_mft, ft

DEVICE_M = datetime(2024, 5, 2, 8, 1, 2, 345678, tzinfo=timezone.utc)
DEVICE_A = datetime(2024, 5, 3, 9, 0, 0, 1, tzinfo=timezone.utc)
DEVICE_C = datetime(2023, 12, 24, 18, 30, 0, tzinfo=timezone.utc)
UT_M = datetime(2024, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
UT_C = datetime(2024, 6, 1, 11, 0, 0, tzinfo=timezone.utc)
CHROME_DIR = "filesystem1/data/data/com.android.chrome/app_chrome/Default"


def ntfs_extra(mtime: datetime, atime: datetime, ctime: datetime, extra_100ns: int = 7) -> bytes:
    times = struct.pack("<3Q", *(ft(t, extra_100ns) for t in (mtime, atime, ctime)))
    body = b"\x00" * 4 + struct.pack("<HH", 1, 24) + times
    return struct.pack("<HH", 0x000A, len(body)) + body


def ut_extra(mtime: datetime, ctime: datetime) -> bytes:
    body = bytes([0b101]) + struct.pack("<II", int(mtime.timestamp()), int(ctime.timestamp()))
    return struct.pack("<HH", 0x5455, len(body)) + body


def _member(zf: zipfile.ZipFile, name: str, data: bytes, extra: bytes = b"") -> None:
    info = zipfile.ZipInfo(name, date_time=(2024, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.extra = extra
    zf.writestr(info, data)


def make_extraction(folder: Path, ufd_value: str = "EXTRACTION_FFS.zip") -> Path:
    """A Cellebrite-style full file system extraction: a .ufd descriptor next to a zip."""
    folder.mkdir(parents=True, exist_ok=True)
    history = make_chrome_history(folder / "_staging")
    archive = folder / "EXTRACTION_FFS.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        times = ntfs_extra(DEVICE_M, DEVICE_A, DEVICE_C)
        _member(zf, f"{CHROME_DIR}/", b"", times)
        _member(zf, f"{CHROME_DIR}/History", history.read_bytes(), times)
        _member(
            zf,
            f"{CHROME_DIR}/History-wal",
            (folder / "_staging" / "History-wal").read_bytes(),
            times,
        )
        _member(zf, "filesystem1/private/var/mobile/notes.txt", b"hello\n", ut_extra(UT_M, UT_C))
        _member(zf, "filesystem1/dos-only.txt", b"no utc times\n")
        _member(zf, "filesystem1/other/History", b"not a database", times)
        _member(zf, "filesystem1/$MFT", build_mft(), times)
        _member(zf, "filesystem1/corrupt.bin", b"x" * 100, times)
    for path in (folder / "_staging").iterdir():
        path.unlink()
    (folder / "_staging").rmdir()
    _corrupt_member(archive, "filesystem1/corrupt.bin")
    ufd = folder / "EXTRACTION_FFS.ufd"
    ufd.write_text(
        "[General]\nVendor=Cellebrite\nExtractionType=FullFileSystem\n"
        f"[Dumps]\nFileDump={ufd_value}\n",
        encoding="utf-8",
    )
    return ufd


def _corrupt_member(archive: Path, name: str) -> None:
    """Flip a byte of a member's compressed data so its CRC check fails."""
    with zipfile.ZipFile(archive) as zf:
        info = zf.getinfo(name)
    data = bytearray(archive.read_bytes())
    start = info.header_offset + 30 + len(info.filename.encode()) + len(info.extra)
    data[start] ^= 0xFF
    archive.write_bytes(bytes(data))


def test_member_times_prefer_ntfs_then_ut():
    source, times = member_times(ntfs_extra(DEVICE_M, DEVICE_A, DEVICE_C, 0), ut_extra(UT_M, UT_C))
    assert source == "zip NTFS field"
    assert times[0] == (MODIFIED, DEVICE_M)
    assert times[2] == (CREATED, DEVICE_C)
    # The central directory carries only the UT mtime; the local header has the rest.
    central_ut = struct.pack("<HHBI", 0x5455, 5, 0b101, int(UT_M.timestamp()))
    assert member_times(central_ut, ut_extra(UT_M, UT_C)) == (
        "zip UT field",
        [(MODIFIED, UT_M), (UT_CTIME, UT_C)],
    )
    assert member_times(b"", b"") == ("", [])


def test_ufd_points_only_at_siblings(tmp_path):
    ufd = make_extraction(tmp_path / "case1", ufd_value="..\\..\\Windows\\EXTRACTION_FFS.zip")
    assert ufd_targets(ufd) == [(ufd.with_name("EXTRACTION_FFS.zip"), "zip")]  # basename only
    lonely = tmp_path / "x" / "LONELY.ufd"
    lonely.parent.mkdir()
    lonely.write_text("[Dumps]\nFileDump=missing.zip\n", encoding="utf-8")
    assert ufd_targets(lonely) == []
    ctx = ParseContext(lonely.parent, lonely.name, "t")
    assert list(UfedParser().parse(lonely, ctx)) == []
    assert "no readable container" in ctx.warnings[0]


def test_ingest_ufd_reads_member_times_and_artifacts(case, tmp_path):
    ufd = make_extraction(tmp_path / "ext")
    archive = ufd.with_name("EXTRACTION_FFS.zip")
    before = {p.name: hash_file(p).sha256 for p in ufd.parent.iterdir()}

    result = ingest(case, ufd, label="PHONE")

    assert not result.errors
    assert not result.fallback_only
    assert result.archive_members == 7  # files only; the directory entry is not scanned
    assert result.archive_members_parsed == 2  # History and $MFT
    assert result.per_parser["chromium_history"] == 3
    assert result.per_parser["mft"] == 68
    assert any(
        "1 member(s) have no usable timestamps (only the zip's local, zone-less DOS time)" in w
        for w in result.warnings
    )
    assert any("filesystem1/corrupt.bin: cannot read" in w for w in result.warnings)
    # The descriptor and the archive are both hashed evidence, and neither was modified.
    hashed = {f.relpath for f in case.evidence_files()}
    assert {"EXTRACTION_FFS.ufd", "EXTRACTION_FFS.zip"} <= hashed
    assert {p.name: hash_file(p).sha256 for p in ufd.parent.iterdir()} == before

    events = list(case.iter_events())
    history = f"EXTRACTION_FFS.zip/{CHROME_DIR}/History"
    visits = sorted(
        e.timestamp_us
        for e in events
        if e.artifact == "chromium_history" and e.timestamp_desc == "Page Visited"
    )
    assert visits == [_us(VISIT_IN_DB), _us(VISIT_IN_WAL)]  # the WAL member was extracted too
    download = next(e for e in events if e.timestamp_desc == "Download Started")
    assert download.timestamp_us == _us(DOWNLOAD_START)
    assert download.path == history

    member = {(e.path, e.timestamp_desc): e for e in events if e.artifact == "zip"}
    created = member[(history, CREATED)]
    assert created.datetime == "2023-12-24T18:30:00.000000Z"
    assert member[(history, MODIFIED)].datetime == "2024-05-02T08:01:02.345678Z"
    notes = "EXTRACTION_FFS.zip/filesystem1/private/var/mobile/notes.txt"
    assert member[(notes, MODIFIED)].datetime == "2024-06-01T12:00:00.000000Z"
    assert member[(notes, UT_CTIME)].datetime == "2024-06-01T11:00:00.000000Z"
    assert not any("dos-only" in path for path, _ in member)
    assert archive.exists()


def _us(dt: datetime) -> int:
    return int((dt - datetime(1970, 1, 1, tzinfo=timezone.utc)).total_seconds() * 1_000_000)


def test_zip_read_via_ufd_or_directly_gives_identical_events(case, tmp_path):
    ufd = make_extraction(tmp_path / "phone")
    first = ingest(case, ufd, label="PHONE")
    second = ingest(case, ufd.with_name("EXTRACTION_FFS.zip"), label="PHONE")
    assert first.inserted > 0
    assert second.inserted == 0  # same paths and fingerprints whichever file was ingested
    assert second.duplicates == first.inserted


def test_selected_parsers_limit_member_parsing(case, tmp_path):
    ufd = make_extraction(tmp_path / "ext")
    result = ingest(case, ufd, label="PHONE", parser_names=["ufed", "mft"])
    assert set(result.per_parser) == {"ufed", "mft"}
    assert result.archive_members_parsed == 1


def test_plain_file_reports_fallback(case, tmp_path):
    note = tmp_path / "readme.txt"
    note.write_text("nothing to parse", encoding="utf-8")
    result = ingest(case, note, label="X")
    assert result.fallback_only
    assert set(result.per_parser) == {"filesystem"}


def test_cli_prints_fallback_note(tmp_path):
    case_dir = tmp_path / "case"
    note = tmp_path / "readme.txt"
    note.write_text("nothing to parse", encoding="utf-8")
    runner = CliRunner(env={"CHRONOSCOPE_OPERATOR": "t"})
    assert (
        runner.invoke(main, ["init", str(case_dir), "--name", "N", "--examiner", "E"]).exit_code
        == 0
    )
    result = runner.invoke(main, ["ingest", str(case_dir), str(note)])
    assert result.exit_code == 0
    assert NO_ARTIFACT_NOTE in result.output


@pytest.mark.parametrize(
    ("parser", "name", "head", "expected"),
    [
        ("chromium_history", "History", b"SQLite format 3\x00rest", True),
        ("chromium_history", "History", b"not sqlite", False),
        ("firefox_history", "places.sqlite", b"SQLite format 3\x00", True),
        ("mft", "$MFT", b"", True),
        ("mft", "dump.bin", build_mft()[:64], True),
        ("bodyfile", "image.body", b"", True),
        ("bodyfile", "x.txt", b"0|/a|1|r/r|0|0|1|1700000000|1|1|0\n", True),
        ("bodyfile", "x.txt", b"hello\n", False),
        ("filesystem", "anything", b"", False),
        ("zip", "inner.zip", b"PK\x03\x04", False),
    ],
)
def test_can_parse_head(parser, name, head, expected):
    registry = discover(include_plugins=False)
    assert registry.parsers[parser].can_parse_head(name, head) is expected


def test_evtx_can_parse_head():
    from chronoscope.parsers.evtx import EvtxParser

    assert EvtxParser().can_parse_head("System.evtx", b"ElfFile\x00...") is True
    assert EvtxParser().can_parse_head("System.evtx", b"MZ") is False
