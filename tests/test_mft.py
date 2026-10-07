from __future__ import annotations

import struct
from datetime import datetime, timedelta, timezone
from pathlib import Path

from chronoscope.hashing import hash_file
from chronoscope.parsers import ParseContext, discover
from chronoscope.parsers.mft import MftParser, parse_record
from chronoscope.timeutil import WINDOWS_EPOCH

USN = 0xBEEF


def utc(*args: int) -> datetime:
    return datetime(*args, tzinfo=timezone.utc)


def ft(dt: datetime, extra_100ns: int = 0) -> int:
    """FILETIME for ``dt`` plus some sub-microsecond ticks."""
    return (dt - WINDOWS_EPOCH) // timedelta(microseconds=1) * 10 + extra_100ns


def _align8(n: int) -> int:
    return (n + 7) & ~7


def _attribute(attr_type: int, content: bytes, attr_id: int) -> bytes:
    length = _align8(0x18 + len(content))
    header = struct.pack(
        "<IIBBHHHIHBB", attr_type, length, 0, 0, 0x18, 0, attr_id, len(content), 0x18, 0, 0
    )
    return (header + content).ljust(length, b"\x00")


def _si(times: tuple[int, int, int, int]) -> bytes:
    return struct.pack("<4Q", *times) + b"\x00" * 40  # 72-byte NTFS 3.x layout


def _fn(parent: int, parent_seq: int, name: str, times, namespace: int = 1, size: int = 0) -> bytes:
    encoded = name.encode("utf-16-le")
    return (
        struct.pack("<Q4QQQII", parent | (parent_seq << 48), *times, size, size, 0, 0)
        + bytes([len(name), namespace])
        + encoded
    )


def _data(size: int) -> bytes:
    return b"A" * size


def make_record(
    sequence: int,
    flags: int,
    si=None,
    names=(),
    data: int | None = None,
    record_size: int = 1024,
) -> bytes:
    """Build one FILE record with a valid update-sequence array."""
    usa_count = record_size // 512 + 1
    first = _align8(0x30 + 2 * usa_count)
    attrs = b""
    if si is not None:
        attrs += _attribute(0x10, _si(si), 0)
    for i, fn in enumerate(names):
        attrs += _attribute(0x30, _fn(*fn), i + 1)
    if data is not None:
        attrs += _attribute(0x80, _data(data), 9)
    attrs += struct.pack("<II", 0xFFFFFFFF, 0)
    used = first + len(attrs)
    header = b"FILE" + struct.pack(
        "<HHQHHHHIIQHHI",
        0x30,
        usa_count,
        0,
        sequence,
        1,
        first,
        flags,
        used,
        record_size,
        0,
        10,
        0,
        0,
    )
    buf = bytearray(header.ljust(first, b"\x00") + attrs)
    assert len(buf) <= record_size
    buf = buf.ljust(record_size, b"\x00")
    struct.pack_into("<H", buf, 0x30, USN)
    for i in range(1, usa_count):
        end = i * 512
        buf[0x30 + 2 * i : 0x30 + 2 * i + 2] = buf[end - 2 : end]
        struct.pack_into("<H", buf, end - 2, USN)
    return bytes(buf)


# Timestamps used by the synthetic volume.
ROOT_T = utc(2023, 1, 1, 8, 0, 0, 123456)
USERS_T = utc(2023, 1, 2, 9, 0, 0, 500000)
DOC_C = utc(2024, 3, 1, 9, 15, 30, 250000)
DOC_M = utc(2024, 3, 1, 10, 20, 0, 999999)
DOC_E = utc(2024, 3, 1, 10, 20, 1, 1)
DOC_A = utc(2024, 3, 2, 7, 0, 0, 42)
DEL_C = utc(2024, 3, 5, 12, 0, 0, 111111)
STOMP_SI = utc(2019, 6, 1, 0, 0, 0)  # whole seconds, backdated
STOMP_FN = utc(2024, 3, 10, 14, 33, 7, 654321)
LONG_NAME = "N" * 100 + "-crosses-the-sector-boundary-" + "x" * 100 + ".txt"


def four(dt: datetime, extra: int = 0) -> tuple[int, int, int, int]:
    return (ft(dt, extra),) * 4


def build_mft(record_size: int = 1024) -> bytes:
    def rec(*args, **kwargs):
        return make_record(*args, record_size=record_size, **kwargs)

    empty = b"\x00" * record_size
    entries = [
        rec(1, 0x01, four(ROOT_T), [(5, 5, "$MFT", four(ROOT_T), 3)], data=0),  # 0
        empty,  # 1-4 unused slots
        empty,
        empty,
        empty,
        rec(5, 0x03, four(ROOT_T), [(5, 5, ".", four(ROOT_T), 3)]),  # 5: root
        rec(2, 0x03, four(USERS_T), [(5, 5, "Users", four(USERS_T), 3)]),  # 6
        rec(  # 7: ordinary file with distinct times and a DOS short name
            4,
            0x01,
            (ft(DOC_C, 7), ft(DOC_M, 3), ft(DOC_E), ft(DOC_A, 9)),
            [
                (6, 2, "PROPOS~1.DOC", four(DOC_C, 7), 2),
                (6, 2, "proposal.docx", four(DOC_C, 7), 1, 300),
            ],
            data=300,
        ),
        rec(3, 0x00, four(DEL_C), [(6, 2, "evil.exe", four(DEL_C), 1, 4096)]),  # 8: deleted
        rec(  # 9: timestomped
            1,
            0x01,
            four(STOMP_SI),
            [(6, 2, "stomped.dll", four(STOMP_FN, 5), 3)],
            data=16,
        ),
        bytearray(rec(1, 0x01, four(DOC_C), [(6, 2, "torn.txt", four(DOC_C), 3)])),  # 10
        rec(1, 0x01, four(DOC_C), [(6, 2, LONG_NAME, four(DOC_C), 1)]),  # 11
        rec(2, 0x00, four(DEL_C), [(12, 7, "orphan.txt", four(DEL_C), 3)]),  # 12: bad parent
        b"BAAD" + b"\x01" * (record_size - 4),  # 13
    ]
    torn = entries[10]
    torn[510:512] = b"\x00\x00"  # sector 0 no longer ends in the update sequence number
    entries[10] = bytes(torn)
    return b"".join(entries)


def _write(tmp_path: Path, name: str = "$MFT", record_size: int = 1024) -> Path:
    path = tmp_path / name
    path.write_bytes(build_mft(record_size))
    return path


def _parse(path: Path):
    ctx = ParseContext(path.parent, path.name, "test")
    return list(MftParser().parse(path, ctx)), ctx


def _by(events, path: str, desc: str):
    matches = [e for e in events if e.path == path and e.timestamp_desc == desc]
    assert len(matches) == 1, (path, desc, matches)
    return matches[0]


def test_detection(tmp_path):
    parser = MftParser()
    named = tmp_path / "$MFT"
    named.write_bytes(b"\x00" * 16)
    assert parser.can_parse(named)
    by_signature = _write(tmp_path, "mft.bin")
    assert parser.can_parse(by_signature)
    big = _write(tmp_path, "image.raw", record_size=4096)
    assert parser.can_parse(big)
    odd = tmp_path / "odd.bin"
    odd.write_bytes(b"FILE" + b"\x00" * 24 + struct.pack("<I", 2048) + b"\x00" * 100)
    assert not parser.can_parse(odd)
    other = tmp_path / "notes.txt"
    other.write_text("FILE nope", encoding="utf-8")
    assert not parser.can_parse(other)
    assert "mft" in discover(include_plugins=False).parsers


def test_regular_file_times_paths_and_size(tmp_path):
    mft = _write(tmp_path)
    before = hash_file(mft).sha256
    events, _ = _parse(mft)
    assert hash_file(mft).sha256 == before

    path = "/Users/proposal.docx"
    assert _by(events, path, "SI Created").timestamp == DOC_C
    assert _by(events, path, "SI Modified").timestamp == DOC_M
    assert _by(events, path, "SI Entry Modified").timestamp == DOC_E
    assert _by(events, path, "SI Accessed").timestamp == DOC_A
    si = _by(events, path, "SI Modified")
    assert si.attributes["filetime"] == ft(DOC_M, 3)  # 100 ns precision kept
    assert si.attributes["entry"] == 7
    assert si.attributes["sequence"] == 4
    assert si.attributes["in_use"] is True
    assert si.attributes["deleted"] is False
    assert si.attributes["is_directory"] is False
    assert si.attributes["size"] == 300
    assert si.attributes["si_created_before_fn"] is False
    assert si.attributes["si_zero_fraction"] is False
    assert si.message == "/Users/proposal.docx (in use, entry 7-4)"

    fn = _by(events, path, "FN Created")
    assert fn.timestamp == DOC_C
    assert fn.attributes["namespace"] == "Win32"
    assert (fn.attributes["parent_entry"], fn.attributes["parent_sequence"]) == (6, 2)
    dos = _by(events, "/Users/PROPOS~1.DOC", "FN Accessed")
    assert dos.attributes["namespace"] == "DOS"
    assert dos.attributes["entry"] == 7

    assert _by(events, "/", "SI Created").timestamp == ROOT_T
    assert _by(events, "/Users", "FN Modified").attributes["is_directory"] is True
    assert _by(events, "/$MFT", "SI Created").attributes["size"] == 0


def test_deleted_entry(tmp_path):
    events, _ = _parse(_write(tmp_path))
    ev = _by(events, "/Users/evil.exe", "SI Created")
    assert ev.timestamp == DEL_C
    assert ev.attributes["in_use"] is False
    assert ev.attributes["deleted"] is True
    assert ev.attributes["sequence"] == 3
    assert ev.attributes["size"] == 4096  # no $DATA: falls back to the FN real size
    assert "(deleted, entry 8-3)" in ev.message
    orphan = _by(events, "/$OrphanFiles/orphan.txt", "FN Created")
    assert orphan.attributes["deleted"] is True


def test_timestomp_indicators(tmp_path):
    events, _ = _parse(_write(tmp_path))
    path = "/Users/stomped.dll"
    for label in ("Created", "Modified", "Entry Modified", "Accessed"):
        si = _by(events, path, f"SI {label}")
        assert si.timestamp == STOMP_SI
        assert si.attributes["si_created_before_fn"] is True
        assert si.attributes["si_zero_fraction"] is True
        assert si.message == (
            "/Users/stomped.dll (in use, entry 9-1) [possible timestomp: SI created before FN "
            "created; SI times have zero sub-second part]"
        )
        fn = _by(events, path, f"FN {label}")
        assert fn.timestamp == STOMP_FN
        assert fn.attributes["filetime"] == ft(STOMP_FN, 5)
        assert "si_created_before_fn" not in fn.attributes


def test_fixups_applied_and_corrupt_records_skipped(tmp_path):
    events, ctx = _parse(_write(tmp_path))
    long_path = f"/Users/{LONG_NAME}"
    assert _by(events, long_path, "FN Created").attributes["fn_name"] == LONG_NAME
    assert not [e for e in events if "torn.txt" in e.path]
    assert ctx.warnings == [
        "$MFT: entry 10: skipped (fixup mismatch in sector 0 (torn write?))",
        "$MFT: entry 13: skipped (record marked BAAD (failed fixup during chkdsk))",
    ]
    # 0, 5, 6, 7 (2 names), 8, 9, 11, 12 -> 8 SI + 9 FN groups of four timestamps.
    assert len(events) == 4 * (8 + 9)


def test_without_fixups_the_name_would_be_corrupt():
    raw = make_record(1, 0x01, four(DOC_C), [(5, 5, LONG_NAME, four(DOC_C), 1)])
    assert struct.unpack_from("<H", raw, 510)[0] == USN
    record = parse_record(raw, 42)
    assert record is not None
    assert record.file_names[0].name == LONG_NAME


def test_4096_byte_records(tmp_path):
    events, ctx = _parse(_write(tmp_path, record_size=4096))
    assert _by(events, "/Users/proposal.docx", "SI Created").timestamp == DOC_C
    assert len(ctx.warnings) == 2
