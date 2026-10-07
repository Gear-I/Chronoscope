from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from chronoscope.audit import GENESIS_HASH, AuditLog
from chronoscope.event import NaiveTimestampError, TimelineEvent
from chronoscope.export import excel_safe
from chronoscope.hashing import hash_file
from chronoscope.timeutil import (
    from_filetime,
    from_unix_seconds,
    from_webkit,
    parse_iso,
    to_iso,
)


def _event(ts: datetime, **kw) -> TimelineEvent:
    return TimelineEvent(ts, "Test Time", "TEST", "test", "msg", **kw)


def test_naive_timestamp_rejected():
    with pytest.raises(NaiveTimestampError):
        _event(datetime(2024, 1, 1, 12, 0))


def test_timestamp_normalised_to_utc():
    plus_two = timezone(timedelta(hours=2))
    ev = _event(datetime(2024, 1, 1, 12, 0, tzinfo=plus_two))
    assert ev.iso == "2024-01-01T10:00:00.000000Z"
    assert (
        ev.fingerprint() == _event(datetime(2024, 1, 1, 10, 0, tzinfo=timezone.utc)).fingerprint()
    )


def test_fingerprint_depends_on_evidence_label():
    ev = _event(datetime(2024, 1, 1, tzinfo=timezone.utc))
    assert ev.fingerprint("HOST-A") != ev.fingerprint("HOST-B")


def test_attributes_must_be_json_serializable():
    with pytest.raises(TypeError):
        _event(datetime(2024, 1, 1, tzinfo=timezone.utc), attributes={"raw": b"\x00"})


def test_epoch_conversions():
    assert to_iso(from_webkit(13_350_000_000_000_000)) == "2024-01-17T21:20:00.000000Z"
    assert from_filetime(116_444_736_000_000_000) == datetime(1970, 1, 1, tzinfo=timezone.utc)
    assert from_unix_seconds("0") is None
    assert to_iso(from_unix_seconds("1700000000.25")) == "2023-11-14T22:13:20.250000Z"
    assert to_iso(from_unix_seconds("-1.5")) == "1969-12-31T23:59:58.500000Z"
    with pytest.raises(ValueError):
        from_unix_seconds("abc")


def test_parse_iso_requires_offset_and_handles_windows_precision():
    assert to_iso(parse_iso("2016-07-08T18:12:51.6816403Z")) == "2016-07-08T18:12:51.681640Z"
    assert to_iso(parse_iso("2016-07-08 18:12:51.68+00:00")) == "2016-07-08T18:12:51.680000Z"
    with pytest.raises(ValueError):
        parse_iso("2016-07-08T18:12:51")


def test_hash_file_known_vector(tmp_path):
    p = tmp_path / "abc"
    p.write_bytes(b"abc")
    h = hash_file(p)
    assert h.size == 3
    assert h.md5 == "900150983cd24fb0d6963f7d28e17f72"
    assert h.sha1 == "a9993e364706816aba3e25717850c26c9cd0d89d"
    assert h.sha256 == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def _log(tmp_path) -> AuditLog:
    log = AuditLog(tmp_path / "audit.jsonl", "tester", "0.0")
    for i in range(4):
        log.append("step", n=i)
    return log


def test_audit_chain_verifies(tmp_path):
    log = _log(tmp_path)
    result = AuditLog.verify(log.path)
    assert result.ok and result.entries == 4
    assert result.head_hash == log.entries()[-1]["hash"] != GENESIS_HASH


def test_audit_detects_modified_entry(tmp_path):
    log = _log(tmp_path)
    lines = log.path.read_text(encoding="utf-8").splitlines()
    entry = json.loads(lines[1])
    entry["details"]["n"] = 99
    lines[1] = json.dumps(entry)
    log.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    result = AuditLog.verify(log.path)
    assert not result.ok
    assert any("modified" in p for p in result.problems)


def test_audit_detects_deleted_entry(tmp_path):
    log = _log(tmp_path)
    lines = log.path.read_text(encoding="utf-8").splitlines()
    del lines[2]
    log.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert not AuditLog.verify(log.path).ok


@pytest.mark.parametrize(
    "value,expected",
    [
        ('=HYPERLINK("x")', '\'=HYPERLINK("x")'),
        ("+1", "'+1"),
        ("@SUM(A1)", "'@SUM(A1)"),
        ("\tcmd", "'\tcmd"),
        ("plain text", "plain text"),
        (12345, 12345),
    ],
)
def test_excel_safe(value, expected):
    assert excel_safe(value) == expected
