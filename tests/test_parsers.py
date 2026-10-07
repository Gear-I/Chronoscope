from __future__ import annotations

from pathlib import Path

import pytest

from chronoscope.hashing import hash_file
from chronoscope.parsers import ParseContext, discover
from chronoscope.parsers.bodyfile import BodyfileParser
from chronoscope.parsers.browsers import ChromiumHistoryParser, FirefoxHistoryParser
from chronoscope.parsers.evtx import EvtxParser, record_to_event

from .conftest import (
    DOWNLOAD_START,
    VISIT_IN_DB,
    VISIT_IN_WAL,
    make_chrome_history,
    make_firefox_places,
)


def _ctx(path: Path) -> ParseContext:
    return ParseContext(path.parent, path.name, "test")


def test_chromium_reads_wal_without_touching_original(tmp_path):
    history = make_chrome_history(tmp_path / "profile")
    before = {p.name: hash_file(p).sha256 for p in history.parent.iterdir()}
    parser = ChromiumHistoryParser()
    assert parser.can_parse(history)
    assert [p.name for p in parser.related_files(history)] == ["History-wal"]

    events = list(parser.parse(history, _ctx(history)))

    visits = sorted(e.timestamp for e in events if e.timestamp_desc == "Page Visited")
    assert visits == [VISIT_IN_DB, VISIT_IN_WAL]  # the second exists only in the WAL
    download = next(e for e in events if e.timestamp_desc == "Download Started")
    assert download.timestamp == DOWNLOAD_START
    assert download.attributes["url"] == "https://cdn.test/payload"  # final hop of the chain
    first = next(e for e in events if e.timestamp == VISIT_IN_DB)
    assert first.attributes["transition"] == "TYPED"  # 0x30000001 & 0xFF
    # No side files created, nothing modified.
    after = {p.name: hash_file(p).sha256 for p in history.parent.iterdir()}
    assert after == before


def test_firefox_visits_and_bookmarks(tmp_path):
    places = make_firefox_places(tmp_path / "profile")
    parser = FirefoxHistoryParser()
    assert parser.can_parse(places)
    events = list(parser.parse(places, _ctx(places)))
    descs = sorted((e.timestamp_desc, e.timestamp) for e in events)
    assert descs == [
        ("Bookmark Added", VISIT_IN_DB),
        ("Page Visited", VISIT_IN_DB),
        ("Page Visited", VISIT_IN_WAL),
    ]
    typed = next(e for e in events if e.timestamp == VISIT_IN_DB and "Visited" in e.timestamp_desc)
    assert typed.attributes["visit_type"] == "TYPED"


def test_browser_parsers_ignore_lookalikes(tmp_path):
    fake = tmp_path / "History"
    fake.write_text("not sqlite", encoding="utf-8")
    assert not ChromiumHistoryParser().can_parse(fake)


BODY = """\
0|C:/Windows/System32/cmd.exe|1234-128-1|r/rrwxrwxrwx|0|0|289792|1700000000|1600000000|1600000100|0
d41d8cd98f00b204e9800998ecf8427e|/weird|name.txt|99|r/rr--r--r--|0|0|0|0|1600000000.5|0|0
this line is garbage
"""


def test_bodyfile(tmp_path):
    body = tmp_path / "image.body"
    body.write_text(BODY, encoding="utf-8")
    parser = BodyfileParser()
    assert parser.can_parse(body)
    ctx = _ctx(body)
    events = list(parser.parse(body, ctx))
    cmd = [e for e in events if e.path == "C:/Windows/System32/cmd.exe"]
    assert {e.timestamp_desc for e in cmd} == {
        "Last Access Time",
        "Content Modification Time",
        "Metadata Change Time",
    }
    weird = [e for e in events if e.path == "/weird|name.txt"]
    assert len(weird) == 1 and weird[0].iso == "2020-09-13T12:26:40.500000Z"
    assert weird[0].attributes["md5"] == "d41d8cd98f00b204e9800998ecf8427e"
    assert len(ctx.warnings) == 1 and "malformed" in ctx.warnings[0]


def test_bodyfile_detected_without_extension(tmp_path):
    body = tmp_path / "fls_output"
    body.write_text(BODY, encoding="utf-8")
    assert BodyfileParser().can_parse(body)


EVTX_XML = """\
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625}"/>
    <EventID>4624</EventID>
    <Level>0</Level>
    <TimeCreated SystemTime="2019-03-19 23:34:25.4416190+00:00"/>
    <EventRecordID>1032</EventRecordID>
    <Channel>Security</Channel>
    <Computer>WS01.corp.local</Computer>
  </System>
  <EventData>
    <Data Name="TargetUserName">alice</Data>
    <Data Name="LogonType">10</Data>
    <Data Name="IpAddress">203.0.113.7</Data>
    <Data>&lt;string&gt;first&lt;/string&gt;
&lt;string&gt;second&lt;/string&gt;
</Data>
  </EventData>
</Event>
"""


def test_evtx_record_conversion():
    ev = record_to_event(EVTX_XML, "Security.evtx")
    assert ev.iso == "2019-03-19T23:34:25.441619Z"
    assert ev.attributes["event_id"] == 4624
    assert ev.attributes["computer"] == "WS01.corp.local"
    assert ev.attributes["data"]["LogonType"] == "10"
    assert ev.attributes["data"]["Data_3"] == ["first", "second"]
    assert "Data_3=first | second" in ev.message
    assert ev.message.startswith("[4624] Microsoft-Windows-Security-Auditing: TargetUserName=alice")


def test_evtx_detection(tmp_path):
    good = tmp_path / "a.evtx"
    good.write_bytes(b"ElfFile\x00" + b"\x00" * 100)
    bad = tmp_path / "b.evtx"
    bad.write_bytes(b"MZ")
    assert EvtxParser().can_parse(good)
    assert not EvtxParser().can_parse(bad)


def test_registry_lists_builtins():
    registry = discover(include_plugins=False)
    expected = {"filesystem", "bodyfile", "chromium_history", "firefox_history", "evtx", "mft"}
    assert expected <= set(registry.parsers) | set(registry.unavailable)


@pytest.mark.skipif(EvtxParser.unavailable_reason() is not None, reason="python-evtx missing")
def test_evtx_parser_handles_garbage_file(tmp_path):
    bogus = tmp_path / "broken.evtx"
    bogus.write_bytes(b"ElfFile\x00" + b"\xff" * 4096)
    ctx = _ctx(bogus)
    assert list(EvtxParser().parse(bogus, ctx)) == []
    assert any("file header:" in w for w in ctx.warnings)


class _Header:
    def __init__(self, minor=2, magic=True, checksum_ok=True):
        self.minor, self.magic, self.ok = minor, magic, checksum_ok

    def check_magic(self):
        return self.magic

    def major_version(self):
        return 3

    def minor_version(self):
        return self.minor

    def checksum(self):
        return 1

    def calculate_checksum(self):
        return 1 if self.ok else 2


def test_evtx_header_accepts_windows11_format():
    from chronoscope.parsers.evtx import header_problem

    assert header_problem(_Header(minor=1)) is None
    assert header_problem(_Header(minor=2)) is None  # python-evtx's verify() rejects this
    assert "version 3.9" in header_problem(_Header(minor=9))
    assert header_problem(_Header(checksum_ok=False)) == "checksum mismatch"
