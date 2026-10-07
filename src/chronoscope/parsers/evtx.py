"""Windows XML event logs (.evtx). Requires the optional ``python-evtx`` dependency."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from chronoscope.event import TimelineEvent
from chronoscope.parsers.base import ParseContext, Parser
from chronoscope.timeutil import parse_iso

EVTX_MAGIC = b"ElfFile\x00"
NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
ARTIFACT = "evtx"
SUPPORTED_VERSIONS = {(3, 1), (3, 2)}  # 3.2 is written by Windows 11
_STRING_ARRAY = re.compile(r"<string>(.*?)</string>", re.S)


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _value(text: str | None) -> str | list[str] | None:
    """python-evtx renders string-array substitutions as literal ``<string>`` markup."""
    if text is None:
        return None
    if text.lstrip().startswith("<string>"):
        items = _STRING_ARRAY.findall(text)
        if items:
            return items if len(items) > 1 else items[0]
    return text.strip()


def _one_line(value: object) -> str:
    if isinstance(value, list):
        value = " | ".join(value)
    return " ".join(str(value).split())


def _event_data(root: ET.Element) -> dict[str, Any]:
    data: dict[str, Any] = {}
    event_data = root.find(f"{NS}EventData")
    if event_data is not None:
        for i, item in enumerate(event_data):
            key = item.get("Name") or f"{_local(item.tag)}_{i}"
            data[key] = _value(item.text)
    user_data = root.find(f"{NS}UserData")
    if user_data is not None:
        for container in user_data:
            for item in container:
                data[_local(item.tag)] = _value(item.text)
    return data


def record_to_event(xml: str, relpath: str) -> TimelineEvent:
    """Convert one rendered EVTX record to an event. Separated out so it is testable."""
    root = ET.fromstring(xml)
    system = root.find(f"{NS}System")
    if system is None:
        raise ValueError("record has no System element")

    def text(tag: str) -> str | None:
        el = system.find(f"{NS}{tag}")
        return el.text if el is not None else None

    created = system.find(f"{NS}TimeCreated")
    if created is None or not created.get("SystemTime"):
        raise ValueError("record has no TimeCreated/@SystemTime")
    provider_el = system.find(f"{NS}Provider")
    provider = provider_el.get("Name", "") if provider_el is not None else ""
    event_id_text = text("EventID") or ""
    event_id: int | str = int(event_id_text) if event_id_text.isdigit() else event_id_text
    data = _event_data(root)

    details = "; ".join(f"{k}={_one_line(v)}" for k, v in data.items() if v not in (None, ""))
    message = f"[{event_id}] {provider}" + (f": {details}" if details else "")
    return TimelineEvent(
        timestamp=parse_iso(created.get("SystemTime", "")),
        timestamp_desc="Event Logged",
        source="EVTX",
        artifact=ARTIFACT,
        message=message,
        path=relpath,
        attributes={
            "event_id": event_id,
            "provider": provider,
            "channel": text("Channel"),
            "computer": text("Computer"),
            "record_number": text("EventRecordID"),
            "level": text("Level"),
            "data": data,
        },
    )


def header_problem(header: Any) -> str | None:
    """Our own header check: python-evtx's ``verify()`` rejects the 3.2 format of Windows 11."""
    if not header.check_magic():
        return "bad magic"
    version = (header.major_version(), header.minor_version())
    if version not in SUPPORTED_VERSIONS:
        return f"unsupported format version {version[0]}.{version[1]}"
    if header.checksum() != header.calculate_checksum():
        return "checksum mismatch"
    return None


class EvtxParser(Parser):
    name = ARTIFACT
    description = "Windows XML event log (.evtx)"

    @classmethod
    def unavailable_reason(cls) -> str | None:
        try:
            import Evtx.Evtx  # noqa: F401
        except ImportError:
            return "python-evtx is not installed (pip install 'chronoscope-forensics[evtx]')"
        return None

    def can_parse(self, path: Path) -> bool:
        try:
            with open(path, "rb") as fh:
                return fh.read(len(EVTX_MAGIC)) == EVTX_MAGIC
        except OSError:
            return False

    def parse(self, path: Path, ctx: ParseContext) -> Iterator[TimelineEvent]:
        from Evtx.Evtx import Evtx  # opens the file read-only via mmap

        with Evtx(str(path)) as log:
            header = log.get_file_header()
            problem = header_problem(header)
            if problem:
                ctx.warn(f"file header: {problem}; records may be missing")
            elif header.is_dirty():
                ctx.warn("log was not cleanly closed (dirty flag set)")
            for index, record in enumerate(log.records()):
                try:
                    yield record_to_event(record.xml(), ctx.relpath)
                except Exception as exc:  # corrupt records are common in carved/dirty logs
                    ctx.warn(f"record #{index}: skipped ({type(exc).__name__}: {exc})")
