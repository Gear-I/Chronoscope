"""Zip archives and Cellebrite UFED extractions (a ``.ufd`` descriptor next to a ``.zip``).

This parser records each archive member's own timestamps, read from the zip's UTC extra
fields: NTFS (0x000A, 100 ns FILETIMEs), extended timestamp (0x5455, POSIX seconds) and the
older Info-ZIP Unix field (0x5855). The plain zip date and time is local time with no zone and
2-second resolution, so it is never turned into an event; members that have nothing else are
counted in a warning. Artifacts *inside* the archive (browser databases, event logs, ...) are
handled by the ingest, which runs the other parsers on matching members.

A ``.ufd`` file is an INI-style descriptor. The archives it names are looked up next to it by
file name only (never by a path taken from the file); if none is named, a ``.zip`` with the
same stem is used.
"""

from __future__ import annotations

import configparser
import re
import struct
import zipfile
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

from chronoscope.event import TimelineEvent
from chronoscope.parsers.base import ParseContext, Parser
from chronoscope.timeutil import from_filetime

ARTIFACT = "zip"
ARCHIVE_SUFFIXES = (".zip",)
UFD_SUFFIX = ".ufd"
LOCAL_HEADER = struct.Struct("<IHHHHHIIIHH")
LOCAL_HEADER_SIGNATURE = 0x04034B50
NTFS_EXTRA = 0x000A
UT_EXTRA = 0x5455
UX_EXTRA = 0x5855

MODIFIED = "Content Modification Time"
ACCESSED = "Last Access Time"
CREATED = "Creation Time"
#: Info-ZIP's spec calls the third UT time "creation", but Info-ZIP itself stores the Unix
#: inode change time there; other writers differ. The label says so rather than guessing.
UT_CTIME = "Change or Creation Time (zip UT ctime)"


def ufd_archives(ufd: Path) -> list[Path]:
    """Archives a ``.ufd`` descriptor refers to, looked up next to it by file name."""
    text = ufd.read_text(encoding="utf-8-sig", errors="replace")
    values: list[str] = []
    config = configparser.ConfigParser(strict=False, interpolation=None)
    try:
        config.read_string(text)
        values = [v for section in config.sections() for _, v in config.items(section)]
    except configparser.Error:
        values = [m.group(1) for m in re.finditer(r"^[^=;#\n]+=\s*(.+?)\s*$", text, re.M)]
    found: list[Path] = []
    for value in values:
        name = PurePosixPath(value.strip().strip('"').replace("\\", "/")).name
        candidate = ufd.with_name(name) if name else None
        if (
            candidate is not None
            and candidate.suffix.lower() in ARCHIVE_SUFFIXES
            and candidate.is_file()
            and candidate not in found
        ):
            found.append(candidate)
    if not found:
        sibling = ufd.with_suffix(".zip")
        if sibling.is_file():
            found.append(sibling)
    return found


def _extra_fields(extra: bytes) -> dict[int, bytes]:
    fields: dict[int, bytes] = {}
    offset = 0
    while offset + 4 <= len(extra):
        header_id, size = struct.unpack_from("<HH", extra, offset)
        data = extra[offset + 4 : offset + 4 + size]
        if len(data) < size:
            break
        fields.setdefault(header_id, data)
        offset += 4 + size
    return fields


def local_extra(fh: Any, info: zipfile.ZipInfo) -> bytes:
    """The extra field from a member's local header (it has more UT times than the central)."""
    fh.seek(info.header_offset)
    header = fh.read(LOCAL_HEADER.size)
    if len(header) < LOCAL_HEADER.size:
        return b""
    fields = LOCAL_HEADER.unpack(header)
    if fields[0] != LOCAL_HEADER_SIGNATURE:
        return b""
    name_length, extra_length = fields[9], fields[10]
    fh.seek(name_length, 1)
    return fh.read(extra_length)


def _posix(value: int) -> datetime | None:
    return datetime.fromtimestamp(value, tz=timezone.utc) if value else None


def member_times(central: bytes, local: bytes) -> tuple[str, list[tuple[str, datetime]]]:
    """(source field, [(description, UTC time)]) from a member's extra fields.

    NTFS times (100 ns) are preferred, then UT (seconds), then UX. Returns ("", []) when the
    member only has the zone-less DOS date and time.
    """
    fields = {**_extra_fields(central), **_extra_fields(local)}
    ntfs = fields.get(NTFS_EXTRA)
    if ntfs and len(ntfs) >= 4:
        offset = 4  # reserved
        while offset + 4 <= len(ntfs):
            tag, size = struct.unpack_from("<HH", ntfs, offset)
            if tag == 1 and size >= 24 and offset + 4 + 24 <= len(ntfs):
                mtime, atime, ctime = struct.unpack_from("<3Q", ntfs, offset + 4)
                times = [(MODIFIED, mtime), (ACCESSED, atime), (CREATED, ctime)]
                return "NTFS", [(d, t) for d, v in times if (t := from_filetime(v))]
            offset += 4 + size
    ut = fields.get(UT_EXTRA)
    if ut:
        flags, offset, times = ut[0], 1, []
        for bit, desc in ((1, MODIFIED), (2, ACCESSED), (4, UT_CTIME)):
            if flags & bit and offset + 4 <= len(ut):
                (value,) = struct.unpack_from("<I", ut, offset)
                offset += 4
                if stamp := _posix(value):
                    times.append((desc, stamp))
        if times:
            return "UT", times
    ux = fields.get(UX_EXTRA)
    if ux and len(ux) >= 8:
        atime, mtime = struct.unpack_from("<II", ux, 0)
        times = [(d, t) for d, v in ((MODIFIED, mtime), (ACCESSED, atime)) if (t := _posix(v))]
        if times:
            return "UX", times
    return "", []


def is_archive(path: Path) -> bool:
    suffix = path.suffix.lower()
    if suffix == UFD_SUFFIX:
        return path.is_file()
    return suffix in ARCHIVE_SUFFIXES and zipfile.is_zipfile(path)


class ArchiveParser(Parser):
    name = ARTIFACT
    description = "Zip archives and Cellebrite UFED extractions (.ufd + .zip): member times"

    def can_parse(self, path: Path) -> bool:
        try:
            return is_archive(path)
        except OSError:
            return False

    def can_parse_head(self, name: str, head: bytes) -> bool:
        return False  # archives inside archives are not opened

    def archives(self, path: Path) -> list[Path]:
        """The zip files this evidence file stands for."""
        if path.suffix.lower() == UFD_SUFFIX:
            return ufd_archives(path)
        return [path]

    def related_files(self, path: Path) -> list[Path]:
        return [p for p in self.archives(path) if p != path]

    def parse(self, path: Path, ctx: ParseContext) -> Iterator[TimelineEvent]:
        archives = self.archives(path)
        if not archives:
            ctx.warn("UFED descriptor names no archive found next to it; nothing to read")
            return
        base = PurePosixPath(ctx.relpath).parent
        for archive in archives:
            relpath = (base / archive.name).as_posix() if archive != path else ctx.relpath
            yield from self._members(archive, relpath, ctx)

    def _members(self, archive: Path, relpath: str, ctx: ParseContext) -> Iterator[TimelineEvent]:
        without_utc = 0
        with zipfile.ZipFile(archive) as zf, open(archive, "rb") as raw:
            for info in zf.infolist():
                try:
                    source, times = member_times(info.extra, local_extra(raw, info))
                except (OSError, struct.error, ValueError) as exc:
                    ctx.warn(f"{relpath}: {info.filename}: unreadable timestamps ({exc})")
                    continue
                if not times:
                    without_utc += 1
                    continue
                member = info.filename
                path = f"{relpath}/{member}"
                attrs = {
                    "archive": relpath,
                    "member": member,
                    "is_dir": info.is_dir(),
                    "size": info.file_size,
                    "compressed_size": info.compress_size,
                    "crc32": f"{info.CRC:08x}",
                    "time_source": source,
                    "dos_time_local": "{:04d}-{:02d}-{:02d} {:02d}:{:02d}:{:02d}".format(
                        *info.date_time
                    ),
                }
                kind = "dir" if info.is_dir() else f"{info.file_size} bytes"
                for desc, stamp in times:
                    yield TimelineEvent(
                        timestamp=stamp,
                        timestamp_desc=desc,
                        source="FILE",
                        artifact=self.name,
                        message=f"{member} ({kind}, in {archive.name})",
                        path=path,
                        attributes=attrs,
                    )
        if without_utc:
            ctx.warn(
                f"{relpath}: {without_utc} member(s) have only the zip's local, zone-less "
                "DOS time; no timestamps recorded for them"
            )
