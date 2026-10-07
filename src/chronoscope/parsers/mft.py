"""Raw NTFS master file tables (``$MFT``), in pure Python.

Each FILE record has its update-sequence (fixup) array applied, then every
``$STANDARD_INFORMATION`` (0x10) and ``$FILE_NAME`` (0x30) attribute is read. All four
timestamps of each become events. Full paths are rebuilt from the ``$FILE_NAME`` parent
references, and two timestomping indicators are flagged on the SI events:

* ``si_created_before_fn``: SI creation time earlier than FN creation time. Tools such as
  ``SetFileTime`` can only rewrite SI, so a backdated SI creation stands out.
* ``si_zero_fraction``: every SI timestamp has a zero sub-second part (whole seconds) while
  the FN timestamps do not. Many timestomping tools only set whole seconds.

Both are indicators, not proof. Limitations: attributes held in extension records (reached
through ``$ATTRIBUTE_LIST``) are not followed, so files with very many hard links may lose some
names. A deleted entry whose parent directory was reused gets a path under ``/$OrphanFiles``.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from chronoscope.event import TimelineEvent
from chronoscope.parsers.base import ParseContext, Parser
from chronoscope.timeutil import from_filetime

ARTIFACT = "mft"
SIGNATURE = b"FILE"
RECORD_SIZES = (1024, 4096)
SECTOR = 512  # the update-sequence stride is always 512 bytes, whatever the disk's sector size
ROOT_ENTRY = 5
ORPHAN_DIR = "/$OrphanFiles"
END_MARKER = 0xFFFFFFFF
STANDARD_INFORMATION = 0x10
FILE_NAME = 0x30
DATA = 0x80
FLAG_IN_USE = 0x01
FLAG_DIRECTORY = 0x02
FILETIME_PER_SECOND = 10_000_000

#: Order of the four timestamps inside both SI and FN attributes.
TIME_LABELS = ("Created", "Modified", "Entry Modified", "Accessed")
NAMESPACES = {0: "POSIX", 1: "Win32", 2: "DOS", 3: "Win32&DOS"}
#: Lower is preferred when choosing the name used for an entry's path.
_NAMESPACE_RANK = {1: 0, 3: 0, 0: 1, 2: 2}


class CorruptRecord(ValueError):
    pass


@dataclass(frozen=True)
class FileName:
    parent_entry: int
    parent_sequence: int
    times: tuple[int, int, int, int]
    namespace: int
    name: str
    real_size: int


@dataclass(frozen=True)
class Record:
    entry: int
    sequence: int
    flags: int
    base_reference: int
    si_times: tuple[int, int, int, int] | None
    file_names: tuple[FileName, ...]
    data_size: int | None

    @property
    def in_use(self) -> bool:
        return bool(self.flags & FLAG_IN_USE)

    @property
    def is_directory(self) -> bool:
        return bool(self.flags & FLAG_DIRECTORY)

    @property
    def primary_name(self) -> FileName | None:
        if not self.file_names:
            return None
        return min(self.file_names, key=lambda fn: _NAMESPACE_RANK.get(fn.namespace, 3))


def apply_fixups(buf: bytearray) -> None:
    """Verify and undo the update-sequence array in place. Raises ``CorruptRecord``."""
    usa_offset, usa_count = struct.unpack_from("<HH", buf, 4)
    if usa_count < 2 or (usa_count - 1) * SECTOR != len(buf):
        raise CorruptRecord(
            f"update sequence count {usa_count} does not fit a {len(buf)}-byte record"
        )
    if usa_offset + 2 * usa_count > SECTOR - 2:
        raise CorruptRecord(f"update sequence array offset {usa_offset:#x} out of range")
    usn = bytes(buf[usa_offset : usa_offset + 2])
    for i in range(1, usa_count):
        end = i * SECTOR
        if buf[end - 2 : end] != usn:
            raise CorruptRecord(f"fixup mismatch in sector {i - 1} (torn write?)")
        buf[end - 2 : end] = buf[usa_offset + 2 * i : usa_offset + 2 * i + 2]


def _split_reference(ref: int) -> tuple[int, int]:
    return ref & 0xFFFF_FFFF_FFFF, ref >> 48


def _attributes(buf: bytearray, first: int, used: int) -> Iterator[tuple[int, int, int]]:
    """Yield ``(type, offset, length)`` for each attribute in a record."""
    offset = first
    while offset + 4 <= used:
        (attr_type,) = struct.unpack_from("<I", buf, offset)
        if attr_type == END_MARKER:
            return
        if offset + 0x18 > used:
            raise CorruptRecord(f"attribute header at {offset:#x} runs past the record")
        (length,) = struct.unpack_from("<I", buf, offset + 4)
        if length < 0x18 or offset + length > used:
            raise CorruptRecord(f"attribute {attr_type:#x} at {offset:#x} has bad length {length}")
        yield attr_type, offset, length
        offset += length
    raise CorruptRecord("attribute list has no end marker")


def _resident(buf: bytearray, offset: int, length: int) -> bytes:
    if buf[offset + 8]:
        raise CorruptRecord(f"attribute at {offset:#x} is unexpectedly non-resident")
    size, content = struct.unpack_from("<IH", buf, offset + 0x10)
    if content + size > length:
        raise CorruptRecord(f"attribute at {offset:#x} content runs past its end")
    return bytes(buf[offset + content : offset + content + size])


def _file_name(content: bytes) -> FileName:
    if len(content) < 66:
        raise CorruptRecord(f"$FILE_NAME too short ({len(content)} bytes)")
    parent_ref, c, m, e, a = struct.unpack_from("<5Q", content, 0)
    (real_size,) = struct.unpack_from("<Q", content, 48)
    name_length, namespace = content[64], content[65]
    raw = content[66 : 66 + 2 * name_length]
    if len(raw) != 2 * name_length:
        raise CorruptRecord("$FILE_NAME name runs past the attribute")
    parent_entry, parent_sequence = _split_reference(parent_ref)
    return FileName(
        parent_entry=parent_entry,
        parent_sequence=parent_sequence,
        times=(c, m, e, a),
        namespace=namespace,
        name=raw.decode("utf-16-le", errors="backslashreplace"),
        real_size=real_size,
    )


def parse_record(raw: bytes, entry: int) -> Record | None:
    """Parse one MFT record. Returns ``None`` for an empty (zero-filled) slot."""
    if raw[:4] != SIGNATURE:
        if not raw.strip(b"\x00"):
            return None
        if raw[:4] == b"BAAD":
            raise CorruptRecord("record marked BAAD (failed fixup during chkdsk)")
        raise CorruptRecord(f"bad signature {bytes(raw[:4])!r}")
    buf = bytearray(raw)
    apply_fixups(buf)
    sequence, _links, first, flags, used = struct.unpack_from("<HHHHI", buf, 0x10)
    (base_reference,) = struct.unpack_from("<Q", buf, 0x20)
    if used > len(buf) or first >= used:
        raise CorruptRecord(f"bad header (first attribute {first:#x}, used size {used})")

    si_times: tuple[int, int, int, int] | None = None
    names: list[FileName] = []
    data_size: int | None = None
    for attr_type, offset, length in _attributes(buf, first, used):
        if attr_type == STANDARD_INFORMATION:
            content = _resident(buf, offset, length)
            if len(content) < 32:
                raise CorruptRecord(f"$STANDARD_INFORMATION too short ({len(content)} bytes)")
            si_times = struct.unpack_from("<4Q", content, 0)
        elif attr_type == FILE_NAME:
            names.append(_file_name(_resident(buf, offset, length)))
        elif attr_type == DATA and buf[offset + 9] == 0 and data_size is None:
            if buf[offset + 8]:  # non-resident: real size is in the header of the first extent
                if length < 0x40:
                    raise CorruptRecord(f"non-resident $DATA at {offset:#x} too short")
                (start_vcn,) = struct.unpack_from("<Q", buf, offset + 0x10)
                if start_vcn == 0:
                    (data_size,) = struct.unpack_from("<Q", buf, offset + 0x30)
            else:
                (data_size,) = struct.unpack_from("<I", buf, offset + 0x10)
    return Record(entry, sequence, flags, base_reference, si_times, tuple(names), data_size)


def _record_size(path: Path) -> int | None:
    try:
        with open(path, "rb") as fh:
            header = fh.read(0x20)
    except OSError:
        return None
    if len(header) < 0x20 or header[:4] != SIGNATURE:
        return None
    (allocated,) = struct.unpack_from("<I", header, 0x1C)
    return allocated if allocated in RECORD_SIZES else None


def _iter_raw(path: Path, record_size: int) -> Iterator[tuple[int, bytes]]:
    with open(path, "rb") as fh:
        entry = 0
        while True:
            raw = fh.read(record_size)
            if not raw:
                return
            yield entry, raw
            entry += 1


def _zero_fraction(values: list[int]) -> bool:
    return bool(values) and all(v % FILETIME_PER_SECOND == 0 for v in values)


class _PathResolver:
    """Rebuilds full paths from ``$FILE_NAME`` parent references, with cycle protection."""

    def __init__(self, records: dict[int, tuple[int, bool, FileName]]) -> None:
        self.records = records  # entry -> (sequence, in_use, primary name)
        self.cache: dict[tuple[int, int], str] = {}

    def _matches(self, entry: int, sequence: int) -> bool:
        seq, in_use, _ = self.records[entry]
        # Deleting an entry bumps its sequence number, so a deleted parent may be one ahead.
        return sequence == 0 or seq == sequence or (not in_use and seq == sequence + 1)

    def directory(self, entry: int, sequence: int) -> str:
        chain: list[tuple[tuple[int, int], str]] = []
        seen: set[int] = set()
        key = (entry, sequence)
        while True:
            if key in self.cache:
                base = self.cache[key]
                break
            e, s = key
            if e == ROOT_ENTRY:
                base = ""
                break
            if e in seen or e not in self.records or not self._matches(e, s):
                base = ORPHAN_DIR
                break
            seen.add(e)
            name = self.records[e][2]
            chain.append((key, name.name))
            key = (name.parent_entry, name.parent_sequence)
        for key, name in reversed(chain):
            base = f"{base}/{name}"
            self.cache[key] = base
        return base

    def full_path(self, name: FileName, entry: int) -> str:
        if entry == ROOT_ENTRY:
            return "/"
        return f"{self.directory(name.parent_entry, name.parent_sequence)}/{name.name}"


class MftParser(Parser):
    name = ARTIFACT
    description = "NTFS master file table ($MFT): SI and FN times, timestomp indicators"

    def can_parse(self, path: Path) -> bool:
        if not path.is_file():
            return False
        return path.name.upper() == "$MFT" or _record_size(path) is not None

    def _names(self, path: Path, record_size: int) -> dict[int, tuple[int, bool, FileName]]:
        """First pass: just the primary name of every base record, for path building."""
        names: dict[int, tuple[int, bool, FileName]] = {}
        for entry, raw in _iter_raw(path, record_size):
            if len(raw) != record_size:
                continue
            try:
                record = parse_record(raw, entry)
            except (CorruptRecord, struct.error):
                continue  # reported in the second pass
            if record is None or record.base_reference:
                continue
            primary = record.primary_name
            if primary is not None:
                names[entry] = (record.sequence, record.in_use, primary)
        return names

    def parse(self, path: Path, ctx: ParseContext) -> Iterator[TimelineEvent]:
        record_size = _record_size(path)
        if record_size is None:
            record_size = RECORD_SIZES[0]
            ctx.warn(f"record 0 has no valid FILE header; assuming {record_size}-byte records")
        resolver = _PathResolver(self._names(path, record_size))
        for entry, raw in _iter_raw(path, record_size):
            if len(raw) != record_size:
                ctx.warn(f"entry {entry}: truncated record ({len(raw)} bytes) skipped")
                continue
            try:
                record = parse_record(raw, entry)
            except (CorruptRecord, struct.error) as exc:
                ctx.warn(f"entry {entry}: skipped ({exc})")
                continue
            if record is None or record.base_reference:
                continue  # empty slot, or an extension record of another entry
            yield from self._events(record, resolver, ctx)

    def _events(
        self, record: Record, resolver: _PathResolver, ctx: ParseContext
    ) -> Iterator[TimelineEvent]:
        primary = record.primary_name
        if primary is not None:
            path = resolver.full_path(primary, record.entry)
        else:
            path = f"{ORPHAN_DIR}/<entry {record.entry}>"
        size = record.data_size
        if size is None and primary is not None and not record.is_directory:
            size = primary.real_size
        state = "in use" if record.in_use else "deleted"
        base: dict[str, Any] = {
            "entry": record.entry,
            "sequence": record.sequence,
            "in_use": record.in_use,
            "deleted": not record.in_use,
            "is_directory": record.is_directory,
            "size": size,
        }
        where = f"{path} ({state}, entry {record.entry}-{record.sequence})"

        if record.si_times is not None:
            si_set = [v for v in record.si_times if v]
            fn_set = [v for v in primary.times if v] if primary else []
            before = primary is not None and 0 < record.si_times[0] < primary.times[0]
            zero = _zero_fraction(si_set) and bool(fn_set) and not _zero_fraction(fn_set)
            indicators = []
            if before:
                indicators.append("SI created before FN created")
            if zero:
                indicators.append("SI times have zero sub-second part")
            message = where + (
                f" [possible timestomp: {'; '.join(indicators)}]" if indicators else ""
            )
            attrs = {**base, "si_created_before_fn": before, "si_zero_fraction": zero}
            yield from self._times("SI", record.si_times, message, path, attrs, record.entry, ctx)

        for fn in record.file_names:
            fn_path = resolver.full_path(fn, record.entry)
            attrs = {
                **base,
                "fn_name": fn.name,
                "namespace": NAMESPACES.get(fn.namespace, str(fn.namespace)),
                "parent_entry": fn.parent_entry,
                "parent_sequence": fn.parent_sequence,
            }
            message = f"{fn_path} ({state}, entry {record.entry}-{record.sequence})"
            yield from self._times("FN", fn.times, message, fn_path, attrs, record.entry, ctx)

    def _times(
        self,
        kind: str,
        values: tuple[int, ...],
        message: str,
        path: str,
        attrs: dict[str, Any],
        entry: int,
        ctx: ParseContext,
    ) -> Iterator[TimelineEvent]:
        for label, value in zip(TIME_LABELS, values, strict=True):
            try:
                ts = from_filetime(value)
            except ValueError:
                ctx.warn(f"entry {entry}: {kind} {label} value {value} out of range")
                continue
            if ts is None:
                continue
            yield TimelineEvent(
                timestamp=ts,
                timestamp_desc=f"{kind} {label}",
                source="MFT",
                artifact=self.name,
                message=message,
                path=path,
                attributes={**attrs, "filetime": value},  # keeps the 100 ns precision
            )
