"""Read-only access to files inside archives and disk images.

A *container* lists its members with their own timestamps (``members()``) and streams member
contents in storage order (``stream()``). Streaming in order matters: 7z and compressed tar
archives can only be decompressed front to back, and reading disk images sequentially is
fastest. Supported:

* ``zip``: zip archives (times from the NTFS, UT and UX extra fields; never the DOS time).
* ``tar``: ``.tar``, ``.tar.gz``/``.tgz``, ``.tar.bz2``/``.tbz2``, ``.tar.xz``/``.txz``.
* ``7z``: needs ``py7zr`` (``pip install 'chronoscope-forensics[archives]'``).
* ``ewf``: EnCase images (``.E01``/``.Ex01`` and their segments), via ``libewf-python``.
* ``raw``: raw disk or partition images (``.dd``, ``.img``, ``.raw``, split ``.001``...).

Disk images need ``pytsk3`` (The Sleuth Kit); ``pip install 'chronoscope-forensics[images]'``
installs it with ``libewf-python``. Every partition with a file system TSK can read is walked,
including deleted entries. Only allocated files have their contents scanned for artifacts;
deleted entries get timestamps only, because their clusters may have been reused.

Timestamps are only ever produced from UTC sources. Zip DOS times and FAT/exFAT times are local
time without a zone, so members that have nothing better get no timestamps, and the parser
reports how many.
"""

from __future__ import annotations

import configparser
import contextlib
import re
import struct
import tarfile
import zipfile
import zlib
from abc import ABC, abstractmethod
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, Protocol

from chronoscope.timeutil import from_filetime, from_unix_ns

MODIFIED = "Content Modification Time"
ACCESSED = "Last Access Time"
CHANGED = "Metadata Change Time"
CREATED = "Creation Time"
#: Info-ZIP's spec calls the third UT time "creation", but Info-ZIP itself stores the Unix
#: inode change time there and other writers differ. The label says so rather than guessing.
UT_CTIME = "Change or Creation Time (zip UT ctime)"

CHUNK = 1024 * 1024
TAR_SUFFIXES = (".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tbz", ".tar.xz", ".txz")
EWF_SUFFIXES = (".e01", ".ex01", ".s01")
RAW_SUFFIXES = (".dd", ".img", ".raw", ".001")
SEVEN_ZIP_MAGIC = b"7z\xbc\xaf\x27\x1c"
EWF_MAGICS = (b"EVF\x09\x0d\x0a\xff\x00", b"EVF2\x0d\x0a\x81\x00", b"LVF\x09\x0d\x0a\xff\x00")
ZIP_NO_TIME = "only the zip's local, zone-less DOS time"
FAT_NO_TIME = "FAT/exFAT times are local time without a zone"

Warn = Callable[[str], None]


class ContainerError(Exception):
    """The container as a whole cannot be read."""


class MissingDependency(ContainerError):
    pass


@dataclass
class Member:
    path: str  # "/"-separated, relative to the container, no leading slash
    is_dir: bool
    size: int
    times: list[tuple[str, datetime]] = field(default_factory=list)
    time_source: str = ""
    readable: bool = True  # a regular file whose contents can be scanned
    no_time_reason: str = ""  # why ``times`` is empty, when it is
    attributes: dict[str, Any] = field(default_factory=dict)


class Sink(Protocol):
    """Receives one member's bytes from ``Container.stream``."""

    wants_more: bool

    def write(self, data: bytes) -> None: ...

    def close(self, ok: bool = True) -> None:
        """End of the member; ``ok`` is False if reading it failed part-way."""


Visitor = Callable[[Member], "Sink | None"]


def _clean(name: str) -> str:
    parts = [p for p in name.replace("\\", "/").split("/") if p not in ("", ".")]
    return "/".join(parts)


class Container(ABC):
    kind: str

    def __init__(self, path: Path, warn: Warn) -> None:
        self.path = path
        self.warn = warn

    @abstractmethod
    def members(self) -> Iterator[Member]:
        """Every member with its metadata; contents are not read."""

    @abstractmethod
    def stream(self, visit: Visitor) -> None:
        """Feed each readable member's bytes to ``visit(member)``'s sink, in storage order.

        A member whose contents cannot be read is reported through ``warn`` and skipped.
        """

    def close(self) -> None:
        return None

    def __enter__(self) -> Container:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def _pump(fh: BinaryIO, sink: Sink) -> None:
    try:
        while sink.wants_more:
            data = fh.read(CHUNK)
            if not data:
                break
            sink.write(data)
    except BaseException:
        sink.close(ok=False)
        raise
    sink.close()


# -- zip -------------------------------------------------------------------------------

NTFS_EXTRA, UT_EXTRA, UX_EXTRA = 0x000A, 0x5455, 0x5855
LOCAL_HEADER = struct.Struct("<IHHHHHIIIHH")
LOCAL_HEADER_SIGNATURE = 0x04034B50
ZIP_READ_ERRORS = (
    RuntimeError,
    NotImplementedError,
    zipfile.BadZipFile,
    zlib.error,
    OSError,
    EOFError,
)


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


def local_extra(fh: BinaryIO, info: zipfile.ZipInfo) -> bytes:
    """The extra field from a member's local header (it has more UT times than the central)."""
    fh.seek(info.header_offset)
    header = fh.read(LOCAL_HEADER.size)
    if len(header) < LOCAL_HEADER.size:
        return b""
    fields = LOCAL_HEADER.unpack(header)
    if fields[0] != LOCAL_HEADER_SIGNATURE:
        return b""
    fh.seek(fields[9], 1)  # file name
    return fh.read(fields[10])


def _posix(value: int) -> datetime | None:
    return datetime.fromtimestamp(value, tz=timezone.utc) if value else None


def zip_member_times(central: bytes, local: bytes) -> tuple[str, list[tuple[str, datetime]]]:
    """(source field, [(description, UTC time)]); NTFS preferred, then UT, then UX."""
    fields = {**_extra_fields(central), **_extra_fields(local)}
    ntfs = fields.get(NTFS_EXTRA)
    if ntfs and len(ntfs) >= 4:
        offset = 4  # reserved
        while offset + 4 <= len(ntfs):
            tag, size = struct.unpack_from("<HH", ntfs, offset)
            if tag == 1 and size >= 24 and offset + 4 + 24 <= len(ntfs):
                mtime, atime, ctime = struct.unpack_from("<3Q", ntfs, offset + 4)
                times = [(MODIFIED, mtime), (ACCESSED, atime), (CREATED, ctime)]
                return "zip NTFS field", [(d, t) for d, v in times if (t := from_filetime(v))]
            offset += 4 + size
    ut = fields.get(UT_EXTRA)
    if ut:
        flags, offset, found = ut[0], 1, []
        for bit, desc in ((1, MODIFIED), (2, ACCESSED), (4, UT_CTIME)):
            if flags & bit and offset + 4 <= len(ut):
                (value,) = struct.unpack_from("<I", ut, offset)
                offset += 4
                if stamp := _posix(value):
                    found.append((desc, stamp))
        if found:
            return "zip UT field", found
    ux = fields.get(UX_EXTRA)
    if ux and len(ux) >= 8:
        atime, mtime = struct.unpack_from("<II", ux, 0)
        found = [(d, t) for d, v in ((MODIFIED, mtime), (ACCESSED, atime)) if (t := _posix(v))]
        if found:
            return "zip UX field", found
    return "", []


class ZipContainer(Container):
    kind = "zip"

    def __init__(self, path: Path, warn: Warn) -> None:
        super().__init__(path, warn)
        try:
            self.zf = zipfile.ZipFile(path)
        except (zipfile.BadZipFile, OSError) as exc:
            raise ContainerError(f"cannot open zip: {exc}") from exc

    def _member(self, info: zipfile.ZipInfo, raw: BinaryIO) -> Member:
        try:
            source, times = zip_member_times(info.extra, local_extra(raw, info))
        except (OSError, struct.error, ValueError) as exc:
            self.warn(f"{info.filename}: unreadable timestamps ({exc})")
            source, times = "", []
        return Member(
            path=_clean(info.filename),
            is_dir=info.is_dir(),
            size=info.file_size,
            times=times,
            time_source=source,
            readable=not info.is_dir(),
            no_time_reason="" if times else ZIP_NO_TIME,
            attributes={
                "compressed_size": info.compress_size,
                "crc32": f"{info.CRC:08x}",
                "dos_time_local": "{:04d}-{:02d}-{:02d} {:02d}:{:02d}:{:02d}".format(
                    *info.date_time
                ),
            },
        )

    def members(self) -> Iterator[Member]:
        with open(self.path, "rb") as raw:
            for info in self.zf.infolist():
                yield self._member(info, raw)

    def stream(self, visit: Visitor) -> None:
        with open(self.path, "rb") as raw:
            for info in self.zf.infolist():
                if info.is_dir():
                    continue
                sink = visit(self._member(info, raw))
                if sink is None:
                    continue
                try:
                    with self.zf.open(info) as fh:
                        _pump(fh, sink)
                except ZIP_READ_ERRORS as exc:
                    self.warn(f"{_clean(info.filename)}: cannot read ({exc})")

    def close(self) -> None:
        self.zf.close()


# -- tar -------------------------------------------------------------------------------


def _pax_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        ns = int(Decimal(value) * 1_000_000_000)
    except (InvalidOperation, ValueError):
        return None
    return from_unix_ns(ns)


class TarContainer(Container):
    kind = "tar"

    def __init__(self, path: Path, warn: Warn) -> None:
        super().__init__(path, warn)
        try:
            self.tf = tarfile.open(path, "r:*")  # noqa: SIM115 (closed in close())
        except (tarfile.TarError, OSError, EOFError) as exc:
            raise ContainerError(f"cannot open tar: {exc}") from exc

    @staticmethod
    def _member(info: tarfile.TarInfo) -> Member:
        pax = info.pax_headers
        times: list[tuple[str, datetime]] = []
        for desc, stamp in (
            (MODIFIED, _pax_time(pax.get("mtime")) or _posix(int(info.mtime))),
            (ACCESSED, _pax_time(pax.get("atime"))),
            (CHANGED, _pax_time(pax.get("ctime"))),
            (CREATED, _pax_time(pax.get("LIBARCHIVE.creationtime"))),
        ):
            if stamp is not None:
                times.append((desc, stamp))
        attrs: dict[str, Any] = {"mode": f"{info.mode:o}", "uid": info.uid, "gid": info.gid}
        if info.issym() or info.islnk():
            attrs["link_target"] = info.linkname
        return Member(
            path=_clean(info.name),
            is_dir=info.isdir(),
            size=info.size,
            times=times,
            time_source="tar header" + (" + pax" if len(times) > 1 else ""),
            readable=info.isfile(),
            no_time_reason="" if times else "tar header has no modification time",
            attributes=attrs,
        )

    def members(self) -> Iterator[Member]:
        try:
            infos = self.tf.getmembers()
        except (tarfile.TarError, OSError, EOFError, zlib.error) as exc:
            self.warn(f"archive truncated or corrupt; stopped listing ({exc})")
            infos = self.tf.members
        for info in infos:
            yield self._member(info)

    def stream(self, visit: Visitor) -> None:
        for info in self.tf.getmembers():
            if not info.isfile():
                continue
            sink = visit(self._member(info))
            if sink is None:
                continue
            try:
                fh = self.tf.extractfile(info)
                if fh is None:
                    sink.close()
                    continue
                with fh:
                    _pump(fh, sink)
            except (tarfile.TarError, OSError, EOFError, zlib.error) as exc:
                self.warn(f"{_clean(info.name)}: cannot read ({exc})")

    def close(self) -> None:
        self.tf.close()


# -- 7z --------------------------------------------------------------------------------


class SevenZipContainer(Container):
    kind = "7z"

    def __init__(self, path: Path, warn: Warn) -> None:
        super().__init__(path, warn)
        try:
            import py7zr
        except ImportError as exc:
            raise MissingDependency(
                "7z needs py7zr (pip install 'chronoscope-forensics[archives]')"
            ) from exc
        self._py7zr = py7zr
        self._open()

    def _open(self) -> None:
        try:
            self.archive = self._py7zr.SevenZipFile(self.path)
        except Exception as exc:  # py7zr raises a variety of its own errors
            raise ContainerError(f"cannot open 7z: {type(exc).__name__}: {exc}") from exc

    def _member(self, entry: Any) -> Member:
        props = entry.file_properties()
        times = []
        for desc, key in (
            (MODIFIED, "lastwritetime"),
            (ACCESSED, "lastaccesstime"),
            (CREATED, "creationtime"),
        ):
            value = props.get(key)
            if value is not None and (stamp := from_filetime(int(value))):
                times.append((desc, stamp))
        is_dir = bool(entry.is_directory)
        return Member(
            path=_clean(entry.filename),
            is_dir=is_dir,
            size=int(entry.uncompressed or 0),
            times=times,
            time_source="7z header",
            readable=not is_dir and not entry.emptystream,
            no_time_reason="" if times else "7z header has no times for this member",
            attributes={"crc32": f"{entry.crc32:08x}" if entry.crc32 is not None else None},
        )

    def members(self) -> Iterator[Member]:
        for entry in self.archive.files:
            yield self._member(entry)

    def stream(self, visit: Visitor) -> None:
        import py7zr.io as pio

        members = {entry.filename: self._member(entry) for entry in self.archive.files}
        warn = self.warn

        class Writer(pio.Py7zIO):
            def __init__(self, sink: Sink | None) -> None:
                self.sink, self.count = sink, 0

            def write(self, data: bytes | bytearray) -> int:
                self.count += len(data)
                if self.sink is not None and self.sink.wants_more:
                    self.sink.write(bytes(data))
                return len(data)

            def read(self, size: int | None = None) -> bytes:
                return b""

            def seek(self, offset: int, whence: int = 0) -> int:
                return offset

            def flush(self) -> None:
                return None

            def size(self) -> int:
                return self.count

            def close(self) -> None:
                if self.sink is not None:
                    self.sink.close()
                    self.sink = None

        class Factory(pio.WriterFactory):
            def __init__(self) -> None:
                self.current: Writer | None = None

            def create(self, filename: str) -> pio.Py7zIO:
                # py7zr before 1.1 never calls Py7zIO.close(), so finish the previous member
                # here; close() is idempotent for versions that do call it.
                if self.current is not None:
                    self.current.close()
                member = members.get(filename)
                sink = visit(member) if member is not None and member.readable else None
                self.current = Writer(sink)
                return self.current

        self.archive.close()
        self._open()  # extract() needs a freshly opened archive
        factory = Factory()
        try:
            self.archive.extract(factory=factory)
        except Exception as exc:  # e.g. a password-protected or damaged archive
            warn(f"stopped reading contents: {type(exc).__name__}: {exc}")
            if factory.current is not None and factory.current.sink is not None:
                factory.current.sink.close(ok=False)
                factory.current.sink = None
        else:
            if factory.current is not None:
                factory.current.close()

    def close(self) -> None:
        self.archive.close()


# -- disk images -----------------------------------------------------------------------

LOCAL_TIME_FILE_SYSTEMS = {2, 4, 8, 10}  # TSK FAT12, FAT16, FAT32, exFAT
FS_NAMES = {1: "NTFS", 2: "FAT12", 4: "FAT16", 8: "FAT32", 10: "exFAT", 128: "ext2", 256: "ext3",
            8192: "ext4", 2048: "ISO9660", 4096: "HFS+", 65536: "APFS"}  # fmt: skip


def ewf_segments(path: Path) -> list[Path]:
    try:
        import pyewf
    except ImportError:
        return [path]
    try:
        return [Path(p) for p in pyewf.glob(str(path))]
    except (OSError, RuntimeError):
        return [path]


def raw_segments(path: Path) -> list[Path]:
    """A split raw image: ``name.001``, ``name.002``... (just ``path`` otherwise)."""
    if path.suffix != ".001":
        return [path]
    segments, number = [], 1
    while (segment := path.with_suffix(f".{number:03d}")).is_file():
        segments.append(segment)
        number += 1
    return segments


class DiskImageContainer(Container):
    kind = "disk"

    def __init__(self, path: Path, warn: Warn, kind: str) -> None:
        super().__init__(path, warn)
        try:
            import pytsk3
        except ImportError as exc:
            raise MissingDependency(
                "disk images need pytsk3 (pip install 'chronoscope-forensics[images]')"
            ) from exc
        self.tsk = pytsk3
        self.kind = kind
        self._handles: list[Any] = []
        self.image = self._open_image(kind)
        self.file_systems = self._file_systems()

    def _open_image(self, kind: str) -> Any:
        tsk = self.tsk

        class ReaderImage(tsk.Img_Info):
            def __init__(self, read: Callable[[int, int], bytes], size: int) -> None:
                self._read, self._size = read, size
                super().__init__(url="", type=tsk.TSK_IMG_TYPE_EXTERNAL)

            def close(self) -> None:
                return None

            def read(self, offset: int, size: int) -> bytes:
                return self._read(offset, size)

            def get_size(self) -> int:
                return self._size

        if kind == "ewf":
            try:
                import pyewf
            except ImportError as exc:
                raise MissingDependency(
                    "E01 images need libewf-python (pip install 'chronoscope-forensics[images]')"
                ) from exc
            handle = pyewf.handle()
            try:
                handle.open([str(p) for p in ewf_segments(self.path)])
            except (OSError, RuntimeError) as exc:
                raise ContainerError(f"cannot open EWF image: {exc}") from exc
            self._handles.append(handle)

            def read_ewf(offset: int, size: int) -> bytes:
                handle.seek(offset)
                return handle.read(size)

            return ReaderImage(read_ewf, handle.get_media_size())

        segments = raw_segments(self.path)
        files = [open(p, "rb") for p in segments]  # noqa: SIM115 (closed in close())
        self._handles.extend(files)
        sizes = [p.stat().st_size for p in segments]

        def read_raw(offset: int, size: int) -> bytes:
            out = bytearray()
            start = 0
            for fh, length in zip(files, sizes, strict=True):
                end = start + length
                if offset < end and size > 0:
                    fh.seek(offset - start)
                    chunk = fh.read(min(size, end - offset))
                    out += chunk
                    offset += len(chunk)
                    size -= len(chunk)
                start = end
            return bytes(out)

        return ReaderImage(read_raw, sum(sizes))

    def _file_systems(self) -> list[tuple[str, Any]]:
        """[(path prefix, FS_Info)] for every readable file system in the image."""
        tsk = self.tsk
        try:
            volumes = tsk.Volume_Info(self.image)
        except OSError:
            volumes = None
        if volumes is None:
            try:
                return [("", tsk.FS_Info(self.image, offset=0))]
            except OSError as exc:
                raise ContainerError("no partition table or file system TSK can read") from exc
        found = []
        block = volumes.info.block_size
        for part in volumes:
            if part.flags != tsk.TSK_VS_PART_FLAG_ALLOC:
                continue
            label = f"partition{part.addr}"
            try:
                found.append((label + "/", tsk.FS_Info(self.image, offset=part.start * block)))
            except OSError:
                desc = part.desc.decode("utf-8", "replace")
                self.warn(f"{label} ({desc}): no file system TSK can read; skipped")
        if not found:
            raise ContainerError("no partition with a file system TSK can read")
        return found

    def _walk(self, fs: Any, prefix: str) -> Iterator[tuple[Member, Any]]:
        tsk = self.tsk
        ftype = int(fs.info.ftype)
        local_time = ftype in LOCAL_TIME_FILE_SYSTEMS
        fs_name = FS_NAMES.get(ftype, f"type {ftype}")
        seen: set[int] = set()
        stack: list[tuple[str, Any]] = [("", fs.open_dir("/"))]
        while stack:
            parent, directory = stack.pop()
            entries = []
            try:
                entries = list(directory)
            except OSError as exc:
                self.warn(f"{prefix}{parent or '/'}: cannot list ({exc})")
            for entry in entries:
                info = entry.info
                name = info.name.name.decode("utf-8", "replace")
                if name in (".", "..") or info.meta is None:
                    continue
                meta = info.meta
                path = f"{parent}/{name}" if parent else name
                allocated = bool(info.name.flags & tsk.TSK_FS_NAME_FLAG_ALLOC) and bool(
                    meta.flags & tsk.TSK_FS_META_FLAG_ALLOC
                )
                virtual = int(meta.type) in (10, 11)  # TSK's $OrphanFiles and similar
                is_dir = int(meta.type) in (
                    int(tsk.TSK_FS_META_TYPE_DIR),
                    int(tsk.TSK_FS_META_TYPE_VIRT_DIR),
                )
                times: list[tuple[str, datetime]] = []
                if not local_time:
                    for desc, attr in (
                        (MODIFIED, "mtime"),
                        (ACCESSED, "atime"),
                        (CHANGED, "ctime"),
                        (CREATED, "crtime"),
                    ):
                        seconds = int(getattr(meta, attr, 0) or 0)
                        if seconds:
                            nano = int(getattr(meta, f"{attr}_nano", 0) or 0)
                            stamp = from_unix_ns(seconds * 1_000_000_000 + nano)
                            if stamp is not None:
                                times.append((desc, stamp))
                member = Member(
                    path=prefix + path,
                    is_dir=is_dir,
                    size=int(meta.size),
                    times=times,
                    time_source=f"{fs_name} (The Sleuth Kit)",
                    readable=allocated and int(meta.type) == int(tsk.TSK_FS_META_TYPE_REG),
                    no_time_reason=(
                        "" if virtual else FAT_NO_TIME if local_time else "no timestamps recorded"
                    ),
                    attributes={
                        "file_system": fs_name,
                        "inode": int(meta.addr),
                        "allocated": allocated,
                        "deleted": not allocated,
                    },
                )
                yield member, entry
                if is_dir and allocated and int(meta.addr) not in seen:
                    seen.add(int(meta.addr))
                    with contextlib.suppress(OSError):  # e.g. an empty or damaged directory
                        stack.append((path, entry.as_directory()))

    def members(self) -> Iterator[Member]:
        for prefix, fs in self.file_systems:
            for member, _ in self._walk(fs, prefix):
                yield member

    def stream(self, visit: Visitor) -> None:
        for prefix, fs in self.file_systems:
            for member, entry in self._walk(fs, prefix):
                if not member.readable:
                    continue
                sink = visit(member)
                if sink is None:
                    continue
                try:
                    offset = 0
                    while sink.wants_more and offset < member.size:
                        data = entry.read_random(offset, min(CHUNK, member.size - offset))
                        if not data:
                            break
                        sink.write(data)
                        offset += len(data)
                except OSError as exc:
                    sink.close(ok=False)
                    self.warn(f"{member.path}: cannot read ({exc})")
                else:
                    sink.close()

    def close(self) -> None:
        for handle in self._handles:
            handle.close()


# -- detection -------------------------------------------------------------------------


def _head(path: Path, size: int = 4096) -> bytes:
    try:
        with open(path, "rb") as fh:
            return fh.read(size)
    except OSError:
        return b""


def _looks_like_disk(head: bytes) -> bool:
    """A partition table or a common boot sector, for raw images with generic suffixes."""
    if len(head) >= 512 and head[510:512] == b"\x55\xaa":
        return True  # MBR or a FAT/NTFS boot sector
    if head[512:520] == b"EFI PART" or head[3:11] == b"NTFS    ":
        return True
    return len(head) >= 1082 and head[1080:1082] == b"\x53\xef"  # ext superblock magic


def container_kind(path: Path) -> str | None:
    """The container format of ``path``, or None. Cheap: a suffix and a few header bytes."""
    if not path.is_file():
        return None
    name = path.name.lower()
    if name.endswith(".zip"):
        return "zip" if zipfile.is_zipfile(path) else None
    if name.endswith(TAR_SUFFIXES):
        try:
            return "tar" if tarfile.is_tarfile(path) else None
        except (OSError, EOFError, tarfile.TarError, zlib.error):
            return None
    head = _head(path)
    if name.endswith(".7z") or head.startswith(SEVEN_ZIP_MAGIC):
        return "7z" if head.startswith(SEVEN_ZIP_MAGIC) else None
    if name.endswith(EWF_SUFFIXES) and head.startswith(EWF_MAGICS):
        return "ewf"
    if name.endswith(RAW_SUFFIXES) and _looks_like_disk(head):
        return "raw"
    return None


def open_container(path: Path, kind: str, warn: Warn) -> Container:
    if kind == "zip":
        return ZipContainer(path, warn)
    if kind == "tar":
        return TarContainer(path, warn)
    if kind == "7z":
        return SevenZipContainer(path, warn)
    if kind in ("ewf", "raw"):
        return DiskImageContainer(path, warn, kind)
    raise ContainerError(f"unknown container kind {kind!r}")


def segments(path: Path, kind: str) -> list[Path]:
    """All files that make up the container (EWF and split raw images have several)."""
    if kind == "ewf":
        return ewf_segments(path)
    if kind == "raw":
        return raw_segments(path)
    return [path]


# -- Cellebrite UFED descriptors -------------------------------------------------------


def ufd_targets(ufd: Path) -> list[tuple[Path, str]]:
    """Containers a ``.ufd`` descriptor names, looked up next to it by file name only.

    Falls back to a supported container with the same stem. Physical extractions are often
    raw ``.bin`` images, so a ``.bin`` named by the descriptor is accepted as a raw image.
    """
    text = ufd.read_text(encoding="utf-8-sig", errors="replace")
    config = configparser.ConfigParser(strict=False, interpolation=None)
    try:
        config.read_string(text)
        values = [v for section in config.sections() for _, v in config.items(section)]
    except configparser.Error:
        values = [m.group(1) for m in re.finditer(r"^[^=;#\n]+=\s*(.+?)\s*$", text, re.M)]
    found: list[tuple[Path, str]] = []
    for value in values:
        name = PurePosixPath(value.strip().strip('"').replace("\\", "/")).name
        if not name:
            continue
        candidate = ufd.with_name(name)
        kind = container_kind(candidate)
        if kind is None and name.lower().endswith(".bin") and _looks_like_disk(_head(candidate)):
            kind = "raw"
        if kind is not None and all(candidate != p for p, _ in found):
            found.append((candidate, kind))
    if not found:
        for sibling in sorted(ufd.parent.glob(ufd.stem + ".*")):
            if sibling != ufd and (kind := container_kind(sibling)):
                found.append((sibling, kind))
                break
    return found
