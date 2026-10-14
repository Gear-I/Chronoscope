"""Parsers for containers: zip, tar and 7z archives, disk images, and Cellebrite UFED.

Each parser records the timestamps of every file inside the container (see
``chronoscope.containers`` for where they come from). Artifacts *inside* a container, such as
a browser database in a phone extraction or ``$MFT`` in an NTFS image, are parsed by the
ingest, which streams the members through the other parsers.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable, Iterator
from pathlib import Path, PurePosixPath
from typing import ClassVar

from chronoscope.containers import (
    ContainerError,
    Member,
    container_kind,
    open_container,
    segments,
    ufd_targets,
)
from chronoscope.event import TimelineEvent
from chronoscope.parsers.base import ParseContext, Parser

UFD_SUFFIX = ".ufd"
#: Member events are labelled by container format, whichever parser reached the container,
#: so a zip ingested directly and through its .ufd gives identical (de-duplicated) events.
ARTIFACT_BY_KIND = {
    "zip": "zip",
    "tar": "tar",
    "7z": "7z",
    "ewf": "disk_image",
    "raw": "disk_image",
}


def container_relpath(evidence_relpath: str, evidence: Path, container: Path) -> str:
    """Where a container sits, relative to the evidence root (siblings of the ingested file)."""
    if container == evidence:
        return evidence_relpath
    return (PurePosixPath(evidence_relpath).parent / container.name).as_posix()


class ContainerParser(Parser):
    #: Container kinds (see ``container_kind``) this parser handles.
    kinds: ClassVar[tuple[str, ...]] = ()

    def can_parse(self, path: Path) -> bool:
        try:
            return container_kind(path) in self.kinds
        except OSError:
            return False

    def can_parse_head(self, name: str, head: bytes) -> bool:
        return False  # containers inside containers are not opened

    def containers(self, path: Path) -> list[tuple[Path, str]]:
        """The containers an evidence file stands for, as (path, kind)."""
        kind = container_kind(path)
        return [(path, kind)] if kind in self.kinds else []

    def related_files(self, path: Path) -> list[Path]:
        files: list[Path] = []
        for container, kind in self.containers(path):
            files += [p for p in segments(container, kind) if p != path and p not in files]
        return files

    def parse(self, path: Path, ctx: ParseContext) -> Iterator[TimelineEvent]:
        targets = self.containers(path)
        if not targets:
            ctx.warn("no readable container found")
            return
        for container, kind in targets:
            relpath = container_relpath(ctx.relpath, path, container)
            # ctx.warn already names the ingested file; name the container only if it differs.
            label = "" if container == path else f"{relpath}: "

            def warn(message: str, label: str = label) -> None:
                ctx.warn(label + message)

            try:
                with open_container(container, kind, warn) as c:
                    artifact = ARTIFACT_BY_KIND[kind]
                    yield from self._events(c.members(), relpath, container.name, artifact, warn)
            except ContainerError as exc:
                warn(str(exc))

    def _events(
        self,
        members: Iterator[Member],
        relpath: str,
        container_name: str,
        artifact: str,
        warn: Callable[[str], None],
    ) -> Iterator[TimelineEvent]:
        without_time: Counter[str] = Counter()
        for member in members:
            if not member.times:
                if member.no_time_reason:
                    without_time[member.no_time_reason] += 1
                continue
            attrs = {
                "container": relpath,
                "member": member.path,
                "is_dir": member.is_dir,
                "size": member.size,
                "time_source": member.time_source,
                **member.attributes,
            }
            kind = "dir" if member.is_dir else f"{member.size} bytes"
            deleted = ", deleted" if member.attributes.get("deleted") else ""
            for desc, stamp in member.times:
                yield TimelineEvent(
                    timestamp=stamp,
                    timestamp_desc=desc,
                    source="FILE",
                    artifact=artifact,
                    message=f"{member.path} ({kind}{deleted}, in {container_name})",
                    path=f"{relpath}/{member.path}",
                    attributes=attrs,
                )
        for reason, count in sorted(without_time.items()):
            warn(f"{count} member(s) have no usable timestamps ({reason})")


class ZipParser(ContainerParser):
    name = "zip"
    description = "Zip archives: each member's times from the zip's UTC extra fields"
    kinds = ("zip",)


class TarParser(ContainerParser):
    name = "tar"
    description = "Tar archives (.tar, .tar.gz, .tar.bz2, .tar.xz): member times"
    kinds = ("tar",)


class SevenZipParser(ContainerParser):
    name = "7z"
    description = "7z archives: member times"
    kinds = ("7z",)

    @classmethod
    def unavailable_reason(cls) -> str | None:
        try:
            import py7zr  # noqa: F401
        except ImportError:
            return "py7zr is not installed (pip install 'chronoscope-forensics[archives]')"
        return None


class DiskImageParser(ContainerParser):
    name = "disk_image"
    description = "Disk images (E01/Ex01, raw .dd/.img/.raw/.001): file system walk via TSK"
    kinds = ("ewf", "raw")

    @classmethod
    def unavailable_reason(cls) -> str | None:
        try:
            import pyewf  # noqa: F401
            import pytsk3  # noqa: F401
        except ImportError:
            return (
                "pytsk3 and libewf-python are not installed "
                "(pip install 'chronoscope-forensics[images]')"
            )
        return None


class UfedParser(ContainerParser):
    name = "ufed"
    description = "Cellebrite UFED extraction descriptor (.ufd) and the zip/image it names"
    kinds = ("zip", "tar", "7z", "ewf", "raw")

    def can_parse(self, path: Path) -> bool:
        return path.suffix.lower() == UFD_SUFFIX and path.is_file()

    def containers(self, path: Path) -> list[tuple[Path, str]]:
        try:
            return ufd_targets(path)
        except OSError:
            return []

    def related_files(self, path: Path) -> list[Path]:
        return super().related_files(path)


#: Container parsers whose formats are opened when the ingest expands members.
CONTAINER_PARSERS: tuple[type[ContainerParser], ...] = (
    ZipParser,
    TarParser,
    SevenZipParser,
    DiskImageParser,
    UfedParser,
)
