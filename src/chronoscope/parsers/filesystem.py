"""File system metadata (MAC/B times) from ``lstat``."""

from __future__ import annotations

import os
import stat
from collections.abc import Iterator
from pathlib import Path

from chronoscope.event import TimelineEvent
from chronoscope.parsers.base import ParseContext, Parser
from chronoscope.timeutil import from_unix_ns


def _kind(mode: int) -> str:
    if stat.S_ISDIR(mode):
        return "directory"
    if stat.S_ISLNK(mode):
        return "symlink"
    if stat.S_ISREG(mode):
        return "file"
    return "other"


def _birth_ns(st: os.stat_result) -> int | None:
    ns = getattr(st, "st_birthtime_ns", None)
    if ns is not None:
        return ns
    birth = getattr(st, "st_birthtime", None)
    if birth is not None:
        return int(birth * 1_000_000_000)
    if os.name == "nt":  # before Python 3.12, st_ctime is the creation time on Windows
        return st.st_ctime_ns
    return None


class FilesystemParser(Parser):
    name = "filesystem"
    description = "File and directory timestamps (modified, accessed, changed, born) via lstat"

    def can_parse(self, path: Path) -> bool:
        return path.exists() or path.is_symlink()

    def parse(self, path: Path, ctx: ParseContext) -> Iterator[TimelineEvent]:
        st = os.lstat(path)
        kind = _kind(st.st_mode)
        times = [
            ("Content Modification Time", st.st_mtime_ns),
            ("Last Access Time", st.st_atime_ns),
        ]
        if os.name != "nt":  # on Windows st_ctime is not the metadata change time
            times.append(("Metadata Change Time", st.st_ctime_ns))
        birth = _birth_ns(st)
        if birth is not None:
            times.append(("Creation Time", birth))

        for desc, ns in times:
            ts = from_unix_ns(ns)
            if ts is None:
                continue
            yield TimelineEvent(
                timestamp=ts,
                timestamp_desc=desc,
                source="FILE",
                artifact=self.name,
                message=f"{ctx.relpath} ({kind}, {st.st_size} bytes)",
                path=ctx.relpath,
                attributes={
                    "kind": kind,
                    "size": st.st_size,
                    "mode": stat.filemode(st.st_mode),
                    "inode": st.st_ino,
                    "timestamp_ns": ns,
                },
            )
