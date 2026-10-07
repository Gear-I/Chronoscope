"""Sleuth Kit body files (``fls -m``, ``ils -m``, and compatible tools).

Format (TSK 3.x): ``MD5|name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|crtime``
with times as POSIX seconds in UTC; 0 means "not set".
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from chronoscope.event import TimelineEvent
from chronoscope.parsers.base import ParseContext, Parser
from chronoscope.timeutil import from_unix_seconds

TIME_FIELDS = (
    ("atime", "Last Access Time"),
    ("mtime", "Content Modification Time"),
    ("ctime", "Metadata Change Time"),
    ("crtime", "Creation Time"),
)


def _split(line: str) -> dict[str, str] | None:
    # The name may itself contain '|', so peel fixed fields off both ends.
    head, sep, rest = line.partition("|")
    if not sep:
        return None
    parts = rest.rsplit("|", 9)
    if len(parts) != 10:
        return None
    keys = ("name", "inode", "mode", "uid", "gid", "size", "atime", "mtime", "ctime", "crtime")
    record = dict(zip(keys, parts, strict=True))
    record["md5"] = head
    return record


class BodyfileParser(Parser):
    name = "bodyfile"
    description = "Sleuth Kit body file (fls -m / mactime input)"

    def can_parse(self, path: Path) -> bool:
        if path.suffix.lower() in (".body", ".bodyfile"):
            return path.is_file()
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                first = fh.readline(65536).rstrip("\r\n")
        except OSError:
            return False
        record = _split(first)
        return record is not None and all(
            record[k].replace(".", "", 1).isdigit() for k, _ in TIME_FIELDS
        )

    def parse(self, path: Path, ctx: ParseContext) -> Iterator[TimelineEvent]:
        with open(path, encoding="utf-8", errors="backslashreplace", newline="") as fh:
            for lineno, raw in enumerate(fh, 1):
                line = raw.rstrip("\r\n")
                if not line:
                    continue
                record = _split(line)
                if record is None:
                    ctx.warn(f"line {lineno}: malformed body file record skipped")
                    continue
                attrs = {
                    "inode": record["inode"],
                    "mode": record["mode"],
                    "uid": record["uid"],
                    "gid": record["gid"],
                    "size": int(record["size"]) if record["size"].isdigit() else record["size"],
                    "line": lineno,
                }
                if record["md5"] not in ("", "0"):
                    attrs["md5"] = record["md5"]
                for key, desc in TIME_FIELDS:
                    try:
                        ts = from_unix_seconds(record[key])
                    except ValueError:
                        ctx.warn(f"line {lineno}: bad {key} value {record[key]!r}")
                        continue
                    if ts is None:
                        continue
                    yield TimelineEvent(
                        timestamp=ts,
                        timestamp_desc=desc,
                        source="FILE",
                        artifact=self.name,
                        message=f"{record['name']} ({record['mode']})",
                        path=record["name"],
                        attributes=attrs,
                    )
