"""Compare a Chronoscope timeline with plaso's output for the same evidence.

Usage::

    log2timeline.py --storage-file case.plaso EVIDENCE
    psort.py -o json_line -w plaso.jsonl case.plaso
    chronoscope export CASE -f jsonl -o timeline.jsonl
    python tools/compare_plaso.py timeline.jsonl plaso.jsonl --out diffs.csv

Every artifact Chronoscope parses is mapped to the plaso events for the same thing:

- chromium_history: chrome:history:page_visited and file_downloaded, on URL / target path
- firefox_history: firefox:places:page_visited and bookmark, on URL
- evtx: windows:evtx:record "Creation Time", on log file name and record number
- mft: fs:stat:ntfs attribute types 0x10 and 0x30, on entry, sequence (+ parent, name)
- bodyfile: fs:bodyfile:entry, on file name
- filesystem: fs:stat, on the path relative to the source (see --strip-prefix)

Within each (artifact, key, time description) group the times are matched exactly, at the
coarser precision of the two tools (100 ns for FILETIME sources, microseconds for browsers).
Unmatched times are reported as "time differs" when both tools have one left over, otherwise
as present in only one tool. Plaso events with no Chronoscope counterpart (other parsers, the
EVTX written time, Firefox bookmark folders, ...) are counted as not compared.

Known, expected differences: plaso emits a Firefox bookmark modification time even when it
equals the added time (Chronoscope does not, so such plaso events are dropped here), and
last-access times in ``filesystem`` change whenever a tool reads the files, so compare those
on a read-only source.

Exit status: 0 when nothing differs, 1 when there are differences, 2 on bad input.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter, defaultdict
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
FILETIME_UNIX_OFFSET = 116_444_736_000_000_000  # 100 ns ticks from 1601 to 1970
WEBKIT_UNIX_OFFSET = 11_644_473_600_000_000  # microseconds from 1601 to 1970
NS = 1
US = 1_000
MS = 1_000_000
SECOND = 1_000_000_000

FS_TIMES = {
    "Content Modification Time": "mtime",
    "Last Access Time": "atime",
    "Metadata Change Time": "ctime",  # Chronoscope
    "Metadata Modification Time": "ctime",  # plaso
    "Creation Time": "crtime",
}
MFT_TIMES = {  # plaso description -> Chronoscope label
    "Creation Time": "Created",
    "Content Modification Time": "Modified",
    "Metadata Modification Time": "Entry Modified",
    "Last Access Time": "Accessed",
}
ARTIFACTS = ("chromium_history", "firefox_history", "evtx", "mft", "bodyfile", "filesystem")


class InputError(Exception):
    pass


@dataclass(frozen=True)
class Stamp:
    """Nanoseconds since 1970 (UTC) and the unit the source actually records."""

    ns: int
    unit: int


@dataclass(frozen=True)
class Event:
    artifact: str
    key: tuple[Any, ...]
    desc: str
    stamp: Stamp


def file_path(text: str | None, strip_prefix: str = "") -> str:
    """Normalise a path for matching: forward slashes, no leading slash or prefix."""
    path = (text or "").replace("\\", "/")
    prefix = strip_prefix.replace("\\", "/").strip("/")
    path = path.lstrip("/")
    if prefix and (path == prefix or path.startswith(prefix + "/")):
        path = path[len(prefix) :].lstrip("/")
    return path


def base_name(text: str | None) -> str:
    return file_path(text).rsplit("/", 1)[-1].lower()


def format_ns(ns: int) -> str:
    seconds, rest = divmod(ns, SECOND)
    stamp = UNIX_EPOCH + timedelta(seconds=seconds)
    return f"{stamp:%Y-%m-%dT%H:%M:%S}.{rest:09d}Z"


# -- Chronoscope side ------------------------------------------------------------------


def _our_stamp(row: dict[str, Any]) -> Stamp:
    attrs = row["attributes"]
    if row["artifact"] == "mft" and "filetime" in attrs:
        return Stamp((attrs["filetime"] - FILETIME_UNIX_OFFSET) * 100, 100)
    if row["artifact"] == "filesystem" and "timestamp_ns" in attrs:
        return Stamp(attrs["timestamp_ns"], NS)
    return Stamp(row["timestamp"] * US, US)


def our_event(row: dict[str, Any]) -> Event | None:
    artifact, desc, attrs = row["artifact"], row["timestamp_desc"], row["attributes"]
    key: tuple[Any, ...]
    if artifact in ("chromium_history", "firefox_history"):
        if desc == "Page Visited":
            key, label = ("visit", attrs.get("url")), "visit"
        elif desc in ("Download Started", "Download Finished"):
            key, label = ("download", attrs.get("target_path")), desc
        elif desc in ("Bookmark Added", "Bookmark Modified"):
            key, label = ("bookmark", attrs.get("url")), desc
        else:
            return None
    elif artifact == "evtx":
        key, label = (base_name(row["path"]), int(attrs["record_number"])), "logged"
    elif artifact == "mft":
        kind, _, label = desc.partition(" ")
        if kind == "SI":
            key = (attrs["entry"], attrs["sequence"], "SI")
        else:
            key = (attrs["entry"], attrs["sequence"], "FN", attrs["parent_entry"], attrs["fn_name"])
    elif artifact == "bodyfile":
        key, label = (row["path"],), FS_TIMES.get(desc, desc)
    elif artifact == "filesystem":
        key, label = (file_path(row["path"]),), FS_TIMES.get(desc, desc)
    else:
        return None
    return Event(artifact, key, label, _our_stamp(row))


def load_chronoscope(path, evidence: str | None, artifacts: set[str]) -> list[Event]:
    events, labels = [], set()
    for row in _json_lines(path):
        if row.get("artifact") not in artifacts:
            continue
        labels.add(row.get("evidence"))
        if evidence is not None and row.get("evidence") != evidence:
            continue
        event = our_event(row)
        if event is not None:
            events.append(event)
    if evidence is None and len(labels) > 1:
        raise InputError(
            f"{path} has events from several evidence labels ({', '.join(sorted(labels))}); "
            "choose one with --evidence"
        )
    return events


# -- plaso side ------------------------------------------------------------------------


def plaso_stamp(row: dict[str, Any]) -> Stamp:
    """Use the original value from ``date_time`` where we know its class, else ``timestamp``."""
    dt = row.get("date_time") or {}
    value = dt.get("timestamp")
    kind = dt.get("__class_name__")
    if isinstance(value, int) and not dt.get("is_local_time"):
        if kind == "Filetime":
            return Stamp((value - FILETIME_UNIX_OFFSET) * 100, 100)
        if kind == "WebKitTime":
            return Stamp((value - WEBKIT_UNIX_OFFSET) * US, US)
        if kind == "PosixTimeInMicroseconds":
            return Stamp(value * US, US)
        if kind == "PosixTimeInNanoseconds":
            return Stamp(value, NS)
        if kind == "PosixTimeInMilliseconds":
            return Stamp(value * MS, MS)
        if kind == "PosixTime":
            return Stamp(value * SECOND, SECOND)
    return Stamp(int(row["timestamp"]) * US, US)


def _reference(value: Any) -> tuple[int, int]:
    value = int(value)
    return value & 0xFFFF_FFFF_FFFF, value >> 48


def plaso_event(row: dict[str, Any], strip_prefix: str) -> Event | None:
    data_type, desc = row.get("data_type", ""), row.get("timestamp_desc", "")
    key: tuple[Any, ...]
    if data_type in ("chrome:history:page_visited", "firefox:places:page_visited"):
        if desc != "Last Visited Time":
            return None
        artifact = "chromium_history" if data_type.startswith("chrome") else "firefox_history"
        key, label = ("visit", row.get("url")), "visit"
    elif data_type == "chrome:history:file_downloaded":
        label = {"Start Time": "Download Started", "End Time": "Download Finished"}.get(desc)
        if label is None:
            return None
        artifact, key = "chromium_history", ("download", row.get("full_path"))
    elif data_type == "firefox:places:bookmark":
        label = {"Added Time": "Bookmark Added", "Content Modification Time": "Bookmark Modified"}
        label = label.get(desc)
        if label is None:
            return None
        artifact, key = "firefox_history", ("bookmark", row.get("url"))
    elif data_type == "windows:evtx:record":
        if desc != "Creation Time":
            return None  # the written time has no Chronoscope counterpart
        artifact, label = "evtx", "logged"
        key = (base_name(row.get("filename") or row.get("display_name")), int(row["record_number"]))
    elif data_type == "fs:stat:ntfs":
        label = MFT_TIMES.get(desc)
        attribute = row.get("attribute_type")
        if label is None or attribute not in (0x10, 0x30) or row.get("file_reference") is None:
            return None
        artifact = "mft"
        entry, sequence = _reference(row["file_reference"])
        if attribute == 0x10:
            key = (entry, sequence, "SI")
        else:
            parent, _ = _reference(row.get("parent_file_reference") or 0)
            key = (entry, sequence, "FN", parent, row.get("name"))
    elif data_type == "fs:bodyfile:entry":
        label = FS_TIMES.get(desc)
        if label is None:
            return None
        artifact, key = "bodyfile", (row.get("filename"),)
    elif data_type == "fs:stat":
        label = FS_TIMES.get(desc)
        if label is None:
            return None
        artifact, key = "filesystem", (file_path(row.get("filename"), strip_prefix),)
    else:
        return None
    return Event(artifact, key, label, plaso_stamp(row))


def load_plaso(path, artifacts: set[str], strip_prefix: str) -> tuple[list[Event], Counter[str]]:
    events: list[Event] = []
    skipped: Counter[str] = Counter()
    for row in _json_lines(path):
        if row.get("__container_type__") not in (None, "event"):
            continue
        if row.get("timestamp_desc") == "Not a time" or not row.get("timestamp"):
            continue
        try:
            event = plaso_event(row, strip_prefix)
        except (KeyError, TypeError, ValueError) as exc:
            raise InputError(f"{path}: unexpected {row.get('data_type')} event ({exc})") from exc
        if event is None:
            skipped[f"{row.get('data_type')}: {row.get('timestamp_desc')}"] += 1
        elif event.artifact in artifacts:
            events.append(event)
    return _drop_plaso_bookmark_echoes(events, skipped), skipped


def _drop_plaso_bookmark_echoes(events: list[Event], skipped: Counter[str]) -> list[Event]:
    """Plaso reports a bookmark's modification time even when it equals the added time."""
    added = {(e.key, e.stamp.ns) for e in events if e.desc == "Bookmark Added"}
    kept = []
    for e in events:
        if e.desc == "Bookmark Modified" and (e.key, e.stamp.ns) in added:
            skipped["firefox:places:bookmark: modification time equal to added time"] += 1
        else:
            kept.append(e)
    return kept


def _json_lines(path) -> Iterator[dict[str, Any]]:
    with open(path, encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            if not line.strip():
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as exc:
                raise InputError(f"{path}:{lineno}: not JSON Lines ({exc})") from exc


# -- comparison ------------------------------------------------------------------------


@dataclass(frozen=True)
class Difference:
    category: str
    artifact: str
    key: str
    desc: str
    chronoscope: str
    plaso: str


@dataclass
class ArtifactStats:
    chronoscope: int = 0
    plaso: int = 0
    matched: int = 0


@dataclass
class Report:
    stats: dict[str, ArtifactStats] = field(default_factory=lambda: defaultdict(ArtifactStats))
    differences: list[Difference] = field(default_factory=list)
    not_compared: Counter[str] = field(default_factory=Counter)


def _key_text(key: tuple[Any, ...]) -> str:
    return " | ".join(str(part) for part in key)


def compare(ours: list[Event], theirs: list[Event]) -> Report:
    report = Report()
    groups: dict[tuple, tuple[list[Stamp], list[Stamp]]] = defaultdict(lambda: ([], []))
    for side, events in ((0, ours), (1, theirs)):
        for e in events:
            groups[(e.artifact, e.key, e.desc)][side].append(e.stamp)
            stats = report.stats[e.artifact]
            if side == 0:
                stats.chronoscope += 1
            else:
                stats.plaso += 1

    for (artifact, key, desc), (a, b) in sorted(groups.items(), key=lambda g: repr(g[0])):
        unit = max(s.unit for s in (*a, *b))
        left = Counter(s.ns // unit for s in a)
        right = Counter(s.ns // unit for s in b)
        common = left & right
        report.stats[artifact].matched += sum(common.values())
        only_a = sorted((left - common).elements())
        only_b = sorted((right - common).elements())
        paired = min(len(only_a), len(only_b))
        for x, y in zip(only_a[:paired], only_b[:paired], strict=True):
            report.differences.append(
                Difference(
                    "time differs",
                    artifact,
                    _key_text(key),
                    desc,
                    format_ns(x * unit),
                    format_ns(y * unit),
                )
            )
        for x in only_a[paired:]:
            report.differences.append(
                Difference(
                    "only in chronoscope", artifact, _key_text(key), desc, format_ns(x * unit), ""
                )
            )
        for y in only_b[paired:]:
            report.differences.append(
                Difference("only in plaso", artifact, _key_text(key), desc, "", format_ns(y * unit))
            )
    return report


def write_differences(report: Report, out) -> None:
    with open(out, "w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["category", "artifact", "key", "desc", "chronoscope", "plaso"])
        for d in report.differences:
            writer.writerow([d.category, d.artifact, d.key, d.desc, d.chronoscope, d.plaso])


def summary(report: Report) -> str:
    header = f"{'artifact':<18} {'chronoscope':>12} {'plaso':>10} {'matched':>10}"
    lines = [header, "-" * len(header)]
    for artifact in sorted(report.stats):
        s = report.stats[artifact]
        lines.append(f"{artifact:<18} {s.chronoscope:>12,} {s.plaso:>10,} {s.matched:>10,}")
    lines.append(f"Differences: {len(report.differences):,}")
    by_kind = Counter((d.artifact, d.category) for d in report.differences)
    for (artifact, category), count in sorted(by_kind.items()):
        lines.append(f"  {artifact:<18} {category:<22} {count:,}")
    if report.not_compared:
        lines.append("Plaso events not compared (no Chronoscope counterpart), top 10:")
        for name, count in report.not_compared.most_common(10):
            lines.append(f"  {count:>10,}  {name}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("chronoscope_jsonl", help="chronoscope export -f jsonl")
    parser.add_argument("plaso_jsonl", help="psort.py -o json_line")
    parser.add_argument("--evidence", help="evidence label to use if the export has several")
    parser.add_argument(
        "--artifact",
        action="append",
        choices=ARTIFACTS,
        help="compare only these Chronoscope artifacts (repeatable; default: all)",
    )
    parser.add_argument(
        "--strip-prefix",
        default="",
        help="leading path to remove from plaso fs:stat file names before matching",
    )
    parser.add_argument("--out", help="write every difference to this CSV file")
    args = parser.parse_args(argv)
    artifacts = set(args.artifact or ARTIFACTS)
    try:
        ours = load_chronoscope(args.chronoscope_jsonl, args.evidence, artifacts)
        theirs, skipped = load_plaso(args.plaso_jsonl, artifacts, args.strip_prefix)
    except (InputError, OSError, KeyError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    report = compare(ours, theirs)
    report.not_compared = skipped
    print(summary(report))
    if args.out:
        write_differences(report, args.out)
        print(f"Differences written to {args.out}")
    return 1 if report.differences else 0


if __name__ == "__main__":
    sys.exit(main())
