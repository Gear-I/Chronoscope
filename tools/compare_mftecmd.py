"""Compare Chronoscope's ``mft`` parser output with MFTECmd's CSV for the same ``$MFT``.

Usage::

    MFTECmd.exe -f $MFT --csv out --csvf mftecmd.csv --at
    chronoscope export CASE -f jsonl -o timeline.jsonl
    python tools/compare_mftecmd.py timeline.jsonl out/mftecmd.csv --out diffs.csv

Run MFTECmd with ``--at`` so it writes every ``$FILE_NAME`` time; without it the FN columns
are blank whenever they equal the SI value, and this script then assumes they are equal.
Add ``--sn`` to MFTECmd and ``--include-dos`` here to compare 8.3 short names as well.

Rows are matched on (entry, sequence, parent entry, file name). For each match the script
compares the in-use and directory flags, the full path, the file size, all four SI and FN
timestamps at the precision MFTECmd printed (100 ns by default), and the SI-before-FN
timestomp flag. Times are compared as raw FILETIME ticks, so nothing is lost to rounding.

MFTECmd's ``uSecZeros`` uses a different rule than Chronoscope's ``si_zero_fraction`` (any of
SI created or modified having zero milliseconds, versus all SI times being whole seconds while
FN times are not), so the two are counted side by side rather than reported as mismatches.

Exit status: 0 when nothing differs, 1 when there are differences, 2 on bad input.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from collections import Counter
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

WINDOWS_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
TICKS_PER_SECOND = 10_000_000

#: Chronoscope label -> MFTECmd column stem.
TIMES = (
    ("Created", "Created"),
    ("Modified", "LastModified"),
    ("Entry Modified", "LastRecordChange"),
    ("Accessed", "LastAccess"),
)
REQUIRED_COLUMNS = (
    "EntryNumber",
    "SequenceNumber",
    "InUse",
    "ParentEntryNumber",
    "ParentPath",
    "FileName",
    "FileSize",
    "IsDirectory",
    "IsAds",
    "SI<FN",
    "uSecZeros",
    "NameType",
    *(f"{stem}0x{kind}" for _, stem in TIMES for kind in ("10", "30")),
)
ROOT_ENTRY = 5
_TIMESTAMP = re.compile(
    r"^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})(?:\.(\d{1,7}))?\s*(Z|[+-]00:?00)?$"
)


class InputError(Exception):
    pass


@dataclass(frozen=True)
class Stamp:
    """A FILETIME and the number of fractional digits it is known to (7 = 100 ns)."""

    ticks: int
    digits: int = 7


def parse_mftecmd_time(text: str) -> Stamp | None:
    text = text.strip()
    if not text:
        return None
    match = _TIMESTAMP.match(text)
    if not match:
        raise InputError(
            f"unrecognised MFTECmd timestamp {text!r} (expected UTC, e.g. --dt default)"
        )
    day, clock, fraction, _offset = match.groups()
    whole = datetime.fromisoformat(f"{day}T{clock}").replace(tzinfo=timezone.utc)
    seconds = (whole - WINDOWS_EPOCH) // timedelta(seconds=1)
    fraction = fraction or ""
    ticks = seconds * TICKS_PER_SECOND + int((fraction + "0000000")[:7])
    return Stamp(ticks, len(fraction))


def same_time(ours: int | None, theirs: Stamp | None) -> bool:
    if ours is None or theirs is None:
        return ours is None and theirs is None
    unit = 10 ** (7 - theirs.digits)
    return ours // unit == theirs.ticks // unit


def format_ticks(ticks: int | None) -> str:
    if ticks is None:
        return ""
    seconds, rest = divmod(ticks, TICKS_PER_SECOND)
    stamp = WINDOWS_EPOCH + timedelta(seconds=seconds)
    return f"{stamp:%Y-%m-%d %H:%M:%S}.{rest:07d}"


def _bool(text: str) -> bool:
    return text.strip().lower() in ("true", "1", "yes")


# -- Chronoscope side ------------------------------------------------------------------


@dataclass
class OurName:
    path: str
    namespace: str
    fn: dict[str, int] = field(default_factory=dict)


@dataclass
class OurEntry:
    in_use: bool
    is_directory: bool
    size: int | None
    si: dict[str, int] = field(default_factory=dict)
    si_created_before_fn: bool = False
    si_zero_fraction: bool = False
    names: dict[tuple[int, str], OurName] = field(default_factory=dict)


def load_chronoscope(path: Path, evidence: str | None) -> dict[tuple[int, int], OurEntry]:
    entries: dict[tuple[int, int], OurEntry] = {}
    labels = set()
    with open(path, encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise InputError(f"{path}:{lineno}: not JSON Lines ({exc})") from exc
            if row.get("artifact") != "mft":
                continue
            labels.add(row.get("evidence"))
            if evidence is not None and row.get("evidence") != evidence:
                continue
            attrs = row["attributes"]
            key = (attrs["entry"], attrs["sequence"])
            entry = entries.setdefault(
                key, OurEntry(attrs["in_use"], attrs["is_directory"], attrs.get("size"))
            )
            kind, _, label = row["timestamp_desc"].partition(" ")
            if kind == "SI":
                entry.si[label] = attrs["filetime"]
                entry.si_created_before_fn = attrs.get("si_created_before_fn", False)
                entry.si_zero_fraction = attrs.get("si_zero_fraction", False)
            elif kind == "FN":
                name_key = (attrs["parent_entry"], attrs["fn_name"])
                name = entry.names.setdefault(
                    name_key, OurName(row["path"], attrs.get("namespace", ""))
                )
                name.fn[label] = attrs["filetime"]
    if evidence is None and len(labels) > 1:
        raise InputError(
            f"{path} has $MFT events from several evidence labels ({', '.join(sorted(labels))}); "
            "choose one with --evidence"
        )
    if not entries:
        raise InputError(f"{path} has no events from the mft parser")
    return entries


def windows_path(path: str) -> str:
    """Chronoscope's ``/Users/a.txt`` in MFTECmd's ``.\\Users\\a.txt`` form."""
    return "." + path.replace("/", "\\")


# -- MFTECmd side ----------------------------------------------------------------------


@dataclass
class TheirRow:
    entry: int
    sequence: int
    parent_entry: int
    name: str
    path: str
    in_use: bool
    is_directory: bool
    size: int
    name_type: str
    si: dict[str, Stamp | None]
    fn: dict[str, Stamp | None]
    fn_inferred: bool
    si_lt_fn: bool
    usec_zeros: bool


def load_mftecmd(path: Path, include_dos: bool) -> Iterator[TheirRow]:
    with open(path, encoding="utf-8-sig", newline="") as fh:
        reader = csv.DictReader(fh)
        missing = [c for c in REQUIRED_COLUMNS if c not in (reader.fieldnames or [])]
        if missing:
            raise InputError(f"{path} is not an MFTECmd $MFT CSV; missing {', '.join(missing)}")
        for number, row in enumerate(reader, 1):
            if _bool(row["IsAds"]):
                continue  # alternate data streams repeat the entry's times
            if row["NameType"].strip().lower() == "dos" and not include_dos:
                continue
            try:
                si = {label: parse_mftecmd_time(row[f"{stem}0x10"]) for label, stem in TIMES}
                fn = {label: parse_mftecmd_time(row[f"{stem}0x30"]) for label, stem in TIMES}
                # Without --at, MFTECmd leaves an FN time blank when it equals the SI time.
                inferred = any(fn[k] is None and si[k] is not None for k, _ in TIMES)
                fn = {label: fn[label] or si[label] for label, _ in TIMES}
                yield TheirRow(
                    entry=int(row["EntryNumber"]),
                    sequence=int(row["SequenceNumber"]),
                    parent_entry=int(row["ParentEntryNumber"]),
                    name=row["FileName"],
                    path=f"{row['ParentPath']}\\{row['FileName']}",
                    in_use=_bool(row["InUse"]),
                    is_directory=_bool(row["IsDirectory"]),
                    size=int(row["FileSize"] or 0),
                    name_type=row["NameType"],
                    si=si,
                    fn=fn,
                    fn_inferred=inferred,
                    si_lt_fn=_bool(row["SI<FN"]),
                    usec_zeros=_bool(row["uSecZeros"]),
                )
            except (InputError, ValueError) as exc:
                raise InputError(f"{path}: row {number}: {exc}") from exc


# -- comparison ------------------------------------------------------------------------


@dataclass(frozen=True)
class Difference:
    category: str
    entry: int
    sequence: int
    name: str
    field: str
    chronoscope: str
    mftecmd: str


@dataclass
class Report:
    matched_rows: int = 0
    compared_values: int = 0
    differences: list[Difference] = field(default_factory=list)
    flags: Counter[str] = field(default_factory=Counter)
    inferred_fn_rows: int = 0

    def add(self, category: str, entry, sequence, name, fld, ours, theirs) -> None:
        self.differences.append(
            Difference(category, entry, sequence, name, fld, str(ours), str(theirs))
        )

    def check(self, row: TheirRow, fld: str, ours: object, theirs: object, category="value"):
        self.compared_values += 1
        if ours != theirs:
            self.add(category, row.entry, row.sequence, row.name, fld, ours, theirs)


def compare(
    ours: dict[tuple[int, int], OurEntry], theirs: Iterable[TheirRow], include_dos: bool
) -> Report:
    report = Report()
    seen: set[tuple[int, int, int, str]] = set()
    for row in theirs:
        key = (row.entry, row.sequence, row.parent_entry, row.name)
        seen.add(key)
        entry = ours.get((row.entry, row.sequence))
        name = entry.names.get((row.parent_entry, row.name)) if entry else None
        if entry is None or name is None:
            report.add("missing in chronoscope", *key[:2], row.name, "row", "", row.path)
            continue
        report.matched_rows += 1
        report.inferred_fn_rows += row.fn_inferred

        report.check(row, "in_use", entry.in_use, row.in_use)
        report.check(row, "is_directory", entry.is_directory, row.is_directory)
        if row.entry != ROOT_ENTRY:
            ours_path = windows_path(name.path)
            category = "orphan path" if "$OrphanFiles" in name.path else "path"
            report.check(row, "path", ours_path, row.path, category)
        if not entry.is_directory:
            report.check(row, "size", entry.size, row.size)
        for label, _stem in TIMES:
            for kind, our_times, their_times in (
                ("SI", entry.si, row.si),
                ("FN", name.fn, row.fn),
            ):
                report.compared_values += 1
                a, b = our_times.get(label), their_times[label]
                if not same_time(a, b):
                    report.add(
                        "timestamp",
                        row.entry,
                        row.sequence,
                        row.name,
                        f"{kind} {label}",
                        format_ticks(a),
                        format_ticks(b.ticks) if b else "",
                    )
        report.check(row, "SI<FN", entry.si_created_before_fn, row.si_lt_fn, "timestomp flag")
        report.flags[f"si_zero_fraction={entry.si_zero_fraction} / uSecZeros={row.usec_zeros}"] += 1

    for (entry_no, sequence), entry in sorted(ours.items()):
        for (parent, name_text), name in sorted(entry.names.items()):
            if name.namespace == "DOS" and not include_dos:
                continue
            if (entry_no, sequence, parent, name_text) not in seen:
                report.add(
                    "missing in mftecmd",
                    entry_no,
                    sequence,
                    name_text,
                    "row",
                    windows_path(name.path),
                    "",
                )
    report.differences.sort(key=lambda d: (d.entry, d.sequence, d.name, d.category, d.field))
    return report


def write_differences(report: Report, out: Path) -> None:
    with open(out, "w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(
            ["category", "entry", "sequence", "name", "field", "chronoscope", "mftecmd"]
        )
        for d in report.differences:
            writer.writerow(
                [d.category, d.entry, d.sequence, d.name, d.field, d.chronoscope, d.mftecmd]
            )


def summary(report: Report) -> str:
    lines = [
        f"Matched rows:        {report.matched_rows:,}",
        f"Values compared:     {report.compared_values:,}",
        f"Differences:         {len(report.differences):,}",
    ]
    for category, count in sorted(Counter(d.category for d in report.differences).items()):
        lines.append(f"  {category:<22} {count:,}")
    by_field = Counter(d.field for d in report.differences if d.category == "timestamp")
    for fld, count in sorted(by_field.items()):
        lines.append(f"    {fld:<20} {count:,}")
    if report.inferred_fn_rows:
        lines.append(
            f"Note: {report.inferred_fn_rows:,} row(s) had no FN times; assumed equal to SI. "
            "Re-run MFTECmd with --at for a full comparison."
        )
    lines.append("Zero sub-second indicators (rules differ; informational):")
    for combo, count in sorted(report.flags.items()):
        lines.append(f"  {combo:<44} {count:,}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("chronoscope_jsonl", type=Path, help="chronoscope export -f jsonl")
    parser.add_argument("mftecmd_csv", type=Path, help="MFTECmd --csv output for the $MFT")
    parser.add_argument("--evidence", help="evidence label to use if the export has several")
    parser.add_argument("--include-dos", action="store_true", help="compare DOS 8.3 names too")
    parser.add_argument("--out", type=Path, help="write every difference to this CSV file")
    args = parser.parse_args(argv)
    try:
        ours = load_chronoscope(args.chronoscope_jsonl, args.evidence)
        report = compare(ours, load_mftecmd(args.mftecmd_csv, args.include_dos), args.include_dos)
    except (InputError, OSError, KeyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(summary(report))
    if args.out:
        write_differences(report, args.out)
        print(f"Differences written to {args.out}")
    return 1 if report.differences else 0


if __name__ == "__main__":
    sys.exit(main())
