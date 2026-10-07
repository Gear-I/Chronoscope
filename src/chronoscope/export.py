"""Timeline export: Timesketch-compatible CSV and JSON Lines."""

from __future__ import annotations

import csv
import json
from collections.abc import Iterable
from typing import IO

from chronoscope.case import StoredEvent

# Timesketch requires message, datetime and timestamp_desc; other columns become attributes.
CSV_COLUMNS = (
    "datetime",
    "timestamp",
    "timestamp_desc",
    "message",
    "source",
    "artifact",
    "evidence",
    "path",
    "attributes",
    "fingerprint",
)

# Characters that make spreadsheet applications interpret a cell as a formula (OWASP).
FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def excel_safe(value: object) -> object:
    """Neutralise CSV formula injection by prefixing dangerous cells with an apostrophe."""
    if isinstance(value, str) and value.startswith(FORMULA_PREFIXES):
        return "'" + value
    return value


def _row(ev: StoredEvent) -> dict[str, object]:
    return {
        "datetime": ev.datetime,
        "timestamp": ev.timestamp_us,
        "timestamp_desc": ev.timestamp_desc,
        "message": ev.message,
        "source": ev.source,
        "artifact": ev.artifact,
        "evidence": ev.evidence_label,
        "path": ev.path,
        "attributes": ev.attributes,
        "fingerprint": ev.fingerprint,
    }


def write_csv(events: Iterable[StoredEvent], fh: IO[str], safe: bool = False) -> int:
    writer = csv.DictWriter(fh, fieldnames=CSV_COLUMNS, lineterminator="\n")
    writer.writeheader()
    count = 0
    for ev in events:
        row = _row(ev)
        if safe:
            row = {k: excel_safe(v) for k, v in row.items()}
        writer.writerow(row)
        count += 1
    return count


def write_jsonl(events: Iterable[StoredEvent], fh: IO[str]) -> int:
    count = 0
    for ev in events:
        row = _row(ev)
        row["attributes"] = json.loads(ev.attributes)
        fh.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
        count += 1
    return count
