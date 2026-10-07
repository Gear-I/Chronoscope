"""Read-only, filtered, paged access to a case's timeline. Used by the desktop GUI.

The case database is opened with SQLite's ``mode=ro``, so browsing a case can never change
it. Viewing is not recorded in the audit log because nothing is produced or modified.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from chronoscope.case import DB_FILE, META_FILE, CaseError, StoredEvent
from chronoscope.timeutil import to_unix_us

COLUMNS = (
    "fingerprint, timestamp_us, datetime, timestamp_desc, source, artifact, message, path, "
    "attributes, evidence_id, evidence_label"
)
_DISTINCT = {"artifact", "evidence_label", "source", "timestamp_desc"}
_FLAGGED = (
    "(json_extract(attributes, '$.si_created_before_fn') = 1 "
    "OR json_extract(attributes, '$.si_zero_fraction') = 1)"
)
_DELETED = "json_extract(attributes, '$.deleted') = 1"


@dataclass(frozen=True)
class Filters:
    text: str = ""
    artifact: str = ""
    evidence: str = ""
    start: datetime | None = None
    end: datetime | None = None
    flagged_only: bool = False
    deleted_only: bool = False


def is_flagged(event: StoredEvent) -> bool:
    attrs = json.loads(event.attributes)
    return bool(attrs.get("si_created_before_fn") or attrs.get("si_zero_fraction"))


def is_deleted(event: StoredEvent) -> bool:
    return bool(json.loads(event.attributes).get("deleted"))


def _like(text: str) -> str:
    escaped = text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


class TimelineReader:
    def __init__(self, directory: str | Path) -> None:
        self.directory = Path(directory)
        meta_path = self.directory / META_FILE
        db_path = self.directory / DB_FILE
        if not meta_path.is_file() or not db_path.is_file():
            raise CaseError(f"not a Chronoscope case directory: {self.directory}")
        self.meta: dict[str, Any] = json.loads(meta_path.read_text(encoding="utf-8"))
        self.db = sqlite3.connect(f"{db_path.resolve().as_uri()}?mode=ro", uri=True)

    def close(self) -> None:
        self.db.close()

    def __enter__(self) -> TimelineReader:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def distinct(self, column: str) -> list[str]:
        if column not in _DISTINCT:
            raise ValueError(f"unsupported column: {column}")
        rows = self.db.execute(f"SELECT DISTINCT {column} FROM events ORDER BY {column}")
        return [row[0] for row in rows]

    def _where(self, f: Filters) -> tuple[str, list[Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if f.text:
            clauses.append(
                "(message LIKE ? ESCAPE '\\' OR path LIKE ? ESCAPE '\\' "
                "OR timestamp_desc LIKE ? ESCAPE '\\')"
            )
            params += [_like(f.text)] * 3
        if f.artifact:
            clauses.append("artifact = ?")
            params.append(f.artifact)
        if f.evidence:
            clauses.append("evidence_label = ?")
            params.append(f.evidence)
        if f.start is not None:
            clauses.append("timestamp_us >= ?")
            params.append(to_unix_us(f.start))
        if f.end is not None:
            clauses.append("timestamp_us <= ?")
            params.append(to_unix_us(f.end))
        if f.flagged_only:
            clauses.append(_FLAGGED)
        if f.deleted_only:
            clauses.append(_DELETED)
        return (f"WHERE {' AND '.join(clauses)}" if clauses else ""), params

    def count(self, filters: Filters) -> int:
        where, params = self._where(filters)
        return int(self.db.execute(f"SELECT COUNT(*) FROM events {where}", params).fetchone()[0])

    def page(self, filters: Filters, offset: int, limit: int) -> list[StoredEvent]:
        """Events matching ``filters`` in timeline order (time, then fingerprint)."""
        where, params = self._where(filters)
        query = (
            f"SELECT {COLUMNS} FROM events {where} "
            "ORDER BY timestamp_us, fingerprint LIMIT ? OFFSET ?"
        )
        return [StoredEvent(*row) for row in self.db.execute(query, [*params, limit, offset])]
