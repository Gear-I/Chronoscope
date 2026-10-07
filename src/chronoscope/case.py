"""A case: a directory holding the case metadata, event database and audit log."""

from __future__ import annotations

import json
import sqlite3
import uuid
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from chronoscope import __version__
from chronoscope.audit import AuditLog
from chronoscope.event import TimelineEvent, canonical_json
from chronoscope.hashing import FileHashes
from chronoscope.timeutil import to_iso, to_unix_us

META_FILE = "case.json"
DB_FILE = "case.db"
AUDIT_FILE = "audit.jsonl"

SCHEMA = """
CREATE TABLE evidence (
    id        INTEGER PRIMARY KEY,
    label     TEXT NOT NULL,
    path      TEXT NOT NULL,
    kind      TEXT NOT NULL,
    added_at  TEXT NOT NULL
);
CREATE TABLE evidence_files (
    evidence_id INTEGER NOT NULL REFERENCES evidence(id),
    relpath     TEXT NOT NULL,
    size        INTEGER NOT NULL,
    md5         TEXT NOT NULL,
    sha1        TEXT NOT NULL,
    sha256      TEXT NOT NULL,
    PRIMARY KEY (evidence_id, relpath)
);
CREATE TABLE events (
    fingerprint    TEXT PRIMARY KEY,
    timestamp_us   INTEGER NOT NULL,
    datetime       TEXT NOT NULL,
    timestamp_desc TEXT NOT NULL,
    source         TEXT NOT NULL,
    artifact       TEXT NOT NULL,
    message        TEXT NOT NULL,
    path           TEXT NOT NULL,
    attributes     TEXT NOT NULL,
    evidence_id    INTEGER NOT NULL REFERENCES evidence(id),
    evidence_label TEXT NOT NULL
);
CREATE INDEX events_by_time ON events (timestamp_us, fingerprint);
"""


class CaseError(Exception):
    pass


@dataclass(frozen=True)
class StoredEvent:
    fingerprint: str
    timestamp_us: int
    datetime: str
    timestamp_desc: str
    source: str
    artifact: str
    message: str
    path: str
    attributes: str
    evidence_id: int
    evidence_label: str


@dataclass(frozen=True)
class EvidenceFile:
    evidence_id: int
    label: str
    root: str
    kind: str
    relpath: str
    size: int
    md5: str
    sha1: str
    sha256: str

    @property
    def location(self) -> Path:
        root = Path(self.root)
        return (root.parent if self.kind == "file" else root) / self.relpath


class Case:
    def __init__(self, directory: Path, meta: dict[str, Any], operator: str) -> None:
        self.directory = directory
        self.meta = meta
        # Autocommit mode: transactions are managed explicitly via ``transaction()``.
        self.db = sqlite3.connect(directory / DB_FILE, isolation_level=None)
        self.db.execute("PRAGMA foreign_keys = ON")
        self.audit = AuditLog(directory / AUDIT_FILE, operator, __version__)

    @classmethod
    def create(cls, directory: str | Path, name: str, examiner: str, operator: str) -> Case:
        directory = Path(directory)
        if directory.exists() and any(directory.iterdir()):
            raise CaseError(f"refusing to create a case in non-empty directory: {directory}")
        directory.mkdir(parents=True, exist_ok=True)
        meta = {
            "case_id": str(uuid.uuid4()),
            "name": name,
            "examiner": examiner,
            "created": to_iso(datetime.now(timezone.utc)),
            "created_with": __version__,
        }
        (directory / META_FILE).write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
        case = cls(directory, meta, operator)
        with case.transaction():
            for statement in SCHEMA.split(";"):
                if statement.strip():
                    case.db.execute(statement)
        case.audit.append("case.create", **meta)
        return case

    @classmethod
    def open(cls, directory: str | Path, operator: str) -> Case:
        directory = Path(directory)
        meta_path = directory / META_FILE
        if not meta_path.is_file() or not (directory / DB_FILE).is_file():
            raise CaseError(f"not a Chronoscope case directory: {directory}")
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        return cls(directory, meta, operator)

    @contextmanager
    def transaction(self) -> Iterator[None]:
        self.db.execute("BEGIN")
        try:
            yield
        except BaseException:
            self.db.execute("ROLLBACK")
            raise
        self.db.execute("COMMIT")

    def close(self) -> None:
        self.db.close()

    def __enter__(self) -> Case:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- evidence ----------------------------------------------------------------------

    def add_evidence(self, label: str, path: Path, kind: str) -> int:
        cur = self.db.execute(
            "INSERT INTO evidence (label, path, kind, added_at) VALUES (?, ?, ?, ?)",
            (label, str(path), kind, to_iso(datetime.now(timezone.utc))),
        )
        return int(cur.lastrowid)

    def add_evidence_file(self, evidence_id: int, relpath: str, hashes: FileHashes) -> None:
        self.db.execute(
            "INSERT OR REPLACE INTO evidence_files VALUES (?, ?, ?, ?, ?, ?)",
            (evidence_id, relpath, hashes.size, hashes.md5, hashes.sha1, hashes.sha256),
        )

    def evidence_files(self) -> list[EvidenceFile]:
        rows = self.db.execute(
            "SELECT e.id, e.label, e.path, e.kind, f.relpath, f.size, f.md5, f.sha1, f.sha256 "
            "FROM evidence_files f JOIN evidence e ON e.id = f.evidence_id "
            "ORDER BY e.id, f.relpath"
        )
        return [EvidenceFile(*row) for row in rows]

    def evidence(self) -> list[tuple[int, str, str, str, str]]:
        return list(self.db.execute("SELECT id, label, path, kind, added_at FROM evidence"))

    # -- events ------------------------------------------------------------------------

    def add_events(
        self, evidence_id: int, label: str, events: Iterable[TimelineEvent]
    ) -> tuple[int, int]:
        """Insert events, ignoring ones already present. Returns (inserted, duplicates).

        All-or-nothing: if ``events`` raises part-way (a parser failing on a corrupt file),
        the events already inserted by this call are rolled back before re-raising.
        """
        inserted = duplicates = 0
        self.db.execute("SAVEPOINT add_events")
        try:
            inserted, duplicates = self._insert_events(evidence_id, label, events)
        except BaseException:
            self.db.execute("ROLLBACK TO add_events")
            self.db.execute("RELEASE add_events")
            raise
        self.db.execute("RELEASE add_events")
        return inserted, duplicates

    def _insert_events(
        self, evidence_id: int, label: str, events: Iterable[TimelineEvent]
    ) -> tuple[int, int]:
        inserted = duplicates = 0
        for ev in events:
            cur = self.db.execute(
                "INSERT OR IGNORE INTO events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    ev.fingerprint(label),
                    ev.timestamp_us,
                    ev.iso,
                    ev.timestamp_desc,
                    ev.source,
                    ev.artifact,
                    ev.message,
                    ev.path,
                    canonical_json(ev.attributes),
                    evidence_id,
                    label,
                ),
            )
            if cur.rowcount:
                inserted += 1
            else:
                duplicates += 1
        return inserted, duplicates

    def iter_events(
        self, start: datetime | None = None, end: datetime | None = None
    ) -> Iterator[StoredEvent]:
        """Events in deterministic order: by time, then by fingerprint."""
        clauses, params = [], []
        if start is not None:
            clauses.append("timestamp_us >= ?")
            params.append(to_unix_us(start))
        if end is not None:
            clauses.append("timestamp_us <= ?")
            params.append(to_unix_us(end))
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        query = (
            "SELECT fingerprint, timestamp_us, datetime, timestamp_desc, source, artifact, "
            "message, path, attributes, evidence_id, evidence_label FROM events "
            f"{where} ORDER BY timestamp_us, fingerprint"
        )
        for row in self.db.execute(query, params):
            yield StoredEvent(*row)

    def event_count(self) -> int:
        return int(self.db.execute("SELECT COUNT(*) FROM events").fetchone()[0])
