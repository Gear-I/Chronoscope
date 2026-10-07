"""Read SQLite artifacts without touching the originals.

Opening a SQLite database, even with ``mode=ro``, can create or modify its ``-wal`` and
``-shm`` side files, and ``immutable=1`` silently ignores the WAL, which is often where the
most recent activity lives. So we copy the database together with its ``-wal`` and
``-journal`` files to a private temporary directory and open the copy normally, letting
SQLite replay the WAL there.
"""

from __future__ import annotations

import shutil
import sqlite3
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

SQLITE_MAGIC = b"SQLite format 3\x00"
SIDE_SUFFIXES = ("-wal", "-journal")


def is_sqlite(path: Path) -> bool:
    try:
        with open(path, "rb") as fh:
            return fh.read(len(SQLITE_MAGIC)) == SQLITE_MAGIC
    except OSError:
        return False


def side_files(path: Path) -> list[Path]:
    return [p for p in (path.with_name(path.name + s) for s in SIDE_SUFFIXES) if p.is_file()]


@contextmanager
def open_sqlite_copy(path: Path) -> Iterator[sqlite3.Connection]:
    with tempfile.TemporaryDirectory(prefix="chronoscope-") as tmp:
        copy = Path(tmp) / path.name
        shutil.copyfile(path, copy)
        for side in side_files(path):
            shutil.copyfile(side, copy.with_name(side.name))
        conn = sqlite3.connect(copy)
        try:
            yield conn
        finally:
            conn.close()


def table_names(conn: sqlite3.Connection) -> set[str]:
    return {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}


def column_names(conn: sqlite3.Connection, table: str) -> set[str]:
    return {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
