from __future__ import annotations

import shutil
import sqlite3
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from chronoscope.case import Case
from chronoscope.timeutil import UNIX_EPOCH, WINDOWS_EPOCH

VISIT_IN_DB = datetime(2024, 3, 1, 9, 30, 0, tzinfo=timezone.utc)
VISIT_IN_WAL = datetime(2024, 3, 1, 10, 45, 0, tzinfo=timezone.utc)
DOWNLOAD_START = datetime(2024, 3, 1, 10, 46, 0, tzinfo=timezone.utc)


def webkit(dt: datetime) -> int:
    return (dt - WINDOWS_EPOCH) // timedelta(microseconds=1)


def prtime(dt: datetime) -> int:
    return (dt - UNIX_EPOCH) // timedelta(microseconds=1)


def _with_pending_wal(dest_dir: Path, name: str, schema: str, committed, pending) -> Path:
    """Build a WAL-mode database whose last transaction exists only in the -wal file.

    The database and -wal are copied to ``dest_dir`` while the writer is still open, which is
    what an examiner gets when collecting from a live or imaged system.
    """
    staging = Path(tempfile.mkdtemp(prefix="chronoscope-test-"))
    conn = sqlite3.connect(staging / name)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA wal_autocheckpoint=0")
    conn.executescript(schema)
    committed(conn)
    conn.commit()
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    pending(conn)
    conn.commit()
    dest_dir.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(staging / name, dest_dir / name)
    shutil.copyfile(staging / f"{name}-wal", dest_dir / f"{name}-wal")
    conn.close()
    shutil.rmtree(staging)
    return dest_dir / name


CHROME_SCHEMA = """
CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER,
                   last_visit_time INTEGER);
CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER,
                     from_visit INTEGER, transition INTEGER);
CREATE TABLE downloads (id INTEGER PRIMARY KEY, target_path TEXT, start_time INTEGER,
                        end_time INTEGER, received_bytes INTEGER, total_bytes INTEGER,
                        mime_type TEXT);
CREATE TABLE downloads_url_chains (id INTEGER, chain_index INTEGER, url TEXT);
"""


def make_chrome_history(dest_dir: Path) -> Path:
    def committed(conn):
        conn.execute("INSERT INTO urls VALUES (1, 'https://example.com/', 'Example', 1, 0)")
        conn.execute("INSERT INTO visits VALUES (1, 1, ?, 0, ?)", (webkit(VISIT_IN_DB), 0x30000001))

    def pending(conn):
        conn.execute(
            "INSERT INTO urls VALUES (2, 'https://evil.test/=HYPERLINK(1)', "
            "'=HYPERLINK(\"http://x\")', 1, 0)"
        )
        conn.execute("INSERT INTO visits VALUES (2, 2, ?, 1, 0)", (webkit(VISIT_IN_WAL),))
        conn.execute(
            "INSERT INTO downloads VALUES (1, 'C:\\Users\\a\\payload.exe', ?, 0, 10, 10, "
            "'application/octet-stream')",
            (webkit(DOWNLOAD_START),),
        )
        conn.execute("INSERT INTO downloads_url_chains VALUES (1, 0, 'https://evil.test/r')")
        conn.execute("INSERT INTO downloads_url_chains VALUES (1, 1, 'https://cdn.test/payload')")

    return _with_pending_wal(dest_dir, "History", CHROME_SCHEMA, committed, pending)


FIREFOX_SCHEMA = """
CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT, title TEXT);
CREATE TABLE moz_historyvisits (id INTEGER PRIMARY KEY, from_visit INTEGER, place_id INTEGER,
                                visit_date INTEGER, visit_type INTEGER);
CREATE TABLE moz_bookmarks (id INTEGER PRIMARY KEY, type INTEGER, fk INTEGER, title TEXT,
                            dateAdded INTEGER, lastModified INTEGER);
"""


def make_firefox_places(dest_dir: Path) -> Path:
    def committed(conn):
        conn.execute("INSERT INTO moz_places VALUES (1, 'https://mozilla.org/', 'Mozilla')")
        conn.execute("INSERT INTO moz_historyvisits VALUES (1, 0, 1, ?, 2)", (prtime(VISIT_IN_DB),))
        conn.execute(
            "INSERT INTO moz_bookmarks VALUES (1, 1, 1, 'Moz', ?, ?)",
            (prtime(VISIT_IN_DB), prtime(VISIT_IN_DB)),
        )

    def pending(conn):
        conn.execute(
            "INSERT INTO moz_historyvisits VALUES (2, 1, 1, ?, 1)", (prtime(VISIT_IN_WAL),)
        )

    return _with_pending_wal(dest_dir, "places.sqlite", FIREFOX_SCHEMA, committed, pending)


@pytest.fixture
def case(tmp_path: Path):
    c = Case.create(tmp_path / "case", "TEST-001", "Examiner", "tester")
    yield c
    c.close()


@pytest.fixture
def evidence_dir(tmp_path: Path) -> Path:
    root = tmp_path / "evidence"
    make_chrome_history(root / "Users" / "a" / "Chrome" / "Default")
    make_firefox_places(root / "Users" / "a" / "Firefox")
    (root / "notes.txt").write_text("nothing to see\n", encoding="utf-8")
    return root
