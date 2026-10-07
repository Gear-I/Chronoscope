"""Browser history: Chromium-family ``History`` and Firefox ``places.sqlite``."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from pathlib import Path

from chronoscope.event import TimelineEvent
from chronoscope.parsers.base import ParseContext, Parser
from chronoscope.parsers.sqlite_copy import (
    column_names,
    is_sqlite,
    open_sqlite_copy,
    side_files,
    table_names,
)
from chronoscope.timeutil import from_prtime, from_webkit

CHROMIUM_TRANSITIONS = {
    0: "LINK",
    1: "TYPED",
    2: "AUTO_BOOKMARK",
    3: "AUTO_SUBFRAME",
    4: "MANUAL_SUBFRAME",
    5: "GENERATED",
    6: "AUTO_TOPLEVEL",
    7: "FORM_SUBMIT",
    8: "RELOAD",
    9: "KEYWORD",
    10: "KEYWORD_GENERATED",
}

FIREFOX_VISIT_TYPES = {
    1: "LINK",
    2: "TYPED",
    3: "BOOKMARK",
    4: "EMBED",
    5: "REDIRECT_PERMANENT",
    6: "REDIRECT_TEMPORARY",
    7: "DOWNLOAD",
    8: "FRAMED_LINK",
    9: "RELOAD",
}


def _page(url: str, title: str | None) -> str:
    return f"{url} ({title})" if title else url


class _SQLiteArtifactParser(Parser):
    filename: str

    def can_parse(self, path: Path) -> bool:
        return path.name == self.filename and is_sqlite(path)

    def related_files(self, path: Path) -> list[Path]:
        return side_files(path)


class ChromiumHistoryParser(_SQLiteArtifactParser):
    name = "chromium_history"
    description = "Chrome / Edge / Brave / Opera 'History' database: visits and downloads"
    filename = "History"

    def parse(self, path: Path, ctx: ParseContext) -> Iterator[TimelineEvent]:
        with open_sqlite_copy(path) as conn:
            tables = table_names(conn)
            if {"urls", "visits"} <= tables:
                yield from self._visits(conn, ctx)
            else:
                ctx.warn("no urls/visits tables; not a Chromium History database?")
            if "downloads" in tables:
                yield from self._downloads(conn, ctx, "downloads_url_chains" in tables)

    def _visits(self, conn: sqlite3.Connection, ctx: ParseContext) -> Iterator[TimelineEvent]:
        rows = conn.execute(
            "SELECT v.id, v.visit_time, u.url, u.title, v.transition, v.from_visit "
            "FROM visits v JOIN urls u ON u.id = v.url ORDER BY v.id"
        )
        for visit_id, visit_time, url, title, transition, from_visit in rows:
            ts = from_webkit(visit_time)
            if ts is None:
                continue
            core = CHROMIUM_TRANSITIONS.get((transition or 0) & 0xFF, "UNKNOWN")
            yield TimelineEvent(
                timestamp=ts,
                timestamp_desc="Page Visited",
                source="WEBHIST",
                artifact=self.name,
                message=f"{_page(url, title)} [{core}]",
                path=ctx.relpath,
                attributes={
                    "url": url,
                    "title": title,
                    "visit_id": visit_id,
                    "from_visit": from_visit,
                    "transition": core,
                    "transition_raw": transition,
                },
            )

    def _downloads(
        self, conn: sqlite3.Connection, ctx: ParseContext, has_chains: bool
    ) -> Iterator[TimelineEvent]:
        cols = column_names(conn, "downloads")
        wanted = [
            c
            for c in (
                "id",
                "target_path",
                "start_time",
                "end_time",
                "received_bytes",
                "total_bytes",
                "tab_url",
                "mime_type",
                "danger_type",
            )
            if c in cols
        ]
        conn.row_factory = sqlite3.Row
        try:
            for row in conn.execute(f"SELECT {', '.join(wanted)} FROM downloads ORDER BY id"):
                record = dict(row)
                url = None
                if has_chains:
                    chain = conn.execute(
                        "SELECT url FROM downloads_url_chains WHERE id = ? "
                        "ORDER BY chain_index DESC LIMIT 1",
                        (record["id"],),
                    ).fetchone()
                    url = chain[0] if chain else None
                record["url"] = url
                target = record.get("target_path") or "<unknown target>"
                for key, desc in (
                    ("start_time", "Download Started"),
                    ("end_time", "Download Finished"),
                ):
                    ts = from_webkit(record.get(key) or 0)
                    if ts is None:
                        continue
                    yield TimelineEvent(
                        timestamp=ts,
                        timestamp_desc=desc,
                        source="WEBHIST",
                        artifact=self.name,
                        message=f"{url or '<unknown url>'} -> {target}",
                        path=ctx.relpath,
                        attributes=record,
                    )
        finally:
            conn.row_factory = None


class FirefoxHistoryParser(_SQLiteArtifactParser):
    name = "firefox_history"
    description = "Firefox 'places.sqlite': visits and bookmarks"
    filename = "places.sqlite"

    def parse(self, path: Path, ctx: ParseContext) -> Iterator[TimelineEvent]:
        with open_sqlite_copy(path) as conn:
            tables = table_names(conn)
            if {"moz_places", "moz_historyvisits"} <= tables:
                yield from self._visits(conn, ctx)
            else:
                ctx.warn("no moz_places/moz_historyvisits tables; not a places.sqlite?")
            if {"moz_places", "moz_bookmarks"} <= tables:
                yield from self._bookmarks(conn, ctx)

    def _visits(self, conn: sqlite3.Connection, ctx: ParseContext) -> Iterator[TimelineEvent]:
        rows = conn.execute(
            "SELECT v.id, v.visit_date, p.url, p.title, v.visit_type, v.from_visit "
            "FROM moz_historyvisits v JOIN moz_places p ON p.id = v.place_id ORDER BY v.id"
        )
        for visit_id, visit_date, url, title, visit_type, from_visit in rows:
            ts = from_prtime(visit_date)
            if ts is None:
                continue
            kind = FIREFOX_VISIT_TYPES.get(visit_type, "UNKNOWN")
            yield TimelineEvent(
                timestamp=ts,
                timestamp_desc="Page Visited",
                source="WEBHIST",
                artifact=self.name,
                message=f"{_page(url, title)} [{kind}]",
                path=ctx.relpath,
                attributes={
                    "url": url,
                    "title": title,
                    "visit_id": visit_id,
                    "from_visit": from_visit,
                    "visit_type": kind,
                },
            )

    def _bookmarks(self, conn: sqlite3.Connection, ctx: ParseContext) -> Iterator[TimelineEvent]:
        rows = conn.execute(
            "SELECT b.id, b.title, b.dateAdded, b.lastModified, p.url "
            "FROM moz_bookmarks b JOIN moz_places p ON p.id = b.fk "
            "WHERE b.type = 1 ORDER BY b.id"
        )
        for bookmark_id, title, added, modified, url in rows:
            stamps = [("Bookmark Added", added)]
            if modified and modified != added:
                stamps.append(("Bookmark Modified", modified))
            for desc, value in stamps:
                ts = from_prtime(value)
                if ts is None:
                    continue
                yield TimelineEvent(
                    timestamp=ts,
                    timestamp_desc=desc,
                    source="WEBHIST",
                    artifact=self.name,
                    message=_page(url, title),
                    path=ctx.relpath,
                    attributes={"url": url, "title": title, "bookmark_id": bookmark_id},
                )
