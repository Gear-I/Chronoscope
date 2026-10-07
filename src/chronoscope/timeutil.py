"""Conversions from the epoch formats found in forensic artifacts to aware UTC datetimes.

Every helper returns ``None`` for the conventional "unset" value (0) so parsers can skip
missing timestamps without special-casing them.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from decimal import ROUND_FLOOR, Decimal, InvalidOperation

UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
WINDOWS_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def _offset(epoch: datetime, microseconds: int) -> datetime:
    try:
        return epoch + timedelta(microseconds=microseconds)
    except OverflowError as exc:
        raise ValueError(f"timestamp out of range: {microseconds} us from {epoch:%Y}") from exc


def from_unix_ns(ns: int) -> datetime | None:
    """POSIX nanoseconds (os.stat ``st_*_ns``). Sub-microsecond precision is truncated."""
    return None if ns == 0 else _offset(UNIX_EPOCH, ns // 1000)


def from_unix_seconds(value: str | int | float) -> datetime | None:
    """POSIX seconds, possibly fractional (Sleuth Kit body files)."""
    try:
        seconds = Decimal(str(value).strip())
    except InvalidOperation as exc:
        raise ValueError(f"not a POSIX timestamp: {value!r}") from exc
    if not seconds.is_finite():
        raise ValueError(f"not a POSIX timestamp: {value!r}")
    micros = int((seconds * 1_000_000).to_integral_value(rounding=ROUND_FLOOR))
    return None if micros == 0 else _offset(UNIX_EPOCH, micros)


def from_webkit(us: int) -> datetime | None:
    """WebKit/Chrome time: microseconds since 1601-01-01 UTC."""
    return None if not us else _offset(WINDOWS_EPOCH, us)


def from_prtime(us: int) -> datetime | None:
    """Mozilla PRTime: microseconds since 1970-01-01 UTC."""
    return None if not us else _offset(UNIX_EPOCH, us)


def from_filetime(value: int) -> datetime | None:
    """Windows FILETIME: 100-nanosecond intervals since 1601-01-01 UTC."""
    return None if not value else _offset(WINDOWS_EPOCH, value // 10)


_FRACTION = re.compile(r"\.(\d+)")


def parse_iso(text: str) -> datetime:
    """Parse an ISO 8601 timestamp that carries an explicit offset.

    Accepts a trailing ``Z``, a space or ``T`` separator and any number of fractional digits
    (Windows event logs use 7). Raises ``ValueError`` if no offset is present, because
    guessing a time zone is never acceptable in casework.
    """
    s = text.strip()
    if s.endswith(("Z", "z")):
        s = s[:-1] + "+00:00"
    s = _FRACTION.sub(lambda m: "." + (m.group(1) + "000000")[:6], s, count=1)
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None or dt.utcoffset() is None:
        raise ValueError(f"timestamp has no UTC offset: {text!r}")
    return dt.astimezone(timezone.utc)


def to_iso(dt: datetime) -> str:
    """Canonical UTC rendering used throughout Chronoscope: ``YYYY-MM-DDTHH:MM:SS.ffffffZ``."""
    dt = dt.astimezone(timezone.utc)
    return (
        f"{dt.year:04d}-{dt.month:02d}-{dt.day:02d}T"
        f"{dt.hour:02d}:{dt.minute:02d}:{dt.second:02d}.{dt.microsecond:06d}Z"
    )


def to_unix_us(dt: datetime) -> int:
    return (dt - UNIX_EPOCH) // timedelta(microseconds=1)
