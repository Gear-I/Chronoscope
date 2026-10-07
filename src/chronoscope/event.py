"""The normalized event type every parser produces."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from chronoscope.timeutil import to_iso, to_unix_us


class NaiveTimestampError(ValueError):
    """Raised when a parser emits a timestamp without time zone information."""


def canonical_json(value: Any) -> str:
    """Deterministic JSON: sorted keys, no whitespace, UTF-8 preserved. Used for hashing."""
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


@dataclass(frozen=True)
class TimelineEvent:
    """One point on the timeline.

    ``timestamp`` must be timezone-aware; it is converted to UTC on construction. Naive
    datetimes are rejected outright so that no parser can silently introduce local-time
    ambiguity into a case.

    ``attributes`` must be JSON-serializable (str, int, float, bool, None, lists, dicts);
    parsers are responsible for decoding bytes and similar types explicitly.
    """

    timestamp: datetime
    timestamp_desc: str
    source: str
    artifact: str
    message: str
    path: str = ""
    attributes: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        ts = self.timestamp
        if not isinstance(ts, datetime):
            raise TypeError(f"timestamp must be a datetime, got {type(ts).__name__}")
        if ts.tzinfo is None or ts.utcoffset() is None:
            raise NaiveTimestampError(
                f"{self.artifact}: naive timestamp {ts!r} for {self.timestamp_desc!r}; "
                "parsers must attach a time zone"
            )
        object.__setattr__(self, "timestamp", ts.astimezone(timezone.utc))
        attrs = dict(self.attributes)
        canonical_json(attrs)  # fail fast on non-serializable values
        object.__setattr__(self, "attributes", attrs)

    @property
    def iso(self) -> str:
        return to_iso(self.timestamp)

    @property
    def timestamp_us(self) -> int:
        return to_unix_us(self.timestamp)

    def fingerprint(self, evidence_label: str = "") -> str:
        """Stable identity used for de-duplication across repeated ingests.

        The evidence label is included so that identical-looking events from two different
        hosts (for example the same system DLL) are never merged.
        """
        payload = [
            evidence_label,
            self.iso,
            self.timestamp_desc,
            self.source,
            self.artifact,
            self.message,
            self.path,
            self.attributes,
        ]
        return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
