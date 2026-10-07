"""Tamper-evident, hash-chained audit log.

Each line of the log is a JSON object whose ``hash`` is the SHA-256 of the entry's other
fields, including ``prev_hash``. Editing, reordering or deleting any entry breaks the chain.

Limitation: a chain cannot reveal that its *newest* entries were cut off. Examiners should
record the head hash (printed by ``chronoscope verify``) in their contemporaneous notes.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from chronoscope.event import canonical_json
from chronoscope.timeutil import to_iso

GENESIS_HASH = "0" * 64


def _entry_hash(entry: dict[str, Any]) -> str:
    body = {k: v for k, v in entry.items() if k != "hash"}
    return hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()


@dataclass
class AuditVerification:
    ok: bool
    entries: int
    head_hash: str
    problems: list[str] = field(default_factory=list)


class AuditLog:
    def __init__(self, path: str | Path, operator: str, tool_version: str) -> None:
        self.path = Path(path)
        self.operator = operator
        self.tool_version = tool_version

    def _tail(self) -> tuple[int, str]:
        if not self.path.exists():
            return 0, GENESIS_HASH
        last = None
        with open(self.path, encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    last = line
        if last is None:
            return 0, GENESIS_HASH
        entry = json.loads(last)
        return entry["seq"], entry["hash"]

    def append(self, action: str, **details: Any) -> dict[str, Any]:
        seq, prev_hash = self._tail()
        entry: dict[str, Any] = {
            "seq": seq + 1,
            "timestamp": to_iso(datetime.now(timezone.utc)),
            "operator": self.operator,
            "tool_version": self.tool_version,
            "action": action,
            "details": details,
            "prev_hash": prev_hash,
        }
        entry["hash"] = _entry_hash(entry)
        with open(self.path, "a", encoding="utf-8", newline="\n") as fh:
            fh.write(canonical_json(entry) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        return entry

    def entries(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        with open(self.path, encoding="utf-8") as fh:
            return [json.loads(line) for line in fh if line.strip()]

    @staticmethod
    def verify(path: str | Path) -> AuditVerification:
        path = Path(path)
        problems: list[str] = []
        prev_hash = GENESIS_HASH
        count = 0
        if not path.exists():
            return AuditVerification(False, 0, GENESIS_HASH, [f"audit log missing: {path}"])
        with open(path, encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, 1):
                if not line.strip():
                    continue
                count += 1
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError as exc:
                    problems.append(f"line {lineno}: not valid JSON ({exc})")
                    prev_hash = "<unknown>"
                    continue
                if entry.get("seq") != count:
                    problems.append(
                        f"line {lineno}: sequence {entry.get('seq')} where {count} expected"
                    )
                if entry.get("prev_hash") != prev_hash:
                    problems.append(f"line {lineno}: prev_hash does not match preceding entry")
                if entry.get("hash") != _entry_hash(entry):
                    problems.append(f"line {lineno}: entry hash mismatch (entry was modified)")
                prev_hash = entry.get("hash", "<missing>")
        return AuditVerification(not problems, count, prev_hash, problems)
