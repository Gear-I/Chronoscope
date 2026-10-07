"""The parser plugin interface.

A parser turns one artifact file into ``TimelineEvent`` objects. Parsers are discovered from
the built-in list and from the ``chronoscope.parsers`` entry-point group, so third-party
parsers can ship as independent packages.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar

from chronoscope.event import TimelineEvent


@dataclass
class ParseContext:
    """Information a parser may need beyond the file itself."""

    evidence_root: Path
    relpath: str
    label: str
    warnings: list[str] = field(default_factory=list)

    def warn(self, message: str) -> None:
        self.warnings.append(f"{self.relpath}: {message}")


class Parser(ABC):
    #: Unique, stable identifier used on the command line and in the audit log.
    name: ClassVar[str]
    #: One-line description shown by ``chronoscope parsers``.
    description: ClassVar[str]

    @classmethod
    def unavailable_reason(cls) -> str | None:
        """Return a reason if the parser cannot run (e.g. optional dependency missing)."""
        return None

    @abstractmethod
    def can_parse(self, path: Path) -> bool:
        """Cheap detection: return True if ``path`` looks like this artifact.

        Must not modify the file and should read as little as possible (a magic number and
        file name is usually enough).
        """

    @abstractmethod
    def parse(self, path: Path, ctx: ParseContext) -> Iterator[TimelineEvent]:
        """Yield events from ``path``. Must never modify the source file."""

    def related_files(self, path: Path) -> list[Path]:
        """Other files this parser reads alongside ``path`` (they are hashed as evidence)."""
        return []
