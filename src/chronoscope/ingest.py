"""Ingest orchestration: walk evidence, dispatch files to parsers, record everything."""

from __future__ import annotations

import os
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from chronoscope.case import Case
from chronoscope.hashing import hash_file
from chronoscope.parsers import ParseContext, Parser, Registry, discover

MAX_AUDITED_WARNINGS = 100
WRITABLE_WARNING = (
    "evidence is on a writable path: reading it may update last-access times. "
    "Ingest from a read-only mount, a write-blocked device, or a verified copy."
)


class IngestError(Exception):
    pass


@dataclass
class IngestResult:
    evidence_id: int
    label: str
    kind: str
    items_seen: int = 0
    inserted: int = 0
    duplicates: int = 0
    per_parser: Counter[str] = field(default_factory=Counter)
    hashed_files: int = 0
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def summary(self) -> dict[str, object]:
        return {
            "evidence_id": self.evidence_id,
            "label": self.label,
            "items_seen": self.items_seen,
            "inserted": self.inserted,
            "duplicates": self.duplicates,
            "events_by_parser": dict(sorted(self.per_parser.items())),
            "hashed_files": self.hashed_files,
            "warning_count": len(self.warnings),
            "warnings": self.warnings[:MAX_AUDITED_WARNINGS],
            "errors": self.errors,
        }


class _Ingestor:
    def __init__(
        self,
        case: Case,
        root: Path,
        result: IngestResult,
        registry: Registry,
        selected: list[Parser] | None,
    ) -> None:
        self.case = case
        self.root = root
        self.result = result
        self.fs = registry.parsers["filesystem"]
        self.selected = selected
        pool = selected if selected is not None else list(registry.parsers.values())
        self.artifact_parsers = [p for p in pool if p is not self.fs]
        self.hashed: set[Path] = set()

    def _relpath(self, path: Path) -> str:
        if self.result.kind == "file":
            return path.name
        rel = path.relative_to(self.root).as_posix()
        return rel

    def _run(self, parser: Parser, path: Path) -> None:
        ctx = ParseContext(self.root, self._relpath(path), self.result.label)
        try:
            inserted, dups = self.case.add_events(
                self.result.evidence_id, self.result.label, parser.parse(path, ctx)
            )
        except Exception as exc:
            self.result.errors.append(
                f"{parser.name} failed on {ctx.relpath}: {type(exc).__name__}: {exc}"
            )
            return
        finally:
            self.result.warnings.extend(f"{parser.name}: {w}" for w in ctx.warnings)
        self.result.inserted += inserted
        self.result.duplicates += dups
        self.result.per_parser[parser.name] += inserted + dups

    def _matches(self, path: Path) -> list[Parser]:
        matched = []
        for parser in self.artifact_parsers:
            try:
                if parser.can_parse(path):
                    matched.append(parser)
            except Exception as exc:
                self.result.errors.append(
                    f"{parser.name} detection failed on {self._relpath(path)}: {exc}"
                )
        return matched

    def _hash(self, paths: list[Path]) -> None:
        for path in paths:
            if path in self.hashed:
                continue
            self.hashed.add(path)
            try:
                hashes = hash_file(path)
            except OSError as exc:
                self.result.errors.append(f"could not hash {self._relpath(path)}: {exc}")
                continue
            self.case.add_evidence_file(self.result.evidence_id, self._relpath(path), hashes)
            self.result.hashed_files += 1

    def _parse_artifacts(self, path: Path, parsers: list[Parser]) -> None:
        to_hash = [path]
        for parser in parsers:
            to_hash.extend(parser.related_files(path))
        self._hash(to_hash)
        for parser in parsers:
            self._run(parser, path)

    def ingest_file(self) -> None:
        path = self.root
        self.result.items_seen = 1
        if self.selected is not None:  # explicit choice: trust the examiner, skip detection
            parsers = self.selected
        else:
            parsers = self._matches(path) or [self.fs]
        # File system times are captured first, before hashing or parsing reads the file.
        if self.fs in parsers:
            self._run(self.fs, path)
        self._parse_artifacts(path, [p for p in parsers if p is not self.fs])
        self._hash([path])

    def ingest_directory(self) -> None:
        fs_on = self.selected is None or self.fs in self.selected
        if fs_on:
            self._run(self.fs, self.root)
        self.result.items_seen += 1

        def onerror(exc: OSError) -> None:
            self.result.errors.append(f"cannot read {exc.filename}: {exc.strerror}")

        for dirpath, dirnames, filenames in os.walk(self.root, onerror=onerror):
            dirnames.sort()
            filenames.sort()
            here = Path(dirpath)
            # Stat subdirectories now, before os.walk lists them (listing can bump atime).
            for name in dirnames:
                self.result.items_seen += 1
                if fs_on:
                    self._run(self.fs, here / name)
            for name in filenames:
                path = here / name
                self.result.items_seen += 1
                if fs_on:
                    self._run(self.fs, path)
                if path.is_symlink():
                    continue  # never follow links out of the evidence tree
                matched = self._matches(path)
                if matched:
                    self._parse_artifacts(path, matched)


def ingest(
    case: Case,
    evidence: str | Path,
    label: str | None = None,
    parser_names: list[str] | None = None,
    registry: Registry | None = None,
) -> IngestResult:
    root = Path(evidence).absolute()
    if not root.exists():
        raise IngestError(f"evidence not found: {root}")
    registry = registry or discover()

    selected: list[Parser] | None = None
    if parser_names:
        problems = []
        for name in parser_names:
            if name not in registry.parsers:
                reason = registry.unavailable.get(name, "unknown parser")
                problems.append(f"{name}: {reason}")
        if problems:
            raise IngestError("cannot use parser(s): " + "; ".join(problems))
        selected = [registry.parsers[n] for n in dict.fromkeys(parser_names)]

    kind = "directory" if root.is_dir() else "file"
    label = label or root.name or str(root)
    case.audit.append(
        "ingest.start",
        evidence=str(root),
        kind=kind,
        label=label,
        parsers=parser_names or "auto",
        available_parsers=sorted(registry.parsers),
    )
    try:
        with case.transaction():
            evidence_id = case.add_evidence(label, root, kind)
            result = IngestResult(evidence_id, label, kind)
            if os.access(root, os.W_OK):
                result.warnings.append(WRITABLE_WARNING)
            ingestor = _Ingestor(case, root, result, registry, selected)
            if kind == "file":
                ingestor.ingest_file()
            else:
                ingestor.ingest_directory()
    except BaseException as exc:
        case.audit.append("ingest.aborted", evidence=str(root), error=repr(exc))
        raise
    case.audit.append("ingest.complete", **result.summary())
    return result
