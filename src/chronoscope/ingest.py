"""Ingest orchestration: walk evidence, dispatch files to parsers, record everything."""

from __future__ import annotations

import os
import re
import shutil
import tempfile
import zipfile
import zlib
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from chronoscope.case import Case
from chronoscope.hashing import hash_file
from chronoscope.parsers import ParseContext, Parser, Registry, discover
from chronoscope.parsers.archive import ArchiveParser
from chronoscope.parsers.base import HEAD_SIZE
from chronoscope.parsers.sqlite_copy import SIDE_SUFFIXES

MAX_AUDITED_WARNINGS = 100
WRITABLE_WARNING = (
    "evidence is on a writable path: reading it may update last-access times. "
    "Ingest from a read-only mount, a write-blocked device, or a verified copy."
)
NO_ARTIFACT_NOTE = (
    "No artifact parser recognised this file; only its own file system timestamps were recorded."
)
_UNSAFE_NAME = re.compile(r'[<>:"/\\|?*\x00-\x1f]')


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
    archive_members: int = 0
    archive_members_parsed: int = 0
    #: True when a single file matched no artifact parser and only got file system times.
    fallback_only: bool = False
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
            "archive_members": self.archive_members,
            "archive_members_parsed": self.archive_members_parsed,
            "fallback_only": self.fallback_only,
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

    def _run(self, parser: Parser, path: Path, relpath: str | None = None) -> None:
        ctx = ParseContext(self.root, relpath or self._relpath(path), self.result.label)
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
        for parser in parsers:
            if isinstance(parser, ArchiveParser):
                self._expand_archives(parser, path)

    # -- archive members ---------------------------------------------------------------

    def _expand_archives(self, archive_parser: ArchiveParser, path: Path) -> None:
        """Run the other artifact parsers on matching members of the archive(s).

        Members are detected from their name and first bytes; only matches (and their SQLite
        side files) are extracted, to a private temporary directory that is removed after.
        The archive itself is hashed as evidence; its members are not hashed separately.
        """
        member_parsers = [p for p in self.artifact_parsers if not isinstance(p, ArchiveParser)]
        if not member_parsers:
            return
        base = PurePosixPath(self._relpath(path)).parent
        for archive in archive_parser.archives(path):
            relpath = self._relpath(path) if archive == path else (base / archive.name).as_posix()
            try:
                with (
                    zipfile.ZipFile(archive) as zf,
                    tempfile.TemporaryDirectory(prefix="chronoscope-zip-") as tmp,
                ):
                    self._scan_members(zf, relpath, member_parsers, Path(tmp))
            except (OSError, zipfile.BadZipFile) as exc:
                self.result.errors.append(f"cannot read archive {relpath}: {exc}")

    def _scan_members(
        self, zf: zipfile.ZipFile, relpath: str, parsers: list[Parser], tmp: Path
    ) -> None:
        names = set(zf.namelist())
        for info in zf.infolist():
            if info.is_dir():
                continue
            self.result.archive_members += 1
            member = f"{relpath}/{info.filename}"
            name = PurePosixPath(info.filename).name
            try:
                with zf.open(info) as fh:
                    head = fh.read(HEAD_SIZE)
            except (
                RuntimeError,
                NotImplementedError,
                zipfile.BadZipFile,
                zlib.error,
                OSError,
            ) as exc:
                self.result.warnings.append(f"{member}: cannot read ({exc})")
                continue
            matched = [p for p in parsers if self._member_matches(p, name, head, member, tmp)]
            if not matched:
                continue
            work = tmp / "member"
            work.mkdir()
            try:
                target = work / (_UNSAFE_NAME.sub("_", name) or "member")
                self._extract(zf, info.filename, target)
                for suffix in SIDE_SUFFIXES:
                    if info.filename + suffix in names:
                        self._extract(
                            zf, info.filename + suffix, target.with_name(target.name + suffix)
                        )
                self.result.archive_members_parsed += 1
                for parser in matched:
                    self._run(parser, target, member)
            except (
                RuntimeError,
                NotImplementedError,
                zipfile.BadZipFile,
                zlib.error,
                OSError,
            ) as exc:
                self.result.warnings.append(f"{member}: cannot extract ({exc})")
            finally:
                shutil.rmtree(work, ignore_errors=True)

    def _member_matches(
        self, parser: Parser, name: str, head: bytes, member: str, tmp: Path
    ) -> bool:
        try:
            verdict = parser.can_parse_head(name, head)
            if verdict is None:  # the parser needs a real file: probe with the head only
                probe = tmp / "probe" / (_UNSAFE_NAME.sub("_", name) or "member")
                probe.parent.mkdir(exist_ok=True)
                probe.write_bytes(head)
                try:
                    verdict = parser.can_parse(probe)
                finally:
                    probe.unlink(missing_ok=True)
            return bool(verdict)
        except Exception as exc:
            self.result.errors.append(f"{parser.name} detection failed on {member}: {exc}")
            return False

    @staticmethod
    def _extract(zf: zipfile.ZipFile, name: str, target: Path) -> None:
        with zf.open(name) as src, open(target, "wb") as dst:
            shutil.copyfileobj(src, dst, 1024 * 1024)

    def ingest_file(self) -> None:
        path = self.root
        self.result.items_seen = 1
        if self.selected is not None:  # explicit choice: trust the examiner, skip detection
            parsers = self.selected
        else:
            parsers = self._matches(path) or [self.fs]
            self.result.fallback_only = parsers == [self.fs]
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
