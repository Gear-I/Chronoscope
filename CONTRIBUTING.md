# Contributing to Chronoscope

Thanks for helping. Most contributions are new parsers, and the core is designed so you can add one without touching anything else.

## Development setup

```bash
python -m venv .venv
. .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest
ruff check . && ruff format --check .
```

## Writing a parser

Subclass `chronoscope.parsers.base.Parser`:

```python
from collections.abc import Iterator
from pathlib import Path

from chronoscope.event import TimelineEvent
from chronoscope.parsers.base import ParseContext, Parser
from chronoscope.timeutil import from_filetime


class PrefetchParser(Parser):
    name = "prefetch"  # stable id: CLI, audit log, fingerprints
    description = "Windows prefetch (.pf)"

    def can_parse(self, path: Path) -> bool:
        # Cheap and side-effect free: a file name and a magic number.
        return path.suffix.lower() == ".pf"

    def parse(self, path: Path, ctx: ParseContext) -> Iterator[TimelineEvent]:
        ...
        yield TimelineEvent(
            timestamp=from_filetime(raw_value),  # always timezone-aware
            timestamp_desc="Last Run Time",
            source="PREFETCH",
            artifact=self.name,
            message=f"{exe_name} run (count {run_count})",
            path=ctx.relpath,
            attributes={"executable": exe_name, "run_count": run_count},
        )
```

Rules:

1. **Never modify the source.** Open files `rb`. For SQLite, use `open_sqlite_copy()` from `chronoscope.parsers.sqlite_copy` and return the side files from `related_files()` so they are hashed.
2. **Always attach a time zone.** Use the helpers in `chronoscope.timeutil`. If the artifact stores local time, the parser must know the zone and say so in its documentation. A naive datetime raises `NaiveTimestampError`.
3. **Return `None` / skip unset timestamps** (0 or empty). Don't emit 1601-01-01 or 1970-01-01 events.
4. **Attributes must be JSON-serializable.** Decode bytes explicitly.
5. **Be deterministic.** The same input must yield the same events. Attributes are part of the fingerprint, so don't put wall-clock time, temp paths, or random IDs in them.
6. **Degrade, don't crash, on bad records.** Call `ctx.warn(...)` and continue. Raise only when the file as a whole can't be read. The ingest then rolls back that parser's output for that file and records the error.
7. **Optional dependencies.** Import them inside `parse()` and override `unavailable_reason()` so the parser shows as unavailable instead of breaking the tool.
8. **Tests.** Build a synthetic artifact in the test (see `tests/conftest.py`) or use a small, redistributable public sample, and note its source and license. Good sources are [NIST CFReDS](https://cfreds.nist.gov/) and [Digital Corpora](https://digitalcorpora.org/). Assert exact timestamps.

Register a built-in parser by adding it to `BUILTIN` in `src/chronoscope/parsers/__init__.py`.

## Shipping a parser as its own package

```toml
# your package's pyproject.toml
[project.entry-points."chronoscope.parsers"]
prefetch = "chronoscope_prefetch:PrefetchParser"
```

After `pip install`, the parser appears in `chronoscope parsers`. Names must be unique, and a plugin can't replace a built-in.

## Pull requests

- Keep changes focused, and include tests.
- Describe how you validated against real data, and against which other tool's output.
- Behaviour changes that affect forensic integrity (hashing, audit log, fingerprints, time handling) need a note in the README.
