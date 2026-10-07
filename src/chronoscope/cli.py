"""Command-line interface."""

from __future__ import annotations

import getpass
import sys
from datetime import datetime
from pathlib import Path

import click

from chronoscope import __version__
from chronoscope.case import Case, CaseError
from chronoscope.export import write_csv, write_jsonl
from chronoscope.hashing import hash_file
from chronoscope.ingest import WRITABLE_WARNING, IngestError, ingest
from chronoscope.parsers import discover
from chronoscope.timeutil import parse_iso
from chronoscope.verify import verify_case

CASE_DIR = click.argument("case_dir", type=click.Path(file_okay=False, path_type=Path))


def _operator(ctx: click.Context) -> str:
    return ctx.obj.get("operator") or getpass.getuser()


def _open(ctx: click.Context, case_dir: Path) -> Case:
    try:
        return Case.open(case_dir, _operator(ctx))
    except CaseError as exc:
        raise click.ClickException(str(exc)) from exc


class AwareDateTime(click.ParamType):
    name = "ISO8601"

    def convert(self, value, param, ctx) -> datetime:  # type: ignore[override]
        if isinstance(value, datetime):
            return value
        try:
            return parse_iso(value)
        except ValueError as exc:
            self.fail(f"{exc} (use e.g. 2024-03-01T00:00:00Z)", param, ctx)


@click.group()
@click.version_option(__version__, prog_name="chronoscope")
@click.option(
    "--operator",
    envvar="CHRONOSCOPE_OPERATOR",
    help="Name recorded in the audit log (default: OS user; env CHRONOSCOPE_OPERATOR).",
)
@click.pass_context
def main(ctx: click.Context, operator: str | None) -> None:
    """Chronoscope: build a unified, forensically sound timeline from many artifacts."""
    ctx.ensure_object(dict)
    ctx.obj["operator"] = operator


@main.command()
@CASE_DIR
@click.option("--name", required=True, help="Case name or number.")
@click.option("--examiner", required=True, help="Examiner responsible for the case.")
@click.pass_context
def init(ctx: click.Context, case_dir: Path, name: str, examiner: str) -> None:
    """Create a new, empty case directory."""
    try:
        case = Case.create(case_dir, name, examiner, ctx.obj.get("operator") or examiner)
    except CaseError as exc:
        raise click.ClickException(str(exc)) from exc
    with case:
        click.echo(f"Created case {case.meta['name']!r} ({case.meta['case_id']}) in {case_dir}")


@main.command(name="ingest")
@CASE_DIR
@click.argument("evidence", type=click.Path(exists=True, path_type=Path))
@click.option("--label", help="Evidence label, e.g. host name (default: evidence file name).")
@click.option(
    "-p",
    "--parser",
    "parsers",
    multiple=True,
    help="Restrict to these parsers (repeatable). Default: auto-detect.",
)
@click.pass_context
def ingest_cmd(
    ctx: click.Context, case_dir: Path, evidence: Path, label: str | None, parsers: tuple[str, ...]
) -> None:
    """Parse EVIDENCE (a file or directory) into the case timeline."""
    with _open(ctx, case_dir) as case:
        try:
            result = ingest(case, evidence, label=label, parser_names=list(parsers) or None)
        except IngestError as exc:
            raise click.ClickException(str(exc)) from exc
    click.echo(
        f"Evidence #{result.evidence_id} [{result.label}]: {result.items_seen} item(s), "
        f"{result.hashed_files} file(s) hashed, {result.inserted} new event(s), "
        f"{result.duplicates} duplicate(s)"
    )
    for name, count in sorted(result.per_parser.items()):
        click.echo(f"  {name:<20} {count}")
    if WRITABLE_WARNING in result.warnings:
        click.secho(f"WARNING: {WRITABLE_WARNING}", fg="yellow", err=True)
    if result.warnings:
        click.echo(f"{len(result.warnings)} warning(s) recorded in the audit log.", err=True)
    for err in result.errors:
        click.echo(f"ERROR: {err}", err=True)
    if result.errors:
        sys.exit(2)


@main.command()
@CASE_DIR
@click.option("-o", "--output", required=True, type=click.Path(dir_okay=False, path_type=Path))
@click.option("-f", "--format", "fmt", type=click.Choice(["csv", "jsonl"]), default="csv")
@click.option("--start", type=AwareDateTime(), help="Only events at or after this time.")
@click.option("--end", type=AwareDateTime(), help="Only events at or before this time.")
@click.option(
    "--excel-safe",
    is_flag=True,
    help="Neutralise spreadsheet formulas in CSV cells. Alters data; recorded in the audit log.",
)
@click.option("--force", is_flag=True, help="Overwrite OUTPUT if it exists.")
@click.pass_context
def export(
    ctx: click.Context,
    case_dir: Path,
    output: Path,
    fmt: str,
    start: datetime | None,
    end: datetime | None,
    excel_safe: bool,
    force: bool,
) -> None:
    """Write the merged, time-sorted timeline to a file."""
    if excel_safe and fmt != "csv":
        raise click.UsageError("--excel-safe only applies to CSV output")
    if output.exists() and not force:
        raise click.ClickException(f"{output} exists; use --force to overwrite")
    with _open(ctx, case_dir) as case:
        events = case.iter_events(start, end)
        with open(output, "w", encoding="utf-8", newline="") as fh:
            count = write_csv(events, fh, excel_safe) if fmt == "csv" else write_jsonl(events, fh)
        digest = hash_file(output)
        case.audit.append(
            "export",
            output=str(output.absolute()),
            format=fmt,
            excel_safe=excel_safe,
            start=start.isoformat() if start else None,
            end=end.isoformat() if end else None,
            events=count,
            sha256=digest.sha256,
        )
    click.echo(f"Wrote {count} event(s) to {output} (SHA-256 {digest.sha256})")


@main.command()
@CASE_DIR
@click.pass_context
def verify(ctx: click.Context, case_dir: Path) -> None:
    """Check the audit log chain and re-hash all recorded evidence."""
    with _open(ctx, case_dir) as case:
        report = verify_case(case)
        entry = case.audit.append(
            "verify",
            ok=report.ok,
            audit_entries=report.audit.entries,
            audit_problems=report.audit.problems,
            files_checked=report.files_checked,
            evidence_problems=report.evidence_problems,
        )
    click.echo(
        f"Audit log: {report.audit.entries} entries, "
        f"{'chain intact' if report.audit.ok else 'CHAIN BROKEN'}"
    )
    for problem in report.audit.problems:
        click.echo(f"  ! {problem}")
    click.echo(
        f"Evidence: {report.files_checked} file(s) re-hashed, "
        f"{len(report.evidence_problems)} problem(s)"
    )
    for problem in report.evidence_problems:
        click.echo(f"  ! {problem}")
    click.echo(f"Audit head hash (record this in your notes): {entry['hash']}")
    if not report.ok:
        sys.exit(1)


@main.command()
@CASE_DIR
@click.pass_context
def log(ctx: click.Context, case_dir: Path) -> None:
    """Print the audit log."""
    with _open(ctx, case_dir) as case:
        for entry in case.audit.entries():
            click.echo(
                f"{entry['seq']:>5}  {entry['timestamp']}  {entry['operator']:<12} "
                f"{entry['action']}"
            )


@main.command()
def parsers() -> None:
    """List available parsers."""
    registry = discover()
    for name, parser in sorted(registry.parsers.items()):
        click.echo(f"{name:<20} {parser.description}  [{registry.origins[name]}]")
    for name, reason in sorted(registry.unavailable.items()):
        click.echo(f"{name:<20} UNAVAILABLE: {reason}")


if __name__ == "__main__":
    main()
