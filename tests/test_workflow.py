"""End-to-end: case creation, ingest, de-duplication, export, verification, CLI."""

from __future__ import annotations

import csv
import json
from pathlib import Path

from click.testing import CliRunner

from chronoscope.cli import main
from chronoscope.hashing import hash_file
from chronoscope.ingest import ingest
from chronoscope.verify import verify_case


def _hashes(root: Path) -> dict[str, str]:
    return {
        p.relative_to(root).as_posix(): hash_file(p).sha256 for p in root.rglob("*") if p.is_file()
    }


def test_directory_ingest_is_read_only_and_idempotent(case, evidence_dir):
    before = _hashes(evidence_dir)

    first = ingest(case, evidence_dir, label="WS01")
    assert not first.errors
    assert first.per_parser["chromium_history"] == 3
    assert first.per_parser["firefox_history"] == 3
    assert first.per_parser["filesystem"] > 0
    # Artifacts and their WAL files are hashed; plain files are only stat'ed.
    assert first.hashed_files == 4

    second = ingest(case, evidence_dir, label="WS01")
    # On a writable volume our own reads during the first pass can bump last-access times
    # (hence the writable-evidence warning). Every other event must be an exact duplicate.
    new = [e for e in case.iter_events() if e.evidence_id == second.evidence_id]
    assert {e.timestamp_desc for e in new} <= {"Last Access Time"}
    assert second.inserted + second.duplicates == first.inserted
    assert any("writable" in w for w in second.warnings)

    assert _hashes(evidence_dir) == before  # contents untouched, no -shm/-wal created


def test_artifact_reingest_adds_no_duplicates(case, evidence_dir):
    parsers = ["chromium_history", "firefox_history"]
    first = ingest(case, evidence_dir, label="WS01", parser_names=parsers)
    second = ingest(case, evidence_dir, label="WS01", parser_names=parsers)
    assert first.inserted == 6
    assert second.inserted == 0 and second.duplicates == 6


def test_same_evidence_under_two_labels_is_not_merged(case, evidence_dir):
    a = ingest(case, evidence_dir, label="HOST-A", parser_names=["chromium_history"])
    b = ingest(case, evidence_dir, label="HOST-B", parser_names=["chromium_history"])
    assert a.inserted == b.inserted == 3


def test_timeline_is_sorted(case, evidence_dir):
    ingest(case, evidence_dir, label="WS01")
    stamps = [e.timestamp_us for e in case.iter_events()]
    assert stamps == sorted(stamps)


def test_single_file_ingest_falls_back_to_filesystem(case, evidence_dir):
    result = ingest(case, evidence_dir / "notes.txt")
    assert set(result.per_parser) == {"filesystem"}
    assert result.hashed_files == 1


def test_verify_detects_tampered_evidence(case, evidence_dir):
    ingest(case, evidence_dir, label="WS01")
    assert verify_case(case).ok
    history = next(evidence_dir.rglob("History"))
    with open(history, "ab") as fh:
        fh.write(b"tamper")
    report = verify_case(case)
    assert not report.ok
    assert any("History" in p for p in report.evidence_problems)


def test_failed_parser_rolls_back_partial_output(case, evidence_dir, tmp_path):
    from chronoscope.parsers import discover

    registry = discover(include_plugins=False)

    class Exploding(type(registry.parsers["bodyfile"])):
        def parse(self, path, ctx):
            yield from super().parse(path, ctx)
            raise RuntimeError("boom")

    registry.parsers["bodyfile"] = Exploding()
    body = tmp_path / "x.body"
    body.write_text("0|/a|1|r/r|0|0|0|1600000000|0|0|0\n", encoding="utf-8")
    result = ingest(case, body, registry=registry)
    assert result.errors and "boom" in result.errors[0]
    assert case.event_count() == 0


def test_cli_end_to_end(tmp_path, evidence_dir):
    runner = CliRunner(env={"CHRONOSCOPE_OPERATOR": "jdoe"})
    case_dir = tmp_path / "cli-case"
    out = tmp_path / "timeline.csv"

    r = runner.invoke(main, ["init", str(case_dir), "--name", "C-1", "--examiner", "J. Doe"])
    assert r.exit_code == 0, r.output
    r = runner.invoke(main, ["ingest", str(case_dir), str(evidence_dir), "--label", "WS01"])
    assert r.exit_code == 0, r.output
    r = runner.invoke(
        main,
        [
            "export",
            str(case_dir),
            "-o",
            str(out),
            "--excel-safe",
            "--start",
            "2024-03-01T00:00:00Z",
            "--end",
            "2024-03-02T00:00:00Z",
        ],
    )
    assert r.exit_code == 0, r.output

    with open(out, encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))
    assert {"message", "datetime", "timestamp_desc"} <= set(rows[0])  # Timesketch columns
    assert len(rows) == 6  # browser events only; file times fall outside the window
    titles = [json.loads(r["attributes"]).get("title") for r in rows]
    assert '=HYPERLINK("http://x")' in titles  # raw value preserved inside attributes JSON
    assert not any(r["message"].startswith("=") for r in rows)

    r = runner.invoke(main, ["export", str(case_dir), "-o", str(out)])
    assert r.exit_code != 0 and "--force" in r.output

    r = runner.invoke(main, ["verify", str(case_dir)])
    assert r.exit_code == 0, r.output
    assert "chain intact" in r.output and "head hash" in r.output

    audit = [
        json.loads(line) for line in (case_dir / "audit.jsonl").read_text("utf-8").splitlines()
    ]
    actions = [e["action"] for e in audit]
    assert actions == ["case.create", "ingest.start", "ingest.complete", "export", "verify"]
    export_entry = audit[3]
    assert export_entry["details"]["excel_safe"] is True
    assert export_entry["details"]["sha256"] == hash_file(out).sha256
    assert {e["operator"] for e in audit} == {"jdoe"}


def test_cli_rejects_naive_time_filter(tmp_path, evidence_dir):
    runner = CliRunner()
    case_dir = tmp_path / "c"
    runner.invoke(main, ["init", str(case_dir), "--name", "x", "--examiner", "y"])
    r = runner.invoke(
        main,
        ["export", str(case_dir), "-o", str(tmp_path / "o.csv"), "--start", "2024-03-01T00:00:00"],
    )
    assert r.exit_code != 0 and "offset" in r.output
