# Chronoscope

Chronoscope ingests artifacts from many sources (file system metadata, browser history, Windows event logs, Sleuth Kit body files), normalizes every timestamp to UTC, and merges them into one sorted, de-duplicated timeline.

It is built for casework: evidence is never modified, every action is recorded in a tamper-evident audit log, and the same input always produces the same output.

> **Status:** v0.1, alpha. Validate results against a second tool before relying on them in a report.

## Install

```bash
pip install "chronoscope-forensics[evtx]"
```

Or, from a checkout:

```bash
pip install -e ".[dev]"
```

The distribution is named `chronoscope-forensics` because `chronoscope` is taken on PyPI. The command and the import name are both `chronoscope`. The `evtx` extra pulls in `python-evtx`. Without it, the event log parser is listed as unavailable and everything else still works. The `gui` extra pulls in PySide6 for the desktop viewer.

## Quick start

```bash
chronoscope init ./case-2024-017 --name "2024-017" --examiner "J. Doe"
chronoscope ingest ./case-2024-017 /mnt/ws01 --label WS01
chronoscope ingest ./case-2024-017 ./ws01-fls.body --label WS01-image
chronoscope export ./case-2024-017 -o timeline.csv --start 2024-03-01T00:00:00Z
chronoscope verify ./case-2024-017
```

Evidence can be any of:

- **One artifact file.** The parser is auto-detected. If nothing matches, Chronoscope records the file's own timestamps.
- **A directory** (a mounted image or a triage collection). Chronoscope records file system timestamps for every file and directory. It also detects and parses any browser databases and event logs it finds inside.
- **An extracted `$MFT`** (for example from `icat image.E01 0` or a triage collector). Every entry, including deleted ones, gets its SI and FN times.
- **A Sleuth Kit body file** (`fls -r -m / image.E01 > image.body`). This is the way to use disk images, including deleted entries.

Use `--parser NAME` (repeatable) to restrict or force parsers, and `chronoscope parsers` to list them. Set the name recorded in the audit log with `--operator` or the `CHRONOSCOPE_OPERATOR` environment variable.

## Parsers

| Name | Artifact | Events |
|---|---|---|
| `filesystem` | Any file or directory (`lstat`) | Modified, accessed, changed (POSIX) and creation times, with nanoseconds kept in attributes |
| `bodyfile` | Sleuth Kit body file | atime / mtime / ctime / crtime per entry |
| `chromium_history` | Chrome, Edge, Brave, Opera `History` | Page visits with transition type, download start and finish |
| `firefox_history` | Firefox `places.sqlite` | Page visits with visit type, bookmarks added or modified |
| `evtx` | Windows `.evtx` (3.1 and Windows 11 3.2) | One event per record, including EventData and UserData fields |
| `mft` | Raw NTFS `$MFT` (1024- or 4096-byte records) | All four `$STANDARD_INFORMATION` and `$FILE_NAME` times per entry, with full path, in-use/deleted flag, entry and sequence numbers, and size. SI events flag possible timestomping: SI created before FN created, or whole-second SI times next to fractional FN times |

## Output

`export` writes the timeline in time order, with ties broken by fingerprint so the order is reproducible.

- **CSV** (default) has the columns `datetime, timestamp, timestamp_desc, message, source, artifact, evidence, path, attributes, fingerprint`. It imports directly into [Timesketch](https://timesketch.org/).
- **JSONL** (`-f jsonl`) has the same fields, with `attributes` as a nested object.

The SHA-256 of every export is recorded in the audit log.

## Desktop viewer

`chronoscope gui ./case-2024-017` opens a desktop timeline viewer built on Qt. You can also run `chronoscope gui` and choose a case with File > Open case. It needs the `gui` extra, which installs PySide6: `pip install 'chronoscope-forensics[gui]'`.

- Events are listed in timeline order and load in batches as you scroll, so large cases open quickly. Select one to see all of its fields and attributes.
- You can filter by text (message, path or description), artifact, evidence label, and time range. Times use ISO 8601 with an offset.
- **Possible timestomp** shows only `$MFT` entries with an SI/FN indicator. These rows are red. Deleted entries are grey.
- The case database is opened read-only (SQLite `mode=ro`), so browsing can't change the case. Viewing isn't recorded in the audit log.

## Forensic design

- **Evidence is opened read-only.** SQLite artifacts are never opened in place. Even a read-only open can create or modify `-wal`/`-shm` side files, and `immutable=1` silently skips the WAL, where the most recent activity often lives. Chronoscope copies the database and its `-wal`/`-journal` to a private temp directory and parses the copy. The tests prove the original's hash is unchanged and no side files appear.
- **Use a read-only source.** Reading files on a writable volume can update their last-access times, and no userland tool can fully prevent that. Ingest from a read-only mount, a write blocker, or a verified working copy. Chronoscope prints a warning, and records it in the audit log, whenever the evidence path is writable. File system timestamps are captured *before* each file is hashed or parsed.
- **Every consumed artifact is hashed.** Each file a parser reads, plus its WAL and journal side files, gets MD5, SHA-1, and SHA-256. Ingesting a single file always hashes that file. `verify` re-hashes all of them. In a directory, files that are only `stat`-ed are not hashed. Hash the source image itself at acquisition, as usual.
- **Times are never guessed.** `TimelineEvent` rejects timestamps without a time zone, so every parser has to deal with time zones explicitly. All output is UTC. `--start`/`--end` likewise require an explicit offset.
- **The audit log is hash-chained.** `audit.jsonl` records each action with time, operator, tool version, and details. Each entry includes the hash of the previous one, so editing, reordering, or deleting any entry is detected by `verify`. *Limitation:* a chain cannot detect that its newest entries were cut off, so record the head hash that `verify` prints in your notes.
- **Ingest is idempotent and atomic.** Each event has a SHA-256 fingerprint that includes its evidence label, so re-ingesting the same evidence adds no duplicates, while the same file on two different hosts is never merged. Each ingest is one database transaction. A parser that fails on a corrupt file has its partial output rolled back, and the error goes in the audit log.
- **CSV formula injection.** Attacker-controlled text, such as a page title of `=HYPERLINK(...)`, can become live when a CSV is opened in Excel. `--excel-safe` prefixes such cells with `'`. This alters the data, so its use is recorded in the audit log. The original values remain in the `attributes` JSON. Timesketch does not need this flag.

## Case layout

```
case-2024-017/
  case.json     case id, name, examiner, creation time, tool version
  case.db       SQLite: evidence, evidence_files (hashes), events
  audit.jsonl   hash-chained audit log
```

## Writing a parser

See [CONTRIBUTING.md](CONTRIBUTING.md). Parsers can live in this repository or ship as separate packages registered through the `chronoscope.parsers` entry-point group.

## Known limitations

- `python-evtx` is pure Python and slow, at roughly 3 minutes for a 20 MB log. A faster backend is planned.
- Disk images are supported through body files rather than opened directly.
- The `$MFT` parser does not follow `$ATTRIBUTE_LIST` into extension records, so a file with very many hard links can miss some names. Deleted entries whose parent directory was reused are placed under `/$OrphanFiles`.
- Planned next: prefetch, LNK, registry hives, and HTML/PDF reports.

## License

MIT. See [LICENSE](LICENSE).
