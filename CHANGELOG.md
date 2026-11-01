# Changelog

All notable changes to Chronoscope are listed here. Versions follow [PEP 440](https://peps.python.org/pep-0440/); `a` releases are alphas for testing and feedback.

## 0.1.0a1 (alpha 1)

First release for outside testing. Results have not yet been validated on real casework, so check anything you rely on against a second tool, and please report what you find (see [Alpha testing](README.md#alpha-testing)).

### Ingest

- Case folders with a SQLite timeline, evidence hashing (MD5, SHA-1, SHA-256) and a hash-chained audit log; `chronoscope verify` checks both.
- Parsers: file system metadata, Sleuth Kit body files, Chromium and Firefox history (including `-wal` and `-journal` files), Windows event logs (`evtx` extra) and raw NTFS `$MFT` files with SI and FN times, full paths, deleted entries and timestomp indicators.
- Containers, read in place without extracting: zip, tar (`.tar.gz`, `.tar.bz2`, `.tar.xz`), 7z (`archives` extra), EnCase `.E01`/`.Ex01` and raw or split raw images with MBR or GPT partitions (`images` extra), and Cellebrite UFED `.ufd` descriptors. Every file inside gets its timestamps, and recognised artifacts inside are parsed.
- Zip members with only a DOS time and FAT/exFAT files get no timestamp events, since those times have no zone; they are counted in a warning.
- A clear note when an ingested file matched no artifact parser and only its own file times were recorded.

### Export

- CSV (with an Excel-safe option) and Timesketch-compatible JSONL, with inclusive `--start`/`--end` filters. Exports are hashed and recorded in the audit log, and the same case always gives byte-identical output.

### Desktop app

- `chronoscope gui` (`gui` extra): a Qt timeline viewer with text, artifact, evidence, time, flagged and deleted filters, plus ingest and export dialogs.

### Validation tools

- `tools/compare_mftecmd.py` compares the `$MFT` parser with Eric Zimmerman's MFTECmd.
- `tools/compare_plaso.py` compares a whole timeline with plaso's `psort` output.
