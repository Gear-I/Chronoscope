"""Tar and 7z archives and disk images (E01, raw, split raw, partitioned), end to end."""

from __future__ import annotations

import gzip
import io
import os
import shutil
import tarfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

from chronoscope.containers import container_kind
from chronoscope.hashing import hash_file
from chronoscope.ingest import ingest
from chronoscope.parsers import discover

from .conftest import DOWNLOAD_START, VISIT_IN_DB, VISIT_IN_WAL, make_chrome_history
from .test_mft import build_mft

DATA = Path(__file__).parent / "data" / "dfvfs"
CHROME = "data/data/com.android.chrome/app_chrome/Default"
PAX_M = "1714636862.123456789"  # 2024-05-02T08:01:02.123456789Z
PAX_A = "1714723200.5"
PAX_C = "1714500000"
PAX_B = "1704067200.25"

needs_7z = pytest.mark.skipif(
    "7z" not in discover(include_plugins=False).parsers, reason="py7zr not installed"
)
needs_tsk = pytest.mark.skipif(
    "disk_image" not in discover(include_plugins=False).parsers,
    reason="pytsk3/libewf-python not installed",
)


def _us(dt: datetime) -> int:
    return int((dt - datetime(1970, 1, 1, tzinfo=timezone.utc)).total_seconds() * 1_000_000)


def _iso(events, path: str, desc: str) -> str:
    [event] = [e for e in events if e.path == path and e.timestamp_desc == desc]
    return event.datetime


def _chrome_files(tmp_path: Path) -> tuple[bytes, bytes]:
    history = make_chrome_history(tmp_path / "staging")
    return history.read_bytes(), history.with_name("History-wal").read_bytes()


def _visits(case) -> list[int]:
    return sorted(
        e.timestamp_us
        for e in case.iter_events()
        if e.artifact == "chromium_history" and e.timestamp_desc == "Page Visited"
    )


# -- tar ---------------------------------------------------------------------------------


def make_tar(path: Path, tmp_path: Path) -> Path:
    history, wal = _chrome_files(tmp_path)
    with tarfile.open(path, "w:gz", format=tarfile.PAX_FORMAT) as tf:
        # The -wal comes first: the database must still be parsed with it.
        for name, data in ((f"{CHROME}/History-wal", wal), (f"{CHROME}/History", history)):
            info = tarfile.TarInfo(f"./{name}")
            info.size = len(data)
            info.mtime = 1714636862
            info.pax_headers = {
                "mtime": PAX_M,
                "atime": PAX_A,
                "ctime": PAX_C,
                "LIBARCHIVE.creationtime": PAX_B,
            }
            tf.addfile(info, io.BytesIO(data))
        plain = tarfile.TarInfo("system/notes.txt")
        plain.size, plain.mtime = 3, 1700000000
        tf.addfile(plain, io.BytesIO(b"hi\n"))
    return path


def test_tar_gz_member_times_and_artifacts(case, tmp_path):
    archive = make_tar(tmp_path / "ffs.tar.gz", tmp_path)
    assert container_kind(archive) == "tar"
    result = ingest(case, archive, label="PHONE")
    assert not result.errors
    assert result.per_parser["chromium_history"] == 3
    assert result.archive_members == 3
    assert result.archive_members_parsed == 1
    assert _visits(case) == [_us(VISIT_IN_DB), _us(VISIT_IN_WAL)]  # the WAL came first

    events = list(case.iter_events())
    history = f"ffs.tar.gz/{CHROME}/History"
    assert _iso(events, history, "Content Modification Time") == "2024-05-02T08:01:02.123456Z"
    assert _iso(events, history, "Last Access Time") == "2024-05-03T08:00:00.500000Z"
    assert _iso(events, history, "Metadata Change Time") == "2024-04-30T18:00:00.000000Z"
    assert _iso(events, history, "Creation Time") == "2024-01-01T00:00:00.250000Z"
    notes = "ffs.tar.gz/system/notes.txt"
    assert _iso(events, notes, "Content Modification Time") == "2023-11-14T22:13:20.000000Z"
    download = next(e for e in events if e.timestamp_desc == "Download Started")
    assert download.timestamp_us == _us(DOWNLOAD_START)
    assert download.path == history


# -- 7z ----------------------------------------------------------------------------------


@needs_7z
def test_7z_member_times_and_artifacts(case, tmp_path):
    import py7zr

    history, wal = _chrome_files(tmp_path)
    staging = tmp_path / "files"
    staging.mkdir()
    stamp_ns = 1714636862_500000000  # py7zr stores times via a float; .5 s is exact
    for name, data in (("History", history), ("History-wal", wal), ("$MFT", build_mft())):
        (staging / name).write_bytes(data)
        os.utime(staging / name, ns=(stamp_ns, stamp_ns))
    archive = tmp_path / "Extraction.7z"
    with py7zr.SevenZipFile(archive, "w") as z:
        for name in ("History", "History-wal", "$MFT"):
            z.write(staging / name, f"{CHROME}/{name}" if "History" in name else f"C/{name}")

    assert container_kind(archive) == "7z"
    result = ingest(case, archive, label="PC")
    assert not result.errors
    assert result.per_parser["chromium_history"] == 3
    assert result.per_parser["mft"] == 68
    assert _visits(case) == [_us(VISIT_IN_DB), _us(VISIT_IN_WAL)]
    events = list(case.iter_events())
    assert _iso(events, "Extraction.7z/C/$MFT", "Content Modification Time") == (
        "2024-05-02T08:01:02.500000Z"
    )


# -- disk images -------------------------------------------------------------------------


def _gunzip(name: str, dest: Path) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(DATA / f"{name}.gz", "rb") as src, open(dest, "wb") as dst:
        shutil.copyfileobj(src, dst)
    return dest


@needs_tsk
def test_ntfs_image_member_times_agree_with_the_mft_parser(case, tmp_path):
    image = _gunzip("ntfs.raw", tmp_path / "evidence" / "ntfs.raw")
    before = hash_file(image).sha256
    assert container_kind(image) == "raw"

    result = ingest(case, image, label="PC")

    assert not result.errors
    assert hash_file(image).sha256 == before
    assert result.per_parser["mft"] > 0  # $MFT inside the image was found and parsed
    events = list(case.iter_events())
    a_file = "ntfs.raw/a_directory/a_file"
    tsk_mtime = _iso(events, a_file, "Content Modification Time")
    assert tsk_mtime == "2019-08-31T10:22:59.958178Z"
    # Two independent readings of the same NTFS record: TSK's walk and Chronoscope's own
    # $MFT parser (SI times, entry 65) must agree.
    [si] = [
        e
        for e in events
        if e.artifact == "mft"
        and e.timestamp_desc == "SI Modified"
        and '"entry":65,' in e.attributes
    ]
    assert si.datetime == tsk_mtime
    assert si.path == "/a_directory/a_file"
    assert '"file_system":"NTFS"' in next(e.attributes for e in events if e.path == a_file)


@needs_tsk
def test_e01_image(case, tmp_path):
    image = tmp_path / "ext2.E01"
    shutil.copyfile(DATA / "ext2.E01", image)
    assert container_kind(image) == "ewf"
    result = ingest(case, image, label="SRV")
    assert not result.errors
    events = list(case.iter_events())
    assert _iso(events, "ext2.E01/passwords.txt", "Content Modification Time") == (
        "2021-07-22T14:07:32.000000Z"
    )
    assert _iso(events, "ext2.E01/a_directory/a_file", "Last Access Time")
    assert {f.relpath for f in case.evidence_files()} == {"ext2.E01"}


@needs_tsk
def test_partitioned_image_and_split_raw(case, tmp_path):
    image = _gunzip("mbr.raw", tmp_path / "disk" / "mbr.raw")
    result = ingest(case, image, label="DISK")
    assert not result.errors
    paths = {e.path for e in case.iter_events() if e.artifact == "disk_image"}
    assert "mbr.raw/partition2/passwords.txt" in paths
    assert "mbr.raw/partition6/passwords.txt" in paths

    # The same image split into three segments gives the same members.
    split = tmp_path / "split"
    split.mkdir()
    data = image.read_bytes()
    third = len(data) // 3 + 1
    for i in range(3):
        (split / f"mbr.{i + 1:03d}").write_bytes(data[i * third : (i + 1) * third])
    result = ingest(case, split / "mbr.001", label="DISK2")
    assert not result.errors
    hashed = {f.relpath for f in case.evidence_files() if f.label == "DISK2"}
    assert hashed == {"mbr.001", "mbr.002", "mbr.003"}
    split_paths = {
        e.path.replace("mbr.001/", "mbr.raw/")
        for e in case.iter_events()
        if e.artifact == "disk_image" and e.evidence_label == "DISK2"
    }
    assert split_paths == paths


@needs_tsk
def test_fat_times_are_not_guessed(case, tmp_path):
    image = _gunzip("fat12.raw", tmp_path / "usb" / "fat12.raw")
    result = ingest(case, image, label="USB")
    assert not result.errors
    assert not [e for e in case.iter_events() if e.artifact == "disk_image"]
    assert any(
        "have no usable timestamps (FAT/exFAT times are local time without a zone)" in w
        for w in result.warnings
    )
    assert result.archive_members >= 3  # contents were still scanned


@needs_tsk
def test_ufd_naming_a_physical_bin_image(case, tmp_path):
    folder = tmp_path / "physical"
    image = _gunzip("ntfs.raw", folder / "PHYSICAL.bin")
    ufd = folder / "Physical.ufd"
    ufd.write_text("[Dumps]\nImage=PHYSICAL.bin\n", encoding="utf-8")
    result = ingest(case, ufd, label="DEV")
    assert not result.errors
    assert result.per_parser["mft"] > 0
    assert {f.relpath for f in case.evidence_files()} == {"Physical.ufd", "PHYSICAL.bin"}
    assert image.exists()


def test_container_kind_detection(tmp_path):
    (tmp_path / "notes.txt").write_text("hello", encoding="utf-8")
    assert container_kind(tmp_path / "notes.txt") is None
    (tmp_path / "fake.zip").write_bytes(b"not a zip")
    assert container_kind(tmp_path / "fake.zip") is None
    (tmp_path / "x.7z").write_bytes(b"7z\xbc\xaf\x27\x1c" + b"\x00" * 32)
    assert container_kind(tmp_path / "x.7z") == "7z"
    (tmp_path / "blank.img").write_bytes(b"\x00" * 4096)
    assert container_kind(tmp_path / "blank.img") is None  # no boot sector or partition table
    (tmp_path / "fake.E01").write_bytes(b"MZ" + b"\x00" * 64)
    assert container_kind(tmp_path / "fake.E01") is None
    (tmp_path / "Report.002").write_bytes(b"\x00" * 1024)
    assert container_kind(tmp_path / "Report.002") is None  # only the first segment


@needs_tsk
def test_corrupt_image_is_an_error_not_a_crash(case, tmp_path):
    bad = tmp_path / "broken.dd"
    bad.write_bytes(b"\x00" * 510 + b"\x55\xaa" + b"\x00" * 4096)  # boot signature, no fs
    result = ingest(case, bad, label="X")
    assert any("no partition table or file system" in w for w in result.warnings + result.errors)
