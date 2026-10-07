"""Evidence hashing."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass
from pathlib import Path

CHUNK_SIZE = 1 << 20


@dataclass(frozen=True)
class FileHashes:
    size: int
    md5: str
    sha1: str
    sha256: str

    def as_dict(self) -> dict[str, str | int]:
        return asdict(self)


def hash_file(path: str | Path) -> FileHashes:
    """Compute MD5, SHA-1 and SHA-256 in a single streaming pass."""
    md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
    size = 0
    with open(path, "rb") as fh:
        while chunk := fh.read(CHUNK_SIZE):
            size += len(chunk)
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return FileHashes(size, md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest())
