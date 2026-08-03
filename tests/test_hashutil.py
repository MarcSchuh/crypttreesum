"""Tests for hashing helpers."""

import hashlib
from pathlib import Path

from crypttreesum.hashutil import sha256_file


def test_sha256_file(tmp_path: Path) -> None:
    path = tmp_path / "sample.txt"
    payload = b"hello crypttreesum"
    path.write_bytes(payload)
    assert sha256_file(path) == hashlib.sha256(payload).hexdigest()
