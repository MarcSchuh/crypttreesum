"""Tests for tree scanning and inode mapping."""

from __future__ import annotations

import errno
import logging
import os
from pathlib import Path

import pytest

from crypttreesum.exceptions import ScanError
from crypttreesum.models import EntryType, FolderRecord, Side
from crypttreesum.scan import ScanLimits, scan_trees


def _link_same_inode(src: Path, dest: Path) -> None:
    """Create ``dest`` as a hardlink to ``src`` so both share an inode."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    os.link(src, dest)


def test_scan_maps_encrypted_via_inode(tmp_path: Path) -> None:
    decrypted = tmp_path / "decrypted"
    encrypted = tmp_path / "encrypted"
    decrypted.mkdir()
    encrypted.mkdir()

    plain = decrypted / "Archiv" / "note.txt"
    plain.parent.mkdir()
    plain.write_text("secret note", encoding="utf-8")

    cipher = encrypted / "kny7b7nx" / "cipher.bin"
    _link_same_inode(plain, cipher)

    meta = encrypted / "gocryptfs.conf"
    meta.write_text("meta", encoding="utf-8")

    result = scan_trees(encrypted, decrypted)
    assert result.issues == []
    by_side_path = {(r.side, r.path): r for r in result.records}

    dec = by_side_path[(Side.DECRYPTED, "Archiv/note.txt")]
    enc = by_side_path[(Side.ENCRYPTED, "kny7b7nx/cipher.bin")]
    enc_meta = by_side_path[(Side.ENCRYPTED, "gocryptfs.conf")]

    assert dec.inode == enc.inode
    assert enc.logical_path == "Archiv/note.txt"
    assert dec.logical_path == "Archiv/note.txt"
    assert enc_meta.logical_path is None
    # Ciphertext and plaintext content hashes differ in real gocryptfs; here the
    # hardlink shares bytes, so digests match — that is fine for mapping tests.
    assert dec.sha256 == enc.sha256
    assert enc_meta.sha256 != dec.sha256


def test_max_depth_root_only(tmp_path: Path) -> None:
    decrypted = tmp_path / "decrypted"
    encrypted = tmp_path / "encrypted"
    decrypted.mkdir()
    encrypted.mkdir()

    (decrypted / "root.txt").write_text("root", encoding="utf-8")
    nested = decrypted / "dir" / "nested.txt"
    nested.parent.mkdir()
    nested.write_text("nested", encoding="utf-8")

    result = scan_trees(
        encrypted,
        decrypted,
        limits=ScanLimits(max_depth=0),
    )
    paths = [r.path for r in result.records if r.side is Side.DECRYPTED]
    assert paths == ["dir", "root.txt"]


def test_max_files_global_deterministic(tmp_path: Path) -> None:
    decrypted = tmp_path / "decrypted"
    encrypted = tmp_path / "encrypted"
    decrypted.mkdir()
    encrypted.mkdir()

    (decrypted / "a.txt").write_text("a", encoding="utf-8")
    (decrypted / "b.txt").write_text("b", encoding="utf-8")
    (encrypted / "z.txt").write_text("z", encoding="utf-8")

    records = scan_trees(
        encrypted,
        decrypted,
        limits=ScanLimits(max_files=2),
    ).records
    assert len(records) == 2
    assert [r.side for r in records] == [Side.DECRYPTED, Side.DECRYPTED]
    assert [r.path for r in records] == ["a.txt", "b.txt"]


def test_scan_rejects_missing_root(tmp_path: Path) -> None:
    with pytest.raises(ScanError, match="not a directory"):
        scan_trees(tmp_path / "missing", tmp_path)


def test_directories_are_always_included_and_have_no_hash(
    tmp_path: Path,
) -> None:
    decrypted = tmp_path / "decrypted"
    encrypted = tmp_path / "encrypted"
    (decrypted / "empty" / "nested").mkdir(parents=True)
    encrypted.mkdir()

    records = scan_trees(encrypted, decrypted).records
    assert [record.path for record in records] == ["empty", "empty/nested"]
    assert all(isinstance(record, FolderRecord) for record in records)
    assert all(record.entry_type is EntryType.DIRECTORY for record in records)
    assert all(not hasattr(record, "sha256") for record in records)


def test_max_files_does_not_count_directories(tmp_path: Path) -> None:
    decrypted = tmp_path / "decrypted"
    encrypted = tmp_path / "encrypted"
    (decrypted / "folder").mkdir(parents=True)
    (decrypted / "folder" / "a.txt").write_text("a", encoding="utf-8")
    (decrypted / "folder" / "b.txt").write_text("b", encoding="utf-8")
    encrypted.mkdir()

    records = scan_trees(
        encrypted,
        decrypted,
        limits=ScanLimits(max_files=1),
    ).records
    assert [record.path for record in records] == ["folder", "folder/a.txt"]


def test_duplicate_decrypted_inode_keeps_first_and_warns(
    tmp_path: Path,
    caplog,
) -> None:
    decrypted = tmp_path / "decrypted"
    encrypted = tmp_path / "encrypted"
    decrypted.mkdir()
    encrypted.mkdir()

    plain = decrypted / "a.txt"
    plain.write_text("shared", encoding="utf-8")
    _link_same_inode(plain, decrypted / "b.txt")
    _link_same_inode(plain, encrypted / "cipher.bin")

    with caplog.at_level(logging.WARNING, logger="crypttreesum.scan"):
        records = scan_trees(encrypted, decrypted).records

    by_side_path = {(r.side, r.path): r for r in records}
    assert by_side_path[(Side.ENCRYPTED, "cipher.bin")].logical_path == "a.txt"
    assert "duplicate decrypted inode" in caplog.text


def test_unreadable_file_is_recorded_without_hash(
    tmp_path: Path,
    monkeypatch,
    caplog,
) -> None:
    decrypted = tmp_path / "decrypted"
    encrypted = tmp_path / "encrypted"
    decrypted.mkdir()
    encrypted.mkdir()

    (decrypted / "good.txt").write_text("fine", encoding="utf-8")
    (decrypted / "broken.vob").write_text("boom", encoding="utf-8")

    def fake_sha256(path: Path) -> str:
        if path.name == "broken.vob":
            raise OSError(errno.EIO, "Input/output error", str(path))
        return "digest"

    monkeypatch.setattr("crypttreesum.scan.sha256_file", fake_sha256)

    with caplog.at_level(logging.ERROR, logger="crypttreesum.scan"):
        result = scan_trees(encrypted, decrypted)

    by_path = {record.path: record for record in result.records}
    assert by_path["broken.vob"].sha256 is None
    assert by_path["good.txt"].sha256 == "digest"

    [issue] = result.issues
    assert issue.operation == "hash"
    assert issue.side is Side.DECRYPTED
    assert issue.path == decrypted / "broken.vob"
    assert "Input/output error" in issue.message
    assert "cannot hash" in caplog.text


def test_unstatable_entry_is_skipped_and_reported(
    tmp_path: Path,
    monkeypatch,
) -> None:
    decrypted = tmp_path / "decrypted"
    encrypted = tmp_path / "encrypted"
    decrypted.mkdir()
    encrypted.mkdir()

    (decrypted / "good.txt").write_text("fine", encoding="utf-8")
    (decrypted / "broken.txt").write_text("boom", encoding="utf-8")

    real_stat = Path.stat

    def fake_stat(self: Path, *, follow_symlinks: bool = True) -> os.stat_result:
        if self.name == "broken.txt":
            raise OSError(errno.EIO, "Input/output error", str(self))
        return real_stat(self, follow_symlinks=follow_symlinks)

    monkeypatch.setattr(Path, "stat", fake_stat)

    result = scan_trees(encrypted, decrypted)

    assert [record.path for record in result.records] == ["good.txt"]
    [issue] = result.issues
    assert issue.operation == "stat"
    assert issue.path.name == "broken.txt"
