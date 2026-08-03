"""CLI smoke tests."""

from __future__ import annotations

import os
from pathlib import Path

from crypttreesum.cli import main
from crypttreesum.manifest import read_manifest
from crypttreesum.models import EntryType, FolderRecord


def test_cli_scan_and_diff(tmp_path: Path) -> None:
    decrypted = tmp_path / "decrypted"
    encrypted = tmp_path / "encrypted"
    decrypted.mkdir()
    encrypted.mkdir()

    plain = decrypted / "file.txt"
    plain.write_text("payload", encoding="utf-8")
    cipher = encrypted / "cipher"
    os.link(plain, cipher)
    (encrypted / "gocryptfs.conf").write_text("conf", encoding="utf-8")

    out_a = tmp_path / "a.jsonl"
    out_b = tmp_path / "b.jsonl"

    assert (
        main(
            [
                "scan",
                "--encrypted",
                str(encrypted),
                "--decrypted",
                str(decrypted),
                "-o",
                str(out_a),
            ],
        )
        == 0
    )
    assert (
        main(
            [
                "scan",
                "--encrypted",
                str(encrypted),
                "--decrypted",
                str(decrypted),
                "-o",
                str(out_b),
                "--max-files",
                "10",
            ],
        )
        == 0
    )

    records = read_manifest(out_a)
    assert len(records) == 3
    assert main(["diff", str(out_a), str(out_b)]) == 0


def test_cli_diff_detects_change(tmp_path: Path, capsys) -> None:
    decrypted = tmp_path / "decrypted"
    encrypted = tmp_path / "encrypted"
    decrypted.mkdir()
    encrypted.mkdir()
    (decrypted / "file.txt").write_text("one", encoding="utf-8")

    out_a = tmp_path / "a.jsonl"
    assert (
        main(
            [
                "scan",
                "--encrypted",
                str(encrypted),
                "--decrypted",
                str(decrypted),
                "-o",
                str(out_a),
            ],
        )
        == 0
    )

    (decrypted / "file.txt").write_text("two", encoding="utf-8")
    out_b = tmp_path / "b.jsonl"
    assert (
        main(
            [
                "scan",
                "--encrypted",
                str(encrypted),
                "--decrypted",
                str(decrypted),
                "-o",
                str(out_b),
            ],
        )
        == 0
    )

    assert main(["diff", str(out_a), str(out_b)]) == 1
    captured = capsys.readouterr()
    assert "hash mismatch" in captured.out


def test_cli_scan_includes_directories_on_request(tmp_path: Path) -> None:
    decrypted = tmp_path / "decrypted"
    encrypted = tmp_path / "encrypted"
    (decrypted / "empty").mkdir(parents=True)
    encrypted.mkdir()
    output = tmp_path / "manifest.jsonl"

    assert (
        main(
            [
                "scan",
                "--encrypted",
                str(encrypted),
                "--decrypted",
                str(decrypted),
                "--include-directories",
                "-o",
                str(output),
            ],
        )
        == 0
    )

    [record] = read_manifest(output)
    assert isinstance(record, FolderRecord)
    assert record.entry_type is EntryType.DIRECTORY
    assert not hasattr(record, "sha256")
