"""Tests for logging configuration and progress output."""

from __future__ import annotations

import logging
from pathlib import Path

from crypttreesum.cli import main
from crypttreesum.logutil import LOGGER_NAME, configure_logging, get_logger


def test_configure_logging_levels() -> None:
    configure_logging(quiet=True)
    assert get_logger().level == logging.WARNING

    configure_logging(verbosity=0, quiet=False)
    assert get_logger().level == logging.INFO

    configure_logging(verbosity=1, quiet=False)
    assert get_logger().level == logging.DEBUG


def test_cli_scan_logs_progress(tmp_path: Path, capsys) -> None:
    decrypted = tmp_path / "decrypted"
    encrypted = tmp_path / "encrypted"
    decrypted.mkdir()
    encrypted.mkdir()
    (decrypted / "file.txt").write_text("payload", encoding="utf-8")

    out = tmp_path / "out.jsonl"
    assert (
        main(
            [
                "scan",
                "--encrypted",
                str(encrypted),
                "--decrypted",
                str(decrypted),
                "-o",
                str(out),
            ],
        )
        == 0
    )

    err = capsys.readouterr().err
    assert "starting scan" in err
    assert "hashing [1/1] decrypted: file.txt" in err
    assert "writing 1 records" in err


def test_cli_quiet_suppresses_info(tmp_path: Path, capsys) -> None:
    decrypted = tmp_path / "decrypted"
    encrypted = tmp_path / "encrypted"
    decrypted.mkdir()
    encrypted.mkdir()
    (decrypted / "file.txt").write_text("payload", encoding="utf-8")

    out = tmp_path / "out.jsonl"
    assert (
        main(
            [
                "-q",
                "scan",
                "--encrypted",
                str(encrypted),
                "--decrypted",
                str(decrypted),
                "-o",
                str(out),
            ],
        )
        == 0
    )

    err = capsys.readouterr().err
    assert "starting scan" not in err
    assert "hashing" not in err


def test_get_logger_nests_under_package() -> None:
    assert get_logger("scan").name == f"{LOGGER_NAME}.scan"
