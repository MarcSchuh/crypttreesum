"""Tests for manifest diffs."""

import logging

from crypttreesum.diff import diff_manifests, format_diff_report
from crypttreesum.models import SCHEMA_VERSION, FileRecord, Side


def _rec(
    *,
    side: Side = Side.DECRYPTED,
    path: str = "a.txt",
    logical_path: str | None = "a.txt",
    sha256: str = "aaa",
    size: int = 1,
    inode: int = 1,
) -> FileRecord:
    return FileRecord(
        schema_version=SCHEMA_VERSION,
        side=side,
        inode=inode,
        path=path,
        logical_path=logical_path,
        sha256=sha256,
        size=size,
        mtime_ns=0,
    )


def test_identical_manifests_ok() -> None:
    records = [
        _rec(),
        _rec(
            side=Side.ENCRYPTED,
            path="cipher",
            logical_path="a.txt",
            sha256="bbb",
            inode=1,
        ),
    ]
    report = diff_manifests(records, list(records))
    assert report.ok


def test_hash_mismatch_and_missing() -> None:
    a = [
        _rec(sha256="aaa"),
        _rec(path="only_a.txt", logical_path="only_a.txt", sha256="x", inode=2),
        _rec(
            side=Side.ENCRYPTED,
            path="meta",
            logical_path=None,
            sha256="meta-a",
            inode=9,
        ),
    ]
    b = [
        _rec(sha256="zzz"),
        _rec(path="only_b.txt", logical_path="only_b.txt", sha256="y", inode=3),
        _rec(
            side=Side.ENCRYPTED,
            path="meta",
            logical_path=None,
            sha256="meta-b",
            inode=9,
        ),
    ]
    report = diff_manifests(a, b)
    assert not report.ok
    assert len(report.hash_mismatch) == 2  # a.txt + meta
    assert [r.logical_path for r in report.missing_in_b] == ["only_a.txt"]
    assert [r.logical_path for r in report.extra_in_b] == ["only_b.txt"]

    text = format_diff_report(report, label_a="a.jsonl", label_b="b.jsonl")
    assert "hash mismatch" in text
    assert "missing in b.jsonl" in text
    assert "DIFF" in text


def test_duplicate_identity_keeps_first_and_warns(caplog) -> None:
    records = [
        _rec(path="first.txt", sha256="aaa", inode=1),
        _rec(path="second.txt", sha256="bbb", inode=2),
    ]
    with caplog.at_level(logging.WARNING, logger="crypttreesum.diff"):
        report = diff_manifests(
            records,
            [_rec(path="first.txt", sha256="aaa", inode=1)],
        )

    assert report.ok
    assert "duplicate identity" in caplog.text
