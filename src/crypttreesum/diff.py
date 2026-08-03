"""Compare two scan manifests."""

from __future__ import annotations

from dataclasses import dataclass, field

from crypttreesum.models import FileRecord


@dataclass(slots=True)
class DiffReport:
    """Detailed differences between two manifests."""

    missing_in_b: list[FileRecord] = field(default_factory=list)
    extra_in_b: list[FileRecord] = field(default_factory=list)
    hash_mismatch: list[tuple[FileRecord, FileRecord]] = field(default_factory=list)
    path_mismatch: list[tuple[FileRecord, FileRecord]] = field(default_factory=list)
    size_mismatch: list[tuple[FileRecord, FileRecord]] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """True when no differences were found."""
        return not (
            self.missing_in_b
            or self.extra_in_b
            or self.hash_mismatch
            or self.path_mismatch
            or self.size_mismatch
        )

    def summary_counts(self) -> dict[str, int]:
        """Return category counts."""
        return {
            "missing_in_b": len(self.missing_in_b),
            "extra_in_b": len(self.extra_in_b),
            "hash_mismatch": len(self.hash_mismatch),
            "path_mismatch": len(self.path_mismatch),
            "size_mismatch": len(self.size_mismatch),
        }


def _index_by_identity(records: list[FileRecord]) -> dict[tuple[str, str], FileRecord]:
    indexed: dict[tuple[str, str], FileRecord] = {}
    for record in records:
        key = record.identity_key()
        if key in indexed:
            continue
        indexed[key] = record
    return indexed


def diff_manifests(
    records_a: list[FileRecord],
    records_b: list[FileRecord],
) -> DiffReport:
    """Diff two manifests.

    Identity is ``(side, logical_path)`` when mapped, otherwise ``(side, path)``
    for unmatched encrypted metadata. SHA-256 equality is the primary integrity
    check across sync hosts.
    """
    index_a = _index_by_identity(records_a)
    index_b = _index_by_identity(records_b)

    report = DiffReport()

    for key, rec_a in sorted(index_a.items()):
        rec_b = index_b.get(key)
        if rec_b is None:
            report.missing_in_b.append(rec_a)
            continue
        if rec_a.sha256 != rec_b.sha256:
            report.hash_mismatch.append((rec_a, rec_b))
        if rec_a.path != rec_b.path:
            report.path_mismatch.append((rec_a, rec_b))
        if rec_a.size != rec_b.size:
            report.size_mismatch.append((rec_a, rec_b))

    for key, rec_b in sorted(index_b.items()):
        if key not in index_a:
            report.extra_in_b.append(rec_b)

    return report


def _fmt_record(record: FileRecord) -> str:
    logical = record.logical_path if record.logical_path is not None else "-"
    return (
        f"side={record.side.value} path={record.path} "
        f"logical_path={logical} inode={record.inode} "
        f"sha256={record.sha256} size={record.size}"
    )


def _append_pair_section(
    lines: list[str],
    title: str,
    pairs: list[tuple[FileRecord, FileRecord]],
) -> None:
    if not pairs:
        return
    lines.append("")
    lines.append(f"{title}:")
    for rec_a, rec_b in pairs:
        lines.append(f"  a: {_fmt_record(rec_a)}")
        lines.append(f"  b: {_fmt_record(rec_b)}")


def format_diff_report(report: DiffReport, *, label_a: str, label_b: str) -> str:
    """Render a human-readable detailed diff."""
    lines: list[str] = [
        f"Comparing {label_a} -> {label_b}",
        "summary: "
        + ", ".join(
            f"{name}={count}" for name, count in report.summary_counts().items()
        ),
        f"result: {'OK' if report.ok else 'DIFF'}",
    ]

    if report.missing_in_b:
        lines.append("")
        lines.append(f"missing in {label_b}:")
        lines.extend(f"  - {_fmt_record(record)}" for record in report.missing_in_b)

    if report.extra_in_b:
        lines.append("")
        lines.append(f"extra in {label_b}:")
        lines.extend(f"  + {_fmt_record(record)}" for record in report.extra_in_b)

    _append_pair_section(lines, "hash mismatch", report.hash_mismatch)
    _append_pair_section(
        lines,
        "path mismatch (same identity, different side path)",
        report.path_mismatch,
    )
    _append_pair_section(lines, "size mismatch", report.size_mismatch)

    return "\n".join(lines) + "\n"
