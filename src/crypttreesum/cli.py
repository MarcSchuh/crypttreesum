"""Command-line interface for crypttreesum."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from crypttreesum import __version__
from crypttreesum.diff import diff_manifests, format_diff_report
from crypttreesum.exceptions import CryptTreeSumError
from crypttreesum.manifest import read_manifest, write_manifest
from crypttreesum.scan import ScanLimits, scan_trees


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="crypttreesum",
        description=(
            "Inventory gocryptfs encrypted/decrypted trees and verify sync "
            "integrity via SHA-256 manifests."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser(
        "scan",
        help="Scan encrypted and decrypted trees into a JSONL manifest",
    )
    scan.add_argument(
        "--encrypted",
        type=Path,
        required=True,
        help="Root of the encrypted (ciphertext) tree",
    )
    scan.add_argument(
        "--decrypted",
        type=Path,
        required=True,
        help="Root of the decrypted (plaintext) tree",
    )
    scan.add_argument(
        "-o",
        "--output",
        type=Path,
        required=True,
        help="Output JSONL manifest path",
    )
    scan.add_argument(
        "--max-depth",
        type=int,
        default=None,
        help="Maximum directory depth from root (root = 0)",
    )
    scan.add_argument(
        "--max-files",
        type=int,
        default=None,
        help="Global maximum number of files to hash (testrun)",
    )

    diff = subparsers.add_parser(
        "diff",
        help="Compare two JSONL manifests and print detailed differences",
    )
    diff.add_argument("manifest_a", type=Path, help="First (reference) manifest")
    diff.add_argument("manifest_b", type=Path, help="Second (candidate) manifest")

    return parser


def _cmd_scan(args: argparse.Namespace) -> int:
    limits = ScanLimits(max_depth=args.max_depth, max_files=args.max_files)
    records = scan_trees(args.encrypted, args.decrypted, limits=limits)
    write_manifest(args.output, records)

    mapped = sum(1 for r in records if r.side.value == "encrypted" and r.logical_path)
    unmatched = sum(
        1 for r in records if r.side.value == "encrypted" and r.logical_path is None
    )
    decrypted = sum(1 for r in records if r.side.value == "decrypted")
    encrypted = sum(1 for r in records if r.side.value == "encrypted")

    print(
        f"wrote {len(records)} records to {args.output} "
        f"(decrypted={decrypted}, encrypted={encrypted}, "
        f"mapped={mapped}, unmatched_encrypted={unmatched})",
        file=sys.stderr,
    )
    return 0


def _cmd_diff(args: argparse.Namespace) -> int:
    records_a = read_manifest(args.manifest_a)
    records_b = read_manifest(args.manifest_b)
    report = diff_manifests(records_a, records_b)
    sys.stdout.write(
        format_diff_report(
            report,
            label_a=str(args.manifest_a),
            label_b=str(args.manifest_b),
        ),
    )
    return 0 if report.ok else 1


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "scan":
            return _cmd_scan(args)
        if args.command == "diff":
            return _cmd_diff(args)
    except CryptTreeSumError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    parser.error(f"unknown command: {args.command}")
    return 2  # pragma: no cover


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
