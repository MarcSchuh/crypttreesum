"""Command-line interface for crypttreesum."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from crypttreesum import __version__
from crypttreesum.diff import diff_manifests, format_diff_report
from crypttreesum.exceptions import CryptTreeSumError
from crypttreesum.logutil import configure_logging, get_logger
from crypttreesum.manifest import read_manifest, write_manifest
from crypttreesum.models import EntryType, Side
from crypttreesum.scan import ScanLimits, scan_trees

_LOG = get_logger("cli")


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
    verbosity = parser.add_mutually_exclusive_group()
    verbosity.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Enable debug logging (repeatable)",
    )
    verbosity.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Only show warnings and errors",
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
    limits = ScanLimits(
        max_depth=args.max_depth,
        max_files=args.max_files,
    )
    records = scan_trees(args.encrypted, args.decrypted, limits=limits)
    write_manifest(args.output, records)

    mapped = sum(1 for r in records if r.side is Side.ENCRYPTED and r.logical_path)
    unmatched = sum(
        1 for r in records if r.side is Side.ENCRYPTED and r.logical_path is None
    )
    decrypted = sum(1 for r in records if r.side is Side.DECRYPTED)
    encrypted = sum(1 for r in records if r.side is Side.ENCRYPTED)
    directories = sum(
        1 for record in records if record.entry_type is EntryType.DIRECTORY
    )

    _LOG.info(
        "wrote %d records to %s "
        "(decrypted=%d, encrypted=%d, directories=%d, mapped=%d, "
        "unmatched_encrypted=%d)",
        len(records),
        args.output,
        decrypted,
        encrypted,
        directories,
        mapped,
        unmatched,
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
    configure_logging(verbosity=args.verbose, quiet=args.quiet)
    try:
        if args.command == "scan":
            return _cmd_scan(args)
        if args.command == "diff":
            return _cmd_diff(args)
    except CryptTreeSumError as exc:
        _LOG.error("%s", exc)
        return 2

    parser.error(f"unknown command: {args.command}")
    return 2  # pragma: no cover


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
