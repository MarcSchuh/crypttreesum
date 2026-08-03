"""JSONL manifest read/write."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from crypttreesum.exceptions import ManifestError
from crypttreesum.models import SCHEMA_VERSION, FileRecord


def write_manifest(path: Path, records: list[FileRecord]) -> None:
    """Write file records as JSONL (one object per line)."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as handle:
            for record in records:
                handle.write(json.dumps(record.to_dict(), ensure_ascii=False))
                handle.write("\n")
    except OSError as exc:
        msg = f"cannot write manifest {path}: {exc}"
        raise ManifestError(msg) from exc


def read_manifest(path: Path) -> list[FileRecord]:
    """Read a JSONL manifest into file records."""
    if not path.is_file():
        msg = f"manifest not found: {path}"
        raise ManifestError(msg)

    records: list[FileRecord] = []
    try:
        with path.open(encoding="utf-8") as handle:
            for line_no, raw in enumerate(handle, start=1):
                line = raw.strip()
                if not line:
                    continue
                try:
                    data: dict[str, Any] = json.loads(line)
                except json.JSONDecodeError as exc:
                    msg = f"invalid JSON on line {line_no} in {path}: {exc}"
                    raise ManifestError(msg) from exc
                try:
                    record = FileRecord.from_dict(data)
                except (KeyError, TypeError, ValueError) as exc:
                    msg = f"invalid record on line {line_no} in {path}: {exc}"
                    raise ManifestError(msg) from exc
                if record.schema_version != SCHEMA_VERSION:
                    msg = (
                        f"unsupported schema_version {record.schema_version} "
                        f"on line {line_no} in {path} "
                        f"(expected {SCHEMA_VERSION})"
                    )
                    raise ManifestError(msg)
                records.append(record)
    except OSError as exc:
        msg = f"cannot read manifest {path}: {exc}"
        raise ManifestError(msg) from exc

    return records
