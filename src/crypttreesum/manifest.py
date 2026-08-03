"""JSONL manifest read/write."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from crypttreesum.exceptions import ManifestError
from crypttreesum.logutil import get_logger
from crypttreesum.models import SCHEMA_VERSION, ManifestRecord, record_from_dict

_LOG = get_logger("manifest")


def write_manifest(path: Path, records: list[ManifestRecord]) -> None:
    """Write manifest records as JSONL (one object per line)."""
    _LOG.info("writing %d records to %s", len(records), path)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as handle:
            for record in records:
                handle.write(json.dumps(record.to_dict(), ensure_ascii=False))
                handle.write("\n")
    except OSError as exc:
        msg = f"cannot write manifest {path}: {exc}"
        raise ManifestError(msg) from exc
    _LOG.info("wrote manifest %s", path)


def read_manifest(path: Path) -> list[ManifestRecord]:
    """Read a JSONL manifest into file records."""
    if not path.is_file():
        msg = f"manifest not found: {path}"
        raise ManifestError(msg)

    _LOG.info("reading manifest %s", path)
    records: list[ManifestRecord] = []
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
                    record = record_from_dict(data)
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

    _LOG.info("loaded %d records from %s", len(records), path)
    return records
