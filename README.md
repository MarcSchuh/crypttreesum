# crypttreesum

Standalone Ubuntu CLI to inventory gocryptfs encrypted/decrypted trees and verify sync integrity via SHA-256.

For installation, ask your LLM.

## Usage

### Scan

```bash
crypttreesum scan \
  --encrypted /path/to/dropbox_encrypted \
  --decrypted /path/to/dropbox_unencrypted \
  -o host-a.jsonl
```

Testrun limits (depth from root = 0, max files global, path-sorted):

```bash
crypttreesum scan \
  --encrypted ./encrypted \
  --decrypted ./decrypted \
  -o sample.jsonl \
  --max-depth 1 \
  --max-files 50
```

Directory records (`entry_type: "directory"`) are always included and have no
`sha256` field. The root directories themselves are not included.
`--max-files` limits hashed files only, not directory entries.

Unreadable files (e.g. I/O errors while hashing) do **not** abort the scan.
They are written with `"sha256": null`, the scan continues, and every failure
is listed once more at the end. Exit code stays `0` as long as the manifest
could be written. `diff` reports such pairs as `unverified` instead of a
hash mismatch.

**Breaking (2.0.0):** file records may carry `"sha256": null`; `scan_trees`
returns a `ScanResult` (`records` + `issues`) instead of a bare list.

### Diff

Compare two manifests of the same construct (e.g. after sync to another host):

```bash
crypttreesum diff host-a.jsonl host-b.jsonl
```

Exit code `0` means match; `1` means differences; `2` means error.

## Manifest

JSONL, one record per file/directory per side. Encrypted entries are mapped to cleartext paths via matching inode numbers (`ls -i`). Unmatched encrypted metadata (`gocryptfs.conf`, `gocryptfs.diriv`, …) keep `logical_path: null`. Unreadable files keep `sha256: null`.
