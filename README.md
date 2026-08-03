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

**Breaking (1.0.0):** `--include-directories` was removed; directory records are
always emitted. Manifests from older versions without directory records will
diff as missing/extra directories against new scans.

### Diff

Compare two manifests of the same construct (e.g. after sync to another host):

```bash
crypttreesum diff host-a.jsonl host-b.jsonl
```

Exit code `0` means match; `1` means differences; `2` means error.

## Manifest

JSONL, one record per file per side. Encrypted entries are mapped to cleartext paths via matching inode numbers (`ls -i`). Unmatched encrypted metadata (`gocryptfs.conf`, `gocryptfs.diriv`, …) keep `logical_path: null`.
