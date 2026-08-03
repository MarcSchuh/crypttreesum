# CI/CD Setup

This repository uses GitHub Actions for continuous integration and deployment.

## Pipeline Overview

The CI pipeline consists of three jobs:

1. **Code Quality** — Ruff lint/format and MyPy
2. **Tests** — pytest with coverage
3. **Security** — Bandit and pip-audit

Additional workflows:

- **Build and Release** — PyInstaller binary on push to `main`
- **Dependency Update** — monthly `uv lock --upgrade`
- **Version Bump on Dependabot PRs** — automatic PATCH bump

## Required Status Checks

Configure these status checks in branch protection rules:

- `quality` (Code Quality)
- `test` (Tests)
- `security` (Security Scan)

## Local Development

```bash
./scripts/setup-dev.sh
uv run pytest
uv run ruff check src/ tests/
```

## Tools Used

- Python 3.13
- uv
- ruff
- mypy
- pytest
- bandit / pip-audit
- PyInstaller
