#!/usr/bin/env bash
# Run every local quality gate, mirroring the CI workflow. Offline; no AWS access.
set -euo pipefail

cd "$(dirname "$0")/.."
BIN="${VENV_BIN:-.venv/bin}"

echo "== ruff (lint + format check)"
"$BIN/ruff" check src tests scripts
"$BIN/ruff" format --check src tests scripts

echo "== mypy (strict)"
"$BIN/mypy" src

echo "== pytest"
"$BIN/python" -m pytest -q

echo "== bandit"
"$BIN/bandit" -q -r src -c pyproject.toml

echo "== pip-audit"
"$BIN/pip-audit" --progress-spinner off --skip-editable

echo "== detect-secrets"
"$BIN/detect-secrets" scan --all-files \
  --exclude-files '\.venv/.*|\.git/.*|.*_cache/.*|reports/dev/.*' \
  --baseline .secrets.baseline

echo "== scenario fixtures in sync"
"$BIN/python" scripts/build_scenarios.py --check

echo "== built-in self-check"
"$BIN/python" -m attackpath validate

echo "all checks passed"
