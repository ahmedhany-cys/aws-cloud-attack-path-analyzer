# Security design

A tool that reads security configuration is itself a target: it is fed untrusted files, it may
hold credentials for an account, and its output is read by people who make decisions from it.
This page lists the safeguards built in and where each one lives.

## Untrusted input

| Safeguard | Where |
|---|---|
| JSON only, parsed with the standard library; no YAML, no pickle, no `eval`, no code execution | `parser/loader.py` |
| Size limit before reading (default 25 MiB, `--max-input-mb`), strict UTF-8 decoding, nesting-depth limit (64), explicit handling of `RecursionError` | `parser/loader.py` |
| Strict schema validation: unknown top-level and statement elements rejected; types, ARN shapes, account ids, enumerations and duplicates checked with precise error locations | `parser/environment_parser.py`, `parser/policy_parser.py` |
| Entity and graph limits (principals, resources, nodes, edges, paths, findings) raising `LimitExceededError` instead of exhausting memory | `config.py`, `graph/model.py`, `graph/paths.py`, `analysis/engine.py` |
| Scoring configuration is TOML parsed with `tomllib`, size-limited and validated | `scoring/model.py` |
| Wildcard patterns are compiled with every character except `*`/`?` escaped (no regex injection) | `iam/matching.py` |

## Output

| Safeguard | Where |
|---|---|
| HTML report: every string passes through `html.escape(quote=True)`; no JavaScript; `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'`; no external resources | `reporting/html_report.py` |
| Markdown report: `<`, `>` and `|` escaped in prose and in code spans; Mermaid labels sanitized; fenced blocks cannot be broken out of | `reporting/markdown_report.py`, `reporting/common.py` |
| JSON report: produced by `json.dumps` from dataclasses; no string concatenation | `reporting/json_report.py` |
| Reports from synthetic inputs carry a prominent notice | all renderers |
| The dashboard never uses `unsafe_allow_html` | `dashboard/app.py` |

## AWS access

| Safeguard | Where |
|---|---|
| The offline analyzer makes no network calls; `boto3` is imported only inside the `aws` package, `streamlit` only inside `dashboard` | package layout |
| Scanning requires an explicit profile, region and `--confirm`; without `--confirm` the planned operations are printed and no API call is made | `aws/scan.py` |
| A botocore `before-call` handler rejects any operation outside the documented read-only allow list, so a code change elsewhere cannot make the adapter write | `aws/safeguards.py` |
| Root credentials are refused (caller ARN ending in `:root`) | `aws/scan.py` |
| Credentials are never printed, logged or written; snapshots are written with mode `0600` into a Git-ignored directory | `aws/scan.py`, `.gitignore` |
| Access-denied and throttling responses are handled and recorded as coverage gaps; partial inventories are labelled as such | `aws/inventory.py` |
| Nothing is uploaded anywhere; there is no telemetry | whole code base |

## Supply chain and repository

| Safeguard | Where |
|---|---|
| Zero runtime dependencies for the offline analyzer; optional extras for AWS and the dashboard | `pyproject.toml` |
| Dependency version ranges plus Dependabot for pip and GitHub Actions | `pyproject.toml`, `.github/dependabot.yml` |
| `pip-audit` in CI and in `make security` | `.github/workflows/ci.yml`, `Makefile` |
| `bandit` static analysis (configured in `pyproject.toml`) | CI, `make security` |
| Secret scanning: `detect-secrets` against a committed baseline on every tracked file, `gitleaks` over the full history | CI, `.secrets.baseline` |
| GitHub Actions pinned to commit SHAs; workflow token restricted to `contents: read`; `persist-credentials: false`; no repository secrets, no AWS credentials in CI | `.github/workflows/ci.yml` |
| Synthetic fixtures use fictional account ids and key ids that do not match real AWS formats | `fixtures/` |
| Local scan output and generated reports are Git-ignored except the labelled sample | `.gitignore` |

## Process

| Safeguard | Where |
|---|---|
| Strict typing (`mypy --strict`) and linting with security rules (`ruff` `S` rules) | `pyproject.toml` |
| Property-based tests over matching, logic and parsing primitives | `tests/unit/test_properties.py` |
| Regression tests that document each fixed defect | `tests/regression/test_fixed_bugs.py` |
| Scenario self-check shipped with the package (`attackpath validate`) | `selfcheck.py` |
| Security reporting policy | `SECURITY.md` |

## Residual risks

* The dashboard runs a local web server (Streamlit) on `localhost`; do not expose it on a shared
  network. It is optional and never started automatically.
* A malicious snapshot can still make the analyzer do a lot of work within the limits; the limits
  are tunable through `Limits` if a smaller budget is needed.
* The analyzer trusts the snapshot's `coverage` declaration. A snapshot that claims completeness it
  does not have will not be contradicted.
