"""The ``aws-scan`` command: opt-in, read-only inventory collection.

Flow: check that the optional ``aws`` extra is installed, validate the service
selection, require an explicit ``--confirm`` before any API call, refuse root
credentials, collect the snapshot, write it with owner-only permissions and,
optionally, analyze it right away. boto3 errors are reported as one line.
"""

from __future__ import annotations

import importlib
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TextIO

from attackpath.analysis.engine import analyze, build_report
from attackpath.aws.inventory import SUPPORTED_SERVICES, AwsInventoryCollector, normalize_services
from attackpath.aws.safeguards import READ_ONLY_OPERATIONS, install_safeguards
from attackpath.exceptions import AttackPathError
from attackpath.parser.loader import load_input
from attackpath.reporting import write_reports

EXIT_OK = 0
EXIT_ERROR = 1
INSTALL_HINT = "pip install 'aws-cloud-attack-path-analyzer[aws]'"
DEFAULT_SCAN_DIR = Path("scans")
DEFAULT_REPORT_DIR = Path("reports")
_SNAPSHOT_MODE = 0o600


def scan_command(
    profile: str,
    region: str,
    output: Path | None,
    services: tuple[str, ...],
    confirm: bool,
    run_analysis: bool,
    report_dir: Path | None,
    max_attempts: int,
) -> int:
    """Run the read-only scan; returns 0 on success and 1 on any error."""
    out, err = sys.stdout, sys.stderr
    if not _boto3_available():
        _say(err, f"error: aws-scan needs boto3, which is an optional dependency: {INSTALL_HINT}")
        return EXIT_ERROR
    try:
        selected = normalize_services(services)
    except AttackPathError as exc:
        _say(err, f"error: {exc}")
        return EXIT_ERROR
    if max_attempts < 1:
        _say(err, "error: --max-attempts must be at least 1")
        return EXIT_ERROR
    if not confirm:
        _print_plan(out, profile, region, selected)
        return EXIT_ERROR

    from botocore.exceptions import BotoCoreError, ClientError

    try:
        session = _create_session(profile, region)
        install_safeguards(session)
        identity = session.client("sts", region_name=region).get_caller_identity()
        account_id = str(identity.get("Account", ""))
        caller_arn = str(identity.get("Arn", ""))
        if caller_arn.endswith(":root"):
            _say(
                err,
                "error: refusing to scan with the account root user; "
                "use an IAM user or role with the read-only policy",
            )
            return EXIT_ERROR
        _say(out, f"account {account_id}, caller {caller_arn}")

        collector = AwsInventoryCollector(
            session, region, services=selected, max_attempts=max_attempts
        )
        snapshot = collector.collect()
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        snapshot_path = output or DEFAULT_SCAN_DIR / f"{account_id}-{stamp}.json"
        _write_snapshot(snapshot, snapshot_path)
        _say(out, f"wrote {snapshot_path}")
        _print_coverage(out, snapshot.get("coverage") or {})

        if run_analysis:
            target = report_dir or DEFAULT_REPORT_DIR / f"{account_id}-{stamp}"
            _run_analysis(out, snapshot_path, target)
    except AttackPathError as exc:
        _say(err, f"error: {exc}")
        return EXIT_ERROR
    except (BotoCoreError, ClientError) as exc:
        _say(err, f"error: {_one_line(exc)}")
        return EXIT_ERROR
    return EXIT_OK


def _boto3_available() -> bool:
    try:
        importlib.import_module("boto3")
    except ImportError:
        return False
    return True


def _create_session(profile: str, region: str) -> Any:
    """Build the boto3 session; kept separate so tests can substitute a stubbed one."""
    boto3 = importlib.import_module("boto3")
    return boto3.session.Session(profile_name=profile, region_name=region)


def _print_plan(out: TextIO, profile: str, region: str, services: tuple[str, ...]) -> None:
    _say(
        out,
        f"aws-scan would make only the following read-only API calls using profile "
        f"{profile!r} (region {region}):",
    )
    for service in ("sts", *services):
        operations = ", ".join(sorted(READ_ONLY_OPERATIONS.get(service, frozenset())))
        _say(out, f"  {service}: {operations}")
    _say(out, "No API call was made. Re-run with --confirm to acknowledge and start the scan.")


def _write_snapshot(snapshot: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(snapshot, indent=2) + "\n"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, _SNAPSHOT_MODE)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(text)
    path.chmod(_SNAPSHOT_MODE)


def _print_coverage(out: TextIO, coverage: dict[str, Any]) -> None:
    services: dict[str, Any] = coverage.get("services") or {}
    summary = ", ".join(
        f"{name}={_status_of(services.get(name))}"
        for name in SUPPORTED_SERVICES
        if name in services
    )
    _say(out, f"coverage: {summary or 'none'}")
    for name in SUPPORTED_SERVICES:
        entry = services.get(name)
        if isinstance(entry, dict):
            for note in entry.get("notes") or []:
                _say(out, f"  {name}: {note}")
    for note in coverage.get("notes") or []:
        _say(out, f"  note: {note}")


def _status_of(entry: Any) -> str:
    if isinstance(entry, dict):
        return str(entry.get("status", "unknown"))
    return str(entry) if entry else "unknown"


def _run_analysis(out: TextIO, snapshot_path: Path, report_dir: Path) -> None:
    loaded = load_input(snapshot_path)
    result = analyze(loaded.environment, mode=loaded.mode, input_warnings=loaded.warnings)
    report = build_report(result, loaded.description)
    counts = report.counts_by_severity()
    _say(out, "findings: " + ", ".join(f"{k}={v}" for k, v in counts.items()))
    for path in write_reports(report, report_dir):
        _say(out, f"wrote {path}")


def _one_line(exc: BaseException) -> str:
    return " ".join(str(exc).split()) or type(exc).__name__


def _say(stream: TextIO, text: str) -> None:
    stream.write(text + "\n")


__all__ = ["EXIT_ERROR", "EXIT_OK", "INSTALL_HINT", "scan_command"]
