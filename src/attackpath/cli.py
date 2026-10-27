"""Command-line interface.

Exit codes: 0 success, 1 analyzer error, 2 usage error, 3 findings at or above
``--fail-on``, 4 self-check failure.
"""

from __future__ import annotations

import argparse
import logging
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import TextIO

from attackpath import __version__
from attackpath.analysis.engine import analyze, build_report
from attackpath.config import AnalysisConfig, Limits
from attackpath.exceptions import AttackPathError
from attackpath.models.finding import AnalysisReport, Severity
from attackpath.parser.loader import load_input
from attackpath.reporting import FORMATS, render, write_reports

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
EXIT_FAIL_ON = 3
EXIT_SELFCHECK = 4

_SEVERITIES = [s.value for s in Severity.ordered()]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="attackpath",
        description=(
            "Offline, graph-based analysis of AWS IAM permission relationships: which identities "
            "could reach sensitive resources, with evidence and least-privilege remediation."
        ),
    )
    parser.add_argument("--verbose", action="store_true", help="debug logging on stderr")
    sub = parser.add_subparsers(dest="command", metavar="command")

    analyze_p = sub.add_parser(
        "analyze", help="analyze a snapshot file or a directory of policy documents"
    )
    analyze_p.add_argument(
        "--input",
        required=True,
        type=Path,
        help="snapshot JSON file or directory of policy JSON files",
    )
    analyze_p.add_argument(
        "--output", type=Path, help="directory to write reports to (default: print to stdout)"
    )
    analyze_p.add_argument(
        "--format",
        choices=[*FORMATS, "all"],
        help="report format; defaults to all formats with --output, json without",
    )
    analyze_p.add_argument(
        "--scoring-config", type=Path, help="TOML file overriding the scoring model"
    )
    analyze_p.add_argument(
        "--max-depth", type=int, default=4, help="maximum path length in hops (default 4)"
    )
    analyze_p.add_argument(
        "--min-severity",
        choices=_SEVERITIES,
        default="informational",
        help="drop findings below this severity",
    )
    analyze_p.add_argument(
        "--fail-on",
        choices=_SEVERITIES,
        help="exit with status 3 if any finding is at or above this severity",
    )
    analyze_p.add_argument(
        "--max-input-mb",
        type=int,
        default=25,
        help="refuse input files larger than this (default 25)",
    )
    analyze_p.add_argument(
        "--check",
        action="append",
        metavar="CHECK-ID",
        help="run only the given check id (repeatable)",
    )
    analyze_p.add_argument("--quiet", action="store_true", help="suppress the console summary")

    validate_p = sub.add_parser(
        "validate", help="validate an input file, or run the built-in scenario self-check"
    )
    validate_p.add_argument(
        "--input", type=Path, help="snapshot or policy file/directory to validate"
    )
    validate_p.add_argument(
        "--list", action="store_true", help="list the built-in scenarios without running them"
    )

    sub.add_parser("version", help="print the version")

    scan_p = sub.add_parser(
        "aws-scan", help="collect a read-only snapshot from an AWS account (optional, opt-in)"
    )
    scan_p.add_argument(
        "--profile", required=True, help="AWS CLI profile to use (never the root user)"
    )
    scan_p.add_argument(
        "--region", required=True, help="region for regional services (Lambda, EC2)"
    )
    scan_p.add_argument(
        "--output",
        type=Path,
        help="snapshot file to write (default: scans/<account>-<timestamp>.json)",
    )
    scan_p.add_argument(
        "--services",
        default="iam,s3,lambda,ec2",
        help="comma-separated services to inventory (default iam,s3,lambda,ec2)",
    )
    scan_p.add_argument(
        "--confirm",
        action="store_true",
        help="required: acknowledge that read-only API calls will be made against the account",
    )
    scan_p.add_argument(
        "--analyze",
        action="store_true",
        help="analyze the snapshot immediately after collecting it",
    )
    scan_p.add_argument(
        "--report-dir", type=Path, help="with --analyze: directory to write reports to"
    )
    scan_p.add_argument(
        "--max-attempts", type=int, default=6, help="retries per throttled API call (default 6)"
    )

    dash_p = sub.add_parser("dashboard", help="launch the optional local Streamlit dashboard")
    dash_p.add_argument(
        "--input", required=True, type=Path, help="snapshot file to load in the dashboard"
    )
    dash_p.add_argument("--port", type=int, default=8501, help="local port (default 8501)")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )
    if args.command is None:
        parser.print_help()
        return EXIT_USAGE
    try:
        if args.command == "analyze":
            return _cmd_analyze(args)
        if args.command == "validate":
            return _cmd_validate(args)
        if args.command == "version":
            print(f"attackpath {__version__}")
            return EXIT_OK
        if args.command == "aws-scan":
            return _cmd_aws_scan(args)
        if args.command == "dashboard":
            return _cmd_dashboard(args)
    except AttackPathError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return EXIT_ERROR
    parser.print_help()
    return EXIT_USAGE


def _cmd_analyze(args: argparse.Namespace) -> int:
    if args.max_depth < 1 or args.max_depth > 10:
        print("error: --max-depth must be between 1 and 10", file=sys.stderr)
        return EXIT_USAGE
    if args.max_input_mb < 1:
        print("error: --max-input-mb must be positive", file=sys.stderr)
        return EXIT_USAGE
    if args.output is None and args.format == "all":
        print("error: --format all requires --output", file=sys.stderr)
        return EXIT_USAGE
    formats: tuple[str, ...]
    if args.output is not None:
        formats = FORMATS if args.format in (None, "all") else (args.format,)
    else:
        formats = (args.format or "json",)

    limits = Limits(max_input_bytes=args.max_input_mb * 1024 * 1024)
    config = AnalysisConfig(
        limits=limits,
        scoring_config_path=args.scoring_config,
        max_path_depth=args.max_depth,
        min_severity=Severity(args.min_severity),
        enabled_checks=frozenset(args.check) if args.check else None,
    )
    loaded = load_input(args.input, limits)
    result = analyze(loaded.environment, config, mode=loaded.mode, input_warnings=loaded.warnings)
    report = build_report(result, loaded.description)

    if args.output is not None:
        written = write_reports(report, args.output, formats)
        if not args.quiet:
            _print_summary(report, sys.stdout)
            for path in written:
                print(f"wrote {path}")
    else:
        sys.stdout.write(render(report, formats[0]))
        if not args.quiet:
            _print_summary(report, sys.stderr)

    if args.fail_on is not None:
        threshold = Severity(args.fail_on)
        if any(f.severity.at_least(threshold) for f in report.findings):
            return EXIT_FAIL_ON
    return EXIT_OK


def _print_summary(report: AnalysisReport, out: TextIO) -> None:
    counts = report.counts_by_severity()
    label = "synthetic" if report.synthetic else report.source
    print(
        f"environment: {report.environment_name} ({label}, account {report.account_id})", file=out
    )
    print("findings: " + ", ".join(f"{k}={v}" for k, v in counts.items()), file=out)
    for finding in report.findings[:8]:
        print(f"  [{finding.severity.value.upper():<13}] {finding.id}  {finding.title}", file=out)
    if len(report.findings) > 8:
        print(f"  ... {len(report.findings) - 8} more", file=out)
    if report.limitations:
        print(f"limitations/warnings: {len(report.limitations)} (see report)", file=out)


def _cmd_validate(args: argparse.Namespace) -> int:
    from attackpath import selfcheck

    if args.input is not None:
        loaded = load_input(args.input)
        env = loaded.environment
        summary = ", ".join(f"{k}={v}" for k, v in env.summary().items())
        print(f"valid {loaded.mode} input: {loaded.description} ({summary})")
        for warning in loaded.warnings:
            print(f"warning: {warning}")
        return EXIT_OK
    scenarios = selfcheck.load_scenarios()
    if args.list:
        for scenario in scenarios:
            print(f"{scenario.name}: {scenario.description}")
        return EXIT_OK
    results = selfcheck.run_all()
    print(selfcheck.format_results(results, verbose=args.verbose))
    return EXIT_OK if all(r.ok for r in results) else EXIT_SELFCHECK


def _cmd_aws_scan(args: argparse.Namespace) -> int:
    from attackpath.aws import scan_command

    return scan_command(
        profile=args.profile,
        region=args.region,
        output=args.output,
        services=tuple(s.strip() for s in args.services.split(",") if s.strip()),
        confirm=args.confirm,
        run_analysis=args.analyze,
        report_dir=args.report_dir,
        max_attempts=args.max_attempts,
    )


def _cmd_dashboard(args: argparse.Namespace) -> int:
    from attackpath.dashboard import launch

    return launch(args.input, port=args.port)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
