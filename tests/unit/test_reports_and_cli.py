from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from attackpath import __version__
from attackpath.analysis.engine import analyze, build_report
from attackpath.cli import EXIT_ERROR, EXIT_FAIL_ON, EXIT_OK, EXIT_USAGE, main
from attackpath.models.finding import AnalysisReport, Confidence, PathStep
from attackpath.reporting import FORMATS, render, write_reports
from attackpath.reporting.common import md_escape, mermaid_path
from tests.conftest import POLICY_DIR, SAMPLE_ENVIRONMENT, allow, env_from, policy

HOSTILE = '<script>alert(1)</script> | `tick` "quote" \\ back'


@pytest.fixture
def hostile_report() -> AnalysisReport:
    env = env_from(
        metadata={"name": HOSTILE, "synthetic": True},
        users=[{"name": "u", "inline_policies": {HOSTILE: policy(allow("*", "*", Sid=HOSTILE))}}],
        s3_buckets=[{"name": "data", "sensitivity": "high", "description": HOSTILE}],
    )
    return build_report(analyze(env), HOSTILE)


@pytest.fixture
def sample_report(sample_env) -> AnalysisReport:
    return build_report(analyze(sample_env), "sample_environment.json")


def test_json_report_is_valid_and_labelled(sample_report: AnalysisReport) -> None:
    data = json.loads(render(sample_report, "json"))
    assert data["synthetic"] is True
    assert any("synthetic fixture" in n for n in data["notices"])
    assert data["summary"]["total_findings"] == len(sample_report.findings) > 0
    assert data["findings"][0]["score_breakdown"]["factors"]


def test_markdown_report_escapes_untrusted_content(hostile_report: AnalysisReport) -> None:
    text = render(hostile_report, "markdown")
    assert "<script>" not in text
    assert "&lt;script&gt;" in text
    assert "```mermaid" in text or "Findings" in text
    assert md_escape("a|b\nc<d") == "a\\|b c&lt;d"


def test_html_report_escapes_and_forbids_scripts(hostile_report: AnalysisReport) -> None:
    html = render(hostile_report, "html")
    assert "<script" not in html.lower()
    assert "&lt;script&gt;" in html
    assert "Content-Security-Policy" in html and "default-src 'none'" in html
    assert "Synthetic environment" in html


def test_mermaid_path_sanitizes_labels() -> None:
    steps = [
        PathStep(
            source='a"b',
            edge="can-assume",
            target="c",
            description="x#y",
            confidence=Confidence.HIGH,
        )
    ]
    diagram = mermaid_path(steps)
    assert '"' not in diagram.replace('["', "").replace('"]', "").replace('-- "', "").replace(
        '" -->', ""
    )
    assert "#quot;" in diagram and "#35;" in diagram
    assert mermaid_path([]) == ""


def test_write_reports_creates_all_formats(sample_report: AnalysisReport, tmp_path: Path) -> None:
    written = write_reports(sample_report, tmp_path / "out")
    assert sorted(p.suffix for p in written) == [".html", ".json", ".md"]
    assert all(p.stat().st_size > 1000 for p in written)
    with pytest.raises(ValueError, match="unknown report format"):
        render(sample_report, "pdf")
    assert FORMATS == ("json", "markdown", "html")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def test_cli_version_and_help(capsys) -> None:
    assert main(["version"]) == EXIT_OK
    assert capsys.readouterr().out.strip() == f"attackpath {__version__}"
    assert main([]) == EXIT_USAGE


def test_cli_analyze_to_stdout_defaults_to_json(capsys) -> None:
    code = main(["analyze", "--input", str(SAMPLE_ENVIRONMENT), "--quiet"])
    assert code == EXIT_OK
    data = json.loads(capsys.readouterr().out)
    assert data["account_id"] == "111111111111"


def test_cli_analyze_writes_reports_and_summary(tmp_path: Path, capsys) -> None:
    out = tmp_path / "reports"
    assert main(["analyze", "--input", str(SAMPLE_ENVIRONMENT), "--output", str(out)]) == EXIT_OK
    captured = capsys.readouterr().out
    assert {p.name for p in out.iterdir()} == {
        "attackpath-report.json",
        "attackpath-report.md",
        "attackpath-report.html",
    }
    assert "findings:" in captured and "wrote" in captured
    assert (
        main(
            [
                "analyze",
                "--input",
                str(SAMPLE_ENVIRONMENT),
                "--output",
                str(out),
                "--format",
                "markdown",
                "--quiet",
            ]
        )
        == EXIT_OK
    )


def test_cli_format_and_filters(capsys) -> None:
    assert (
        main(["analyze", "--input", str(SAMPLE_ENVIRONMENT), "--format", "html", "--quiet"])
        == EXIT_OK
    )
    assert capsys.readouterr().out.startswith("<!DOCTYPE html>")
    assert main(["analyze", "--input", str(SAMPLE_ENVIRONMENT), "--format", "all"]) == EXIT_USAGE
    assert (
        main(
            [
                "analyze",
                "--input",
                str(SAMPLE_ENVIRONMENT),
                "--quiet",
                "--min-severity",
                "critical",
                "--check",
                "ADMIN",
            ]
        )
        == EXIT_OK
    )
    data = json.loads(capsys.readouterr().out)
    assert {f["check_id"] for f in data["findings"]} == {"ADMIN"}
    assert all(f["severity"] == "critical" for f in data["findings"])


def test_cli_fail_on_and_errors(tmp_path: Path, capsys) -> None:
    assert (
        main(["analyze", "--input", str(SAMPLE_ENVIRONMENT), "--quiet", "--fail-on", "critical"])
        == EXIT_FAIL_ON
    )
    capsys.readouterr()
    assert main(["analyze", "--input", str(tmp_path / "missing.json"), "--quiet"]) == EXIT_ERROR
    assert "error:" in capsys.readouterr().err
    assert main(["analyze", "--input", str(SAMPLE_ENVIRONMENT), "--max-depth", "0"]) == EXIT_USAGE
    assert (
        main(["analyze", "--input", str(SAMPLE_ENVIRONMENT), "--max-input-mb", "0"]) == EXIT_USAGE
    )
    huge = tmp_path / "huge.json"
    huge.write_text("[" + "0," * 600_000 + "0]", encoding="utf-8")
    assert main(["analyze", "--input", str(huge), "--max-input-mb", "1", "--quiet"]) == EXIT_ERROR
    with pytest.raises(SystemExit):
        main(["analyze", "--input", str(SAMPLE_ENVIRONMENT), "--min-severity", "extreme"])


def test_cli_policy_directory_and_scoring_config(tmp_path: Path, capsys) -> None:
    scoring = tmp_path / "scoring.toml"
    scoring.write_text(
        "[weights]\npermission_breadth=1\nescalation_potential=1\nresource_sensitivity=1\ntrust_boundary=1\nexposure=1\nreachability=1\n"
        "[thresholds]\ncritical=99\nhigh=98\nmedium=97\nlow=96\n",
        encoding="utf-8",
    )
    assert (
        main(["analyze", "--input", str(POLICY_DIR), "--quiet", "--scoring-config", str(scoring)])
        == EXIT_OK
    )
    data = json.loads(capsys.readouterr().out)
    assert data["scoring"]["source"] == str(scoring)
    assert all(
        f["severity"] in ("informational", "low")
        for f in data["findings"]
        if f["check_id"] != "COVERAGE-PARTIAL"
    )
    assert (
        main(
            [
                "analyze",
                "--input",
                str(POLICY_DIR),
                "--quiet",
                "--scoring-config",
                str(tmp_path / "nope.toml"),
            ]
        )
        == EXIT_ERROR
    )


def test_cli_validate_input_and_selfcheck(capsys) -> None:
    assert main(["validate", "--input", str(SAMPLE_ENVIRONMENT)]) == EXIT_OK
    assert "valid environment input" in capsys.readouterr().out
    assert main(["validate", "--list"]) == EXIT_OK
    assert "01-overly-broad-role" in capsys.readouterr().out
    assert main(["validate"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "[PASS]" in out and "[FAIL]" not in out


def test_module_entry_point_runs_in_a_subprocess() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "attackpath", "version"], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0 and __version__ in result.stdout
