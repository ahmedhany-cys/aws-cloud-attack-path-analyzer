"""Tests for the ``aws-scan`` command wiring (stubbed clients, no credentials, no network)."""

from __future__ import annotations

import json
import stat
import sys
from pathlib import Path
from typing import Any

import pytest

from attackpath.aws import scan as scan_module
from attackpath.aws.scan import scan_command

boto3 = pytest.importorskip("boto3")
from botocore.exceptions import ProfileNotFound  # noqa: E402
from botocore.stub import Stubber  # noqa: E402

pytestmark = pytest.mark.aws

ACCOUNT = "123456789012"
REGION = "us-east-1"
SCANNER_ARN = f"arn:aws:iam::{ACCOUNT}:user/scanner"


def run(**overrides: Any) -> int:
    options: dict[str, Any] = {
        "profile": "scanner",
        "region": REGION,
        "output": None,
        "services": ("iam", "s3", "lambda"),
        "confirm": True,
        "run_analysis": False,
        "report_dir": None,
        "max_attempts": 6,
    }
    options.update(overrides)
    return scan_command(**options)


def _fail_if_session_is_created(*_: Any, **__: Any) -> Any:
    raise AssertionError("a boto3 session must not be created")


@pytest.fixture
def stubbed(monkeypatch: pytest.MonkeyPatch) -> dict[str, Stubber]:
    """A fake-credential session whose clients are all stubbed, injected into the command."""
    session = boto3.session.Session(
        aws_access_key_id="testing",
        aws_secret_access_key="testing",  # pragma: allowlist secret
        region_name=REGION,
    )
    built = {name: session.client(name) for name in ("sts", "iam", "s3", "lambda")}
    stubs = {name: Stubber(client) for name, client in built.items()}
    for stub in stubs.values():
        stub.activate()
    monkeypatch.setattr(session, "client", lambda name, **_: built[name])
    monkeypatch.setattr(scan_module, "_create_session", lambda profile, region: session)
    return stubs


def _identity(stubs: dict[str, Stubber], arn: str = SCANNER_ARN, times: int = 1) -> None:
    for _ in range(times):
        stubs["sts"].add_response(
            "get_caller_identity",
            {"UserId": "AIDAEXAMPLE000000001", "Account": ACCOUNT, "Arn": arn},
            {},
        )


def _empty_inventory(stubs: dict[str, Stubber]) -> None:
    stubs["iam"].add_response(
        "get_account_authorization_details",
        {
            "UserDetailList": [],
            "GroupDetailList": [],
            "RoleDetailList": [],
            "Policies": [],
            "IsTruncated": False,
        },
        {},
    )
    stubs["s3"].add_response("list_buckets", {"Buckets": [], "Owner": {"ID": "o"}}, {})
    stubs["lambda"].add_response("list_functions", {"Functions": []}, {})


def test_without_confirm_prints_plan_makes_no_api_call_and_returns_1(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(scan_module, "_create_session", _fail_if_session_is_created)

    assert run(confirm=False) == 1

    captured = capsys.readouterr()
    assert "--confirm" in captured.out
    assert "No API call was made" in captured.out
    for operation in (
        "sts: GetCallerIdentity",
        "GetAccountAuthorizationDetails",
        "ListBuckets",
        "ListFunctions",
    ):
        assert operation in captured.out
    assert "testing" not in captured.out  # never echo anything credential-like
    assert captured.err == ""


def test_root_caller_is_refused(
    stubbed: dict[str, Stubber], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _identity(stubbed, arn=f"arn:aws:iam::{ACCOUNT}:root")

    assert run(output=tmp_path / "snapshot.json") == 1

    captured = capsys.readouterr()
    assert "root" in captured.err
    assert not (tmp_path / "snapshot.json").exists()
    for stub in stubbed.values():
        stub.assert_no_pending_responses()


def test_unknown_service_is_rejected_before_any_session(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(scan_module, "_create_session", _fail_if_session_is_created)
    assert run(services=("iam", "rds")) == 1
    assert "unsupported service(s): rds" in capsys.readouterr().err
    assert run(max_attempts=0) == 1
    assert "--max-attempts" in capsys.readouterr().err


def test_missing_boto3_reports_the_install_hint(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setitem(sys.modules, "boto3", None)  # makes ``import boto3`` fail
    assert run(confirm=False) == 1
    assert "[aws]" in capsys.readouterr().err


def test_successful_scan_writes_private_snapshot_and_reports(
    stubbed: dict[str, Stubber],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.chdir(tmp_path)
    _identity(stubbed, times=2)  # once by the command, once by the collector
    _empty_inventory(stubbed)

    assert run(run_analysis=True) == 0

    for stub in stubbed.values():
        stub.assert_no_pending_responses()
    captured = capsys.readouterr()
    assert captured.err == ""
    assert f"account {ACCOUNT}, caller {SCANNER_ARN}" in captured.out
    assert "coverage: iam=complete, s3=complete, lambda=complete" in captured.out
    assert "findings:" in captured.out

    (snapshot_path,) = list((tmp_path / "scans").glob(f"{ACCOUNT}-*.json"))
    assert stat.S_IMODE(snapshot_path.stat().st_mode) == 0o600
    snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
    assert snapshot["account_id"] == ACCOUNT
    assert snapshot["metadata"]["source"] == "aws-scan"
    assert snapshot["metadata"]["synthetic"] is False
    (report_dir,) = list((tmp_path / "reports").glob(f"{ACCOUNT}-*"))
    assert {p.name for p in report_dir.iterdir()} == {
        "attackpath-report.json",
        "attackpath-report.md",
        "attackpath-report.html",
    }
    report = json.loads((report_dir / "attackpath-report.json").read_text(encoding="utf-8"))
    assert report["account_id"] == ACCOUNT


def test_explicit_output_and_report_dir_are_honoured(
    stubbed: dict[str, Stubber], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _identity(stubbed, times=2)
    _empty_inventory(stubbed)
    output = tmp_path / "nested" / "dir" / "snapshot.json"
    output.parent.mkdir(parents=True)
    output.write_text("stale", encoding="utf-8")
    output.chmod(0o644)

    assert run(output=output, run_analysis=True, report_dir=tmp_path / "out") == 0

    assert stat.S_IMODE(output.stat().st_mode) == 0o600  # tightened even when the file existed
    assert json.loads(output.read_text(encoding="utf-8"))["schema_version"] == "1.0"
    assert (tmp_path / "out" / "attackpath-report.html").exists()
    assert f"wrote {output}" in capsys.readouterr().out


def test_profile_not_found_is_a_single_line_error(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def missing_profile(profile: str, region: str) -> Any:
        raise ProfileNotFound(profile=profile)

    monkeypatch.setattr(scan_module, "_create_session", missing_profile)

    assert run(profile="nope") == 1

    captured = capsys.readouterr()
    assert captured.err.count("\n") == 1
    assert captured.err.startswith("error: ")
    assert "nope" in captured.err
    assert "Traceback" not in captured.err


def test_client_error_from_sts_is_a_single_line_error(
    stubbed: dict[str, Stubber], capsys: pytest.CaptureFixture[str]
) -> None:
    stubbed["sts"].add_client_error(
        "get_caller_identity", "InvalidClientTokenId", "The security token is invalid", 403
    )

    assert run() == 1

    captured = capsys.readouterr()
    assert captured.err.count("\n") == 1
    assert "InvalidClientTokenId" in captured.err
    assert "GetCallerIdentity" in captured.err


def test_collector_failure_is_reported_without_traceback(
    stubbed: dict[str, Stubber], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _identity(stubbed, times=1)
    stubbed["sts"].add_client_error("get_caller_identity", "ExpiredToken", "expired", 403)

    assert run(output=tmp_path / "snapshot.json") == 1

    captured = capsys.readouterr()
    assert captured.err.startswith("error: sts:GetCallerIdentity failed (ExpiredToken)")
    assert not (tmp_path / "snapshot.json").exists()
