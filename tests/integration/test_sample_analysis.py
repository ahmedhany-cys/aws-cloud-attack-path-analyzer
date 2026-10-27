"""End-to-end analysis of the shipped fixtures."""

from __future__ import annotations

from attackpath.analysis.engine import analyze, build_report
from attackpath.config import AnalysisConfig
from attackpath.models.finding import EvidenceKind, Severity
from attackpath.parser.loader import load_input
from tests.conftest import POLICY_DIR, role_arn, user_arn


def _by_check(findings, check_id, principal=None, resource=None):
    return [
        f
        for f in findings
        if f.check_id == check_id
        and (principal is None or f.affected_principal == principal)
        and (resource is None or f.affected_resource == resource)
    ]


def test_sample_environment_key_findings(sample_env) -> None:
    result = analyze(sample_env)
    findings = result.findings
    assert 30 <= len(findings) <= 60, "the demo should stay readable"
    admin = _by_check(findings, "ADMIN", role_arn("ops-admin-legacy"))
    assert admin and admin[0].severity is Severity.CRITICAL
    break_glass = _by_check(findings, "ADMIN", user_arn("break-glass-admin"))
    assert break_glass and break_glass[0].severity is Severity.HIGH, (
        "MFA and no keys lower the exposure"
    )
    path = _by_check(
        findings, "PATH-ADMIN", user_arn("legacy-automation"), role_arn("ops-admin-legacy")
    )
    assert path and path[0].severity is Severity.CRITICAL and len(path[0].attack_path) == 1
    anonymous = _by_check(findings, "TRUST-ANONYMOUS", role_arn("vendor-support-access"))
    assert anonymous and anonymous[0].severity is Severity.CRITICAL
    assert _by_check(findings, "PASSROLE-BROAD", user_arn("ci-deployer"))
    assert _by_check(findings, "CREDENTIAL-WRITE", user_arn("helpdesk-operator"))
    assert _by_check(findings, "LAMBDA-WRITE", user_arn("ci-deployer"))
    public = _by_check(findings, "S3-PUBLIC-POLICY", resource="arn:aws:s3:::legacy-backups")
    assert public and public[0].severity is Severity.HIGH
    mitigated = _by_check(
        findings, "S3-PUBLIC-POLICY", resource="arn:aws:s3:::archive-with-restricted-policy"
    )
    assert (
        mitigated
        and mitigated[0].severity is Severity.LOW
        and "mitigated-by-block-public-access" in mitigated[0].tags
    )
    assert not _by_check(
        findings,
        "SENSITIVE-ACCESS",
        user_arn("analyst-readonly"),
        "arn:aws:s3:::customer-pii-exports",
    )
    indeterminate = _by_check(
        findings,
        "SENSITIVE-ACCESS",
        role_arn("finance-reporting"),
        "arn:aws:s3:::customer-pii-exports",
    )
    assert indeterminate and indeterminate[0].evidence_kind is EvidenceKind.INDETERMINATE
    assert _by_check(findings, "COVERAGE-PARTIAL") and _by_check(
        findings, "COVERAGE-UNRESOLVED-POLICY"
    )
    assert _by_check(findings, "LAMBDA-PUBLIC-INVOKE")
    assert not [
        f
        for f in findings
        if f.affected_principal == role_arn("lambda-thumbnailer-least-priv")
        and f.severity.rank >= Severity.MEDIUM.rank
    ]
    assert findings == sorted(findings, key=lambda f: (-f.severity.rank, -f.score, f.id))
    assert all(f.remediation.summary and f.impact and f.references for f in findings)


def test_report_metadata(sample_env) -> None:
    result = analyze(sample_env, AnalysisConfig(min_severity=Severity.HIGH))
    assert all(f.severity.at_least(Severity.HIGH) for f in result.findings)
    report = build_report(result, "sample")
    assert report.synthetic and report.graph.node_count > 20 and report.graph.paths_found > 0
    assert report.coverage["services"]["lambda"]["status"] == "partial"
    assert report.analysis_seconds is not None and report.analysis_seconds < 30


def test_policy_directory_mode() -> None:
    loaded = load_input(POLICY_DIR)
    result = analyze(loaded.environment, mode=loaded.mode)
    checks = {
        (f.check_id, f.affected_principal.rsplit("/", 1)[-1] if f.affected_principal else None)
        for f in result.findings
    }
    assert ("ADMIN", "admin-wildcard") in checks
    assert ("IAM-WRITE", "iam-write-broad") in checks
    assert ("PASSROLE-BROAD", "passrole-unrestricted") in checks
    assert not any(principal == "least-privilege-s3" for _, principal in checks)
    wildcard = [f for f in result.findings if f.check_id == "WILDCARD"]
    assert wildcard and wildcard[0].evidence_kind is EvidenceKind.INDETERMINATE, (
        "the conditional Deny is honoured"
    )
    report = build_report(result, "policies")
    assert any("policy-only mode" in item for item in report.limitations)


def test_analysis_is_deterministic(sample_env) -> None:
    first = [f.id for f in analyze(sample_env).findings]
    second = [f.id for f in analyze(sample_env).findings]
    assert first == second
