from __future__ import annotations

import json
from pathlib import Path

import pytest

from attackpath.analysis.context import finding_id
from attackpath.exceptions import ConfigError
from attackpath.models.finding import (
    AnalysisReport,
    Category,
    Confidence,
    EvidenceKind,
    FactorScore,
    Finding,
    GraphSummary,
    Remediation,
    Severity,
)
from attackpath.scoring.model import FACTORS, Scorer, load_scoring_config

FULL = {name: FactorScore(1.0, 0, "max") for name in FACTORS}
ZERO = {name: FactorScore(0.0, 0, "none") for name in FACTORS}


def test_default_config_loads_and_sums_weights() -> None:
    cfg = load_scoring_config()
    assert set(cfg.weights) == set(FACTORS)
    assert cfg.thresholds[Severity.CRITICAL] > cfg.thresholds[Severity.LOW]
    assert cfg.to_dict()["source"] == "built-in"


def test_scorer_extremes_and_thresholds() -> None:
    scorer = Scorer()
    sev, score, breakdown = scorer.score(FULL, EvidenceKind.OBSERVED, Confidence.HIGH)
    assert sev is Severity.CRITICAL and score == 100.0 and breakdown.base_score == 100.0
    sev, score, _ = scorer.score(ZERO, EvidenceKind.OBSERVED, Confidence.HIGH)
    assert sev is Severity.INFORMATIONAL and score == 0.0
    assert scorer.severity_for(79.99) is Severity.HIGH
    assert scorer.severity_for(80) is Severity.CRITICAL
    assert scorer.severity_for(19.9) is Severity.INFORMATIONAL


def test_multipliers_caps_and_overrides() -> None:
    scorer = Scorer()
    sev, score, breakdown = scorer.score(
        FULL, EvidenceKind.INDETERMINATE, Confidence.LOW, ["p1", "p2"]
    )
    assert breakdown.confidence_multiplier == pytest.approx(0.5 * 0.75)
    assert breakdown.precondition_multiplier == pytest.approx(1 - 0.08 * 2)
    assert score == pytest.approx(100 * 0.375 * 0.84, abs=0.01)
    assert sev is Severity.LOW and breakdown.cap_applied is None
    sev, _, _ = scorer.score(FULL, EvidenceKind.HYPOTHETICAL, Confidence.HIGH)
    assert sev is Severity.HIGH, "0.7 multiplier keeps hypothetical findings below critical"
    sev, _, breakdown = scorer.score(
        FULL, EvidenceKind.OBSERVED, Confidence.HIGH, check_id="COVERAGE-PARTIAL"
    )
    assert sev is Severity.INFORMATIONAL and "fixed" in (breakdown.cap_applied or "")
    sev, _, _ = scorer.score(
        FULL, EvidenceKind.OBSERVED, Confidence.HIGH, check_id="EVAL-INDETERMINATE"
    )
    assert sev is Severity.LOW
    _, _, breakdown = scorer.score(FULL, EvidenceKind.OBSERVED, Confidence.HIGH, ["p"] * 20)
    assert breakdown.precondition_multiplier == 0.5, "the floor bounds the precondition penalty"


def test_evidence_caps_apply_when_multipliers_do_not_reduce_enough(tmp_path: Path) -> None:
    path = tmp_path / "scoring.toml"
    path.write_text(
        "[weights]\n"
        + "\n".join(f"{f} = 1" for f in FACTORS)
        + "\n[evidence_multipliers]\nhypothetical = 1.0\nindeterminate = 1.0\n"
        "[thresholds]\ncritical = 80\nhigh = 60\nmedium = 40\nlow = 20\n"
        "[severity_caps]\nhypothetical = 'high'\nindeterminate = 'medium'\n",
        encoding="utf-8",
    )
    scorer = Scorer(load_scoring_config(path))
    sev, score, breakdown = scorer.score(FULL, EvidenceKind.HYPOTHETICAL, Confidence.HIGH)
    assert (
        score == 100.0 and sev is Severity.HIGH and "hypothetical" in (breakdown.cap_applied or "")
    )
    sev, _, breakdown = scorer.score(FULL, EvidenceKind.INDETERMINATE, Confidence.HIGH)
    assert sev is Severity.MEDIUM and "indeterminate" in (breakdown.cap_applied or "")
    sev, _, _ = scorer.score(FULL, EvidenceKind.OBSERVED, Confidence.HIGH)
    assert sev is Severity.CRITICAL


def test_factor_values_are_clamped_and_missing_factors_default_to_zero() -> None:
    scorer = Scorer()
    _, _, breakdown = scorer.score(
        {"exposure": FactorScore(5.0, 0, "too big")}, EvidenceKind.OBSERVED, Confidence.HIGH
    )
    assert breakdown.factors["exposure"].value == 1.0
    assert breakdown.factors["reachability"].value == 0.0


def test_custom_config_from_toml(tmp_path: Path) -> None:
    path = tmp_path / "scoring.toml"
    path.write_text(
        """
[weights]
permission_breadth = 10
escalation_potential = 10
resource_sensitivity = 10
trust_boundary = 10
exposure = 10
reachability = 50
[thresholds]
critical = 90
high = 70
medium = 50
low = 30
[check_overrides.WILDCARD]
max_severity = "low"
""",
        encoding="utf-8",
    )
    cfg = load_scoring_config(path)
    assert cfg.source == str(path) and cfg.weights["reachability"] == 50
    scorer = Scorer(cfg)
    assert scorer.severity_for(85) is Severity.HIGH
    sev, _, _ = scorer.score(FULL, EvidenceKind.OBSERVED, Confidence.HIGH, check_id="WILDCARD")
    assert sev is Severity.LOW


@pytest.mark.parametrize(
    ("body", "message"),
    [
        ("[weights]\npermission_breadth = 1\n", "weights missing"),
        (
            "[weights]\n"
            + "\n".join(f"{f} = 1" for f in FACTORS)
            + "\nbogus = 1\n[thresholds]\ncritical=80\nhigh=60\nmedium=40\nlow=20\n",
            "unknown weight",
        ),
        (
            "[weights]\n"
            + "\n".join(f"{f} = 0" for f in FACTORS)
            + "\n[thresholds]\ncritical=80\nhigh=60\nmedium=40\nlow=20\n",
            "positive",
        ),
        (
            "[weights]\n"
            + "\n".join(f"{f} = 1" for f in FACTORS)
            + "\n[thresholds]\ncritical=10\nhigh=60\nmedium=40\nlow=20\n",
            "decrease",
        ),
        (
            "[weights]\n"
            + "\n".join(f"{f} = 1" for f in FACTORS)
            + "\n[thresholds]\ncritical=80\nhigh=60\nmedium=40\n",
            "thresholds.low is required",
        ),
        (
            "[weights]\n"
            + "\n".join(f"{f} = 1" for f in FACTORS)
            + "\n[thresholds]\ncritical=80\nhigh=60\nmedium=40\nlow=20\n[severity_caps]\nindeterminate='gigantic'\n",
            "invalid severity",
        ),
        (
            "[weights]\n"
            + "\n".join(f"{f} = 1" for f in FACTORS)
            + "\n[thresholds]\ncritical=80\nhigh=60\nmedium=40\nlow=20\n[evidence_multipliers]\nobserved = 3\n",
            "must be in 0..1",
        ),
        ("not toml at all = = =", "invalid TOML"),
    ],
)
def test_invalid_configs_are_rejected(tmp_path: Path, body: str, message: str) -> None:
    path = tmp_path / "bad.toml"
    path.write_text(body, encoding="utf-8")
    with pytest.raises(ConfigError, match=message):
        load_scoring_config(path)


def test_missing_config_file() -> None:
    with pytest.raises(ConfigError, match="not a file"):
        load_scoring_config(Path("/nonexistent/scoring.toml"))


def test_finding_ids_are_deterministic_and_distinct() -> None:
    a = finding_id("ADMIN", "arn:a", None)
    assert a == finding_id("ADMIN", "arn:a", None) and a.startswith("APA-ADMIN-")
    assert a != finding_id("ADMIN", "arn:b", None) != finding_id("WILDCARD", "arn:a", None)


def test_finding_and_report_serialize_to_json() -> None:
    finding = Finding(
        id="APA-X-1",
        check_id="X",
        category=Category.EXCESSIVE_PERMISSIONS,
        title="t",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        evidence_kind=EvidenceKind.OBSERVED,
        description="d",
        impact="i",
        remediation=Remediation(
            summary="s", steps=("a",), suggested_policy={"Version": "2012-10-17"}
        ),
        score=61.25,
    )
    report = AnalysisReport(
        tool_version="0.1.0",
        schema_version="1.0",
        generated_at="now",
        input_description="x",
        account_id="111111111111",
        environment_name="e",
        synthetic=True,
        source="fixture",
        environment_summary={"users": 1},
        coverage={},
        findings=[finding],
        graph=GraphSummary(),
    )
    data = report.to_dict()
    json.dumps(data)
    assert data["summary"]["by_severity"]["high"] == 1
    assert data["findings"][0]["remediation"]["steps"] == ["a"]
    assert data["findings"][0]["severity"] == "high"
    assert report.counts_by_category() == {"excessive-permissions": 1}
    assert Severity.ordered()[0] is Severity.CRITICAL and Severity.LOW.at_least(
        Severity.INFORMATIONAL
    )
