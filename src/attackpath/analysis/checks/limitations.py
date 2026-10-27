"""Statements the evaluator could not fully decide, reported instead of guessed."""

from __future__ import annotations

from attackpath.analysis import references as ref
from attackpath.analysis.context import AnalysisContext
from attackpath.models.finding import (
    Category,
    Confidence,
    Evidence,
    EvidenceKind,
    FactorScore,
    Finding,
    Remediation,
)

CHECK_IDS: tuple[str, ...] = ("EVAL-INDETERMINATE",)

_KINDS = ("condition", "policy-variable", "principal-match")


def run(ctx: AnalysisContext) -> list[Finding]:
    if not ctx.config.is_check_enabled("EVAL-INDETERMINATE"):
        return []
    grouped: dict[str, list[str]] = {}
    for kind in _KINDS:
        for detail, _count in ctx.evaluator.limitations.by_kind(kind):
            statement, _, reason = detail.partition(": ")
            if kind == "policy-variable":
                reason = (
                    "resource pattern contains a policy variable that cannot be resolved offline"
                )
            elif kind == "principal-match":
                reason = "principal element cannot be matched to an identity offline"
            grouped.setdefault(statement, [])
            if reason and reason not in grouped[statement]:
                grouped[statement].append(reason)
    findings: list[Finding] = []
    for statement, reasons in sorted(grouped.items()):
        findings.append(
            ctx.finding(
                check_id="EVAL-INDETERMINATE",
                category=Category.EVALUATION_LIMITATION,
                title=f"Statement could not be fully evaluated: {statement}",
                description=(
                    f"{statement} contains elements whose effect depends on request-time context or on "
                    "constructs the analyzer does not implement: "
                    + "; ".join(reasons)
                    + ". Findings that "
                    "depend on it are marked indeterminate rather than reported as allowed or denied."
                ),
                impact=(
                    "The real permission may be broader or narrower than reported; a human review of the "
                    "statement, or a policy-simulator run with the real context values, is required."
                ),
                remediation=Remediation(
                    summary="Review the statement manually and prefer condition keys whose values are static (aws:PrincipalArn, aws:PrincipalOrgID, aws:SourceAccount) over request-time keys.",
                    steps=(
                        "Run the IAM policy simulator with the context keys set to the values a real request would carry.",
                        "If the condition is meant as a safeguard, verify that a request without the key is denied as intended.",
                    ),
                    verification_steps=(
                        "Re-run the analyzer; the finding remains until the statement is simplified or the analyzer gains support for the construct.",
                    ),
                ),
                evidence_kind=EvidenceKind.INDETERMINATE,
                confidence=Confidence.LOW,
                factors={
                    "permission_breadth": FactorScore(0.3, 0, "unknown"),
                    "escalation_potential": FactorScore(0.3, 0, "unknown"),
                    "resource_sensitivity": FactorScore(0.3, 0, "unknown"),
                    "trust_boundary": FactorScore(0.0, 0, "not applicable"),
                    "exposure": FactorScore(0.3, 0, "unknown"),
                    "reachability": FactorScore(0.3, 0, "unknown"),
                },
                resource=statement,
                evidence=[Evidence(source=statement, detail="; ".join(reasons))],
                references=[ref.CONDITION_KEYS, ref.POLICY_SIMULATOR],
                tags=["indeterminate"],
            )
        )
    return findings
