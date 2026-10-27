"""Inventory coverage: what the snapshot does not contain."""

from __future__ import annotations

from attackpath.analysis import references as ref
from attackpath.analysis.context import AnalysisContext
from attackpath.models.environment import CoverageStatus
from attackpath.models.finding import (
    Category,
    Confidence,
    Evidence,
    EvidenceKind,
    FactorScore,
    Finding,
    Remediation,
)

CHECK_IDS: tuple[str, ...] = (
    "COVERAGE-PARTIAL",
    "COVERAGE-UNRESOLVED-POLICY",
    "COVERAGE-UNRESOLVED-ROLE",
)

_ZERO = {
    "permission_breadth": FactorScore(0.0, 0, "not applicable"),
    "escalation_potential": FactorScore(0.0, 0, "not applicable"),
    "resource_sensitivity": FactorScore(0.0, 0, "not applicable"),
    "trust_boundary": FactorScore(0.0, 0, "not applicable"),
    "exposure": FactorScore(0.0, 0, "not applicable"),
    "reachability": FactorScore(0.0, 0, "not applicable"),
}


def run(ctx: AnalysisContext) -> list[Finding]:
    findings: list[Finding] = []
    if ctx.config.is_check_enabled("COVERAGE-PARTIAL"):
        findings.extend(_partial(ctx))
    if ctx.config.is_check_enabled("COVERAGE-UNRESOLVED-POLICY"):
        findings.extend(_unresolved_policies(ctx))
    if ctx.config.is_check_enabled("COVERAGE-UNRESOLVED-ROLE"):
        findings.extend(_unresolved_roles(ctx))
    return findings


def _partial(ctx: AnalysisContext) -> list[Finding]:
    coverage = ctx.env.coverage
    items: list[tuple[str, str, tuple[str, ...]]] = []
    if not coverage.services:
        items.append(
            (
                "all",
                "undeclared",
                ("the snapshot declares no coverage information; completeness is unknown",),
            )
        )
    for service, entry in coverage.incomplete_services():
        items.append((service, entry.status.value, entry.notes))
    findings: list[Finding] = []
    for service, status, notes in items:
        findings.append(
            ctx.finding(
                check_id="COVERAGE-PARTIAL",
                category=Category.COVERAGE,
                title=f"Inventory coverage for {service} is {status}",
                description=(
                    f"The snapshot records {service} coverage as {status}. "
                    + ("; ".join(notes) + ". " if notes else "")
                    + "Findings about resources or identities that were not inventoried cannot be produced, "
                    "so the absence of findings for them is not evidence of safety."
                ),
                impact="Risk in the uninventoried parts of the account is unknown, not absent.",
                remediation=Remediation(
                    summary="Grant the inventory identity the documented read-only permissions and re-run the collection for the affected service and regions.",
                    steps=("See docs/aws-setup.md for the least-privilege read-only policy.",),
                    verification_steps=(
                        "Re-run the collection and confirm the coverage section reports complete.",
                    ),
                ),
                evidence_kind=EvidenceKind.OBSERVED,
                confidence=Confidence.HIGH,
                factors=_ZERO,
                resource=service,
                evidence=[
                    Evidence(
                        source="coverage",
                        detail=f"{service}: {status}" + (" - " + "; ".join(notes) if notes else ""),
                    )
                ],
                references=[ref.GET_ACCOUNT_AUTHORIZATION_DETAILS],
                tags=["coverage"],
                key=(status,),
            )
        )
    return findings


def _unresolved_policies(ctx: AnalysisContext) -> list[Finding]:
    referencing: dict[str, list[str]] = {}
    for principal in ctx.env.principals():
        for arn in ctx.evaluator.unresolved_policies_for(principal):
            referencing.setdefault(arn, []).append(ctx.label(principal))
        if (
            principal.permissions_boundary_arn
            and ctx.env.managed_policy(principal.permissions_boundary_arn) is None
        ):
            referencing.setdefault(principal.permissions_boundary_arn, []).append(
                f"{ctx.label(principal)} (permissions boundary)"
            )
    for group in ctx.env.groups:
        for arn in group.attached_policy_arns:
            if ctx.env.managed_policy(arn) is None:
                referencing.setdefault(arn, []).append(f"group {group.name}")
    findings: list[Finding] = []
    for arn, users in sorted(referencing.items()):
        names = sorted(set(users))
        findings.append(
            ctx.finding(
                check_id="COVERAGE-UNRESOLVED-POLICY",
                category=Category.COVERAGE,
                title=f"Policy document {arn} is referenced but not present in the snapshot",
                description=(
                    f"{', '.join(names)} reference {arn}, but its document is not in the snapshot. "
                    "Evaluations for these identities are marked indeterminate where the missing document could change the outcome."
                ),
                impact="Permissions granted by the missing document are invisible; the affected identities may be more privileged than reported.",
                remediation=Remediation(
                    summary="Include the policy document in the snapshot (the AWS collector fetches attached managed policies automatically when iam:GetPolicyVersion is permitted).",
                    verification_steps=(
                        "Re-run the analysis after adding the document; the finding disappears and dependent findings gain confidence.",
                    ),
                ),
                evidence_kind=EvidenceKind.OBSERVED,
                confidence=Confidence.HIGH,
                factors=_ZERO,
                resource=arn,
                evidence=[Evidence(source="snapshot", detail=f"referenced by {', '.join(names)}")],
                references=[ref.GET_ACCOUNT_AUTHORIZATION_DETAILS, ref.POLICY_EVALUATION_LOGIC],
                tags=["coverage", "unresolved-policy"],
            )
        )
    return findings


def _unresolved_roles(ctx: AnalysisContext) -> list[Finding]:
    missing: dict[str, list[str]] = {}
    for fn in ctx.env.lambda_functions:
        if fn.role_arn and ctx.env.role(fn.role_arn) is None:
            missing.setdefault(fn.role_arn, []).append(fn.name)
    findings: list[Finding] = []
    for arn, names in sorted(missing.items()):
        findings.append(
            ctx.finding(
                check_id="COVERAGE-UNRESOLVED-ROLE",
                category=Category.COVERAGE,
                title=f"Execution role {arn} is used by functions but not present in the snapshot",
                description=f"Functions {', '.join(sorted(names))} run under {arn}, whose policies are not in the snapshot; what those functions can reach is unknown.",
                impact="The permissions of the affected workloads cannot be assessed.",
                remediation=Remediation(
                    summary="Include the role in the snapshot (check IAM coverage and whether the role lives in another account).",
                    verification_steps=("Re-run the analysis after adding the role.",),
                ),
                evidence_kind=EvidenceKind.OBSERVED,
                confidence=Confidence.HIGH,
                factors=_ZERO,
                resource=arn,
                evidence=[
                    Evidence(source="snapshot", detail=f"used by {', '.join(sorted(names))}")
                ],
                references=[ref.LAMBDA_EXECUTION_ROLE],
                tags=["coverage", "unresolved-role"],
            )
        )
    return findings


__all__ = ["CHECK_IDS", "CoverageStatus", "run"]
