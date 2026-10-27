"""Excessive permissions: administrative access and wildcard grants."""

from __future__ import annotations

from attackpath.analysis import references as ref
from attackpath.analysis.context import AnalysisContext
from attackpath.analysis.remediation import (
    POLICY_ASSUMPTIONS_GENERIC,
    least_privilege_steps,
    rerun_step,
    simulate_step,
)
from attackpath.iam.evaluator import Decision
from attackpath.iam.matching import (
    action_breadth,
    is_full_wildcard,
    is_service_wildcard,
    resource_breadth,
    service_of,
)
from attackpath.models.environment import Principal, Sensitivity
from attackpath.models.finding import (
    Category,
    Confidence,
    Evidence,
    EvidenceKind,
    FactorScore,
    Finding,
    Remediation,
)

CHECK_IDS: tuple[str, ...] = ("ADMIN", "WILDCARD")

_CONTROL_PLANE_SERVICES = frozenset({"*", "iam", "sts", "organizations", "sso", "identitystore"})
_COMPUTE_SERVICES = frozenset(
    {"lambda", "ec2", "ecs", "eks", "cloudformation", "ssm", "codebuild", "glue"}
)
_DATA_SERVICES = frozenset({"s3", "kms", "secretsmanager", "dynamodb", "rds", "ssm", "sqs", "sns"})


def run(ctx: AnalysisContext) -> list[Finding]:
    findings: list[Finding] = []
    if not ctx.config.is_check_enabled("ADMIN") and not ctx.config.is_check_enabled("WILDCARD"):
        return findings
    max_bucket_sensitivity = _max_bucket_sensitivity(ctx)
    for principal in ctx.env.principals():
        node = ctx.graph.node(principal.arn)
        if node is None:
            continue
        if ctx.config.is_check_enabled("ADMIN") and node.is_admin.is_true:
            findings.append(_admin_finding(ctx, principal, definite=True))
            continue  # wildcard statements are implied by administrative access
        if (
            ctx.config.is_check_enabled("ADMIN")
            and node.is_admin.is_unknown
            and node.attrs.get("admin_evidence")
        ):
            # Some probes are definitely allowed and the rest depend on unresolved
            # context; a principal whose only uncertainty is a missing document is
            # covered by the coverage check instead.
            findings.append(_admin_finding(ctx, principal, definite=False))
            continue
        if ctx.config.is_check_enabled("WILDCARD"):
            findings.extend(_wildcard_findings(ctx, principal, max_bucket_sensitivity))
    return findings


def _max_bucket_sensitivity(ctx: AnalysisContext) -> float:
    values = {
        Sensitivity.HIGH: 1.0,
        Sensitivity.MEDIUM: 0.6,
        Sensitivity.LOW: 0.2,
        Sensitivity.UNKNOWN: 0.4,
    }
    return max((values[b.sensitivity] for b in ctx.env.s3_buckets), default=0.5)


def _admin_finding(ctx: AnalysisContext, principal: Principal, definite: bool) -> Finding:
    label = ctx.label(principal)
    node = ctx.graph.node(principal.arn)
    evidence: list[Evidence] = []
    admin_refs = node.attrs.get("admin_evidence", []) if node else []
    for doc, st in ctx.identity_allow_statements(principal):
        if doc.ref(st).describe() in admin_refs:
            evidence.append(
                Evidence(
                    source=doc.source,
                    detail=f"{st.label()} grants administrative access",
                    statement=st.raw,
                )
            )
    unresolved = ctx.evaluator.unresolved_policies_for(principal)
    preconditions: list[str] = []
    if definite:
        kind, confidence = EvidenceKind.OBSERVED, Confidence.HIGH
        title = f"{label} has administrative permissions"
        description = (
            f"{label} is allowed every probed high-impact action (IAM user and policy management, "
            "sts:AssumeRole, S3, EC2, Lambda, KMS) on any resource, with no Deny statement or "
            "permissions boundary restricting it."
        )
    else:
        kind, confidence = EvidenceKind.INDETERMINATE, Confidence.LOW
        title = f"{label} may have administrative permissions"
        description = (
            f"{label} is allowed most probed high-impact actions on any resource, but at least one "
            "evaluation depends on a condition or policy document the analyzer could not resolve."
        )
        preconditions.append(
            "unresolved policy documents or conditions grant the remaining actions"
        )
    if unresolved:
        description += f" Attached policies not present in the snapshot: {', '.join(unresolved)}."
    factors = {
        "permission_breadth": FactorScore(1.0, 0, "all actions on all resources"),
        "escalation_potential": FactorScore(1.0, 0, "full control of IAM"),
        "resource_sensitivity": FactorScore(1.0, 0, "every resource in the account"),
        "trust_boundary": FactorScore(0.0, 0, "same account"),
        "exposure": ctx.exposure(principal),
        "reachability": FactorScore(1.0, 0, "direct permission"),
    }
    remediation = Remediation(
        summary=(
            "Replace administrative access with task-scoped policies; keep a separate, "
            "MFA-protected break-glass identity if emergency access is required."
        ),
        steps=least_privilege_steps(label)
        + (
            "If this identity is an intentional break-glass administrator, document it, enforce MFA, "
            "remove long-lived access keys and alert on its use.",
        ),
        policy_assumptions=POLICY_ASSUMPTIONS_GENERIC,
        verification_steps=(
            simulate_step(principal.arn, ["iam:AttachUserPolicy", "iam:CreateAccessKey"], "*"),
            rerun_step("ADMIN", label),
        ),
    )
    return ctx.finding(
        check_id="ADMIN",
        category=Category.EXCESSIVE_PERMISSIONS,
        title=title,
        description=description,
        impact=(
            "Compromise of this identity's credentials gives complete control over the account: "
            "every resource, every other identity and all audit configuration."
        ),
        remediation=remediation,
        evidence_kind=kind,
        confidence=confidence,
        factors=factors,
        principal=principal.arn,
        evidence=evidence,
        preconditions=preconditions,
        references=[ref.LEAST_PRIVILEGE, ref.POLICY_EVALUATION_LOGIC, ref.MFA],
        tags=["administrative-access"],
    )


def _wildcard_findings(
    ctx: AnalysisContext, principal: Principal, bucket_sensitivity: float
) -> list[Finding]:
    findings: list[Finding] = []
    label = ctx.label(principal)
    for doc, st in ctx.identity_allow_statements(principal):
        broad_actions = st.uses_not_action or any(
            is_full_wildcard(a) or is_service_wildcard(a) for a in st.actions
        )
        res_breadth = 0.9 if st.uses_not_resource else resource_breadth(st.resources)
        if not broad_actions or res_breadth < 0.7:
            continue
        services = sorted({service_of(a) for a in st.actions}) if not st.uses_not_action else ["*"]
        act_breadth = 0.9 if st.uses_not_action else action_breadth(st.actions)
        escalation = _escalation_for_services(services)
        sensitivity = bucket_sensitivity if "s3" in services or "*" in services else 0.5
        conditions = "; ".join(c.describe() for c in st.conditions)
        kind = EvidenceKind.OBSERVED
        preconditions: list[str] = []
        if conditions:
            kind = EvidenceKind.INFERRED
            preconditions.append(f"statement conditions must hold: {conditions}")
        # Ask the evaluator whether a Deny elsewhere (possibly conditional) cancels the grant.
        probe_action = "*" if "*" in services else f"{services[0]}:*"
        probe = ctx.evaluator.evaluate(principal, probe_action, "*")
        if probe.decision is Decision.EXPLICIT_DENY:
            continue
        extra_evidence: list[Evidence] = []
        if probe.decision is Decision.INDETERMINATE:
            kind = EvidenceKind.INDETERMINATE
            preconditions.extend(probe.unknown_reasons())
            extra_evidence = [m.to_evidence() for m in probe.deny_matches]
        actions_text = (
            ", ".join(st.actions) if st.actions else "NotAction " + ", ".join(st.not_actions)
        )
        resources_text = (
            ", ".join(st.resources)
            if st.resources
            else "NotResource " + ", ".join(st.not_resources)
        )
        findings.append(
            ctx.finding(
                check_id="WILDCARD",
                category=Category.EXCESSIVE_PERMISSIONS,
                title=f"{label} is granted {actions_text} on {resources_text}",
                description=(
                    f"{doc.source} {st.label()} allows {actions_text} on {resources_text}"
                    + (f" subject to conditions ({conditions})" if conditions else "")
                    + ". Wildcard grants cover actions the workload does not need, including any "
                    "that AWS adds to the service in the future."
                ),
                impact=_wildcard_impact(services),
                remediation=Remediation(
                    summary="Scope the statement to the explicit actions and resource ARNs the workflow needs.",
                    steps=least_privilege_steps(label),
                    policy_assumptions=POLICY_ASSUMPTIONS_GENERIC,
                    verification_steps=(
                        simulate_step(
                            principal.arn,
                            [f"{services[0]}:*" if services[0] != "*" else "iam:CreateUser"],
                            "*",
                        ),
                        rerun_step("WILDCARD", label),
                    ),
                ),
                evidence_kind=kind,
                confidence=Confidence.HIGH,
                factors={
                    "permission_breadth": FactorScore(
                        act_breadth * res_breadth,
                        0,
                        f"actions {act_breadth:.2f} x resources {res_breadth:.2f}",
                    ),
                    "escalation_potential": FactorScore(
                        escalation, 0, f"services: {', '.join(services)}"
                    ),
                    "resource_sensitivity": FactorScore(
                        sensitivity, 0, "sensitivity of reachable data"
                    ),
                    "trust_boundary": FactorScore(0.0, 0, "same account"),
                    "exposure": ctx.exposure(principal),
                    "reachability": FactorScore(1.0, 0, "direct permission"),
                },
                principal=principal.arn,
                evidence=[
                    Evidence(
                        source=doc.source,
                        detail=f"{st.label()} grants {actions_text} on {resources_text}",
                        statement=st.raw,
                    ),
                    *extra_evidence,
                ],
                preconditions=preconditions,
                references=[ref.LEAST_PRIVILEGE, ref.IAM_ACTIONS],
                tags=["wildcard"] + [f"service:{s}" for s in services],
                key=(doc.source, str(st.index)),
            )
        )
    return findings


def _escalation_for_services(services: list[str]) -> float:
    if any(s in _CONTROL_PLANE_SERVICES for s in services):
        return 0.9
    if any(s in _COMPUTE_SERVICES for s in services):
        return 0.6
    if any(s in _DATA_SERVICES for s in services):
        return 0.4
    return 0.3


def _wildcard_impact(services: list[str]) -> str:
    if any(s in _CONTROL_PLANE_SERVICES for s in services):
        return (
            "Full control of IAM or STS lets the identity grant itself or others any permission; "
            "a compromise of its credentials is equivalent to administrative access."
        )
    if any(s in _COMPUTE_SERVICES for s in services):
        return (
            "Unrestricted control of compute services allows deploying or changing workloads, "
            "which run under their own execution roles and may reach sensitive data."
        )
    return (
        "Unrestricted access to data services lets the identity read, modify or delete every "
        "object of that service in the account, not only the data its workflow needs."
    )
