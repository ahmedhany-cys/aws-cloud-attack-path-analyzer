"""Direct access by principals to buckets declared sensitive."""

from __future__ import annotations

from attackpath.analysis import references as ref
from attackpath.analysis.context import AnalysisContext
from attackpath.analysis.remediation import (
    POLICY_ASSUMPTIONS_GENERIC,
    least_privilege_steps,
    rerun_step,
    simulate_step,
)
from attackpath.graph.builder import WRITE_CLASSES
from attackpath.graph.model import Edge, EdgeType, NodeType
from attackpath.models.environment import Principal, Role, S3Bucket, Sensitivity
from attackpath.models.finding import (
    Category,
    FactorScore,
    Finding,
    Remediation,
)

CHECK_IDS: tuple[str, ...] = ("SENSITIVE-ACCESS",)


def run(ctx: AnalysisContext) -> list[Finding]:
    if not ctx.config.is_check_enabled("SENSITIVE-ACCESS"):
        return []
    findings: list[Finding] = []
    for bucket in ctx.env.s3_buckets:
        if bucket.sensitivity not in (Sensitivity.HIGH, Sensitivity.MEDIUM):
            continue
        for edge in ctx.graph.in_edges(bucket.arn, EdgeType.CAN_ACCESS):
            source = ctx.graph.node(edge.source)
            if (
                source is None
                or source.type not in (NodeType.USER, NodeType.ROLE)
                or source.is_admin.is_true
                or edge.attrs.get("public_only")
            ):
                continue
            principal = ctx.env.principal(edge.source)
            if principal is None:
                continue
            findings.append(_finding(ctx, principal, bucket, edge))
    return findings


def _finding(ctx: AnalysisContext, principal: Principal, bucket: S3Bucket, edge: Edge) -> Finding:
    access: dict[str, str] = edge.attrs.get("access", {})
    denied: dict[str, str] = edge.attrs.get("denied", {})
    classes = sorted(access)
    definite = sorted(c for c, d in access.items() if d == "allowed")
    conditional = sorted(c for c, d in access.items() if d != "allowed")
    workload = isinstance(principal, Role) and ctx.is_workload(principal)
    label = ctx.label(principal)
    who = f"Workload {label}" if workload else label[0].upper() + label[1:]
    if "policy" in access:
        breadth, escalation = 1.0, 0.7
    elif WRITE_CLASSES & set(access):
        breadth, escalation = 0.8, 0.3
    else:
        breadth, escalation = 0.5, 0.1
    description = (
        f"{who} can perform {', '.join(definite) if definite else 'no definite'} operations on "
        f"{bucket.name} (declared sensitivity: {bucket.sensitivity.value})"
        + (
            f"; {', '.join(conditional)} depend on conditions the analyzer could not evaluate"
            if conditional
            else ""
        )
        + (f". Explicit Deny statements prevent: {', '.join(sorted(denied))}" if denied else "")
        + "."
    )
    if workload:
        node = ctx.graph.node(principal.arn)
        services = ", ".join(node.attrs.get("workload_services", [])) if node else ""
        functions = ", ".join(node.attrs.get("used_by_lambdas", [])) if node else ""
        description += (
            " The role is assumed by AWS services"
            + (f" ({services})" if services else "")
            + (f" and used by functions {functions}" if functions else "")
            + "; its permissions are only as safe as the code that runs under it."
        )
    remediation = Remediation(
        summary="Grant the principal only the actions and object prefixes its workflow needs on this bucket, and deny the rest explicitly.",
        steps=least_privilege_steps(label)
        + (
            "For workload roles, scope S3 access to the exact bucket and prefix the handler reads or writes.",
            "Consider a bucket policy that denies access from principals other than an allow-list (aws:PrincipalArn) for high-sensitivity data.",
        ),
        suggested_policy={
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject"],
                    "Resource": "arn:aws:s3:::<needed-bucket>/<needed-prefix>/*",
                },
                {
                    "Effect": "Allow",
                    "Action": ["s3:ListBucket"],
                    "Resource": "arn:aws:s3:::<needed-bucket>",
                    "Condition": {"StringLike": {"s3:prefix": ["<needed-prefix>/*"]}},
                },
            ],
        },
        policy_assumptions=POLICY_ASSUMPTIONS_GENERIC
        + (
            "Replace s3:GetObject with the write actions if the workflow writes, and remove ListBucket if listing is not required.",
        ),
        verification_steps=(
            simulate_step(principal.arn, ["s3:GetObject", "s3:PutObject"], f"{bucket.arn}/*"),
            rerun_step("SENSITIVE-ACCESS", f"{label} on bucket {bucket.name}"),
        ),
    )
    return ctx.finding(
        check_id="SENSITIVE-ACCESS",
        category=Category.SENSITIVE_ACCESS,
        title=f"{who} can {'/'.join(classes)} sensitive bucket {bucket.name}",
        description=description,
        impact=(
            "If this identity's credentials or code are compromised, the sensitive data in the bucket is "
            + ("readable, modifiable or deletable" if WRITE_CLASSES & set(access) else "readable")
            + " without any further step."
        ),
        remediation=remediation,
        evidence_kind=edge.evidence_kind,
        confidence=edge.confidence,
        factors={
            "permission_breadth": FactorScore(breadth, 0, "access classes: " + ", ".join(classes)),
            "escalation_potential": FactorScore(
                escalation, 0, "bucket policy control" if "policy" in access else "data access"
            ),
            "resource_sensitivity": ctx.sensitivity_factor(bucket),
            "trust_boundary": FactorScore(
                0.0 if bucket.account_id == principal.account_id else 0.8,
                0,
                "same account"
                if bucket.account_id == principal.account_id
                else "cross-account bucket",
            ),
            "exposure": ctx.exposure(principal),
            "reachability": FactorScore(1.0, 0, "direct permission"),
        },
        principal=principal.arn,
        resource=bucket.arn,
        evidence=list(edge.evidence),
        preconditions=list(edge.preconditions),
        references=[ref.LEAST_PRIVILEGE, ref.S3_BUCKET_POLICIES]
        + ([ref.LAMBDA_EXECUTION_ROLE] if workload else []),
        tags=["sensitive-data"]
        + (["workload"] if workload else [])
        + (["write-access"] if WRITE_CLASSES & set(access) else []),
    )
