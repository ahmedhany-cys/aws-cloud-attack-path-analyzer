"""Resource exposure: public and cross-account access to buckets and functions."""

from __future__ import annotations

from attackpath.analysis import references as ref
from attackpath.analysis.context import AnalysisContext
from attackpath.analysis.remediation import (
    POLICY_ASSUMPTIONS_GENERIC,
    access_analyzer_step,
    bucket_policy_status_step,
    rerun_step,
)
from attackpath.graph.builder import WRITE_CLASSES
from attackpath.graph.model import Edge, EdgeType, NodeType
from attackpath.models.environment import LambdaFunction, S3Bucket
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
    "S3-PUBLIC-POLICY",
    "S3-PUBLIC-ACL",
    "S3-EXTERNAL-ACCESS",
    "LAMBDA-PUBLIC-INVOKE",
    "LAMBDA-EXTERNAL-INVOKE",
)

_PAB_ALL = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}


def run(ctx: AnalysisContext) -> list[Finding]:
    findings: list[Finding] = []
    for bucket in ctx.env.s3_buckets:
        for edge in ctx.graph.in_edges(bucket.arn, EdgeType.CAN_ACCESS):
            source = ctx.graph.node(edge.source)
            if source is None:
                continue
            if source.type is NodeType.ANONYMOUS and ctx.config.is_check_enabled(
                "S3-PUBLIC-POLICY"
            ):
                findings.append(_public_policy(ctx, bucket, edge))
            elif source.type in (
                NodeType.EXTERNAL_ACCOUNT,
                NodeType.EXTERNAL_PRINCIPAL,
            ) and ctx.config.is_check_enabled("S3-EXTERNAL-ACCESS"):
                findings.append(_external_access(ctx, bucket, edge))
        if ctx.config.is_check_enabled("S3-PUBLIC-ACL") and (
            bucket.acl_public_read or bucket.acl_public_write
        ):
            findings.append(_public_acl(ctx, bucket))
    for fn in ctx.env.lambda_functions:
        for edge in ctx.graph.in_edges(fn.arn, EdgeType.CAN_ACCESS):
            source = ctx.graph.node(edge.source)
            if source is None:
                continue
            if source.type is NodeType.ANONYMOUS and ctx.config.is_check_enabled(
                "LAMBDA-PUBLIC-INVOKE"
            ):
                findings.append(_lambda_invoke(ctx, fn, edge, public=True))
            elif source.type in (
                NodeType.EXTERNAL_ACCOUNT,
                NodeType.EXTERNAL_PRINCIPAL,
            ) and ctx.config.is_check_enabled("LAMBDA-EXTERNAL-INVOKE"):
                findings.append(_lambda_invoke(ctx, fn, edge, public=False))
    return findings


def _access_breadth(edge: Edge) -> tuple[float, str]:
    access = edge.attrs.get("access", {})
    classes = sorted(access)
    if WRITE_CLASSES & set(classes):
        return 1.0, "includes write, delete or policy access: " + ", ".join(classes)
    return 0.6, "read-only access: " + ", ".join(classes)


def _public_policy(ctx: AnalysisContext, bucket: S3Bucket, edge: Edge) -> Finding:
    breadth, breadth_note = _access_breadth(edge)
    pab = bucket.public_access_block
    mitigated = pab is not None and pab.restrict_public_buckets
    conditional = edge.evidence_kind is EvidenceKind.INDETERMINATE
    tags = ["public-access"]
    preconditions = list(edge.preconditions)
    if mitigated:
        tags.append("mitigated-by-block-public-access")
        title = f"Bucket {bucket.name} has a public bucket policy (blocked by Block Public Access)"
        exposure = FactorScore(
            0.3,
            0,
            "RestrictPublicBuckets is enabled; the public statement is inert while it stays enabled",
        )
        kind, confidence = EvidenceKind.OBSERVED, Confidence.HIGH
        impact = (
            "No public access is possible while RestrictPublicBuckets stays enabled, but the policy "
            "would become effective the moment the setting is relaxed."
        )
    elif conditional:
        title = (
            f"Bucket {bucket.name} may be publicly accessible (conditions could not be evaluated)"
        )
        exposure = FactorScore(
            0.8, 0, "public statement narrowed by conditions the analyzer cannot evaluate"
        )
        kind, confidence = EvidenceKind.INDETERMINATE, Confidence.LOW
        impact = "If the conditions are satisfiable by arbitrary callers, the bucket contents are public."
    else:
        title = f"Bucket {bucket.name} is publicly accessible through its bucket policy"
        exposure = FactorScore(
            1.0, 0, "no Block Public Access setting prevents the public statement"
        )
        kind, confidence = EvidenceKind.OBSERVED, Confidence.HIGH
        impact = "Anyone on the internet can perform the granted S3 operations on the bucket without credentials."
    remediation = Remediation(
        summary='Enable all four Block Public Access settings and remove the Principal "*" statement; serve genuinely public content through CloudFront with origin access control.',
        steps=(
            "Confirm whether any consumer legitimately relies on anonymous access (S3 server access logs or CloudTrail data events).",
            "Enable BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy and RestrictPublicBuckets on the bucket (and at the account level).",
            "Replace the anonymous statement with grants to specific principals, or front the bucket with CloudFront using origin access control.",
        ),
        suggested_policy={"PublicAccessBlockConfiguration": dict(_PAB_ALL)},
        policy_assumptions=POLICY_ASSUMPTIONS_GENERIC
        + (
            "Enabling Block Public Access immediately stops any anonymous consumer; coordinate the change with the content owners.",
        ),
        verification_steps=(
            bucket_policy_status_step(bucket.name),
            access_analyzer_step(),
            rerun_step("S3-PUBLIC-POLICY", f"bucket {bucket.name}"),
        ),
    )
    return ctx.finding(
        check_id="S3-PUBLIC-POLICY",
        category=Category.RESOURCE_EXPOSURE,
        title=title,
        description=(
            f'The bucket policy of {bucket.name} grants {", ".join(sorted(edge.attrs.get("access", {})))} to Principal "*". '
            + (
                f"Block Public Access: {_pab_text(bucket)}. "
                if pab
                else "No Block Public Access configuration is recorded for the bucket. "
            )
            + f"Declared sensitivity: {bucket.sensitivity.value}."
        ),
        impact=impact,
        remediation=remediation,
        evidence_kind=kind,
        confidence=confidence,
        factors={
            "permission_breadth": FactorScore(breadth, 0, breadth_note),
            "escalation_potential": FactorScore(
                0.6 if "policy" in edge.attrs.get("access", {}) else 0.1,
                0,
                "bucket policy changes"
                if "policy" in edge.attrs.get("access", {})
                else "data access only",
            ),
            "resource_sensitivity": ctx.sensitivity_factor(bucket),
            "trust_boundary": FactorScore(
                0.3 if mitigated else 1.0,
                0,
                "boundary crossing blocked while RestrictPublicBuckets stays enabled"
                if mitigated
                else "anonymous access",
            ),
            "exposure": exposure,
            "reachability": FactorScore(
                0.5 if mitigated else 1.0,
                0,
                "inert until the Block Public Access setting is relaxed" if mitigated else "direct",
            ),
        },
        resource=bucket.arn,
        evidence=list(edge.evidence),
        preconditions=preconditions,
        references=[ref.S3_BLOCK_PUBLIC_ACCESS, ref.S3_BUCKET_POLICIES],
        tags=tags,
    )


def _public_acl(ctx: AnalysisContext, bucket: S3Bucket) -> Finding:
    pab = bucket.public_access_block
    mitigated = pab is not None and pab.ignore_public_acls
    modes = [
        m
        for m, flag in (("read", bucket.acl_public_read), ("write", bucket.acl_public_write))
        if flag
    ]
    title = f"Bucket {bucket.name} has a public ACL ({', '.join(modes)})" + (
        " (ignored by Block Public Access)" if mitigated else ""
    )
    return ctx.finding(
        check_id="S3-PUBLIC-ACL",
        category=Category.RESOURCE_EXPOSURE,
        title=title,
        description=(
            f"The bucket ACL of {bucket.name} grants {', '.join(modes)} access to AllUsers or AuthenticatedUsers. "
            + (
                f"Block Public Access: {_pab_text(bucket)}."
                if pab
                else "No Block Public Access configuration is recorded for the bucket."
            )
        ),
        impact="ACL grants bypass the bucket policy review process and are easy to overlook; public write ACLs allow anyone to upload or overwrite objects.",
        remediation=Remediation(
            summary="Enable IgnorePublicAcls and BlockPublicAcls, switch the bucket to bucket-owner-enforced object ownership, and remove the public grants.",
            steps=(
                "Set Object Ownership to BucketOwnerEnforced, which disables ACLs entirely.",
                "Enable all four Block Public Access settings.",
                "Grant any remaining access through the bucket policy to explicit principals.",
            ),
            suggested_policy={
                "PublicAccessBlockConfiguration": dict(_PAB_ALL),
                "OwnershipControls": {"Rules": [{"ObjectOwnership": "BucketOwnerEnforced"}]},
            },
            policy_assumptions=POLICY_ASSUMPTIONS_GENERIC,
            verification_steps=(
                f"aws s3api get-bucket-acl --bucket {bucket.name} (expect no AllUsers/AuthenticatedUsers grants)",
                bucket_policy_status_step(bucket.name),
                rerun_step("S3-PUBLIC-ACL", f"bucket {bucket.name}"),
            ),
        ),
        evidence_kind=EvidenceKind.OBSERVED,
        confidence=Confidence.HIGH,
        factors={
            "permission_breadth": FactorScore(
                1.0 if bucket.acl_public_write else 0.6,
                0,
                "write ACL" if bucket.acl_public_write else "read ACL",
            ),
            "escalation_potential": FactorScore(0.1, 0, "data access only"),
            "resource_sensitivity": ctx.sensitivity_factor(bucket),
            "trust_boundary": FactorScore(1.0, 0, "anonymous access"),
            "exposure": FactorScore(
                0.3 if mitigated else 1.0,
                0,
                "IgnorePublicAcls enabled" if mitigated else "ACL is effective",
            ),
            "reachability": FactorScore(1.0, 0, "direct"),
        },
        resource=bucket.arn,
        evidence=[
            Evidence(
                source=f"s3:{bucket.arn}",
                detail=f"ACL public {', '.join(modes)} recorded in the snapshot",
            )
        ],
        references=[ref.S3_ACL, ref.S3_BLOCK_PUBLIC_ACCESS],
        tags=["public-access", "acl"] + (["mitigated-by-block-public-access"] if mitigated else []),
    )


def _external_access(ctx: AnalysisContext, bucket: S3Bucket, edge: Edge) -> Finding:
    breadth, breadth_note = _access_breadth(edge)
    source = ctx.graph.node(edge.source)
    known = bool(source and source.attrs.get("known"))
    label = ctx.node_label(edge.source)
    return ctx.finding(
        check_id="S3-EXTERNAL-ACCESS",
        category=Category.RESOURCE_EXPOSURE,
        title=f"Bucket {bucket.name} grants {', '.join(sorted(edge.attrs.get('access', {})))} to {label}",
        description=(
            f"The bucket policy of {bucket.name} allows principals of {label} to perform "
            f"{', '.join(sorted(edge.attrs.get('access', {})))}. Cross-account access also requires an "
            "identity-policy Allow in the other account, which is outside the snapshot. "
            + (
                "The account is declared as a known partner."
                if known
                else "The account is not declared as a known partner in the snapshot."
            )
        ),
        impact="Data in the bucket is governed by another account's identity management; a compromise there extends to this bucket.",
        remediation=Remediation(
            summary="Grant cross-account access to specific roles with a narrow prefix and action list, and document the data-sharing agreement.",
            steps=(
                "Replace account-root principals with the specific external role ARN.",
                "Limit actions to those required (for example s3:GetObject on a prefix) and add aws:PrincipalOrgID or aws:PrincipalArn conditions.",
                "Record the external account in the environment inventory as a known partner once approved.",
            ),
            policy_assumptions=POLICY_ASSUMPTIONS_GENERIC,
            verification_steps=(
                access_analyzer_step(),
                rerun_step("S3-EXTERNAL-ACCESS", f"bucket {bucket.name}"),
            ),
        ),
        evidence_kind=EvidenceKind.HYPOTHETICAL,
        confidence=Confidence.MEDIUM,
        factors={
            "permission_breadth": FactorScore(breadth, 0, breadth_note),
            "escalation_potential": FactorScore(0.2, 0, "data access"),
            "resource_sensitivity": ctx.sensitivity_factor(bucket),
            "trust_boundary": FactorScore(0.8, 0, "cross-account"),
            "exposure": FactorScore(
                0.6 if known else 0.8,
                0,
                "known partner" if known else "undeclared external account",
            ),
            "reachability": FactorScore(1.0, 0, "direct"),
        },
        resource=bucket.arn,
        principal=edge.source if not edge.source.startswith("account:") else None,
        evidence=list(edge.evidence),
        preconditions=list(edge.preconditions),
        references=[ref.S3_BUCKET_POLICIES, ref.ACCESS_ANALYZER],
        tags=["cross-account-access"],
        key=(edge.source,),
    )


def _lambda_invoke(
    ctx: AnalysisContext, fn: LambdaFunction, edge: Edge, *, public: bool
) -> Finding:
    role_node = ctx.graph.node(fn.role_arn) if fn.role_arn else None
    privilege = (
        ctx.privilege_factor(role_node)
        if role_node
        else FactorScore(0.4, 0, "execution role unknown")
    )
    label = "anyone" if public else ctx.node_label(edge.source)
    check_id = "LAMBDA-PUBLIC-INVOKE" if public else "LAMBDA-EXTERNAL-INVOKE"
    conditional = edge.evidence_kind is EvidenceKind.INDETERMINATE
    return ctx.finding(
        check_id=check_id,
        category=Category.RESOURCE_EXPOSURE,
        title=f"Function {fn.name} can be invoked by {label}"
        + (" (subject to unevaluated conditions)" if conditional else ""),
        description=(
            f"The resource policy of {fn.name} allows {', '.join(sorted(edge.attrs.get('access', {})))} for {label}. "
            f"The function runs under {fn.role_arn or 'an unknown role'}: {privilege.rationale}."
        ),
        impact="Every invocation executes the function's code with its execution role; unauthenticated invocation turns the function into a public entry point into the account.",
        remediation=Remediation(
            summary="Require authentication for the function URL or API, and restrict the resource policy to the specific caller.",
            steps=(
                "If a function URL is used, set AuthType to AWS_IAM, or front the function with API Gateway using an authorizer.",
                'Replace Principal "*" with the invoking service or account and add aws:SourceArn / aws:SourceAccount conditions.',
                "Minimise the execution role's permissions to what the handler needs.",
            ),
            policy_assumptions=POLICY_ASSUMPTIONS_GENERIC,
            verification_steps=(
                f"aws lambda get-policy --function-name {fn.name} (expect no Principal * statement)",
                rerun_step(check_id, f"function {fn.name}"),
            ),
        ),
        evidence_kind=edge.evidence_kind if public else EvidenceKind.HYPOTHETICAL,
        confidence=edge.confidence if public else Confidence.MEDIUM,
        factors={
            "permission_breadth": FactorScore(0.5, 0, "invoke only"),
            "escalation_potential": FactorScore(privilege.value, 0, privilege.rationale),
            "resource_sensitivity": FactorScore(privilege.value, 0, "reach of the execution role"),
            "trust_boundary": FactorScore(
                1.0 if public else 0.8, 0, "anonymous" if public else "cross-account"
            ),
            "exposure": FactorScore(
                1.0 if public else 0.8, 0, "public entry point" if public else "external account"
            ),
            "reachability": FactorScore(1.0, 0, "direct"),
        },
        resource=fn.arn,
        evidence=list(edge.evidence),
        preconditions=list(edge.preconditions),
        references=[ref.LAMBDA_RESOURCE_POLICY, ref.LAMBDA_EXECUTION_ROLE],
        tags=["public-access" if public else "cross-account-access", "lambda"],
        key=(edge.source,),
    )


def _pab_text(bucket: S3Bucket) -> str:
    pab = bucket.public_access_block
    if pab is None:
        return "not configured"
    return (
        f"BlockPublicAcls={pab.block_public_acls}, IgnorePublicAcls={pab.ignore_public_acls}, "
        f"BlockPublicPolicy={pab.block_public_policy}, RestrictPublicBuckets={pab.restrict_public_buckets}"
    )
