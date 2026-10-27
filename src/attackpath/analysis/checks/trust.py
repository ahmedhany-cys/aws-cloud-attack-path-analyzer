"""Role trust relationships: anonymous and cross-account trust."""

from __future__ import annotations

from attackpath.analysis import references as ref
from attackpath.analysis.context import AnalysisContext
from attackpath.analysis.remediation import POLICY_ASSUMPTIONS_GENERIC, get_role_step, rerun_step
from attackpath.graph.builder import TrustEntry
from attackpath.graph.model import EdgeType
from attackpath.models.environment import Role
from attackpath.models.finding import (
    Category,
    Confidence,
    Evidence,
    EvidenceKind,
    FactorScore,
    Finding,
    Remediation,
)

CHECK_IDS: tuple[str, ...] = ("TRUST-ANONYMOUS", "TRUST-CROSS-ACCOUNT")

#: Condition keys that narrow a wildcard principal to a controlled set of callers.
_NARROWING_KEYS = frozenset(
    {
        "aws:principalorgid",
        "aws:principalorgpaths",
        "aws:principalarn",
        "aws:principalaccount",
        "aws:sourcearn",
        "aws:sourceaccount",
    }
)


def run(ctx: AnalysisContext) -> list[Finding]:
    findings: list[Finding] = []
    for role in ctx.env.roles:
        seen: set[tuple[str, str]] = set()
        for entry in ctx.trust(role):
            key = (entry.kind, entry.value)
            if key in seen:
                continue
            seen.add(key)
            if entry.kind == "anonymous" and ctx.config.is_check_enabled("TRUST-ANONYMOUS"):
                findings.append(_anonymous_trust(ctx, role, entry))
            elif entry.kind in (
                "cross-account",
                "cross-account-principal",
            ) and ctx.config.is_check_enabled("TRUST-CROSS-ACCOUNT"):
                findings.append(_cross_account_trust(ctx, role, entry))
    return findings


def _role_capability(
    ctx: AnalysisContext, role: Role
) -> tuple[FactorScore, FactorScore, FactorScore]:
    node = ctx.graph.node(role.arn)
    if node is None:
        return (
            FactorScore(0.5, 0, "unknown"),
            FactorScore(0.5, 0, "unknown"),
            FactorScore(0.5, 0, "unknown"),
        )
    privilege = ctx.privilege_factor(node)
    breadth = FactorScore(
        float(node.attrs.get("breadth", 0.0)), 0, "breadth of the role's own permissions"
    )
    sensitivity = FactorScore(privilege.value, 0, privilege.rationale)
    return breadth, privilege, sensitivity


def _anonymous_trust(ctx: AnalysisContext, role: Role, entry: TrustEntry) -> Finding:
    breadth, escalation, sensitivity = _role_capability(ctx, role)
    keys = {k.lower() for k in entry.condition_keys}
    conditions = "; ".join(c.describe() for c in entry.conditions)
    edge = next(
        (e for e in ctx.graph.in_edges(role.arn, EdgeType.CAN_ASSUME) if e.source == "anonymous"),
        None,
    )
    preconditions: list[str] = list(edge.preconditions) if edge else []
    if not entry.conditions:
        kind, confidence, trust_value = EvidenceKind.OBSERVED, Confidence.HIGH, 1.0
        title = f"Role {role.name} can be assumed by any AWS principal"
        detail = 'The trust policy names Principal "*" with no condition: any AWS account can call sts:AssumeRole on it.'
    elif keys & _NARROWING_KEYS:
        kind, confidence, trust_value = EvidenceKind.INFERRED, Confidence.MEDIUM, 0.5
        title = f"Role {role.name} trusts a wildcard principal narrowed only by conditions"
        detail = (
            f'The trust policy names Principal "*" and relies on conditions ({conditions}) to limit '
            "callers. The restriction is only as strong as those condition values."
        )
    else:
        kind, confidence, trust_value = EvidenceKind.INDETERMINATE, Confidence.LOW, 0.8
        title = f"Role {role.name} trusts a wildcard principal with conditions the analyzer cannot evaluate"
        detail = (
            f'The trust policy names Principal "*" with conditions ({conditions}) whose request-time '
            "values are unknown; whether they meaningfully restrict callers cannot be decided offline."
        )
    remediation = Remediation(
        summary='Name the specific principals that need the role instead of "*"; for organization-wide access use aws:PrincipalOrgID.',
        steps=(
            "List the accounts and roles that legitimately assume this role (CloudTrail AssumeRole events).",
            'Replace Principal "*" with those principal ARNs (or account roots plus an sts:ExternalId condition for third parties).',
            "If any principal in your organization must assume it, keep a wildcard only together with a StringEquals aws:PrincipalOrgID condition.",
        ),
        suggested_policy={
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": ["arn:aws:iam::<trusted-account-id>:role/<trusted-role>"]},
                    "Action": "sts:AssumeRole",
                    "Condition": {"StringEquals": {"aws:PrincipalOrgID": "<o-your-org-id>"}},
                }
            ],
        },
        policy_assumptions=POLICY_ASSUMPTIONS_GENERIC
        + ("Remove the aws:PrincipalOrgID condition if callers are outside your organization.",),
        verification_steps=(
            get_role_step(role.name),
            "If IAM Access Analyzer is enabled, confirm it reports no public finding for the role.",
            rerun_step("TRUST-ANONYMOUS", f"role {role.name}"),
        ),
    )
    return ctx.finding(
        check_id="TRUST-ANONYMOUS",
        category=Category.TRUST_RELATIONSHIP,
        title=title,
        description=detail
        + f" The role's own permissions determine what a caller gains: {escalation.rationale}.",
        impact="Anyone able to satisfy the trust policy obtains the role's permissions without any credential of this account.",
        remediation=remediation,
        evidence_kind=kind,
        confidence=confidence,
        factors={
            "permission_breadth": breadth,
            "escalation_potential": escalation,
            "resource_sensitivity": sensitivity,
            "trust_boundary": FactorScore(trust_value, 0, "trust extends beyond the account"),
            "exposure": FactorScore(1.0, 0, "reachable by any AWS principal"),
            "reachability": FactorScore(1.0, 0, "single sts:AssumeRole call"),
        },
        principal=role.arn,
        evidence=[
            Evidence(
                source=role.trust_policy.source,
                detail=f"{entry.statement.label()} names Principal * "
                + (f"with conditions {conditions}" if conditions else "without conditions"),
                statement=entry.statement.raw,
            )
        ],
        preconditions=preconditions,
        references=[ref.PRINCIPAL_ELEMENT, ref.CONDITION_KEYS, ref.CROSS_ACCOUNT_ROLES],
        tags=["anonymous-trust"] + (["condition-restricted"] if entry.conditions else []),
        key=(entry.value,),
    )


def _cross_account_trust(ctx: AnalysisContext, role: Role, entry: TrustEntry) -> Finding:
    breadth, escalation, sensitivity = _role_capability(ctx, role)
    external = next((e for e in ctx.env.external_principals if e.arn == entry.value), None)
    known = external is not None and external.known
    account = entry.value
    conditions = "; ".join(c.describe() for c in entry.conditions)
    preconditions: list[str] = [
        f"a principal in the trusted account must hold an identity-policy Allow for sts:AssumeRole on {role.arn}"
    ]
    tags = ["cross-account-trust"]
    if entry.requires_external_id:
        preconditions.append("the caller must present the configured sts:ExternalId")
        tags.append("external-id-required")
        suffix = " (sts:ExternalId required)"
    elif entry.kind == "cross-account":
        tags.append("missing-external-id")
        suffix = " without an sts:ExternalId condition"
    else:
        suffix = ""
    whole_account = entry.kind == "cross-account"
    title = (
        f"Role {role.name} trusts {'account' if whole_account else 'principal'} {account}{suffix}"
    )
    description = (
        f"{role.trust_policy.source} {entry.statement.label()} allows {entry.value} to assume the role"
        + (f" subject to conditions ({conditions})" if conditions else "")
        + ". "
        + (
            "Trusting an entire account delegates the decision of who may assume the role to that account's administrators. "
            if whole_account
            else ""
        )
        + (
            "The trusted account is declared as a known partner in the snapshot. "
            if known
            else "The trusted account is not declared as a known partner in the snapshot. "
        )
        + f"What a caller gains: {escalation.rationale}."
    )
    remediation = Remediation(
        summary="Trust the specific external role rather than the account root, and require an sts:ExternalId for third-party access.",
        steps=(
            "Confirm with the owner of the trusted account which role or user needs access and why.",
            "Replace the account-root principal with that principal's ARN.",
            "For vendor or third-party access add a Condition with StringEquals sts:ExternalId set to a value only the vendor knows.",
            "Limit the role's own permissions to what the integration needs and set a short MaxSessionDuration.",
        ),
        suggested_policy={
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": f"arn:aws:iam::{entry.value if whole_account and len(entry.value) == 12 else '<trusted-account-id>'}:role/<integration-role>"
                    },
                    "Action": "sts:AssumeRole",
                    "Condition": {"StringEquals": {"sts:ExternalId": "<unique-external-id>"}},
                }
            ],
        },
        policy_assumptions=POLICY_ASSUMPTIONS_GENERIC
        + (
            "The ExternalId condition is only meaningful for third parties; omit it for roles your own organization controls.",
        ),
        verification_steps=(
            get_role_step(role.name),
            rerun_step("TRUST-CROSS-ACCOUNT", f"role {role.name}"),
        ),
    )
    return ctx.finding(
        check_id="TRUST-CROSS-ACCOUNT",
        category=Category.TRUST_RELATIONSHIP,
        title=title,
        description=description,
        impact="Principals in the trusted account can obtain this role's permissions; the security of this account then depends on the other account's identity management.",
        remediation=remediation,
        evidence_kind=EvidenceKind.OBSERVED,
        confidence=Confidence.HIGH,
        factors={
            "permission_breadth": breadth,
            "escalation_potential": escalation,
            "resource_sensitivity": sensitivity,
            "trust_boundary": FactorScore(0.8, 0, "trust crosses an account boundary"),
            "exposure": FactorScore(
                0.6 if known else 0.8,
                0,
                "known partner account" if known else "account not declared as a known partner",
            ),
            "reachability": FactorScore(1.0, 0, "single sts:AssumeRole call"),
        },
        principal=role.arn,
        evidence=[
            Evidence(
                source=role.trust_policy.source,
                detail=f"{entry.statement.label()} names {entry.value}"
                + (f" with conditions {conditions}" if conditions else ""),
                statement=entry.statement.raw,
            )
        ],
        preconditions=preconditions,
        references=[ref.CROSS_ACCOUNT_ROLES, ref.EXTERNAL_ID, ref.PRINCIPAL_ELEMENT],
        tags=tags,
        key=(entry.value,),
    )
