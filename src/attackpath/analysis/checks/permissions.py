"""Broad grants of security-relevant permissions.

Each check probes a representative resource through the evaluator (so explicit
denies, boundaries and conditions are honoured) and reports the grant as a
configuration finding with least-privilege guidance.
"""

from __future__ import annotations

from dataclasses import dataclass

from attackpath.analysis import references as ref
from attackpath.analysis.context import AnalysisContext
from attackpath.analysis.remediation import (
    POLICY_ASSUMPTIONS_GENERIC,
    rerun_step,
    simulate_step,
)
from attackpath.graph.model import EdgeType
from attackpath.iam.evaluator import Decision, EvaluationResult
from attackpath.iam.matching import resource_breadth
from attackpath.models.environment import Principal
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
    "ASSUME-BROAD",
    "PASSROLE-BROAD",
    "IAM-WRITE",
    "CREDENTIAL-WRITE",
    "LAMBDA-WRITE",
)

_IAM_WRITE_ACTIONS: tuple[tuple[str, str], ...] = (
    ("iam:AttachUserPolicy", "user"),
    ("iam:AttachRolePolicy", "role"),
    ("iam:AttachGroupPolicy", "group"),
    ("iam:PutUserPolicy", "user"),
    ("iam:PutRolePolicy", "role"),
    ("iam:PutGroupPolicy", "group"),
    ("iam:CreatePolicyVersion", "policy"),
    ("iam:SetDefaultPolicyVersion", "policy"),
    ("iam:UpdateAssumeRolePolicy", "role"),
    ("iam:AddUserToGroup", "group"),
    ("iam:DeleteUserPermissionsBoundary", "user"),
    ("iam:DeleteRolePermissionsBoundary", "role"),
)
_CREDENTIAL_ACTIONS: tuple[str, ...] = (
    "iam:CreateAccessKey",
    "iam:UpdateAccessKey",
    "iam:CreateLoginProfile",
    "iam:UpdateLoginProfile",
    "iam:DeactivateMFADevice",
    "iam:CreateServiceSpecificCredential",
)
_LAMBDA_WRITE_ACTIONS: tuple[str, ...] = (
    "lambda:UpdateFunctionCode",
    "lambda:UpdateFunctionConfiguration",
    "lambda:CreateFunction",
    "lambda:AddPermission",
)
_PASS_ROLE_CONSUMERS: tuple[tuple[str, str], ...] = (
    ("lambda:CreateFunction", "lambda.amazonaws.com"),
    ("ec2:RunInstances", "ec2.amazonaws.com"),
    ("cloudformation:CreateStack", "cloudformation.amazonaws.com"),
    ("ecs:RunTask", "ecs-tasks.amazonaws.com"),
    ("glue:CreateJob", "glue.amazonaws.com"),
    ("codebuild:CreateProject", "codebuild.amazonaws.com"),
)


@dataclass
class Grant:
    action: str
    result: EvaluationResult
    breadth: float
    condition_keys: tuple[str, ...]

    @property
    def conditional(self) -> bool:
        return self.result.decision is Decision.INDETERMINATE

    def evidence(self) -> list[Evidence]:
        return [m.to_evidence() for m in self.result.allow_matches]


def probe_arns(account_id: str) -> dict[str, str]:
    return {
        "user": f"arn:aws:iam::{account_id}:user/probe-user",
        "role": f"arn:aws:iam::{account_id}:role/probe-role",
        "group": f"arn:aws:iam::{account_id}:group/probe-group",
        "policy": f"arn:aws:iam::{account_id}:policy/probe-policy",
        "function": f"arn:aws:lambda:us-east-1:{account_id}:function:probe-function",
    }


def probe(ctx: AnalysisContext, principal: Principal, action: str, resource: str) -> Grant | None:
    result = ctx.evaluator.evaluate(principal, action, resource)
    if not result.is_possible or not result.allow_matches:
        return None
    breadth = 0.0
    keys: list[str] = []
    for match in result.allow_matches:
        raw = match.ref.statement
        if "NotResource" in raw:
            breadth = max(breadth, 0.9)
        else:
            resources = raw.get("Resource", [])
            resources = [resources] if isinstance(resources, str) else list(resources)
            breadth = max(breadth, resource_breadth(str(r) for r in resources))
        condition = raw.get("Condition") or {}
        if isinstance(condition, dict):
            for block in condition.values():
                if isinstance(block, dict):
                    keys.extend(str(k) for k in block)
    return Grant(action, result, breadth, tuple(dict.fromkeys(keys)))


def run(ctx: AnalysisContext) -> list[Finding]:
    findings: list[Finding] = []
    for principal in ctx.env.principals():
        if ctx.is_admin(principal):
            continue  # reported by ADMIN
        arns = probe_arns(principal.account_id)
        if ctx.config.is_check_enabled("ASSUME-BROAD"):
            findings.extend(_assume_broad(ctx, principal, arns))
        if ctx.config.is_check_enabled("PASSROLE-BROAD"):
            findings.extend(_passrole_broad(ctx, principal, arns))
        if ctx.config.is_check_enabled("IAM-WRITE"):
            findings.extend(_iam_write(ctx, principal, arns))
        if ctx.config.is_check_enabled("CREDENTIAL-WRITE"):
            findings.extend(_credential_write(ctx, principal, arns))
        if ctx.config.is_check_enabled("LAMBDA-WRITE"):
            findings.extend(_lambda_write(ctx, principal, arns))
    return findings


def _kind_and_confidence(grants: list[Grant]) -> tuple[EvidenceKind, Confidence, list[str]]:
    preconditions: list[str] = []
    if all(g.conditional for g in grants):
        for g in grants:
            preconditions.extend(g.result.unknown_reasons())
        return EvidenceKind.INDETERMINATE, Confidence.LOW, list(dict.fromkeys(preconditions))
    return EvidenceKind.OBSERVED, Confidence.HIGH, preconditions


def _assume_broad(
    ctx: AnalysisContext, principal: Principal, arns: dict[str, str]
) -> list[Finding]:
    grant = probe(ctx, principal, "sts:AssumeRole", arns["role"])
    if grant is None or grant.breadth < 0.7:
        return []
    label = ctx.label(principal)
    assumable = [
        ctx.node_label(e.target) for e in ctx.graph.out_edges(principal.arn, EdgeType.CAN_ASSUME)
    ]
    admin_targets = [
        ctx.node_label(e.target)
        for e in ctx.graph.out_edges(principal.arn, EdgeType.CAN_ASSUME)
        if (n := ctx.graph.node(e.target)) is not None and n.is_admin.is_true
    ]
    kind, confidence, preconditions = _kind_and_confidence([grant])
    description = (
        f"{label} may call sts:AssumeRole on a broad resource pattern (breadth {grant.breadth:.2f}). "
        "Which roles it can actually assume also depends on each role's trust policy; "
        + (
            f"in this snapshot the trust policies admit {len(assumable)} role(s): {', '.join(assumable)}."
            if assumable
            else "no role in this snapshot trusts it, so the grant is currently dormant but would "
            "activate for any future role that trusts the account."
        )
    )
    escalation = 0.9 if admin_targets else (0.7 if assumable else 0.4)
    return [
        ctx.finding(
            check_id="ASSUME-BROAD",
            category=Category.EXCESSIVE_PERMISSIONS,
            title=f"{label} may assume any role matching a broad pattern",
            description=description,
            impact=(
                "Every role whose trust policy admits this identity (or its whole account) becomes "
                "reachable; administrative roles among them: "
                + (", ".join(admin_targets) if admin_targets else "none in this snapshot")
                + "."
            ),
            remediation=Remediation(
                summary="List the specific role ARNs this identity needs in the sts:AssumeRole statement.",
                steps=(
                    "Identify the roles this identity assumes (CloudTrail AssumeRole events).",
                    "Replace the wildcard Resource with those role ARNs.",
                    "Review the trust policies of roles that currently rely on account-root trust.",
                ),
                suggested_policy={
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "sts:AssumeRole",
                            "Resource": ["arn:aws:iam::<account-id>:role/<needed-role>"],
                        }
                    ],
                },
                policy_assumptions=POLICY_ASSUMPTIONS_GENERIC,
                verification_steps=(
                    simulate_step(principal.arn, ["sts:AssumeRole"], arns["role"]),
                    rerun_step("ASSUME-BROAD", label),
                ),
            ),
            evidence_kind=kind,
            confidence=confidence,
            factors={
                "permission_breadth": FactorScore(grant.breadth, 0, "resource pattern breadth"),
                "escalation_potential": FactorScore(
                    escalation,
                    0,
                    f"{len(assumable)} assumable role(s), {len(admin_targets)} administrative",
                ),
                "resource_sensitivity": FactorScore(
                    1.0 if admin_targets else 0.5, 0, "reach of assumable roles"
                ),
                "trust_boundary": FactorScore(0.0, 0, "same account"),
                "exposure": ctx.exposure(principal),
                "reachability": FactorScore(1.0, 0, "direct permission"),
            },
            principal=principal.arn,
            evidence=grant.evidence(),
            preconditions=preconditions,
            references=[ref.LEAST_PRIVILEGE, ref.CROSS_ACCOUNT_ROLES],
            tags=["broad-assume-role"],
        )
    ]


def _passrole_broad(
    ctx: AnalysisContext, principal: Principal, arns: dict[str, str]
) -> list[Finding]:
    grant = probe(ctx, principal, "iam:PassRole", arns["role"])
    if grant is None or grant.breadth < 0.7:
        return []
    restricted = any(k.lower() == "iam:passedtoservice" for k in grant.condition_keys)
    if restricted:
        return []
    label = ctx.label(principal)
    consumers = [
        f"{action} ({service})"
        for action, service in _PASS_ROLE_CONSUMERS
        if (
            g := probe(
                ctx,
                principal,
                action,
                "*" if action != "lambda:CreateFunction" else arns["function"],
            )
        )
        is not None
        and not g.conditional
    ]
    service_roles = [
        role.name
        for role in ctx.env.roles
        if (n := ctx.graph.node(role.arn)) is not None and n.attrs.get("workload_services")
    ]
    admin_service_roles = [
        role.name
        for role in ctx.env.roles
        if (n := ctx.graph.node(role.arn)) is not None
        and n.attrs.get("workload_services")
        and n.is_admin.is_true
    ]
    kind, confidence, preconditions = _kind_and_confidence([grant])
    escalation = 0.9 if (consumers and admin_service_roles) else (0.7 if consumers else 0.5)
    return [
        ctx.finding(
            check_id="PASSROLE-BROAD",
            category=Category.PRIVILEGE_ESCALATION,
            title=f"{label} may pass any role to AWS services",
            description=(
                f"{label} holds iam:PassRole on a broad resource pattern (breadth {grant.breadth:.2f}) "
                "without an iam:PassedToService condition. "
                + (
                    f"It also holds service permissions that consume a passed role: {', '.join(consumers)}. "
                    if consumers
                    else "No paired service permission (such as lambda:CreateFunction or ec2:RunInstances) was found for it in this snapshot. "
                )
                + (
                    f"Roles in this snapshot that services can run under: {', '.join(service_roles)}"
                    + (
                        f"; administrative among them: {', '.join(admin_service_roles)}."
                        if admin_service_roles
                        else "."
                    )
                    if service_roles
                    else "No service-trusted roles exist in this snapshot."
                )
            ),
            impact=(
                "Passing a more privileged role to a service the identity controls lets a workload run "
                "with that role's permissions; the identity's effective privilege becomes that of the "
                "most privileged role any service will accept."
            ),
            remediation=Remediation(
                summary="Restrict iam:PassRole to the specific role ARN(s) and services the workflow uses.",
                steps=(
                    "Identify which roles are passed and to which services (CloudTrail PassRole context).",
                    "Scope the Resource element to those role ARNs.",
                    "Add a StringEquals iam:PassedToService condition naming the consuming service.",
                ),
                suggested_policy={
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "iam:PassRole",
                            "Resource": "arn:aws:iam::<account-id>:role/<function-execution-role>",
                            "Condition": {
                                "StringEquals": {"iam:PassedToService": "lambda.amazonaws.com"}
                            },
                        }
                    ],
                },
                policy_assumptions=POLICY_ASSUMPTIONS_GENERIC
                + (
                    "Replace lambda.amazonaws.com with the service that actually consumes the role.",
                ),
                verification_steps=(
                    simulate_step(principal.arn, ["iam:PassRole"], arns["role"]),
                    rerun_step("PASSROLE-BROAD", label),
                ),
            ),
            evidence_kind=kind,
            confidence=confidence,
            factors={
                "permission_breadth": FactorScore(grant.breadth, 0, "resource pattern breadth"),
                "escalation_potential": FactorScore(
                    escalation, 0, "paired service permissions and service-trusted roles"
                ),
                "resource_sensitivity": FactorScore(
                    1.0 if admin_service_roles else 0.6, 0, "reach of service-trusted roles"
                ),
                "trust_boundary": FactorScore(0.0, 0, "same account"),
                "exposure": ctx.exposure(principal),
                "reachability": FactorScore(0.8, 0, "requires a paired service action"),
            },
            principal=principal.arn,
            evidence=grant.evidence(),
            preconditions=preconditions,
            references=[ref.PASS_ROLE, ref.LEAST_PRIVILEGE],
            tags=["pass-role"],
        )
    ]


def _iam_write(ctx: AnalysisContext, principal: Principal, arns: dict[str, str]) -> list[Finding]:
    grants = [
        g
        for action, kind in _IAM_WRITE_ACTIONS
        if (g := probe(ctx, principal, action, arns[kind])) is not None and g.breadth >= 0.7
    ]
    if not grants:
        return []
    label = ctx.label(principal)
    actions = [g.action for g in grants]
    kind, confidence, preconditions = _kind_and_confidence(grants)
    evidence: list[Evidence] = []
    for g in grants:
        for item in g.evidence():
            if item not in evidence:
                evidence.append(item)
    return [
        ctx.finding(
            check_id="IAM-WRITE",
            category=Category.PRIVILEGE_ESCALATION,
            title=f"{label} may change IAM policies and attachments broadly",
            description=(
                f"{label} is allowed {', '.join(actions)} on broad resource patterns. "
                "These actions change what other identities (or this one) are permitted to do."
            ),
            impact=(
                "Permission to attach, create or rewrite policies is equivalent to being able to grant "
                "any permission; the identity's effective privilege is administrative even though no "
                "administrative policy is attached."
            ),
            remediation=Remediation(
                summary="Limit IAM write actions to specific resources and require a permissions boundary on anything created or modified.",
                steps=(
                    "Move IAM administration to a dedicated, MFA-protected role used only for that purpose.",
                    "Scope Resource to the specific users, roles, groups or policies this identity manages.",
                    "Add a Condition requiring iam:PermissionsBoundary on Create/Put/Attach actions so delegated administrators cannot exceed the boundary.",
                ),
                suggested_policy={
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": ["iam:AttachRolePolicy", "iam:PutRolePolicy"],
                            "Resource": "arn:aws:iam::<account-id>:role/app-*",
                            "Condition": {
                                "StringEquals": {
                                    "iam:PermissionsBoundary": "arn:aws:iam::<account-id>:policy/<boundary>"
                                }
                            },
                        }
                    ],
                },
                policy_assumptions=POLICY_ASSUMPTIONS_GENERIC
                + ("The boundary policy must exist and must itself exclude IAM administration.",),
                verification_steps=(
                    simulate_step(principal.arn, actions[:3], arns["role"]),
                    rerun_step("IAM-WRITE", label),
                ),
            ),
            evidence_kind=kind,
            confidence=confidence,
            factors={
                "permission_breadth": FactorScore(
                    max(g.breadth for g in grants), 0, "resource pattern breadth"
                ),
                "escalation_potential": FactorScore(1.0, 0, "can grant arbitrary permissions"),
                "resource_sensitivity": FactorScore(1.0, 0, "IAM configuration"),
                "trust_boundary": FactorScore(0.0, 0, "same account"),
                "exposure": ctx.exposure(principal),
                "reachability": FactorScore(0.9, 0, "direct permission on IAM"),
            },
            principal=principal.arn,
            evidence=evidence,
            preconditions=preconditions,
            references=[ref.PERMISSIONS_BOUNDARIES, ref.IAM_ACTIONS, ref.LEAST_PRIVILEGE],
            tags=["iam-write"],
        )
    ]


def _credential_write(
    ctx: AnalysisContext, principal: Principal, arns: dict[str, str]
) -> list[Finding]:
    grants = [
        g
        for action in _CREDENTIAL_ACTIONS
        if (g := probe(ctx, principal, action, arns["user"])) is not None and g.breadth >= 0.7
    ]
    if not grants:
        return []
    label = ctx.label(principal)
    actions = [g.action for g in grants]
    kind, confidence, preconditions = _kind_and_confidence(grants)
    privileged_users = [
        u.name
        for u in ctx.env.users
        if (n := ctx.graph.node(u.arn)) is not None
        and n.is_admin.is_true
        and u.arn != principal.arn
    ]
    evidence: list[Evidence] = []
    for g in grants:
        for item in g.evidence():
            if item not in evidence:
                evidence.append(item)
    return [
        ctx.finding(
            check_id="CREDENTIAL-WRITE",
            category=Category.PRIVILEGE_ESCALATION,
            title=f"{label} may create or change credentials of other users",
            description=(
                f"{label} is allowed {', '.join(actions)} on a broad user pattern, i.e. for users other than itself. "
                + (
                    f"Administrative users in this snapshot: {', '.join(privileged_users)}."
                    if privileged_users
                    else "No administrative users exist in this snapshot."
                )
            ),
            impact=(
                "Issuing an access key or console password for another user yields that user's "
                "permissions; the identity's effective privilege is the most privileged user it can "
                "issue credentials for."
            ),
            remediation=Remediation(
                summary="Limit credential management to the identity's own user, or to a dedicated help-desk role with an explicit list of managed users.",
                steps=(
                    "Scope the Resource to arn:aws:iam::<account-id>:user/${aws:username} for self-service credential rotation.",
                    "For help-desk workflows, enumerate the managed users explicitly and exclude administrators with a Deny.",
                    "Require MFA (aws:MultiFactorAuthPresent) for these actions.",
                ),
                suggested_policy={
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": [
                                "iam:CreateAccessKey",
                                "iam:UpdateAccessKey",
                                "iam:DeleteAccessKey",
                            ],
                            "Resource": "arn:aws:iam::<account-id>:user/${aws:username}",
                            "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}},
                        }
                    ],
                },
                policy_assumptions=POLICY_ASSUMPTIONS_GENERIC
                + ("${aws:username} only resolves for IAM users, not roles.",),
                verification_steps=(
                    simulate_step(principal.arn, ["iam:CreateAccessKey"], arns["user"]),
                    rerun_step("CREDENTIAL-WRITE", label),
                ),
            ),
            evidence_kind=kind,
            confidence=confidence,
            factors={
                "permission_breadth": FactorScore(
                    max(g.breadth for g in grants), 0, "user pattern breadth"
                ),
                "escalation_potential": FactorScore(
                    1.0 if privileged_users else 0.7,
                    0,
                    "administrative users reachable"
                    if privileged_users
                    else "no administrative users in snapshot",
                ),
                "resource_sensitivity": FactorScore(
                    1.0 if privileged_users else 0.6, 0, "credentials of other users"
                ),
                "trust_boundary": FactorScore(0.0, 0, "same account"),
                "exposure": ctx.exposure(principal),
                "reachability": FactorScore(0.9, 0, "direct permission"),
            },
            principal=principal.arn,
            evidence=evidence,
            preconditions=preconditions,
            references=[ref.ACCESS_KEYS, ref.MFA, ref.LEAST_PRIVILEGE],
            tags=["credential-management"],
        )
    ]


def _lambda_write(
    ctx: AnalysisContext, principal: Principal, arns: dict[str, str]
) -> list[Finding]:
    grants = [
        g
        for action in _LAMBDA_WRITE_ACTIONS
        if (g := probe(ctx, principal, action, arns["function"])) is not None and g.breadth >= 0.7
    ]
    if not grants:
        return []
    label = ctx.label(principal)
    actions = [g.action for g in grants]
    kind, confidence, preconditions = _kind_and_confidence(grants)
    function_roles: list[str] = []
    privileged_roles: list[str] = []
    for fn in ctx.env.lambda_functions:
        if not fn.role_arn:
            continue
        node = ctx.graph.node(fn.role_arn)
        role_label = ctx.node_label(fn.role_arn)
        function_roles.append(f"{fn.name} -> {role_label}")
        if node is not None and (
            node.is_admin.is_true or ctx.sensitive_buckets_reachable(fn.role_arn)
        ):
            privileged_roles.append(f"{fn.name} ({role_label})")
    evidence: list[Evidence] = []
    for g in grants:
        for item in g.evidence():
            if item not in evidence:
                evidence.append(item)
    return [
        ctx.finding(
            check_id="LAMBDA-WRITE",
            category=Category.PRIVILEGE_ESCALATION,
            title=f"{label} may change the code or configuration of any Lambda function",
            description=(
                f"{label} is allowed {', '.join(actions)} on a broad function pattern. "
                "Function code runs with the function's execution role, so changing it changes who "
                "effectively holds that role's permissions. "
                + (
                    f"Functions whose roles are administrative or reach sensitive buckets: {', '.join(privileged_roles)}."
                    if privileged_roles
                    else f"Functions in this snapshot: {len(function_roles)}; none runs under an administrative or sensitive-data role."
                )
            ),
            impact=(
                "A deployment identity with unrestricted write access to functions effectively holds the "
                "union of all execution roles' permissions."
            ),
            remediation=Remediation(
                summary="Scope deployment permissions to the specific functions each pipeline owns.",
                steps=(
                    "Scope Resource to the ARNs (or a naming prefix) of the functions this identity deploys.",
                    "Use separate deployment identities per application so one pipeline cannot modify another's functions.",
                    "Keep privileged functions behind code signing (lambda:CodeSigningConfig) where possible.",
                ),
                suggested_policy={
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": [
                                "lambda:UpdateFunctionCode",
                                "lambda:UpdateFunctionConfiguration",
                            ],
                            "Resource": "arn:aws:lambda:<region>:<account-id>:function:<app-prefix>-*",
                        }
                    ],
                },
                policy_assumptions=POLICY_ASSUMPTIONS_GENERIC,
                verification_steps=(
                    simulate_step(principal.arn, ["lambda:UpdateFunctionCode"], arns["function"]),
                    rerun_step("LAMBDA-WRITE", label),
                ),
            ),
            evidence_kind=kind,
            confidence=confidence,
            factors={
                "permission_breadth": FactorScore(
                    max(g.breadth for g in grants), 0, "function pattern breadth"
                ),
                "escalation_potential": FactorScore(
                    0.9 if privileged_roles else 0.5, 0, "privilege of the execution roles involved"
                ),
                "resource_sensitivity": FactorScore(
                    0.9 if privileged_roles else 0.5, 0, "reach of execution roles"
                ),
                "trust_boundary": FactorScore(0.0, 0, "same account"),
                "exposure": ctx.exposure(principal),
                "reachability": FactorScore(0.8, 0, "requires the function to run"),
            },
            principal=principal.arn,
            evidence=evidence,
            preconditions=preconditions,
            references=[ref.LAMBDA_PERMISSIONS, ref.LAMBDA_EXECUTION_ROLE, ref.LEAST_PRIVILEGE],
            tags=["workload-configuration"],
        )
    ]
