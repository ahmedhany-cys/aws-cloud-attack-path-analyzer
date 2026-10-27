"""Multi-hop reachability: which identities can reach administrative roles or sensitive data."""

from __future__ import annotations

from attackpath.analysis import references as ref
from attackpath.analysis.context import AnalysisContext
from attackpath.analysis.remediation import (
    POLICY_ASSUMPTIONS_GENERIC,
    get_role_step,
    rerun_step,
    simulate_step,
)
from attackpath.graph.builder import WRITE_CLASSES
from attackpath.graph.model import Edge, EdgeType, NodeType
from attackpath.graph.paths import AttackPath
from attackpath.models.finding import Category, FactorScore, Finding, Remediation

CHECK_IDS: tuple[str, ...] = ("PATH-ADMIN", "PATH-SENSITIVE")


def run(ctx: AnalysisContext) -> list[Finding]:
    findings: list[Finding] = []
    for paths in ctx.paths.by_pair().values():
        primary = paths[0]
        if primary.target_kind == "admin":
            if not ctx.config.is_check_enabled("PATH-ADMIN"):
                continue
            findings.append(_finding(ctx, primary, len(paths) - 1, "PATH-ADMIN"))
        else:
            if primary.length < 2 or not ctx.config.is_check_enabled("PATH-SENSITIVE"):
                continue  # single-hop access is reported by SENSITIVE-ACCESS / exposure checks
            if all(e.type in _WORKLOAD_EDGES for e in primary.edges[:-1]):
                # function -> its own execution role -> bucket (or instance -> its instance
                # role -> bucket) is the same fact that SENSITIVE-ACCESS reports for the
                # workload role.
                continue
            findings.append(_finding(ctx, primary, len(paths) - 1, "PATH-SENSITIVE"))
    return findings


_WORKLOAD_EDGES = frozenset({EdgeType.EXECUTES_AS, EdgeType.RUNS_AS})
_OUTSIDE_SOURCES = frozenset({NodeType.ANONYMOUS, NodeType.INTERNET})
_PRINCIPAL_SOURCES = frozenset(
    {
        NodeType.USER,
        NodeType.ROLE,
        NodeType.LAMBDA_FUNCTION,
        NodeType.EC2_INSTANCE,
        NodeType.EXTERNAL_PRINCIPAL,
    }
)


def _hop_fix(ctx: AnalysisContext, edge: Edge) -> str:
    target = ctx.node_label(edge.target)
    source = ctx.node_label(edge.source)
    if edge.type is EdgeType.CAN_ASSUME:
        return (
            f"Narrow the trust policy of {target} so it no longer admits {source}, or remove "
            f"{source}'s sts:AssumeRole permission on it."
        )
    if edge.type is EdgeType.EXECUTES_AS:
        return f"Reduce the permissions of execution role {target} to what function {source} needs."
    if edge.type is EdgeType.RUNS_AS:
        return (
            f"Reduce the permissions of instance role {target} to what {source} needs, and "
            "require IMDSv2 so that its credentials cannot be read through SSRF."
        )
    if edge.type is EdgeType.NETWORK_EXPOSED:
        return (
            f"Restrict the security-group ingress of {target} to known source ranges or remove "
            "its public address; use SSM Session Manager instead of exposed management ports."
        )
    if edge.type is EdgeType.CAN_ACCESS:
        return f"Scope {source}'s S3 permissions (and the bucket policy of {target}) to the required prefix and actions."
    return f"Review the {edge.type.value} relationship between {source} and {target}."


def _finding(ctx: AnalysisContext, path: AttackPath, alternatives: int, check_id: str) -> Finding:
    source_node = ctx.graph.node(path.source)
    target_node = ctx.graph.node(path.target)
    source_label = ctx.node_label(path.source)
    target_label = ctx.node_label(path.target)
    is_admin = check_id == "PATH-ADMIN"
    last = path.edges[-1]
    if is_admin:
        breadth = FactorScore(1.0, 0, "administrative permissions at the end of the path")
        escalation = FactorScore(1.0, 0, "reaches administrative permissions")
        sensitivity = FactorScore(1.0, 0, "every resource in the account")
    else:
        access = last.attrs.get("access", {})
        breadth = FactorScore(
            1.0 if WRITE_CLASSES & set(access) else 0.5,
            0,
            "access classes: " + ", ".join(sorted(access)),
        )
        escalation = (
            FactorScore(0.6, 0, "a foothold on the instance yields its role credentials")
            if any(e.type is EdgeType.NETWORK_EXPOSED for e in path.edges)
            else FactorScore(0.3, 0, "data access through intermediate identities")
        )
        bucket = ctx.env.bucket(path.target)
        sensitivity = ctx.sensitivity_factor(bucket) if bucket else FactorScore(0.5, 0, "unknown")
    if source_node is not None and source_node.type in _OUTSIDE_SOURCES:
        trust = FactorScore(1.0, 0, "path starts outside any account")
    elif source_node is not None and source_node.type in (
        NodeType.EXTERNAL_ACCOUNT,
        NodeType.EXTERNAL_PRINCIPAL,
    ):
        trust = FactorScore(0.8, 0, "path starts in another account")
    else:
        trust = FactorScore(0.0, 0, "path stays inside the account")
    exposure = (
        ctx.exposure_for_node(source_node) if source_node else FactorScore(0.4, 0, "unknown source")
    )
    steps = path.steps()
    description = (
        f"{source_label} can reach {target_label} in {path.length} step(s): {path.describe(ctx.graph)}. "
        + (
            f"{alternatives} alternative path(s) with the same endpoints exist. "
            if alternatives
            else ""
        )
        + f"Weakest evidence along the path: {path.evidence_kind.value}; confidence: {path.confidence.value}."
    )
    hop_fixes = tuple(_hop_fix(ctx, e) for e in path.edges)
    verification = [rerun_step(check_id, f"{source_label} -> {target_label}")]
    network_entry = any(e.type is EdgeType.NETWORK_EXPOSED for e in path.edges)
    for edge in path.edges:
        if edge.type is EdgeType.NETWORK_EXPOSED:
            instance = ctx.env.instance(edge.target)
            if instance is not None:
                verification.append(
                    f"aws ec2 describe-instances --instance-ids {instance.instance_id} "
                    "--query 'Reservations[].Instances[].[PublicIpAddress,SecurityGroups,"
                    "MetadataOptions.HttpTokens]' (expect no public address or no "
                    "internet-wide ingress)"
                )
        if edge.type is EdgeType.CAN_ASSUME and target_node is not None:
            verification.append(
                simulate_step(
                    edge.source
                    if not edge.source.startswith(("account:", "anonymous"))
                    else "<caller-arn>",
                    ["sts:AssumeRole"],
                    edge.target,
                )
            )
            role = ctx.env.role(edge.target)
            if role is not None:
                verification.append(get_role_step(role.name))
    return ctx.finding(
        check_id=check_id,
        category=Category.ATTACK_PATH,
        title=f"{source_label} can reach {target_label} in {path.length} step(s)",
        description=description,
        impact=_impact(is_admin, network_entry),
        remediation=Remediation(
            summary="Break the path at its weakest hop; the first hop is usually the cheapest to fix.",
            steps=hop_fixes,
            policy_assumptions=POLICY_ASSUMPTIONS_GENERIC,
            verification_steps=tuple(verification),
        ),
        evidence_kind=path.evidence_kind,
        confidence=path.confidence,
        factors={
            "permission_breadth": breadth,
            "escalation_potential": escalation,
            "resource_sensitivity": sensitivity,
            "trust_boundary": trust,
            "exposure": exposure,
            "reachability": ctx.hops_factor(path.length),
        },
        principal=path.source
        if source_node is not None and source_node.type in _PRINCIPAL_SOURCES
        else None,
        resource=path.target,
        evidence=[ev for step in steps for ev in step.evidence],
        attack_path=steps,
        preconditions=list(path.preconditions),
        references=[ref.POLICY_EVALUATION_LOGIC, ref.CROSS_ACCOUNT_ROLES, ref.LEAST_PRIVILEGE]
        + ([ref.EC2_SECURITY_GROUP_RULES, ref.EC2_IMDS] if network_entry else []),
        tags=["reachability", "multi-hop" if path.length > 1 else "single-hop"]
        + (["network", "multi-service"] if network_entry else []),
        key=(path.source, path.target),
    )


def _impact(is_admin: bool, network_entry: bool) -> str:
    if network_entry:
        return (
            "Anyone on the internet who compromises a service on the exposed instance obtains the "
            "instance role's credentials from the metadata service and, from there, "
            + (
                "administrative control of the account."
                if is_admin
                else "the sensitive data at the end of the path."
            )
        )
    if is_admin:
        return "A compromise of the starting identity extends to administrative control of the account."
    return (
        "A compromise of the starting identity extends to the sensitive data at the end of the "
        "path, even though it has no direct permission on it."
    )
