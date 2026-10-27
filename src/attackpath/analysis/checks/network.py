"""Network exposure: instances reachable from the internet, and instance-credential hygiene.

The network model is deliberately small (see ``docs/methodology.md``): an instance is
considered reachable from the internet when it is running, has a public address and at
least one of its security groups allows inbound traffic from ``0.0.0.0/0`` or ``::/0``.
Route tables, network ACLs, load balancers and host firewalls are outside the snapshot
and appear as preconditions or limitations, never as assumptions.
"""

from __future__ import annotations

from attackpath.analysis import references as ref
from attackpath.analysis.context import AnalysisContext
from attackpath.analysis.remediation import POLICY_ASSUMPTIONS_GENERIC, rerun_step
from attackpath.graph.model import Edge, EdgeType, Node
from attackpath.models.environment import Ec2Instance
from attackpath.models.finding import (
    Category,
    Confidence,
    Evidence,
    EvidenceKind,
    FactorScore,
    Finding,
    Remediation,
)

CHECK_IDS: tuple[str, ...] = ("EC2-PUBLIC-EXPOSURE", "EC2-IMDSV1")


def run(ctx: AnalysisContext) -> list[Finding]:
    findings: list[Finding] = []
    for instance in ctx.env.ec2_instances:
        node = ctx.graph.node(instance.arn)
        if node is None:
            continue
        exposure_edges = ctx.graph.in_edges(instance.arn, EdgeType.NETWORK_EXPOSED)
        if exposure_edges and ctx.config.is_check_enabled("EC2-PUBLIC-EXPOSURE"):
            findings.append(_public_exposure(ctx, instance, node, exposure_edges[0]))
        if (
            instance.role_arn
            and instance.is_running
            and instance.imdsv2_required is False
            and ctx.config.is_check_enabled("EC2-IMDSV1")
        ):
            findings.append(_imdsv1(ctx, instance, bool(exposure_edges)))
    return findings


def _role_factors(
    ctx: AnalysisContext, instance: Ec2Instance
) -> tuple[Node | None, FactorScore, FactorScore, FactorScore]:
    """(role node, permission breadth, escalation potential, resource sensitivity)."""
    role_node = ctx.graph.node(instance.role_arn) if instance.role_arn else None
    if role_node is None:
        return (
            None,
            FactorScore(0.1, 0, "no IAM role attached to the instance"),
            FactorScore(0.2, 0, "no role credentials to obtain on the instance"),
            FactorScore(0.4, 0, "no bucket access known for the instance"),
        )
    privilege = ctx.privilege_factor(role_node)
    breadth = FactorScore(privilege.value, 0, f"reach of the instance role: {privilege.rationale}")
    if role_node.is_admin.is_true:
        escalation = FactorScore(1.0, 0, "the instance role is administrative")
    elif role_node.is_admin.is_unknown:
        escalation = FactorScore(0.8, 0, "the instance role may be administrative")
    elif ctx.sensitive_buckets_reachable(role_node.id):
        escalation = FactorScore(0.7, 0, "the instance role reaches sensitive buckets")
    else:
        escalation = FactorScore(
            0.4, 0, "instance role credentials are obtainable through the metadata service"
        )
    return role_node, breadth, escalation, ctx.max_bucket_sensitivity(role_node.id)


def _ports_text(edge: Edge) -> str:
    management: dict[str, str] = edge.attrs.get("management_ports", {})
    if edge.attrs.get("all_ports"):
        return "all ports"
    ports = str(edge.attrs.get("ports", ""))
    if not management:
        return ports
    named = ", ".join(f"{port} ({name})" for port, name in management.items())
    return f"{ports}; management ports open: {named}"


def _public_exposure(
    ctx: AnalysisContext, instance: Ec2Instance, node: Node, edge: Edge
) -> Finding:
    role_node, breadth, escalation, sensitivity = _role_factors(ctx, instance)
    management: dict[str, str] = edge.attrs.get("management_ports", {})
    all_ports = bool(edge.attrs.get("all_ports"))
    routing_known = instance.internet_facing is not None
    groups = ", ".join(edge.attrs.get("security_groups", [])) or "unknown security groups"
    role_text = (
        f"It runs as {ctx.node_label(role_node.id)} ({breadth.rationale})."
        if role_node is not None
        else "No IAM role is attached to it."
    )
    imds_text = (
        " IMDSv1 is still allowed, so a server-side request forgery or local file read is "
        "enough to retrieve the role credentials."
        if instance.imdsv2_required is False and role_node is not None
        else ""
    )
    if all_ports:
        exposure = FactorScore(1.0, 0, "every port is open to the internet")
    elif management:
        exposure = FactorScore(
            1.0,
            0,
            "management or database ports open to the internet: " + ", ".join(management.values()),
        )
    else:
        exposure = FactorScore(0.7, 0, f"application ports only ({edge.attrs.get('ports')})")
    if management or all_ports:
        # An exposed management service is a foothold in itself: the host (its compute and its
        # network position) is at risk even when the instance role is modest.
        if escalation.value < 0.6:
            escalation = FactorScore(
                0.6, 0, "an exposed management service offers a direct foothold on the host"
            )
        if sensitivity.value < 0.5:
            sensitivity = FactorScore(
                0.5, 0, "the instance itself: compute and network foothold inside the VPC"
            )
    first_port = next(iter(management), None) or "443"
    return ctx.finding(
        check_id="EC2-PUBLIC-EXPOSURE",
        category=Category.NETWORK_EXPOSURE,
        title=f"Instance {instance.label} is reachable from the internet on {_ports_text(edge)}",
        description=(
            f"{instance.instance_id} has public address {instance.public_ip} and security group(s) "
            f"{groups} allow inbound {edge.attrs.get('ports')} from any address. {role_text}"
            + imds_text
            + (
                ""
                if routing_known
                else " Whether the subnet routes to an internet gateway is not recorded in the snapshot."
            )
        ),
        impact=(
            "Exposed management or database ports can be brute-forced or exploited directly, and any "
            "compromise of the instance yields its role credentials from the metadata service."
            if management or all_ports
            else "A vulnerability in the exposed application turns the instance, and its role credentials, into an entry point into the account."
        ),
        remediation=Remediation(
            summary=(
                "Remove the internet-wide ingress rules; reach the instance through SSM Session "
                "Manager or a VPN and keep only application ports behind a load balancer."
            ),
            steps=(
                "Replace 0.0.0.0/0 and ::/0 sources with the specific CIDR ranges (or a managed prefix list) that need access.",
                "Use AWS Systems Manager Session Manager for shell access and delete the SSH/RDP rules.",
                "Serve application ports through an Application Load Balancer or CloudFront and move the instance to a private subnet.",
                "Require IMDSv2 (HttpTokens=required) and scope the instance role to what the workload needs.",
            ),
            suggested_policy={
                "IpPermissions": [
                    {
                        "IpProtocol": "tcp",
                        "FromPort": int(first_port),
                        "ToPort": int(first_port),
                        "IpRanges": [
                            {
                                "CidrIp": "<trusted-source-cidr>",
                                "Description": "replace with the range that needs access",
                            }
                        ],
                    }
                ]
            },
            policy_assumptions=POLICY_ASSUMPTIONS_GENERIC
            + (
                "Removing an ingress rule interrupts any client that currently connects from the internet; confirm legitimate sources from VPC flow logs first.",
            ),
            verification_steps=(
                f"aws ec2 describe-security-groups --group-ids {' '.join(edge.attrs.get('security_groups', []))} (expect no 0.0.0.0/0 or ::/0 source)",
                f"aws ec2 describe-instances --instance-ids {instance.instance_id} --query 'Reservations[].Instances[].[PublicIpAddress,MetadataOptions.HttpTokens]'",
                rerun_step("EC2-PUBLIC-EXPOSURE", f"instance {instance.label}"),
            ),
        ),
        evidence_kind=EvidenceKind.OBSERVED,
        confidence=Confidence.HIGH if routing_known else Confidence.MEDIUM,
        factors={
            "permission_breadth": breadth,
            "escalation_potential": escalation,
            "resource_sensitivity": sensitivity,
            "trust_boundary": FactorScore(1.0, 0, "reachable from any internet address"),
            "exposure": exposure,
            "reachability": FactorScore(1.0, 0, "direct"),
        },
        resource=instance.arn,
        evidence=list(edge.evidence),
        preconditions=[] if routing_known else [p for p in edge.preconditions if "gateway" in p],
        references=[
            ref.EC2_SECURITY_GROUP_RULES,
            ref.SSM_SESSION_MANAGER,
            ref.EC2_IMDS,
            ref.EC2_IAM_ROLES,
        ],
        tags=["network", "public-access"]
        + (["management-port"] if management or all_ports else []),
    )


def _imdsv1(ctx: AnalysisContext, instance: Ec2Instance, exposed: bool) -> Finding:
    role_node, breadth, _escalation, sensitivity = _role_factors(ctx, instance)
    role_label = ctx.node_label(role_node.id) if role_node else str(instance.role_arn)
    if role_node is not None and role_node.is_admin.is_true:
        escalation = FactorScore(
            0.9, 0, "administrative role credentials retrievable without a session token"
        )
    else:
        escalation = FactorScore(
            0.6,
            0,
            "role credentials retrievable by any SSRF or local request without a session token",
        )
    return ctx.finding(
        check_id="EC2-IMDSV1",
        category=Category.NETWORK_EXPOSURE,
        title=f"Instance {instance.label} allows IMDSv1 while running as {role_label}",
        description=(
            f"{instance.instance_id} does not require session tokens for the instance metadata "
            f"service (HttpTokens is optional), and it holds the credentials of {role_label}. "
            "A single unauthenticated GET to 169.254.169.254 from the instance returns those "
            "credentials; IMDSv2 requires a PUT-obtained token with a hop limit, which blocks the "
            "common SSRF and misconfigured-proxy cases."
            + (" The instance is also reachable from the internet." if exposed else "")
        ),
        impact="Any request-forgery or local-file-read flaw in software on the instance becomes a direct path to its IAM role credentials.",
        remediation=Remediation(
            summary="Require IMDSv2 on the instance (HttpTokens=required) and enforce it for new launches.",
            steps=(
                f"aws ec2 modify-instance-metadata-options --instance-id {instance.instance_id} --http-tokens required --http-endpoint enabled",
                "Set MetadataOptions.HttpTokens=required in launch templates, and enable the account-level default (ec2 modify-instance-metadata-defaults).",
                "Confirm agents and SDKs on the instance support IMDSv2 before enforcing (modern AWS SDKs and the SSM agent do).",
            ),
            policy_assumptions=POLICY_ASSUMPTIONS_GENERIC
            + (
                "Software that still uses IMDSv1 calls loses credential access once tokens are required.",
            ),
            verification_steps=(
                f"aws ec2 describe-instances --instance-ids {instance.instance_id} --query 'Reservations[].Instances[].MetadataOptions' (expect HttpTokens=required)",
                rerun_step("EC2-IMDSV1", f"instance {instance.label}"),
            ),
        ),
        evidence_kind=EvidenceKind.OBSERVED,
        confidence=Confidence.HIGH,
        factors={
            "permission_breadth": breadth,
            "escalation_potential": escalation,
            "resource_sensitivity": sensitivity,
            "trust_boundary": FactorScore(
                0.0, 0, "the metadata service is reachable only from the instance"
            ),
            "exposure": FactorScore(
                0.8 if exposed else 0.4,
                0,
                "instance reachable from the internet"
                if exposed
                else "instance not directly reachable from the internet",
            ),
            "reachability": FactorScore(0.6, 0, "requires a request-forgery or local-access flaw"),
        },
        resource=instance.arn,
        principal=instance.role_arn,
        evidence=[
            Evidence(
                source=f"ec2:{instance.arn}",
                detail=f"MetadataOptions.HttpTokens is optional; instance profile provides {instance.role_arn}",
            )
        ],
        references=[ref.EC2_IMDS, ref.EC2_IAM_ROLES],
        tags=["network", "imds", "credential-exposure"],
    )
