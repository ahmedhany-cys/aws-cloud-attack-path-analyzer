"""Network exposure: parsing, graph edges, the EC2 checks and internet-sourced paths."""

from __future__ import annotations

from typing import Any

import pytest

from attackpath.analysis.engine import analyze
from attackpath.exceptions import InputError
from attackpath.graph.builder import INTERNET_NODE_ID, build_graph, exposure_label
from attackpath.graph.model import EdgeType, NodeType
from attackpath.iam.evaluator import PolicyEvaluator
from attackpath.models.environment import IngressRule
from attackpath.models.finding import EvidenceKind, Severity
from attackpath.parser.environment_parser import parse_environment
from tests.conftest import ACCOUNT, allow, env_from, policy, snapshot

EC2_TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "ec2.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}
ROLE_ARN = f"arn:aws:iam::{ACCOUNT}:role/instance-role"
INSTANCE_ARN = f"arn:aws:ec2:us-east-1:{ACCOUNT}:instance/i-0123456789abcdef0"


def public_rule(port: int | None = 22, protocol: str = "tcp") -> dict[str, Any]:
    rule: dict[str, Any] = {"protocol": protocol, "cidrs": ["0.0.0.0/0"]}
    if port is not None:
        rule.update(from_port=port, to_port=port)
    return rule


def instance(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "instance_id": "i-0123456789abcdef0",
        "name": "web-1",
        "public_ip": "203.0.113.10",
        "internet_facing": True,
        "security_groups": ["sg-web"],
        "role_arn": ROLE_ARN,
        "imdsv2_required": True,
    }
    base.update(overrides)
    return base


def environment(
    rules: list[dict[str, Any]], role_policy: dict[str, Any], **instance_overrides: Any
):
    return env_from(
        roles=[
            {
                "name": "instance-role",
                "trust_policy": EC2_TRUST,
                "inline_policies": {"p": role_policy},
            }
        ],
        s3_buckets=[{"name": "pii", "sensitivity": "high"}, {"name": "logs", "sensitivity": "low"}],
        security_groups=[{"group_id": "sg-web", "ingress": rules}],
        ec2_instances=[instance(**instance_overrides)],
    )


# ---------------------------------------------------------------------------
# parsing
# ---------------------------------------------------------------------------


def test_security_groups_and_instances_parse_with_derived_fields() -> None:
    warnings: list[str] = []
    env = parse_environment(
        snapshot(
            security_groups=[
                {
                    "group_id": "sg-web",
                    "name": "web",
                    "ingress": [
                        {"protocol": "-1", "cidrs": ["0.0.0.0/0"]},
                        {"protocol": "tcp", "from_port": 80, "to_port": 81, "ipv6_cidrs": ["::/0"]},
                        {
                            "protocol": "tcp",
                            "from_port": 5432,
                            "to_port": 5432,
                            "source_groups": ["sg-app"],
                        },
                    ],
                }
            ],
            ec2_instances=[instance(security_groups=["sg-web", "sg-missing"], state="Running")],
        ),
        "t",
        warnings=warnings,
    )
    group = env.security_group("sg-web")
    assert group is not None and len(group.ingress) == 3
    assert group.ingress[0].protocol == "all" and group.ingress[0].all_ports
    assert group.ingress[1].is_public and group.ingress[1].ports() == [80, 81]
    assert not group.ingress[2].is_public
    inst = env.instance(INSTANCE_ARN)
    assert inst is not None and inst.is_running and inst.label == "web-1"
    assert inst.region == "us-east-1" and inst.account_id == ACCOUNT
    assert env.summary()["ec2_instances"] == 1 and env.summary()["security_groups"] == 1
    assert env.resource_count == 1
    assert any("sg-missing" in w for w in warnings)


@pytest.mark.parametrize(
    ("rule", "message"),
    [
        ({"protocol": "gre", "cidrs": ["0.0.0.0/0"]}, "unsupported protocol"),
        ({"protocol": "tcp", "from_port": 80, "cidrs": ["0.0.0.0/0"]}, "given together"),
        (
            {"protocol": "tcp", "from_port": 90, "to_port": 80, "cidrs": ["0.0.0.0/0"]},
            "must not exceed",
        ),
        (
            {"protocol": "tcp", "from_port": 0, "to_port": 70000, "cidrs": ["0.0.0.0/0"]},
            "between 0 and 65535",
        ),
        (
            {"protocol": "tcp", "from_port": 22, "to_port": 22, "cidrs": ["0.0.0.0/33"]},
            "not a valid CIDR",
        ),
        ({"protocol": "tcp", "from_port": 22, "to_port": 22}, "needs cidrs"),
    ],
)
def test_invalid_ingress_rules_are_rejected(rule: dict[str, Any], message: str) -> None:
    with pytest.raises(InputError, match=message):
        env_from(security_groups=[{"group_id": "sg-x", "ingress": [rule]}])


def test_invalid_instances_are_rejected() -> None:
    with pytest.raises(InputError, match="not an IP address"):
        env_from(ec2_instances=[instance(public_ip="not-an-ip")])
    with pytest.raises(InputError, match="not an EC2 instance ARN"):
        env_from(ec2_instances=[instance(arn="arn:aws:s3:::bucket")])
    with pytest.raises(InputError, match="duplicate"):
        env_from(ec2_instances=[instance(), instance()])
    with pytest.raises(InputError, match="duplicate"):
        env_from(security_groups=[{"group_id": "sg-a"}, {"group_id": "sg-a"}])


def test_exposure_label_is_compact_and_sorted() -> None:
    rules = [
        IngressRule("tcp", 443, 443, ("0.0.0.0/0",)),
        IngressRule("tcp", 22, 22, ("0.0.0.0/0",)),
        IngressRule("udp", 500, 510, ("0.0.0.0/0",)),
        IngressRule("icmp", None, None, ("0.0.0.0/0",)),
    ]
    assert exposure_label(rules) == "icmp (all types), tcp 22, tcp 443, udp 500-510"
    assert exposure_label([IngressRule("all", None, None, ("0.0.0.0/0",))]) == "all ports"
    assert IngressRule("tcp", 0, 65535, ("0.0.0.0/0",)).all_ports
    assert IngressRule("tcp", 20, 25, ("0.0.0.0/0",)).management_ports() == {
        22: "SSH",
        23: "Telnet",
    }


# ---------------------------------------------------------------------------
# graph construction
# ---------------------------------------------------------------------------


def test_internet_edge_needs_public_rule_public_ip_and_running_state() -> None:
    read_pii = policy(
        allow(["s3:GetObject", "s3:ListBucket"], ["arn:aws:s3:::pii", "arn:aws:s3:::pii/*"])
    )

    def exposure_edges(env):
        graph = build_graph(env, PolicyEvaluator(env))
        return graph.in_edges(INSTANCE_ARN, EdgeType.NETWORK_EXPOSED)

    exposed = exposure_edges(environment([public_rule(22)], read_pii))
    assert len(exposed) == 1
    edge = exposed[0]
    assert edge.source == INTERNET_NODE_ID and edge.is_transition
    assert edge.evidence_kind is EvidenceKind.HYPOTHETICAL
    assert edge.attrs["management_ports"] == {"22": "SSH"} and edge.attrs["ports"] == "tcp 22"
    assert any("exploitable" in p for p in edge.preconditions)
    assert not any("gateway" in p for p in edge.preconditions)

    assert (
        exposure_edges(
            environment(
                [{"protocol": "tcp", "from_port": 22, "to_port": 22, "cidrs": ["10.0.0.0/8"]}],
                read_pii,
            )
        )
        == []
    )
    assert exposure_edges(environment([public_rule(22)], read_pii, public_ip=None)) == []
    assert exposure_edges(environment([public_rule(22)], read_pii, state="stopped")) == []
    assert exposure_edges(environment([public_rule(22)], read_pii, internet_facing=False)) == []
    unknown_routing = exposure_edges(environment([public_rule(22)], read_pii, internet_facing=None))
    assert unknown_routing and any("gateway" in p for p in unknown_routing[0].preconditions)


def test_runs_as_edge_and_role_attributes() -> None:
    env = environment([public_rule(443)], policy(allow("s3:GetObject", "arn:aws:s3:::logs/*")))
    graph = build_graph(env, PolicyEvaluator(env))
    runs_as = graph.out_edges(INSTANCE_ARN, EdgeType.RUNS_AS)
    assert [e.target for e in runs_as] == [ROLE_ARN] and runs_as[0].is_transition
    role = graph.node(ROLE_ARN)
    assert role is not None and role.attrs["used_by_instances"] == ["web-1"]
    node = graph.node(INSTANCE_ARN)
    assert node is not None and node.type is NodeType.EC2_INSTANCE
    assert node.attrs["public_ingress"] == ["tcp 443 from 0.0.0.0/0"]
    stopped = environment([public_rule(443)], policy(allow("s3:GetObject", "*")), state="stopped")
    assert (
        build_graph(stopped, PolicyEvaluator(stopped)).out_edges(INSTANCE_ARN, EdgeType.RUNS_AS)
        == []
    )


# ---------------------------------------------------------------------------
# checks and paths
# ---------------------------------------------------------------------------


def test_internet_path_to_sensitive_bucket_is_reported_once_as_multi_service() -> None:
    env = environment(
        [public_rule(None, "all")],
        policy(
            allow(["s3:GetObject", "s3:ListBucket"], ["arn:aws:s3:::pii", "arn:aws:s3:::pii/*"])
        ),
        imdsv2_required=False,
    )
    result = analyze(env)
    by_check: dict[str, list] = {}
    for finding in result.findings:
        by_check.setdefault(finding.check_id, []).append(finding)

    paths = by_check.get("PATH-SENSITIVE", [])
    assert len(paths) == 1, [f.title for f in paths]
    path = paths[0]
    assert path.attack_path[0].source == INTERNET_NODE_ID
    assert [step.edge for step in path.attack_path] == ["network-exposed", "runs-as", "can-access"]
    assert path.evidence_kind is EvidenceKind.HYPOTHETICAL
    assert path.severity.rank <= Severity.HIGH.rank
    assert {"network", "multi-service", "multi-hop"} <= set(path.tags)
    assert path.title.lower().startswith("the internet can reach bucket pii")
    assert "metadata service" in path.impact

    exposure = by_check["EC2-PUBLIC-EXPOSURE"]
    assert len(exposure) == 1 and exposure[0].severity is Severity.CRITICAL
    assert exposure[0].evidence_kind is EvidenceKind.OBSERVED
    assert "all ports" in exposure[0].title and "management-port" in exposure[0].tags
    assert exposure[0].affected_resource == INSTANCE_ARN

    imds = by_check["EC2-IMDSV1"]
    assert len(imds) == 1 and imds[0].affected_principal == ROLE_ARN
    assert "IMDSv1" in imds[0].title

    workload = [f for f in by_check.get("SENSITIVE-ACCESS", []) if f.affected_principal == ROLE_ARN]
    assert workload and "workload" in workload[0].tags


def test_private_instance_with_imdsv2_produces_no_network_findings() -> None:
    env = environment(
        [public_rule(22)],
        policy(allow("s3:GetObject", "arn:aws:s3:::pii/*")),
        public_ip=None,
        internet_facing=False,
    )
    checks = {f.check_id for f in analyze(env).findings}
    assert not {"EC2-PUBLIC-EXPOSURE", "EC2-IMDSV1", "PATH-SENSITIVE"} & checks


def test_exposure_severity_tracks_ports_and_role_privilege() -> None:
    admin_all_ports = analyze(environment([public_rule(None, "all")], policy(allow("*", "*"))))
    web_only_no_role = analyze(
        environment(
            [public_rule(443)], policy(allow("s3:GetObject", "arn:aws:s3:::logs/*")), role_arn=None
        )
    )
    first = next(f for f in admin_all_ports.findings if f.check_id == "EC2-PUBLIC-EXPOSURE")
    second = next(f for f in web_only_no_role.findings if f.check_id == "EC2-PUBLIC-EXPOSURE")
    assert first.severity is Severity.CRITICAL
    assert second.severity.rank < first.severity.rank
    assert second.severity.rank <= Severity.MEDIUM.rank
    assert "No IAM role is attached" in second.description
    assert "management-port" not in second.tags
    admin_sources = {
        f.attack_path[0].source for f in admin_all_ports.findings if f.check_id == "PATH-ADMIN"
    }
    # Both the exposed instance and the internet (through it) reach the administrative role.
    assert admin_sources == {INSTANCE_ARN, INTERNET_NODE_ID}


def test_imdsv1_requires_a_role_and_optional_tokens() -> None:
    no_role = analyze(
        environment(
            [public_rule(443)],
            policy(allow("s3:GetObject", "*")),
            role_arn=None,
            imdsv2_required=False,
        )
    )
    unknown = analyze(
        environment([public_rule(443)], policy(allow("s3:GetObject", "*")), imdsv2_required=None)
    )
    assert "EC2-IMDSV1" not in {f.check_id for f in no_role.findings}
    assert "EC2-IMDSV1" not in {f.check_id for f in unknown.findings}


def test_unknown_security_group_is_recorded_on_the_node() -> None:
    env = env_from(ec2_instances=[instance(security_groups=["sg-unknown"])])
    graph = build_graph(env, PolicyEvaluator(env))
    node = graph.node(INSTANCE_ARN)
    assert node is not None and node.attrs["unresolved_security_groups"] == ["sg-unknown"]
    assert graph.in_edges(INSTANCE_ARN, EdgeType.NETWORK_EXPOSED) == []
