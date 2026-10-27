from __future__ import annotations

import pytest

from attackpath.config import AnalysisConfig, Limits
from attackpath.exceptions import LimitExceededError
from attackpath.graph.builder import ANONYMOUS_NODE_ID, account_node_id, build_graph, trust_entries
from attackpath.graph.model import AttackGraph, Edge, EdgeType, Node, NodeType
from attackpath.graph.paths import find_attack_paths
from attackpath.iam.evaluator import PolicyEvaluator
from attackpath.models.environment import Sensitivity
from attackpath.models.finding import Confidence, EvidenceKind
from attackpath.tri import Tri
from tests.conftest import (
    ACCOUNT,
    OTHER_ACCOUNT,
    account_root,
    allow,
    deny,
    env_from,
    policy,
    role_arn,
    trust,
    user_arn,
)


def node(node_id: str, node_type: NodeType = NodeType.ROLE, **attrs) -> Node:
    return Node(id=node_id, type=node_type, label=node_id, account_id=ACCOUNT, attrs=attrs)


def test_graph_dedupes_edges_and_enforces_limits() -> None:
    g = AttackGraph(Limits(max_graph_nodes=2, max_graph_edges=1))
    g.add_node(node("a"))
    g.add_node(node("b"))
    assert g.add_edge(Edge("a", "b", EdgeType.CAN_ASSUME, "x"))
    assert not g.add_edge(Edge("a", "b", EdgeType.CAN_ASSUME, "x"))
    with pytest.raises(LimitExceededError):
        g.add_edge(Edge("b", "a", EdgeType.CAN_ASSUME, "y"))
    with pytest.raises(LimitExceededError):
        g.add_node(node("c"))
    with pytest.raises(KeyError):
        g.add_edge(Edge("a", "zzz", EdgeType.CAN_ASSUME, "x"))
    assert g.summary().edges_by_type == {"can-assume": 1}


def test_dot_output_escapes_labels() -> None:
    g = AttackGraph()
    g.add_node(Node(id='weird"id', type=NodeType.USER, label='say "hi"\nnow'))
    dot = g.to_dot()
    assert (
        'weird\\"id' in dot
        and 'say \\"hi\\"' in dot
        and "\n" not in dot.split("[label=")[1].split("]")[0]
    )


def test_builder_structure_and_trust_entries(sample_env) -> None:
    graph = build_graph(sample_env, PolicyEvaluator(sample_env))
    assert graph.node(account_node_id(ACCOUNT)) is not None
    assert graph.node(ANONYMOUS_NODE_ID) is not None
    assert graph.node(account_node_id(OTHER_ACCOUNT)) is not None
    member = graph.out_edges(user_arn("analyst-readonly"), EdgeType.MEMBER_OF)
    assert len(member) == 1
    executes = graph.out_edges(
        f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:image-resizer", EdgeType.EXECUTES_AS
    )
    assert executes[0].target == role_arn("lambda-image-resizer")
    admin_node = graph.node(role_arn("ops-admin-legacy"))
    assert (
        admin_node is not None and admin_node.is_admin is Tri.TRUE and admin_node.privilege == 1.0
    )
    entries = trust_entries(sample_env.role(role_arn("vendor-support-access")))  # type: ignore[arg-type]
    assert entries[0].kind == "anonymous"
    kinds = {e.kind for e in trust_entries(sample_env.role(role_arn("ops-admin-legacy")))}  # type: ignore[arg-type]
    assert kinds == {"same-account", "service"}
    external = trust_entries(sample_env.role(role_arn("third-party-monitoring")))  # type: ignore[arg-type]
    assert external[0].kind == "cross-account" and external[0].requires_external_id
    placeholder = graph.node(role_arn("cleanup-role-missing"))
    assert placeholder is not None and placeholder.attrs.get("unresolved")


def test_builder_can_assume_edges(sample_env) -> None:
    graph = build_graph(sample_env, PolicyEvaluator(sample_env))
    targets = {
        e.target for e in graph.out_edges(user_arn("legacy-automation"), EdgeType.CAN_ASSUME)
    }
    assert role_arn("ops-admin-legacy") in targets and role_arn("vendor-support-access") in targets
    assert role_arn("partner-integration") not in targets, (
        "cross-account-only trust does not admit local users"
    )
    anonymous = graph.out_edges(ANONYMOUS_NODE_ID, EdgeType.CAN_ASSUME)
    assert [e.target for e in anonymous] == [role_arn("vendor-support-access")]
    assert anonymous[0].evidence_kind is EvidenceKind.OBSERVED
    partner = graph.out_edges(account_node_id(OTHER_ACCOUNT), EdgeType.CAN_ASSUME)
    assert partner[0].evidence_kind is EvidenceKind.HYPOTHETICAL and partner[0].preconditions


def test_builder_access_edges_record_decisions_and_denies(sample_env) -> None:
    graph = build_graph(sample_env, PolicyEvaluator(sample_env))
    analyst = user_arn("analyst-readonly")
    pii = "arn:aws:s3:::customer-pii-exports"
    assert not [e for e in graph.out_edges(analyst, EdgeType.CAN_ACCESS) if e.target == pii]
    finance = next(
        e
        for e in graph.out_edges(analyst, EdgeType.CAN_ACCESS)
        if e.target == "arn:aws:s3:::finance-reports"
    )
    assert set(finance.attrs["access"]) == {"read", "list"}
    assert set(finance.attrs["denied"]) == {"delete", "policy"}
    public = next(
        e
        for e in graph.out_edges(analyst, EdgeType.CAN_ACCESS)
        if e.target == "arn:aws:s3:::legacy-backups"
    )
    assert not public.attrs["public_only"], "the analyst has an identity grant too"
    pipeline = list(graph.out_edges(role_arn("data-pipeline-worker"), EdgeType.CAN_ACCESS))
    assert all(e.attrs["public_only"] and not e.traversable for e in pipeline)
    anonymous_archive = next(
        e
        for e in graph.out_edges(ANONYMOUS_NODE_ID, EdgeType.CAN_ACCESS)
        if e.target.endswith("archive-with-restricted-policy")
    )
    assert (
        anonymous_archive.attrs["blocked_by_public_access_block"]
        and not anonymous_archive.traversable
    )


def test_builder_prefilter_skips_principals_without_s3_statements() -> None:
    env = env_from(
        users=[{"name": "nos3", "inline_policies": {"p": policy(allow("ec2:DescribeInstances"))}}],
        s3_buckets=[{"name": "data", "sensitivity": "high"}],
    )
    graph = build_graph(env, PolicyEvaluator(env))
    assert graph.out_edges(user_arn("nos3"), EdgeType.CAN_ACCESS) == []


def test_path_search_depth_dedupe_and_truncation() -> None:
    g = AttackGraph()
    for name in ("u", "r1", "r2", "r3"):
        g.add_node(node(name, NodeType.USER if name == "u" else NodeType.ROLE))
    g.add_node(Node(id="admin", type=NodeType.ROLE, label="admin", is_admin=Tri.TRUE))
    g.add_node(
        Node(
            id="bucket",
            type=NodeType.S3_BUCKET,
            label="bucket",
            sensitivity=Sensitivity.HIGH,
            attrs={"sensitive": True},
        )
    )
    g.add_edge(Edge("u", "r1", EdgeType.CAN_ASSUME, "a"))
    g.add_edge(Edge("u", "r2", EdgeType.CAN_ASSUME, "a"))
    g.add_edge(Edge("r1", "r3", EdgeType.CAN_ASSUME, "a"))
    g.add_edge(
        Edge(
            "r2",
            "r3",
            EdgeType.CAN_ASSUME,
            "a",
            confidence=Confidence.LOW,
            evidence_kind=EvidenceKind.INDETERMINATE,
        )
    )
    g.add_edge(Edge("r3", "admin", EdgeType.CAN_ASSUME, "a"))
    g.add_edge(Edge("r3", "bucket", EdgeType.CAN_ACCESS, "s3 read"))
    g.add_edge(Edge("r1", "bucket", EdgeType.CAN_ACCESS, "s3 read", traversable=False))
    result = find_attack_paths(g, ["u"], max_depth=4)
    pairs = result.by_pair()
    assert len(pairs[("u", "admin")]) == 2 and len(pairs[("u", "bucket")]) == 2
    primary = pairs[("u", "admin")][0]
    assert primary.nodes == ("u", "r1", "r3", "admin"), (
        "the observed path ranks before the conditional one"
    )
    assert primary.evidence_kind is EvidenceKind.INFERRED and primary.confidence is Confidence.HIGH
    assert all(p.key for p in result.paths)
    shallow = find_attack_paths(g, ["u"], max_depth=2)
    assert shallow.paths == []
    capped = find_attack_paths(g, ["u"], max_depth=4, max_paths_per_pair=1)
    assert capped.truncated and len(capped.by_pair()[("u", "admin")]) == 1
    total_capped = find_attack_paths(g, ["u"], max_depth=4, max_total_paths=1)
    assert total_capped.truncated and len(total_capped.paths) == 1
    assert find_attack_paths(g, ["admin"], max_depth=4).sources_searched == 0


def test_executes_as_is_a_transition_and_access_is_terminal() -> None:
    g = AttackGraph()
    g.add_node(node("fn", NodeType.LAMBDA_FUNCTION))
    g.add_node(node("role"))
    g.add_node(Node(id="b", type=NodeType.S3_BUCKET, label="b", attrs={"sensitive": True}))
    g.add_node(Node(id="b2", type=NodeType.S3_BUCKET, label="b2", attrs={"sensitive": False}))
    g.add_edge(Edge("fn", "role", EdgeType.EXECUTES_AS, "executes as"))
    g.add_edge(Edge("role", "b", EdgeType.CAN_ACCESS, "s3 read"))
    g.add_edge(Edge("role", "b2", EdgeType.CAN_ACCESS, "s3 read"))
    result = find_attack_paths(g, ["fn"], max_depth=3)
    assert [p.target for p in result.paths] == ["b"]
    assert result.paths[0].steps()[0].edge == "executes-as"


def test_build_graph_respects_config_limits() -> None:
    env = env_from(users=[{"name": "a"}, {"name": "b"}])
    with pytest.raises(LimitExceededError):
        build_graph(env, PolicyEvaluator(env), AnalysisConfig(limits=Limits(max_graph_nodes=2)))


def test_deny_in_trust_policy_removes_assume_edge() -> None:
    env = env_from(
        users=[{"name": "alice", "inline_policies": {"p": policy(allow("sts:AssumeRole"))}}],
        roles=[
            {
                "name": "guarded",
                "trust_policy": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": account_root(),
                            "Action": "sts:AssumeRole",
                        },
                        {
                            "Effect": "Deny",
                            "Principal": {"AWS": user_arn("alice")},
                            "Action": "sts:AssumeRole",
                        },
                    ],
                },
            }
        ],
    )
    graph = build_graph(env, PolicyEvaluator(env))
    assert graph.out_edges(user_arn("alice"), EdgeType.CAN_ASSUME) == []
    assert deny is not None and trust is not None  # helpers imported for symmetry with other tests
