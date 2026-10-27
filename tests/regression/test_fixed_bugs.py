"""Regression tests for defects found and fixed during development.

Each test documents the original symptom so the behaviour cannot silently return.
"""

from __future__ import annotations

from attackpath.analysis.engine import analyze
from attackpath.graph.builder import build_graph
from attackpath.graph.model import AttackGraph, Edge, EdgeType, Node, NodeType
from attackpath.graph.paths import find_attack_paths
from attackpath.iam.evaluator import Decision, PolicyEvaluator
from attackpath.models.finding import Confidence, EvidenceKind
from attackpath.tri import Tri
from tests.conftest import ACCOUNT, allow, env_from, policy, user_arn

PUBLIC_READ = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::pub/*",
        }
    ],
}


def test_bucket_policy_evaluation_does_not_collapse_tri_state() -> None:
    """Symptom: evaluating a principal against a bucket policy raised TypeError because a
    ``Tri`` value was used in a boolean ``or`` expression inside the evaluator."""
    env = env_from(
        users=[{"name": "u", "inline_policies": {"p": policy(allow("s3:GetObject"))}}],
        s3_buckets=[{"name": "pub", "bucket_policy": PUBLIC_READ}],
    )
    ev = PolicyEvaluator(env)
    bucket = env.s3_buckets[0]
    result = ev.evaluate(
        env.users[0],
        "s3:GetObject",
        "arn:aws:s3:::pub/x",
        resource_policy=bucket.bucket_policy,
        resource_account=ACCOUNT,
    )
    assert result.decision is Decision.ALLOWED


def test_primary_path_prefers_strong_evidence_over_key_order() -> None:
    """Symptom: with two paths of equal length, the one reported as primary was chosen by
    string order, so a conditional path could hide a definite one."""
    g = AttackGraph()
    g.add_node(Node(id="u", type=NodeType.USER, label="u"))
    g.add_node(Node(id="a-conditional", type=NodeType.ROLE, label="a"))
    g.add_node(Node(id="z-definite", type=NodeType.ROLE, label="z"))
    g.add_node(Node(id="admin", type=NodeType.ROLE, label="admin", is_admin=Tri.TRUE))
    g.add_edge(
        Edge(
            "u",
            "a-conditional",
            EdgeType.CAN_ASSUME,
            "x",
            confidence=Confidence.LOW,
            evidence_kind=EvidenceKind.INDETERMINATE,
        )
    )
    g.add_edge(Edge("u", "z-definite", EdgeType.CAN_ASSUME, "x"))
    g.add_edge(Edge("a-conditional", "admin", EdgeType.CAN_ASSUME, "x"))
    g.add_edge(Edge("z-definite", "admin", EdgeType.CAN_ASSUME, "x"))
    primary = find_attack_paths(g, ["u"], max_depth=3).by_pair()[("u", "admin")][0]
    assert primary.nodes[1] == "z-definite"


def test_public_bucket_access_is_not_repeated_per_principal() -> None:
    """Symptom: a public bucket policy produced one sensitive-access finding for every
    principal in the account (and one reachability path each) in addition to the
    public-exposure finding."""
    env = env_from(
        users=[
            {"name": f"u{i}", "inline_policies": {"p": policy(allow("ec2:DescribeInstances"))}}
            for i in range(5)
        ],
        s3_buckets=[{"name": "pub", "sensitivity": "high", "bucket_policy": PUBLIC_READ}],
    )
    graph = build_graph(env, PolicyEvaluator(env))
    edges = [e for e in graph.edges_of_type(EdgeType.CAN_ACCESS) if e.source == user_arn("u0")]
    assert edges and all(e.attrs["public_only"] and not e.traversable for e in edges)
    result = analyze(env)
    checks = [f.check_id for f in result.findings]
    assert checks.count("S3-PUBLIC-POLICY") == 1
    assert "SENSITIVE-ACCESS" not in checks and "PATH-SENSITIVE" not in checks


def test_missing_policy_document_alone_is_not_a_privilege_finding() -> None:
    """Symptom: a principal whose attached policy was absent from the snapshot was reported
    as possibly administrative and as conditionally able to assume every account-trusted
    role, purely because the evaluator could not see the document."""
    env = env_from(
        users=[{"name": "u", "attached_policies": [f"arn:aws:iam::{ACCOUNT}:policy/missing"]}],
        roles=[
            {
                "name": "ops",
                "trust_policy": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:root"},
                            "Action": "sts:AssumeRole",
                        }
                    ],
                },
                "inline_policies": {"all": policy(allow("*"))},
            }
        ],
    )
    result = analyze(env)
    checks = {f.check_id for f in result.findings}
    assert "COVERAGE-UNRESOLVED-POLICY" in checks
    assert not any(
        f.check_id == "ADMIN" and f.affected_principal == user_arn("u") for f in result.findings
    )
    assert "PATH-ADMIN" not in checks
    assert result.graph.out_edges(user_arn("u"), EdgeType.CAN_ASSUME) == []
