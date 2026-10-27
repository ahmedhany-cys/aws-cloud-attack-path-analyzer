"""Regression tests for defects found and fixed during development.

Each test documents the original symptom so the behaviour cannot silently return.
"""

from __future__ import annotations

from attackpath.analysis.engine import analyze
from attackpath.graph.builder import build_graph
from attackpath.graph.model import AttackGraph, Edge, EdgeType, Node, NodeType
from attackpath.graph.paths import find_attack_paths
from attackpath.iam.evaluator import Decision, LimitationLog, PolicyEvaluator
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


def test_indeterminate_statement_title_keeps_the_full_statement_label() -> None:
    """Symptom: a statement with a ``Sid`` and a request-time condition was reported as
    ``... statement[0] (Sid`` with the rest of the label leaking into the evidence detail,
    because the limitation log stored the statement label and the reason in one string that
    the check split at the first colon. Found on the first full-coverage run against a real
    account, where every ``DenyInsecureTransport`` bucket statement was affected."""
    log = LimitationLog()
    log.record("condition", "doc statement[0] (Sid: X)", "request context key k is not known")
    assert log.by_kind("condition") == [
        ("doc statement[0] (Sid: X)", "request context key k is not known", 1)
    ]
    assert log.entries() == [
        ("condition", "doc statement[0] (Sid: X): request context key k is not known", 1)
    ]

    env = env_from(
        users=[
            {
                "name": "u",
                "inline_policies": {
                    "p": policy(
                        allow(
                            "s3:GetObject",
                            "arn:aws:s3:::data/*",
                            Sid="ReadViaEndpoint",
                            Condition={"StringEquals": {"aws:SourceVpce": "vpce-0123"}},
                        )
                    )
                },
            }
        ],
        s3_buckets=[{"name": "data"}],
    )
    findings = [f for f in analyze(env).findings if f.check_id == "EVAL-INDETERMINATE"]
    assert len(findings) == 1
    finding = findings[0]
    assert finding.title.endswith("statement[0] (Sid: ReadViaEndpoint)")
    assert finding.evidence[0].source.endswith("statement[0] (Sid: ReadViaEndpoint)")
    assert finding.evidence[0].detail.startswith("request context key aws:SourceVpce")


OBJECT = "arn:aws:s3:::data/report.csv"


def test_negated_condition_operator_is_true_when_the_key_is_absent() -> None:
    """Symptom (found by the documentation-sourced IAM corpus): a Deny guarded by
    ``StringNotEquals aws:SourceVpce`` did not apply to a request known to carry no
    ``aws:SourceVpce``, so the request was allowed. AWS evaluates a negated operator as true
    when the key is absent, so the Deny applies."""
    env = env_from(
        users=[
            {
                "name": "u",
                "inline_policies": {
                    "p": policy(
                        allow("s3:*"),
                        {
                            "Effect": "Deny",
                            "Action": "s3:*",
                            "Resource": "*",
                            "Condition": {"StringNotEquals": {"aws:SourceVpce": "vpce-1"}},
                        },
                    )
                },
            }
        ]
    )
    ev = PolicyEvaluator(env)
    user = env.users[0]
    absent = ev.evaluate(user, "s3:GetObject", OBJECT, extra_context={"aws:SourceVpce": None})
    assert absent.decision is Decision.EXPLICIT_DENY
    matching = ev.evaluate(user, "s3:GetObject", OBJECT, extra_context={"aws:SourceVpce": "vpce-1"})
    assert matching.decision is Decision.ALLOWED
    assert ev.evaluate(user, "s3:GetObject", OBJECT).decision is Decision.INDETERMINATE


def test_forallvalues_is_true_for_an_absent_multivalued_key() -> None:
    """Symptom (same corpus): ``ForAllValues:StringEquals aws:TagKeys`` was false for a request
    known to carry no tag keys, although AWS defines it as true for the empty set; ``ForAnyValue``
    stays false."""

    def user_with(operator: str) -> dict[str, object]:
        return {
            "name": "u",
            "inline_policies": {
                "p": policy(
                    allow(
                        "ec2:CreateTags",
                        "*",
                        Condition={f"{operator}:StringEquals": {"aws:TagKeys": ["env"]}},
                    )
                )
            },
        }

    instance = f"arn:aws:ec2:us-east-1:{ACCOUNT}:instance/i-0123456789abcdef0"
    for_all = env_from(users=[user_with("ForAllValues")])
    ev = PolicyEvaluator(for_all)
    none = ev.evaluate(
        for_all.users[0], "ec2:CreateTags", instance, extra_context={"aws:TagKeys": None}
    )
    assert none.decision is Decision.ALLOWED
    extra = ev.evaluate(
        for_all.users[0],
        "ec2:CreateTags",
        instance,
        extra_context={"aws:TagKeys": ["env", "owner"]},
    )
    assert extra.decision is Decision.IMPLICIT_DENY
    for_any = env_from(users=[user_with("ForAnyValue")])
    assert (
        PolicyEvaluator(for_any)
        .evaluate(for_any.users[0], "ec2:CreateTags", instance, extra_context={"aws:TagKeys": None})
        .decision
        is Decision.IMPLICIT_DENY
    )


def test_policy_variables_are_literal_without_version_2012_10_17() -> None:
    """Symptom (same corpus): ``${aws:username}`` was substituted in a document that has no
    ``Version`` element, although AWS treats it as literal text there."""
    unversioned = {"Statement": [allow("s3:GetObject", "arn:aws:s3:::home/${aws:username}/*")]}
    env = env_from(users=[{"name": "alice", "inline_policies": {"p": unversioned}}])
    ev = PolicyEvaluator(env)
    alice = env.users[0]
    assert (
        ev.evaluate(alice, "s3:GetObject", "arn:aws:s3:::home/alice/x").decision
        is Decision.IMPLICIT_DENY
    )
    literal_object = "arn:aws:s3:::home/${aws:username}/x"
    assert ev.evaluate(alice, "s3:GetObject", literal_object).decision is Decision.ALLOWED
    versioned = env_from(
        users=[
            {
                "name": "alice",
                "inline_policies": {
                    "p": policy(allow("s3:GetObject", "arn:aws:s3:::home/${aws:username}/*"))
                },
            }
        ]
    )
    result = PolicyEvaluator(versioned).evaluate(
        versioned.users[0], "s3:GetObject", "arn:aws:s3:::home/alice/x"
    )
    assert result.decision is Decision.ALLOWED


def test_same_account_bucket_policy_naming_the_account_root_delegates_to_the_account() -> None:
    """Symptom (raised while building the corpus): a bucket policy whose Principal is the
    account root was treated like one naming the user, granting access on its own. AWS treats
    an account principal as delegation: the identity still needs an identity-based allow."""
    root_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:root"},
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::data/*",
            }
        ],
    }
    env = env_from(
        users=[
            {"name": "nobody"},
            {
                "name": "reader",
                "inline_policies": {"p": policy(allow("s3:GetObject", "arn:aws:s3:::data/*"))},
            },
        ],
        s3_buckets=[{"name": "data", "bucket_policy": root_policy}],
    )
    ev = PolicyEvaluator(env)
    bucket = env.s3_buckets[0]
    kwargs = {"resource_policy": bucket.bucket_policy, "resource_account": ACCOUNT}
    assert (
        ev.evaluate(env.users[0], "s3:GetObject", OBJECT, **kwargs).decision
        is Decision.IMPLICIT_DENY
    )
    assert ev.evaluate(env.users[1], "s3:GetObject", OBJECT, **kwargs).decision is Decision.ALLOWED

    direct_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": user_arn("nobody")},
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::data/*",
            }
        ],
    }
    direct = env_from(
        users=[{"name": "nobody"}], s3_buckets=[{"name": "data", "bucket_policy": direct_policy}]
    )
    result = PolicyEvaluator(direct).evaluate(
        direct.users[0],
        "s3:GetObject",
        OBJECT,
        resource_policy=direct.s3_buckets[0].bucket_policy,
        resource_account=ACCOUNT,
    )
    assert result.decision is Decision.ALLOWED
