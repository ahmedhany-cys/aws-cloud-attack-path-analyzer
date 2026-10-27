from __future__ import annotations

from attackpath.iam.evaluator import Decision, LimitationLog, PolicyEvaluator
from attackpath.iam.principals import PrincipalIdentity
from attackpath.parser.policy_parser import parse_policy_document
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

BUCKET = "arn:aws:s3:::data"
OBJ = "arn:aws:s3:::data/file"


def user_with(*statements, name: str = "alice", **extra):
    return {"name": name, "inline_policies": {"p": policy(*statements)}, **extra}


def test_allow_and_implicit_deny() -> None:
    env = env_from(users=[user_with(allow("s3:GetObject", "arn:aws:s3:::data/*"))])
    ev = PolicyEvaluator(env)
    alice = env.users[0]
    assert ev.evaluate(alice, "s3:GetObject", OBJ).decision is Decision.ALLOWED
    assert ev.evaluate(alice, "s3:PutObject", OBJ).decision is Decision.IMPLICIT_DENY
    assert (
        ev.evaluate(alice, "s3:GetObject", "arn:aws:s3:::other/file").decision
        is Decision.IMPLICIT_DENY
    )


def test_explicit_deny_wins_over_allow() -> None:
    env = env_from(users=[user_with(allow("s3:*"), deny("s3:GetObject", "arn:aws:s3:::data/*"))])
    ev = PolicyEvaluator(env)
    result = ev.evaluate(env.users[0], "s3:GetObject", OBJ)
    assert result.decision is Decision.EXPLICIT_DENY
    assert result.allow_matches and result.deny_matches
    assert ev.evaluate(env.users[0], "s3:PutObject", OBJ).decision is Decision.ALLOWED


def test_deny_with_unknown_condition_is_indeterminate() -> None:
    env = env_from(
        users=[
            user_with(
                allow("s3:*"),
                deny("s3:*", Condition={"NotIpAddress": {"aws:SourceIp": "198.51.100.0/24"}}),
            )
        ]
    )
    ev = PolicyEvaluator(env)
    result = ev.evaluate(env.users[0], "s3:GetObject", OBJ)
    assert result.decision is Decision.INDETERMINATE
    assert any("Deny statement applies" in r for r in result.reasons)
    assert any("aws:SourceIp" in r for r in result.unknown_reasons())
    # Providing the context resolves it.
    allowed = ev.evaluate(
        env.users[0], "s3:GetObject", OBJ, extra_context={"aws:SourceIp": "198.51.100.7"}
    )
    assert allowed.decision is Decision.ALLOWED
    denied = ev.evaluate(
        env.users[0], "s3:GetObject", OBJ, extra_context={"aws:SourceIp": "203.0.113.9"}
    )
    assert denied.decision is Decision.EXPLICIT_DENY


def test_allow_with_unknown_condition_is_indeterminate_not_allowed() -> None:
    env = env_from(
        users=[
            user_with(
                allow("s3:GetObject", "*", Condition={"StringEquals": {"aws:SourceVpce": "vpce-1"}})
            )
        ]
    )
    ev = PolicyEvaluator(env)
    result = ev.evaluate(env.users[0], "s3:GetObject", OBJ)
    assert result.decision is Decision.INDETERMINATE
    assert result.is_possible and not result.is_allowed
    assert len(ev.limitations) >= 1


def test_permissions_boundary_intersects_identity_policy() -> None:
    boundary_arn = f"arn:aws:iam::{ACCOUNT}:policy/boundary"
    env = env_from(
        users=[user_with(allow("*"), permissions_boundary=boundary_arn)],
        managed_policies=[{"arn": boundary_arn, "document": policy(allow("s3:GetObject"))}],
    )
    ev = PolicyEvaluator(env)
    alice = env.users[0]
    assert ev.evaluate(alice, "s3:GetObject", OBJ).decision is Decision.ALLOWED
    boundary_blocked = ev.evaluate(alice, "iam:CreateUser", "*")
    assert boundary_blocked.decision is Decision.IMPLICIT_DENY
    assert boundary_blocked.boundary_allow is Tri.FALSE
    assert ev.is_admin_equivalent(alice)[0] is Tri.FALSE


def test_unresolved_boundary_and_attached_policy_make_results_indeterminate() -> None:
    env = env_from(
        users=[
            {"name": "a", "attached_policies": [f"arn:aws:iam::{ACCOUNT}:policy/missing"]},
            {
                "name": "b",
                "inline_policies": {"p": policy(allow("*"))},
                "permissions_boundary": f"arn:aws:iam::{ACCOUNT}:policy/missing-boundary",
            },
        ]
    )
    log = LimitationLog()
    ev = PolicyEvaluator(env, log)
    a = ev.evaluate(env.users[0], "s3:GetObject", OBJ)
    assert a.decision is Decision.INDETERMINATE
    assert a.unresolved_policies == [f"arn:aws:iam::{ACCOUNT}:policy/missing"]
    assert ev.unresolved_policies_for(env.users[0]) == a.unresolved_policies
    b = ev.evaluate(env.users[1], "s3:GetObject", OBJ)
    assert b.decision is Decision.INDETERMINATE and b.boundary_allow is Tri.UNKNOWN
    kinds = {kind for kind, _, _ in log.entries()}
    assert {"unresolved-policy", "unresolved-boundary"} <= kinds


def test_group_policies_apply_to_users() -> None:
    env = env_from(
        users=[{"name": "alice", "groups": ["readers"]}],
        groups=[{"name": "readers", "inline_policies": {"r": policy(allow("s3:GetObject"))}}],
    )
    ev = PolicyEvaluator(env)
    assert ev.evaluate(env.users[0], "s3:GetObject", OBJ).decision is Decision.ALLOWED
    assert len(ev.identity_policies(env.users[0])) == 1


def test_resource_policy_same_account_or_and_cross_account_and() -> None:
    bucket_policy = parse_policy_document(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": user_arn("alice")},
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::data/*",
                },
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{OTHER_ACCOUNT}:root"},
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::data/*",
                },
                {
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "s3:DeleteObject",
                    "Resource": "arn:aws:s3:::data/*",
                },
            ],
        },
        "bucket-policy",
    )
    env = env_from(
        users=[
            {"name": "alice"},
            {"name": "bob", "inline_policies": {"p": policy(allow("s3:DeleteObject"))}},
        ]
    )
    ev = PolicyEvaluator(env)
    alice, bob = env.users
    # Same account: the bucket policy alone is enough for alice.
    assert (
        ev.evaluate(
            alice, "s3:GetObject", OBJ, resource_policy=bucket_policy, resource_account=ACCOUNT
        ).decision
        is Decision.ALLOWED
    )
    # Bob has no grant anywhere for GetObject.
    assert (
        ev.evaluate(
            bob, "s3:GetObject", OBJ, resource_policy=bucket_policy, resource_account=ACCOUNT
        ).decision
        is Decision.IMPLICIT_DENY
    )
    # A resource-policy Deny beats bob's identity Allow.
    assert (
        ev.evaluate(
            bob, "s3:DeleteObject", OBJ, resource_policy=bucket_policy, resource_account=ACCOUNT
        ).decision
        is Decision.EXPLICIT_DENY
    )
    # Cross-account bucket: alice needs an identity allow too (she has none).
    assert (
        ev.evaluate(
            alice,
            "s3:GetObject",
            OBJ,
            resource_policy=bucket_policy,
            resource_account=OTHER_ACCOUNT,
        ).decision
        is Decision.IMPLICIT_DENY
    )
    # Resource-policy-only evaluation for an external account principal.
    external = PrincipalIdentity.account(OTHER_ACCOUNT)
    assert (
        ev.evaluate_resource_policy(bucket_policy, external, "s3:GetObject", OBJ).decision
        is Decision.ALLOWED
    )
    assert (
        ev.evaluate_resource_policy(
            bucket_policy, PrincipalIdentity.anonymous(), "s3:GetObject", OBJ
        ).decision
        is Decision.IMPLICIT_DENY
    )


def test_trust_direct_naming_needs_no_identity_permission() -> None:
    env = env_from(
        users=[{"name": "alice"}],
        roles=[{"name": "target", "trust_policy": trust({"AWS": user_arn("alice")})}],
    )
    ev = PolicyEvaluator(env)
    result = ev.can_assume(PrincipalIdentity.from_principal(env.users[0]), env.roles[0])
    assert result.decision is Decision.ALLOWED
    assert not result.identity_permission_required and result.identity_permission is None


def test_trust_account_root_requires_identity_permission() -> None:
    env = env_from(
        users=[
            {"name": "alice"},
            user_with(allow("sts:AssumeRole", role_arn("target")), name="bob"),
        ],
        roles=[{"name": "target", "trust_policy": trust(account_root())}],
    )
    ev = PolicyEvaluator(env)
    alice, bob = env.users
    denied = ev.can_assume(PrincipalIdentity.from_principal(alice), env.roles[0])
    assert denied.decision is Decision.IMPLICIT_DENY and denied.identity_permission_required
    allowed = ev.can_assume(PrincipalIdentity.from_principal(bob), env.roles[0])
    assert allowed.decision is Decision.ALLOWED and allowed.identity_permission is not None


def test_trust_external_id_condition_becomes_precondition() -> None:
    env = env_from(
        roles=[
            {
                "name": "vendor",
                "trust_policy": trust(
                    account_root(OTHER_ACCOUNT),
                    Condition={"StringEquals": {"sts:ExternalId": "abc"}},
                ),
            }
        ]
    )
    ev = PolicyEvaluator(env)
    result = ev.can_assume(PrincipalIdentity.account(OTHER_ACCOUNT), env.roles[0])
    assert result.decision is Decision.INDETERMINATE
    assert any("sts:ExternalId" in p for p in result.preconditions)
    assert any("identity-policy Allow" in p for p in result.preconditions)
    with_context = ev.can_assume(
        PrincipalIdentity.account(OTHER_ACCOUNT), env.roles[0], {"sts:ExternalId": "abc"}
    )
    assert with_context.trust.decision is Decision.ALLOWED


def test_anonymous_trust_and_explicit_trust_deny() -> None:
    env = env_from(
        users=[user_with(allow("sts:AssumeRole"), name="alice")],
        roles=[
            {"name": "open", "trust_policy": trust("*")},
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
            },
        ],
    )
    ev = PolicyEvaluator(env)
    anonymous = ev.can_assume(PrincipalIdentity.anonymous(), env.role(role_arn("open")))  # type: ignore[arg-type]
    assert anonymous.decision is Decision.ALLOWED
    alice = PrincipalIdentity.from_principal(env.users[0])
    assert ev.can_assume(alice, env.role(role_arn("guarded"))).decision is Decision.EXPLICIT_DENY  # type: ignore[arg-type]


def test_admin_probe_true_false_unknown() -> None:
    env = env_from(
        users=[
            user_with(allow("*"), name="admin"),
            user_with(allow("s3:*"), name="s3only"),
            user_with(
                allow("*", "*", Condition={"Bool": {"aws:MultiFactorAuthPresent": "true"}}),
                name="mfa-admin",
            ),
        ]
    )
    ev = PolicyEvaluator(env)
    admin, s3only, mfa_admin = env.users
    assert ev.is_admin_equivalent(admin)[0] is Tri.TRUE
    assert ev.is_admin_equivalent(admin)[1], "admin evidence refs are collected"
    assert ev.is_admin_equivalent(s3only) == (Tri.FALSE, [])
    assert ev.is_admin_equivalent(mfa_admin)[0] is Tri.UNKNOWN


def test_request_context_contains_static_facts() -> None:
    env = env_from(
        users=[{"name": "alice", "tags": {"Team": "sec"}}],
        s3_buckets=[{"name": "data", "tags": {"Class": "pii"}}],
    )
    ev = PolicyEvaluator(env)
    ctx = ev.request_context(
        PrincipalIdentity.from_principal(env.users[0]), "arn:aws:s3:::data", {"Extra": "1"}
    )
    assert ctx["aws:username"] == "alice"
    assert ctx["aws:principaltag/team"] == "sec"
    assert ctx["aws:resourcetag/class"] == "pii"
    assert ctx["aws:resourceaccount"] == ACCOUNT
    assert ctx["aws:principaltype"] == "User" and ctx["extra"] == "1"
    anon = ev.request_context(PrincipalIdentity.anonymous())
    assert anon["aws:principalarn"] is None and anon["aws:principaltype"] == "Anonymous"


def test_evidence_and_limitation_log() -> None:
    env = env_from(
        users=[user_with(allow("s3:GetObject", "arn:aws:s3:::${aws:PrincipalTag/bucket}/*"))]
    )
    log = LimitationLog()
    ev = PolicyEvaluator(env, log)
    result = ev.evaluate(env.users[0], "s3:GetObject", OBJ)
    assert result.decision is Decision.INDETERMINATE
    assert result.evidence()[0].statement is not None
    assert log.by_kind("policy-variable")
    log.record("x", "y")
    log.record("x", "y")
    assert ("x", "y", 2) in log.entries()
