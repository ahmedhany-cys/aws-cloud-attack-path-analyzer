from __future__ import annotations

import pytest

from attackpath.iam.matching import (
    action_breadth,
    action_matches,
    arn_matches,
    is_service_wildcard,
    resource_breadth,
    service_of,
    statement_action_matches,
    statement_resource_matches,
    substitute_policy_variables,
    wildcard_match,
)
from attackpath.models.policy import Effect, Statement
from attackpath.tri import Tri


@pytest.mark.parametrize(
    ("pattern", "action", "expected"),
    [
        ("*", "s3:GetObject", True),
        ("s3:*", "s3:GetObject", True),
        ("s3:Get*", "s3:GetObject", True),
        ("s3:get*", "S3:GETOBJECT", True),
        ("s3:Get?bject", "s3:GetObject", True),
        ("s3:GetObject", "s3:GetObjectAcl", False),
        ("s3:*", "iam:PassRole", False),
        ("iam:Pass*", "iam:PassRole", True),
        ("s3:GetObject", "s3:GetObject", True),
    ],
)
def test_action_matches(pattern: str, action: str, expected: bool) -> None:
    assert action_matches(pattern, action) is expected


def test_arn_matching_is_case_sensitive_with_wildcards() -> None:
    assert arn_matches("arn:aws:s3:::bucket/*", "arn:aws:s3:::bucket/key") is Tri.TRUE
    assert arn_matches("arn:aws:s3:::bucket/*", "arn:aws:s3:::bucket") is Tri.FALSE
    assert arn_matches("arn:aws:s3:::Bucket/*", "arn:aws:s3:::bucket/key") is Tri.FALSE
    assert (
        arn_matches("arn:aws:iam::*:role/?eploy", "arn:aws:iam::111111111111:role/deploy")
        is Tri.TRUE
    )
    assert arn_matches("*", "anything") is Tri.TRUE


def test_regex_metacharacters_in_patterns_are_literal() -> None:
    assert not wildcard_match("a.b", "axb", ignore_case=False)
    assert wildcard_match("a.b", "a.b", ignore_case=False)
    assert not wildcard_match("a+b", "aab", ignore_case=False)


def test_policy_variables_resolve_or_become_unknown() -> None:
    pattern = "arn:aws:iam::111111111111:user/${aws:username}"
    assert arn_matches(pattern, "arn:aws:iam::111111111111:user/alice") is Tri.UNKNOWN
    assert (
        arn_matches(pattern, "arn:aws:iam::111111111111:user/alice", {"aws:username": "alice"})
        is Tri.TRUE
    )
    assert (
        arn_matches(pattern, "arn:aws:iam::111111111111:user/bob", {"aws:username": "alice"})
        is Tri.FALSE
    )
    substituted, unresolved = substitute_policy_variables(
        "${aws:username}/${aws:PrincipalTag/team}", {"aws:username": "x"}
    )
    assert substituted.startswith("x/")
    assert unresolved == ["aws:PrincipalTag/team"]


def test_policy_variable_default_values_are_supported() -> None:
    substituted, unresolved = substitute_policy_variables(
        "${aws:username, 'none'}", {"aws:username": "me"}
    )
    assert substituted == "me" and unresolved == []
    assert substitute_policy_variables("${*}", None) == ("*", [])


def test_statement_level_matching_with_not_elements() -> None:
    st = Statement(
        index=0,
        effect=Effect.ALLOW,
        not_actions=("iam:*",),
        not_resources=("arn:aws:s3:::secret/*",),
    )
    assert statement_action_matches(st, "s3:GetObject")
    assert not statement_action_matches(st, "iam:CreateUser")
    assert statement_resource_matches(st, "arn:aws:s3:::other/key") is Tri.TRUE
    assert statement_resource_matches(st, "arn:aws:s3:::secret/key") is Tri.FALSE
    trust_like = Statement(index=1, effect=Effect.ALLOW, actions=("sts:AssumeRole",))
    assert statement_resource_matches(trust_like, "arn:aws:iam::111111111111:role/x") is Tri.TRUE
    empty = Statement(index=2, effect=Effect.ALLOW)
    assert not statement_action_matches(empty, "s3:GetObject")


def test_breadth_heuristics_are_monotonic() -> None:
    assert action_breadth(["*"]) == 1.0
    assert action_breadth(["s3:*"]) > action_breadth(["s3:Get*"]) > action_breadth(["s3:GetObject"])
    assert action_breadth([]) == 0.0
    assert resource_breadth(["*"]) == 1.0
    assert resource_breadth(["arn:aws:s3:::bucket/*"]) > resource_breadth(
        ["arn:aws:s3:::bucket/key"]
    )
    assert resource_breadth([]) == 0.0
    assert service_of("s3:GetObject") == "s3" and service_of("*") == "*"
    assert (
        is_service_wildcard("s3:*")
        and not is_service_wildcard("*")
        and not is_service_wildcard("s3:Get*")
    )
