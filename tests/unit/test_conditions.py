from __future__ import annotations

import pytest

from attackpath.iam.conditions import SUPPORTED_OPERATORS, evaluate_condition, evaluate_conditions
from attackpath.models.policy import Condition
from attackpath.tri import Tri


def cond(operator: str, key: str, *values: str) -> Condition:
    return Condition(operator=operator, key=key, values=tuple(values))


def test_string_equals_true_false_unknown() -> None:
    c = cond("StringEquals", "aws:PrincipalAccount", "111111111111")
    assert evaluate_condition(c, {"aws:principalaccount": "111111111111"})[0] is Tri.TRUE
    assert evaluate_condition(c, {"aws:principalaccount": "222222222222"})[0] is Tri.FALSE
    result, reason = evaluate_condition(c, {})
    assert result is Tri.UNKNOWN
    assert reason is not None and "aws:PrincipalAccount" in reason


def test_missing_key_semantics() -> None:
    # Known-absent key: the condition does not match, unless the operator is ...IfExists.
    assert (
        evaluate_condition(
            cond("StringEquals", "aws:SourceVpce", "vpce-1"), {"aws:sourcevpce": None}
        )[0]
        is Tri.FALSE
    )
    assert (
        evaluate_condition(
            cond("StringEqualsIfExists", "aws:SourceVpce", "vpce-1"), {"aws:sourcevpce": None}
        )[0]
        is Tri.TRUE
    )
    assert (
        evaluate_condition(cond("StringEqualsIfExists", "aws:SourceVpce", "vpce-1"), {})[0]
        is Tri.TRUE
    )


def test_null_operator() -> None:
    c = cond("Null", "aws:TokenIssueTime", "true")
    assert evaluate_condition(c, {"aws:tokenissuetime": None})[0] is Tri.TRUE
    assert evaluate_condition(c, {"aws:tokenissuetime": "2024-01-01T00:00:00Z"})[0] is Tri.FALSE
    assert evaluate_condition(c, {})[0] is Tri.UNKNOWN


def test_negated_operators() -> None:
    c = cond("StringNotEquals", "aws:PrincipalOrgID", "o-123")
    assert evaluate_condition(c, {"aws:principalorgid": "o-123"})[0] is Tri.FALSE
    assert evaluate_condition(c, {"aws:principalorgid": "o-999"})[0] is Tri.TRUE
    assert (
        evaluate_condition(
            cond("StringNotLike", "s3:prefix", "private/*"), {"s3:prefix": "public/x"}
        )[0]
        is Tri.TRUE
    )


def test_set_operators() -> None:
    c = cond("ForAllValues:StringEquals", "aws:TagKeys", "team", "env")
    assert evaluate_condition(c, {"aws:tagkeys": ["team", "env"]})[0] is Tri.TRUE
    assert evaluate_condition(c, {"aws:tagkeys": ["team", "owner"]})[0] is Tri.FALSE
    assert evaluate_condition(c, {"aws:tagkeys": []})[0] is Tri.TRUE
    any_c = cond("ForAnyValue:StringEquals", "aws:TagKeys", "team")
    assert evaluate_condition(any_c, {"aws:tagkeys": ["owner", "team"]})[0] is Tri.TRUE
    assert evaluate_condition(any_c, {"aws:tagkeys": ["owner"]})[0] is Tri.FALSE


def test_ip_numeric_date_bool_arn_operators() -> None:
    assert (
        evaluate_condition(
            cond("IpAddress", "aws:SourceIp", "10.0.0.0/8"), {"aws:sourceip": "10.1.2.3"}
        )[0]
        is Tri.TRUE
    )
    assert (
        evaluate_condition(
            cond("NotIpAddress", "aws:SourceIp", "10.0.0.0/8"), {"aws:sourceip": "10.1.2.3"}
        )[0]
        is Tri.FALSE
    )
    assert (
        evaluate_condition(
            cond("IpAddress", "aws:SourceIp", "2001:db8::/32"), {"aws:sourceip": "2001:db8::1"}
        )[0]
        is Tri.TRUE
    )
    assert (
        evaluate_condition(cond("NumericLessThan", "s3:max-keys", "10"), {"s3:max-keys": "5"})[0]
        is Tri.TRUE
    )
    assert (
        evaluate_condition(
            cond("NumericGreaterThanEquals", "s3:max-keys", "10"), {"s3:max-keys": "5"}
        )[0]
        is Tri.FALSE
    )
    assert (
        evaluate_condition(
            cond("DateGreaterThan", "aws:CurrentTime", "2024-01-01T00:00:00Z"),
            {"aws:currenttime": "2025-06-01T00:00:00Z"},
        )[0]
        is Tri.TRUE
    )
    assert (
        evaluate_condition(
            cond("DateLessThan", "aws:EpochTime", "1700000000"), {"aws:epochtime": "1600000000"}
        )[0]
        is Tri.TRUE
    )
    assert (
        evaluate_condition(
            cond("Bool", "aws:MultiFactorAuthPresent", "true"),
            {"aws:multifactorauthpresent": "True"},
        )[0]
        is Tri.TRUE
    )
    assert (
        evaluate_condition(
            cond("ArnLike", "aws:SourceArn", "arn:aws:sns:*:111111111111:*"),
            {"aws:sourcearn": "arn:aws:sns:us-east-1:111111111111:topic"},
        )[0]
        is Tri.TRUE
    )
    assert (
        evaluate_condition(
            cond("ArnNotEquals", "aws:PrincipalArn", "arn:aws:iam::111111111111:role/a"),
            {"aws:principalarn": "arn:aws:iam::111111111111:role/a"},
        )[0]
        is Tri.FALSE
    )


def test_unevaluable_values_and_unsupported_operators_are_unknown() -> None:
    result, reason = evaluate_condition(
        cond("IpAddress", "aws:SourceIp", "not-an-ip"), {"aws:sourceip": "10.0.0.1"}
    )
    assert result is Tri.UNKNOWN and reason and "could not be evaluated" in reason
    result, reason = evaluate_condition(
        cond("NumericEquals", "s3:max-keys", "ten"), {"s3:max-keys": "10"}
    )
    assert result is Tri.UNKNOWN
    result, reason = evaluate_condition(
        cond("StringEqualsIgnoreCaseIfNotExists", "k", "v"), {"k": "v"}
    )
    assert result is Tri.UNKNOWN and reason and "unsupported condition operator" in reason
    assert "StringEquals" in SUPPORTED_OPERATORS and "Null" in SUPPORTED_OPERATORS


def test_policy_variables_in_condition_values() -> None:
    c = cond("StringEquals", "s3:prefix", "home/${aws:username}")
    assert (
        evaluate_condition(c, {"s3:prefix": "home/alice", "aws:username": "alice"})[0] is Tri.TRUE
    )
    result, reason = evaluate_condition(c, {"s3:prefix": "home/alice"})
    assert result is Tri.UNKNOWN and reason and "policy variable" in reason


def test_evaluate_conditions_combines_with_and_semantics() -> None:
    conds = [cond("StringEquals", "a", "1"), cond("StringEquals", "b", "2")]
    assert evaluate_conditions(conds, {"a": "1", "b": "2"}) == (Tri.TRUE, [])
    assert evaluate_conditions(conds, {"a": "1", "b": "3"})[0] is Tri.FALSE
    result, reasons = evaluate_conditions(conds, {"a": "1"})
    assert result is Tri.UNKNOWN and len(reasons) == 1
    # A definite FALSE short-circuits even when another entry is unknown.
    assert evaluate_conditions(conds, {"b": "9"})[0] is Tri.FALSE
    assert evaluate_conditions([], {}) == (Tri.TRUE, [])


@pytest.mark.parametrize("operator", sorted(SUPPORTED_OPERATORS))
def test_every_supported_operator_accepts_a_context_value(operator: str) -> None:
    value = {"Bool": "true", "Null": "false"}.get(operator, "1")
    if operator.startswith(("Ip", "NotIp")):
        value = "10.0.0.1"
    result, _ = evaluate_condition(cond(operator, "k", value), {"k": value})
    assert result in (Tri.TRUE, Tri.FALSE)
