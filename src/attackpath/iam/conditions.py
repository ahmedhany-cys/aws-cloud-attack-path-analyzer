"""Evaluation of IAM ``Condition`` blocks against a partially known request context.

The request context is a mapping from lower-cased condition keys to a value, a
list of values, or ``None`` (meaning the key is known to be absent). Keys missing
from the mapping are *unknown*: the static snapshot cannot tell what value a
future request would carry, so the condition evaluates to ``UNKNOWN`` rather than
to a guess. Unsupported operators also yield ``UNKNOWN`` with a reason.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable, Iterable, Mapping
from datetime import UTC, datetime

from attackpath.iam.matching import substitute_policy_variables, wildcard_match
from attackpath.models.policy import Condition
from attackpath.tri import Tri

RequestContext = Mapping[str, str | list[str] | None]


class _UnevaluableError(Exception):
    """Raised by a matcher when values cannot be compared (bad number, bad IP)."""


def _eq(cond: str, ctx: str) -> bool:
    return cond == ctx


def _eq_ignore_case(cond: str, ctx: str) -> bool:
    return cond.lower() == ctx.lower()


def _like(cond: str, ctx: str) -> bool:
    return wildcard_match(cond, ctx, ignore_case=False)


def _arn_like(cond: str, ctx: str) -> bool:
    return wildcard_match(cond, ctx, ignore_case=False)


def _bool(cond: str, ctx: str) -> bool:
    return cond.strip().lower() == ctx.strip().lower()


def _number(value: str) -> float:
    try:
        return float(value)
    except ValueError as exc:
        raise _UnevaluableError(f"non-numeric value {value!r}") from exc


def _numeric(op: Callable[[float, float], bool]) -> Callable[[str, str], bool]:
    def matcher(cond: str, ctx: str) -> bool:
        return op(_number(ctx), _number(cond))

    return matcher


def _date(value: str) -> datetime:
    text = value.strip()
    if text.isdigit():
        return datetime.fromtimestamp(int(text), tz=UTC)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise _UnevaluableError(f"unparseable date {value!r}") from exc
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _date_cmp(op: Callable[[datetime, datetime], bool]) -> Callable[[str, str], bool]:
    def matcher(cond: str, ctx: str) -> bool:
        return op(_date(ctx), _date(cond))

    return matcher


def _ip(cond: str, ctx: str) -> bool:
    try:
        network = ipaddress.ip_network(cond.strip(), strict=False)
        address = ipaddress.ip_address(ctx.strip())
    except ValueError as exc:
        raise _UnevaluableError(f"invalid IP value: {exc}") from exc
    return address in network


# base operator -> (matcher, negated)
_OPERATORS: dict[str, tuple[Callable[[str, str], bool], bool]] = {
    "StringEquals": (_eq, False),
    "StringNotEquals": (_eq, True),
    "StringEqualsIgnoreCase": (_eq_ignore_case, False),
    "StringNotEqualsIgnoreCase": (_eq_ignore_case, True),
    "StringLike": (_like, False),
    "StringNotLike": (_like, True),
    "ArnEquals": (_arn_like, False),
    "ArnLike": (_arn_like, False),
    "ArnNotEquals": (_arn_like, True),
    "ArnNotLike": (_arn_like, True),
    "Bool": (_bool, False),
    "NumericEquals": (_numeric(lambda a, b: a == b), False),
    "NumericNotEquals": (_numeric(lambda a, b: a == b), True),
    "NumericLessThan": (_numeric(lambda a, b: a < b), False),
    "NumericLessThanEquals": (_numeric(lambda a, b: a <= b), False),
    "NumericGreaterThan": (_numeric(lambda a, b: a > b), False),
    "NumericGreaterThanEquals": (_numeric(lambda a, b: a >= b), False),
    "DateEquals": (_date_cmp(lambda a, b: a == b), False),
    "DateNotEquals": (_date_cmp(lambda a, b: a == b), True),
    "DateLessThan": (_date_cmp(lambda a, b: a < b), False),
    "DateLessThanEquals": (_date_cmp(lambda a, b: a <= b), False),
    "DateGreaterThan": (_date_cmp(lambda a, b: a > b), False),
    "DateGreaterThanEquals": (_date_cmp(lambda a, b: a >= b), False),
    "IpAddress": (_ip, False),
    "NotIpAddress": (_ip, True),
    "BinaryEquals": (_eq, False),
}

SUPPORTED_OPERATORS = frozenset(_OPERATORS) | {"Null"}


def evaluate_condition(condition: Condition, context: RequestContext) -> tuple[Tri, str | None]:
    """Evaluate one condition entry. Returns ``(result, reason)``; reason set when UNKNOWN."""
    key = condition.key.lower()
    base = condition.base_operator
    variables = {k: v if isinstance(v, str) else None for k, v in context.items()}

    values: list[str] = []
    for raw in condition.values:
        if "${" in raw:
            substituted, unresolved = substitute_policy_variables(raw, variables)
            if unresolved:
                return (
                    Tri.UNKNOWN,
                    f"policy variable(s) {', '.join(unresolved)} in {condition.describe()} cannot be resolved offline",
                )
            values.append(substituted)
        else:
            values.append(raw)

    if base == "Null":
        if key not in context:
            return (
                Tri.UNKNOWN,
                f"request context key {condition.key} is not known from static configuration",
            )
        absent = context[key] is None
        want_absent = values[0].strip().lower() == "true" if values else True
        return Tri.of(absent == want_absent), None

    if base not in _OPERATORS:
        return Tri.UNKNOWN, f"unsupported condition operator {condition.operator}"

    if key not in context:
        if condition.if_exists:
            return Tri.TRUE, None
        return (
            Tri.UNKNOWN,
            f"request context key {condition.key} is not known from static configuration",
        )

    ctx_raw = context[key]
    if ctx_raw is None:
        # AWS: a missing key does not match unless the operator is ...IfExists.
        return (Tri.TRUE, None) if condition.if_exists else (Tri.FALSE, None)

    ctx_values = [ctx_raw] if isinstance(ctx_raw, str) else list(ctx_raw)
    matcher, negated = _OPERATORS[base]

    try:
        if condition.set_operator == "ForAllValues":
            result = all(_matches_any(matcher, negated, values, cv) for cv in ctx_values)
        else:
            # Single-valued operators and ForAnyValue: at least one context value must match.
            result = any(_matches_any(matcher, negated, values, cv) for cv in ctx_values)
    except _UnevaluableError as exc:
        return Tri.UNKNOWN, f"{condition.describe()} could not be evaluated: {exc}"
    return Tri.of(result), None


def _matches_any(
    matcher: Callable[[str, str], bool], negated: bool, values: Iterable[str], ctx_value: str
) -> bool:
    matched = any(matcher(v, ctx_value) for v in values)
    return (not matched) if negated else matched


def evaluate_conditions(
    conditions: Iterable[Condition], context: RequestContext
) -> tuple[Tri, list[str]]:
    """AND together all condition entries; collect reasons for UNKNOWN outcomes."""
    result = Tri.TRUE
    reasons: list[str] = []
    for condition in conditions:
        value, reason = evaluate_condition(condition, context)
        if value is Tri.FALSE:
            return Tri.FALSE, []
        if value is Tri.UNKNOWN:
            result = Tri.UNKNOWN
            if reason:
                reasons.append(reason)
    return result, reasons
