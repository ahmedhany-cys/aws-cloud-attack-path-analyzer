"""Action and resource matching with IAM wildcard semantics.

* Actions are matched case-insensitively; ``*`` and ``?`` are wildcards.
* Resource ARNs are matched case-sensitively; ``*`` and ``?`` are wildcards.
* Policy variables such as ``${aws:username}`` are substituted from the request
  context when known; otherwise the match is ``UNKNOWN`` instead of being guessed.
"""

from __future__ import annotations

import functools
import re
from collections.abc import Iterable, Mapping

from attackpath.models.policy import Statement
from attackpath.tri import Tri, tri_any, tri_not

POLICY_VARIABLE_RE = re.compile(r"\$\{([^}]*)\}")


@functools.lru_cache(maxsize=8192)
def _compile(pattern: str, ignore_case: bool) -> re.Pattern[str]:
    parts: list[str] = []
    for char in pattern:
        if char == "*":
            parts.append(".*")
        elif char == "?":
            parts.append(".")
        else:
            parts.append(re.escape(char))
    flags = re.IGNORECASE if ignore_case else 0
    return re.compile("^" + "".join(parts) + "$", flags | re.DOTALL)


def wildcard_match(pattern: str, value: str, *, ignore_case: bool) -> bool:
    """Return True when ``value`` matches ``pattern`` using ``*`` and ``?`` wildcards."""
    if pattern == "*":
        return True
    if "*" not in pattern and "?" not in pattern:
        return pattern.lower() == value.lower() if ignore_case else pattern == value
    return _compile(pattern, ignore_case).match(value) is not None


def action_matches(pattern: str, action: str) -> bool:
    """IAM action matching (case-insensitive, wildcard-aware)."""
    return wildcard_match(pattern, action, ignore_case=True)


def substitute_policy_variables(
    pattern: str, variables: Mapping[str, str | None] | None
) -> tuple[str, list[str]]:
    """Replace ``${key}`` placeholders; return the new string and unresolved keys."""
    unresolved: list[str] = []

    def _replace(match: re.Match[str]) -> str:
        key = match.group(1)
        if key == "*" or key == "?" or key == "$":
            return key
        name = key.split(",", 1)[0].strip().lower()
        value = variables.get(name) if variables else None
        if value is None:
            unresolved.append(key)
            return match.group(0)
        return value

    return POLICY_VARIABLE_RE.sub(_replace, pattern), unresolved


def arn_matches(pattern: str, arn: str, variables: Mapping[str, str | None] | None = None) -> Tri:
    """Resource matching; ``UNKNOWN`` when a policy variable cannot be resolved."""
    if "${" in pattern:
        pattern, unresolved = substitute_policy_variables(pattern, variables)
        if unresolved:
            return Tri.UNKNOWN
    return Tri.of(wildcard_match(pattern, arn, ignore_case=False))


def statement_action_matches(statement: Statement, action: str) -> bool:
    if statement.actions:
        return any(action_matches(p, action) for p in statement.actions)
    if statement.not_actions:
        return not any(action_matches(p, action) for p in statement.not_actions)
    return False


def statement_resource_matches(
    statement: Statement, arn: str, variables: Mapping[str, str | None] | None = None
) -> Tri:
    """Resource match for ``statement``; statements without a resource element apply."""
    if statement.resources:
        return tri_any(arn_matches(p, arn, variables) for p in statement.resources)
    if statement.not_resources:
        return tri_not(tri_any(arn_matches(p, arn, variables) for p in statement.not_resources))
    return Tri.TRUE


# ---------------------------------------------------------------------------
# breadth heuristics used by the scoring model
# ---------------------------------------------------------------------------


def service_of(action: str) -> str:
    if action == "*":
        return "*"
    return action.split(":", 1)[0].lower() if ":" in action else action.lower()


def is_full_wildcard(pattern: str) -> bool:
    return pattern.strip() == "*"


def is_service_wildcard(pattern: str) -> bool:
    """``s3:*`` style patterns that grant every action of one service."""
    if ":" not in pattern:
        return False
    service, name = pattern.split(":", 1)
    return name == "*" and "*" not in service and "?" not in service


def has_wildcard(pattern: str) -> bool:
    return "*" in pattern or "?" in pattern


def action_breadth(patterns: Iterable[str]) -> float:
    """Score 0..1 estimating how many actions a set of action patterns covers."""
    score = 0.0
    count = 0
    for pattern in patterns:
        count += 1
        if is_full_wildcard(pattern):
            return 1.0
        if is_service_wildcard(pattern):
            score = max(score, 0.7)
        elif has_wildcard(pattern):
            score = max(score, 0.5)
        else:
            score = max(score, 0.15)
    if count == 0:
        return 0.0
    return min(1.0, score + min(0.2, 0.01 * count))


def resource_breadth(patterns: Iterable[str]) -> float:
    """Score 0..1 estimating how many resources a set of resource patterns covers."""
    score = 0.0
    seen = False
    for pattern in patterns:
        seen = True
        if is_full_wildcard(pattern):
            return 1.0
        if pattern.endswith((":*", "::*")) or (pattern.endswith("/*") and pattern.count("/") == 1):
            score = max(score, 0.7)
        elif has_wildcard(pattern):
            score = max(score, 0.5)
        else:
            score = max(score, 0.2)
    return score if seen else 0.0
