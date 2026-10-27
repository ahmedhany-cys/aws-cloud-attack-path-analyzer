"""Three-valued logic used by the policy evaluator.

Authorization questions answered from a static configuration snapshot are often
undecidable: a policy condition may depend on request-time context (source IP,
MFA state, VPC endpoint, tags) that the snapshot does not contain. Instead of
guessing, every combination step carries an explicit ``UNKNOWN`` value using
Kleene's strong three-valued logic. ``UNKNOWN`` surfaces in findings as an
"indeterminate" evaluation rather than being silently treated as allowed or denied.
"""

from __future__ import annotations

from collections.abc import Iterable
from enum import Enum


class Tri(Enum):
    """A truth value that may be undecidable from the available evidence."""

    TRUE = "true"
    FALSE = "false"
    UNKNOWN = "unknown"

    @classmethod
    def of(cls, value: bool) -> Tri:
        """Lift a Python boolean into the three-valued domain."""
        return cls.TRUE if value else cls.FALSE

    def __bool__(self) -> bool:  # pragma: no cover - defensive
        # Using a Tri in a boolean context would silently collapse UNKNOWN into
        # True (the Enum default). Fail loudly so such bugs cannot hide.
        raise TypeError("Tri values must be compared explicitly (e.g. `t is Tri.TRUE`)")

    @property
    def is_true(self) -> bool:
        return self is Tri.TRUE

    @property
    def is_false(self) -> bool:
        return self is Tri.FALSE

    @property
    def is_unknown(self) -> bool:
        return self is Tri.UNKNOWN


def tri_and(*values: Tri) -> Tri:
    """Kleene conjunction. ``FALSE`` dominates, then ``UNKNOWN``; empty input is ``TRUE``."""
    return tri_all(values)


def tri_or(*values: Tri) -> Tri:
    """Kleene disjunction. ``TRUE`` dominates, then ``UNKNOWN``; empty input is ``FALSE``."""
    return tri_any(values)


def tri_not(value: Tri) -> Tri:
    if value is Tri.TRUE:
        return Tri.FALSE
    if value is Tri.FALSE:
        return Tri.TRUE
    return Tri.UNKNOWN


def tri_all(values: Iterable[Tri]) -> Tri:
    result = Tri.TRUE
    for value in values:
        if value is Tri.FALSE:
            return Tri.FALSE
        if value is Tri.UNKNOWN:
            result = Tri.UNKNOWN
    return result


def tri_any(values: Iterable[Tri]) -> Tri:
    result = Tri.FALSE
    for value in values:
        if value is Tri.TRUE:
            return Tri.TRUE
        if value is Tri.UNKNOWN:
            result = Tri.UNKNOWN
    return result
