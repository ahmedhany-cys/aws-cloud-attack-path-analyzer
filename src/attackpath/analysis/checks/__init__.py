"""Registry of analysis checks.

Each module exposes ``CHECK_IDS`` and ``run(ctx) -> list[Finding]``. Checks are pure
functions of the :class:`~attackpath.analysis.context.AnalysisContext`; they never
mutate the environment and never make network calls.
"""

from __future__ import annotations

from collections.abc import Callable

from attackpath.analysis.checks import (
    coverage,
    excessive,
    exposure,
    limitations,
    network,
    paths,
    permissions,
    sensitive_access,
    trust,
)
from attackpath.analysis.context import AnalysisContext
from attackpath.models.finding import Finding

CheckFn = Callable[[AnalysisContext], list[Finding]]

ALL_CHECKS: tuple[tuple[str, CheckFn], ...] = (
    ("excessive", excessive.run),
    ("trust", trust.run),
    ("permissions", permissions.run),
    ("exposure", exposure.run),
    ("network", network.run),
    ("sensitive_access", sensitive_access.run),
    ("paths", paths.run),
    ("limitations", limitations.run),
    ("coverage", coverage.run),
)

ALL_CHECK_IDS: tuple[str, ...] = tuple(
    check_id
    for module in (
        excessive,
        trust,
        permissions,
        exposure,
        network,
        sensitive_access,
        paths,
        limitations,
        coverage,
    )
    for check_id in module.CHECK_IDS
)

__all__ = ["ALL_CHECKS", "ALL_CHECK_IDS", "CheckFn"]
