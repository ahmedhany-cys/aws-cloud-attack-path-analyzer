"""IAM authorization semantics: matching, conditions, principals and the evaluator."""

from __future__ import annotations

from attackpath.iam.evaluator import (
    AssumeResult,
    Decision,
    EvaluationResult,
    LimitationLog,
    PolicyEvaluator,
    StatementMatch,
)
from attackpath.iam.matching import action_matches, arn_matches, wildcard_match
from attackpath.iam.principals import PrincipalIdentity, principal_matches

__all__ = [
    "AssumeResult",
    "Decision",
    "EvaluationResult",
    "LimitationLog",
    "PolicyEvaluator",
    "PrincipalIdentity",
    "StatementMatch",
    "action_matches",
    "arn_matches",
    "principal_matches",
    "wildcard_match",
]
