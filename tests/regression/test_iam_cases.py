"""Documentation-sourced regression corpus for the IAM policy evaluator.

``iam_cases.json`` holds requests whose expected outcome is fixed by the AWS
documentation cited in each case, never by this project's evaluator. Confirmed
cases must keep passing. Disputed cases (the evaluator disagrees with the documented
rule) are collected as strict ``xfail`` so they stay visible without failing the
suite until a maintainer adjudicates them. See ``docs/iam-regression-cases.md``.
"""

from __future__ import annotations

import copy
import json
import re
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

from attackpath.iam.evaluator import Decision, PolicyEvaluator
from attackpath.models.environment import Environment
from attackpath.parser.environment_parser import parse_environment
from tests.conftest import ACCOUNT, OTHER_ACCOUNT, snapshot

CASES_PATH = Path(__file__).with_name("iam_cases.json")
DOCS_PREFIX = "https://docs.aws.amazon.com/"
MIN_CASES, MAX_CASES = 30, 45
MAX_CORPUS_BYTES = 80 * 1024

AREAS = frozenset(
    {
        "evaluation-order",
        "wildcards",
        "not-elements",
        "boundary",
        "resource-policy",
        "conditions",
        "policy-variables",
        "principals",
    }
)
STATUSES = frozenset({"confirmed", "disputed"})
EXPECTED_DECISIONS: dict[str, Decision] = {
    "allowed": Decision.ALLOWED,
    "explicit_deny": Decision.EXPLICIT_DENY,
    "implicit_deny": Decision.IMPLICIT_DENY,
    "indeterminate": Decision.INDETERMINATE,
}
REQUIRED_KEYS = frozenset(
    {"id", "title", "area", "source", "environment", "request", "expected", "status", "simulator"}
)
OPTIONAL_KEYS = frozenset({"resource_policy_of", "note"})
ENVIRONMENT_SECTIONS = frozenset({"users", "groups", "roles", "managed_policies", "s3_buckets"})
CASE_ID_RE = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")

Case = dict[str, Any]


def load_cases() -> list[Case]:
    document = json.loads(CASES_PATH.read_text("utf-8"))
    return [dict(case) for case in document["cases"]]


CASES: list[Case] = load_cases()
CASE_IDS: list[str] = [case["id"] for case in CASES]


def build_environment(case: Case) -> Environment:
    """Parse the case's snapshot fragment through the regular environment parser."""
    return parse_environment(snapshot(**copy.deepcopy(case["environment"])), case["id"])


def evaluate_case(case: Case) -> Decision:
    """Run the request of ``case`` through :class:`PolicyEvaluator` and return the decision."""
    env = build_environment(case)
    request = case["request"]
    principal = env.principal(request["principal"])
    assert principal is not None, f"{case['id']}: {request['principal']} is not in the environment"
    resource_policy = None
    resource_account = None
    bucket_name = case.get("resource_policy_of")
    if bucket_name is not None:
        bucket = env.bucket(f"arn:aws:s3:::{bucket_name}")
        assert bucket is not None, f"{case['id']}: bucket {bucket_name} is not in the environment"
        assert bucket.bucket_policy is not None, f"{case['id']}: bucket {bucket_name} has no policy"
        resource_policy = bucket.bucket_policy
        resource_account = bucket.account_id
    result = PolicyEvaluator(env).evaluate(
        principal,
        request["action"],
        request["resource"],
        resource_policy=resource_policy,
        resource_account=resource_account,
        extra_context=request.get("context"),
    )
    return result.decision


def _marks(case: Case) -> Sequence[pytest.MarkDecorator]:
    if case["status"] != "disputed":
        return ()
    return (pytest.mark.xfail(strict=True, reason=case["note"]),)


OUTCOME_PARAMS = [pytest.param(case, id=case["id"], marks=_marks(case)) for case in CASES]


@pytest.mark.parametrize("case", OUTCOME_PARAMS)
def test_documented_outcome(case: Case) -> None:
    expected = EXPECTED_DECISIONS[case["expected"]]
    decision = evaluate_case(case)
    assert decision is expected, (
        f"{case['id']}: expected {case['expected']} per {case['source']['url']} "
        f"({case['source']['rule']}) but the evaluator returned {decision.value}"
    )


# ---------------------------------------------------------------------------
# corpus integrity
# ---------------------------------------------------------------------------


def test_corpus_size_is_within_bounds() -> None:
    assert MIN_CASES <= len(CASES) <= MAX_CASES
    assert CASES_PATH.stat().st_size <= MAX_CORPUS_BYTES


def test_corpus_is_canonically_formatted() -> None:
    text = CASES_PATH.read_text("utf-8")
    assert text == json.dumps(json.loads(text), indent=2) + "\n"


def test_case_ids_are_unique_and_well_formed() -> None:
    assert len(CASE_IDS) == len(set(CASE_IDS)), "duplicate case ids"
    assert all(CASE_ID_RE.fullmatch(case_id) for case_id in CASE_IDS)


def test_every_area_is_covered() -> None:
    assert {case["area"] for case in CASES} == AREAS


@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
def test_case_schema(case: Case) -> None:
    keys = set(case)
    assert keys >= REQUIRED_KEYS, f"missing keys: {sorted(REQUIRED_KEYS - keys)}"
    assert keys <= REQUIRED_KEYS | OPTIONAL_KEYS, f"unknown keys: {sorted(keys - REQUIRED_KEYS)}"
    assert case["title"].strip()
    assert case["area"] in AREAS
    assert case["expected"] in EXPECTED_DECISIONS
    assert case["status"] in STATUSES

    source = case["source"]
    assert set(source) == {"url", "rule"}
    assert source["url"].startswith(DOCS_PREFIX), source["url"]
    assert source["rule"].strip()

    assert set(case["environment"]) <= ENVIRONMENT_SECTIONS
    request = case["request"]
    assert (
        {"principal", "action", "resource"}
        <= set(request)
        <= {
            "principal",
            "action",
            "resource",
            "context",
        }
    )
    for key, value in request.get("context", {}).items():
        assert isinstance(key, str) and ":" in key, key
        assert (
            value is None
            or isinstance(value, str)
            or (isinstance(value, list) and all(isinstance(item, str) for item in value))
        ), f"context value for {key} must be null, a string or a list of strings"

    simulator = case["simulator"]
    assert set(simulator) <= {"supported", "note"}
    assert isinstance(simulator["supported"], bool)
    if not simulator["supported"]:
        assert simulator.get("note"), "unsupported simulator cases must explain why"

    if case["status"] == "disputed":
        assert case.get("note"), "disputed cases must carry a note"
    else:
        assert "note" not in case, "only disputed cases carry a note"

    # Only the two synthetic accounts may appear anywhere in a case.
    assert set(re.findall(r"\b\d{12}\b", json.dumps(case))) <= {ACCOUNT, OTHER_ACCOUNT}


@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
def test_case_environment_is_consistent(case: Case) -> None:
    env = build_environment(case)
    request = case["request"]
    assert env.principal(request["principal"]) is not None
    bucket_name = case.get("resource_policy_of")
    if bucket_name is not None:
        bucket = env.bucket(f"arn:aws:s3:::{bucket_name}")
        assert bucket is not None and bucket.bucket_policy is not None
        assert request["resource"].startswith(f"arn:aws:s3:::{bucket_name}")
