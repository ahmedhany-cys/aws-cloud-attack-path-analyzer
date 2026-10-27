"""Property-based tests for the matching, logic and parsing primitives."""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from attackpath.analysis.context import finding_id
from attackpath.iam.conditions import evaluate_condition
from attackpath.iam.matching import action_matches, arn_matches, wildcard_match
from attackpath.models.policy import Condition
from attackpath.parser.policy_parser import parse_policy_document
from attackpath.tri import Tri, tri_and, tri_or

actions = st.from_regex(r"[a-z0-9-]{1,10}:[A-Za-z0-9]{1,16}", fullmatch=True)
literals = st.text(
    alphabet=st.characters(blacklist_characters="*?", blacklist_categories=("Cs",)),
    min_size=1,
    max_size=30,
)
tris = st.sampled_from(list(Tri))


@given(actions)
def test_star_matches_every_action(action: str) -> None:
    assert action_matches("*", action)
    assert action_matches(action.split(":")[0] + ":*", action)


@given(literals)
def test_literal_patterns_match_only_themselves(value: str) -> None:
    assert wildcard_match(value, value, ignore_case=False)
    assert arn_matches(value, value) is Tri.TRUE
    assert arn_matches(value + "x", value) is Tri.FALSE


@given(actions)
def test_action_matching_is_case_insensitive(action: str) -> None:
    assert action_matches(action.upper(), action.lower())


@given(tris, tris, tris)
def test_kleene_laws(a: Tri, b: Tri, c: Tri) -> None:
    assert tri_and(a, b) is tri_and(b, a)
    assert tri_or(a, b) is tri_or(b, a)
    assert tri_and(a, tri_and(b, c)) is tri_and(tri_and(a, b), c)
    assert tri_or(a, tri_or(b, c)) is tri_or(tri_or(a, b), c)
    assert tri_and(a, Tri.TRUE) is a and tri_or(a, Tri.FALSE) is a


@given(literals)
def test_string_equals_is_reflexive(value: str) -> None:
    result, _ = evaluate_condition(Condition("StringEquals", "k", (value,)), {"k": value})
    assert result is Tri.TRUE


@given(st.text(min_size=1, max_size=20), st.text(max_size=20))
def test_finding_ids_are_stable_and_well_formed(check_id: str, part: str) -> None:
    first = finding_id(check_id, part)
    assert first == finding_id(check_id, part)
    assert first.startswith(f"APA-{check_id}-") and len(first.rsplit("-", 1)[1]) == 8


@settings(max_examples=200)
@given(
    st.lists(
        st.fixed_dictionaries(
            {
                "Effect": st.sampled_from(["Allow", "Deny"]),
                "Action": st.one_of(actions, st.lists(actions, min_size=1, max_size=4)),
                "Resource": st.one_of(
                    st.just("*"), literals, st.lists(literals, min_size=1, max_size=3)
                ),
            }
        ),
        min_size=1,
        max_size=5,
    )
)
def test_parser_accepts_any_well_formed_statement_list(statements: list[dict]) -> None:
    doc = parse_policy_document({"Version": "2012-10-17", "Statement": statements}, "prop")
    assert len(doc.statements) == len(statements)
    for raw, parsed in zip(statements, doc.statements, strict=True):
        expected = raw["Action"] if isinstance(raw["Action"], list) else [raw["Action"]]
        assert list(parsed.actions) == expected
