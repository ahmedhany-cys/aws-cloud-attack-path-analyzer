from __future__ import annotations

import json
from pathlib import Path

import pytest

from attackpath.config import Limits
from attackpath.exceptions import InputError, LimitExceededError
from attackpath.models.environment import CoverageStatus, Sensitivity
from attackpath.models.policy import Effect
from attackpath.parser.environment_parser import parse_environment
from attackpath.parser.loader import POLICY_ONLY_ACCOUNT, classify_document, load_input, read_json
from attackpath.parser.policy_parser import parse_policy_document
from tests.conftest import (
    ACCOUNT,
    POLICY_DIR,
    SAMPLE_ENVIRONMENT,
    allow,
    deny,
    policy,
    snapshot,
    trust,
)

# ---------------------------------------------------------------------------
# policy documents
# ---------------------------------------------------------------------------


def test_policy_parser_normalizes_strings_and_lists() -> None:
    doc = parse_policy_document(
        {
            "Version": "2012-10-17",
            "Statement": {
                "Sid": "One",
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": ["arn:aws:s3:::a/*", "arn:aws:s3:::b/*"],
                "Condition": {
                    "Bool": {"aws:SecureTransport": True},
                    "NumericLessThan": {"s3:max-keys": 10},
                },
            },
        },
        "test",
    )
    (st,) = doc.statements
    assert st.sid == "One" and st.effect is Effect.ALLOW
    assert st.actions == ("s3:GetObject",) and len(st.resources) == 2
    assert {(c.operator, c.key, c.values) for c in st.conditions} == {
        ("Bool", "aws:SecureTransport", ("true",)),
        ("NumericLessThan", "s3:max-keys", ("10",)),
    }
    assert st.label() == "statement[0] (Sid: One)"


def test_policy_parser_principals() -> None:
    doc = parse_policy_document(
        trust({"AWS": ["arn:aws:iam::111111111111:root", "*"], "Service": "lambda.amazonaws.com"}),
        "t",
    )
    spec = doc.statements[0].principal
    assert spec is not None and spec.is_anonymous and spec.service == ("lambda.amazonaws.com",)
    star = parse_policy_document(trust("*"), "t").statements[0].principal
    assert star is not None and star.wildcard


@pytest.mark.parametrize(
    ("statement", "message"),
    [
        ({"Effect": "allow", "Action": "s3:*", "Resource": "*"}, "Effect must be exactly"),
        (
            {"Effect": "Allow", "Action": "s3:*", "NotAction": "iam:*", "Resource": "*"},
            "cannot be combined",
        ),
        ({"Effect": "Allow", "Resource": "*"}, "needs an Action or NotAction"),
        ({"Effect": "Allow", "Action": [], "Resource": "*"}, "cannot be empty"),
        (
            {"Effect": "Allow", "Action": "s3:*", "Resource": "*", "Bogus": 1},
            "unsupported statement element",
        ),
        ({"Effect": "Allow", "Action": ["s3:*", 5], "Resource": "*"}, "must be strings"),
        (
            {"Effect": "Allow", "Action": "s3:*", "Resource": "*", "Principal": {"Robot": "x"}},
            "unsupported principal type",
        ),
        (
            {
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": "*",
                "Condition": {"StringEquals": "x"},
            },
            "must be an object",
        ),
        (
            {
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": "*",
                "Condition": {"StringEquals": {"k": {"nested": 1}}},
            },
            "condition values must be",
        ),
    ],
)
def test_policy_parser_rejects_invalid_statements(statement: dict, message: str) -> None:
    with pytest.raises(InputError, match=message):
        parse_policy_document({"Version": "2012-10-17", "Statement": [statement]}, "test")


def test_policy_parser_document_level_errors_and_warnings() -> None:
    with pytest.raises(InputError, match="missing the Statement"):
        parse_policy_document({"Version": "2012-10-17"}, "t")
    with pytest.raises(InputError, match="must be a JSON object"):
        parse_policy_document(["not", "a", "policy"], "t")
    with pytest.raises(InputError, match="Statement must be"):
        parse_policy_document({"Statement": "oops"}, "t")
    warnings: list[str] = []
    parse_policy_document({"Statement": [allow("s3:*")]}, "t", warnings=warnings)
    assert any("no Version" in w for w in warnings)
    warnings.clear()
    parse_policy_document(
        {"Version": "1999-01-01", "Statement": [allow("s3:*")]}, "t", warnings=warnings
    )
    assert any("unrecognized policy Version" in w for w in warnings)


# ---------------------------------------------------------------------------
# environment snapshots
# ---------------------------------------------------------------------------


def test_environment_parser_builds_arns_and_indexes() -> None:
    env = parse_environment(
        snapshot(
            users=[{"name": "alice", "path": "/team/", "groups": ["devs"]}],
            groups=[{"name": "devs"}],
            roles=[{"name": "deploy", "trust_policy": trust({"Service": "lambda.amazonaws.com"})}],
            s3_buckets=[{"name": "data", "sensitivity": "High", "tags": {"k": "v"}}],
            lambda_functions=[{"name": "fn", "role_arn": f"arn:aws:iam::{ACCOUNT}:role/deploy"}],
        ),
        "t",
    )
    assert env.users[0].arn == f"arn:aws:iam::{ACCOUNT}:user/team/alice"
    assert env.role(f"arn:aws:iam::{ACCOUNT}:role/deploy") is not None
    assert env.bucket("arn:aws:s3:::data").sensitivity is Sensitivity.HIGH  # type: ignore[union-attr]
    assert env.lambda_functions[0].arn == f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:fn"
    assert env.summary()["users"] == 1 and env.principal_count == 2
    assert env.coverage.is_complete and env.coverage.status_of("iam") is CoverageStatus.COMPLETE


def test_environment_parser_coverage_forms_and_metadata() -> None:
    env = parse_environment(
        snapshot(
            coverage={
                "services": {
                    "iam": "complete",
                    "lambda": {"status": "partial", "notes": ["eu-west-1 denied"]},
                },
                "notes": ["n"],
            },
            metadata={
                "name": "x",
                "synthetic": True,
                "source": "aws-scan",
                "regions": ["us-east-1"],
            },
        ),
        "t",
    )
    assert env.coverage.status_of("lambda") is CoverageStatus.PARTIAL
    assert env.coverage.incomplete_services()[0][1].notes == ("eu-west-1 denied",)
    assert env.coverage.status_of("s3") is CoverageStatus.UNKNOWN
    assert env.metadata.source == "aws-scan" and env.metadata.regions == ["us-east-1"]


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"account_id": "123"}, "12-digit"),
        ({"schema_version": "9.9"}, "unsupported schema_version"),
        ({"surprise": {}}, "unsupported top-level"),
        ({"users": [{"name": "a"}, {"name": "a"}]}, "duplicate entry"),
        (
            {"users": [{"name": "a", "arn": "arn:aws:iam::111111111111:role/a"}]},
            "is not an IAM user ARN",
        ),
        ({"roles": [{"name": "r"}]}, "missing trust_policy"),
        (
            {"roles": [{"name": "r", "trust_policy": policy(allow("sts:AssumeRole"))}]},
            "no Principal element",
        ),
        ({"s3_buckets": [{"name": "b", "sensitivity": "top-secret"}]}, "invalid sensitivity"),
        (
            {"s3_buckets": [{"name": "b", "bucket_policy": policy(allow("s3:GetObject"))}]},
            "no Principal element",
        ),
        (
            {"managed_policies": [{"arn": "arn:aws:s3:::nope", "document": policy(allow("s3:*"))}]},
            "not an IAM managed policy ARN",
        ),
        ({"managed_policies": [{"arn": "arn:aws:iam::aws:policy/X"}]}, "missing its document"),
        ({"coverage": {"services": {"iam": "sometimes"}}}, "invalid coverage status"),
        ({"users": [{"name": "a", "mfa_enabled": "yes"}]}, "must be true or false"),
        ({"users": [{"name": "a", "tags": {"k": 1}}]}, "string pairs"),
        ({"lambda_functions": [{"name": "f", "role_arn": "not-an-arn"}]}, "is not an ARN"),
        ({"users": "nope"}, "must be a list"),
    ],
)
def test_environment_parser_rejects_invalid_documents(overrides: dict, message: str) -> None:
    with pytest.raises(InputError, match=message):
        parse_environment(snapshot(**overrides), "t")


def test_environment_parser_warns_on_unknown_group_and_enforces_limits() -> None:
    warnings: list[str] = []
    parse_environment(snapshot(users=[{"name": "a", "groups": ["ghost"]}]), "t", warnings=warnings)
    assert any("unknown group" in w for w in warnings)
    with pytest.raises(LimitExceededError, match="principals exceed"):
        parse_environment(
            snapshot(users=[{"name": "a"}, {"name": "b"}]), "t", limits=Limits(max_principals=1)
        )
    with pytest.raises(LimitExceededError, match="resources exceed"):
        parse_environment(
            snapshot(s3_buckets=[{"name": "a"}, {"name": "b"}]), "t", limits=Limits(max_resources=1)
        )


# ---------------------------------------------------------------------------
# loader
# ---------------------------------------------------------------------------


def test_read_json_enforces_size_encoding_syntax_and_depth(tmp_path: Path) -> None:
    big = tmp_path / "big.json"
    big.write_bytes(b"[" + b"1," * 50 + b"1]")
    with pytest.raises(LimitExceededError, match="size limit"):
        read_json(big, Limits(max_input_bytes=10))
    bad_utf8 = tmp_path / "bad.json"
    bad_utf8.write_bytes(b'{"a": "\xff"}')
    with pytest.raises(InputError, match="not valid UTF-8"):
        read_json(bad_utf8)
    bad_json = tmp_path / "syntax.json"
    bad_json.write_text('{"a": }', encoding="utf-8")
    with pytest.raises(InputError, match="invalid JSON at line 1"):
        read_json(bad_json)
    deep = tmp_path / "deep.json"
    deep.write_text("[" * 80 + "]" * 80, encoding="utf-8")
    with pytest.raises(LimitExceededError, match="nesting"):
        read_json(deep, Limits(max_json_depth=20))
    with pytest.raises(InputError, match="not a file"):
        read_json(tmp_path / "missing.json")


def test_classify_document() -> None:
    assert classify_document(json.loads(SAMPLE_ENVIRONMENT.read_text())) == "environment"
    assert classify_document(policy(allow("s3:*"))) == "policy"
    assert classify_document({"foo": 1}) == "unknown"
    assert classify_document([]) == "unknown"


def test_load_input_environment_and_policy_file(tmp_json) -> None:
    loaded = load_input(SAMPLE_ENVIRONMENT)
    assert loaded.mode == "environment" and loaded.environment.account_id == ACCOUNT
    single = load_input(tmp_json(policy(allow("iam:*")), "admin.json"))
    assert single.mode == "policy-files"
    assert single.environment.account_id == POLICY_ONLY_ACCOUNT
    assert single.environment.roles[0].name == "admin"
    assert single.environment.coverage.status_of("s3") is CoverageStatus.MISSING


def test_load_input_policy_directory() -> None:
    loaded = load_input(POLICY_DIR)
    names = sorted(r.name for r in loaded.environment.roles)
    assert names == sorted(p.stem for p in POLICY_DIR.glob("*.json"))
    assert loaded.environment.metadata.synthetic


def test_load_input_errors(tmp_path: Path, tmp_json) -> None:
    with pytest.raises(InputError, match="no such file"):
        load_input(tmp_path / "missing.json")
    with pytest.raises(InputError, match="unrecognized document"):
        load_input(tmp_json({"hello": "world"}))
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(InputError, match=r"no \.json files"):
        load_input(empty)
    mixed = tmp_path / "mixed"
    mixed.mkdir()
    (mixed / "env.json").write_text(SAMPLE_ENVIRONMENT.read_text(), encoding="utf-8")
    with pytest.raises(InputError, match="analyze snapshot files individually"):
        load_input(mixed)
    (mixed / "env.json").write_text(json.dumps({"x": 1}), encoding="utf-8")
    with pytest.raises(InputError, match="not an IAM policy document"):
        load_input(mixed)
    with pytest.raises(LimitExceededError, match="policy files exceed"):
        load_input(POLICY_DIR, Limits(max_policy_files=1))


def test_policy_directory_sanitizes_and_deduplicates_names(tmp_path: Path) -> None:
    d = tmp_path / "pol"
    d.mkdir()
    (d / "weird name!.json").write_text(json.dumps(policy(allow("s3:*"))), encoding="utf-8")
    (d / "weird-name!.json").write_text(json.dumps(policy(deny("s3:*"))), encoding="utf-8")
    loaded = load_input(d)
    names = [r.name for r in loaded.environment.roles]
    assert len(set(names)) == 2 and all(" " not in n and "!" not in n for n in names)
