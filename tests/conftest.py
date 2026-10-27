"""Shared fixtures and snapshot builders for the test suite."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from attackpath.models.environment import Environment
from attackpath.parser.environment_parser import parse_environment

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "fixtures"
SAMPLE_ENVIRONMENT = FIXTURES / "sample_environment.json"
POLICY_DIR = FIXTURES / "iam_policies"
SCENARIO_DIR = FIXTURES / "scenarios"
PACKAGE_SCENARIO_DIR = ROOT / "src" / "attackpath" / "data" / "scenarios"

ACCOUNT = "111111111111"
OTHER_ACCOUNT = "222222222222"


def allow(actions: Any, resources: Any = "*", **extra: Any) -> dict[str, Any]:
    statement: dict[str, Any] = {"Effect": "Allow", "Action": actions, "Resource": resources}
    statement.update(extra)
    return statement


def deny(actions: Any, resources: Any = "*", **extra: Any) -> dict[str, Any]:
    statement: dict[str, Any] = {"Effect": "Deny", "Action": actions, "Resource": resources}
    statement.update(extra)
    return statement


def policy(*statements: dict[str, Any]) -> dict[str, Any]:
    return {"Version": "2012-10-17", "Statement": list(statements)}


def trust(principal: Any, **extra: Any) -> dict[str, Any]:
    statement: dict[str, Any] = {
        "Effect": "Allow",
        "Principal": principal,
        "Action": "sts:AssumeRole",
    }
    statement.update(extra)
    return {"Version": "2012-10-17", "Statement": [statement]}


def account_root(account: str = ACCOUNT) -> dict[str, str]:
    return {"AWS": f"arn:aws:iam::{account}:root"}


def snapshot(**sections: Any) -> dict[str, Any]:
    """A minimal valid snapshot document with the given sections overridden."""
    base: dict[str, Any] = {
        "schema_version": "1.0",
        "metadata": {"name": "test", "synthetic": True},
        "account_id": ACCOUNT,
        "coverage": {"services": {"iam": "complete", "s3": "complete", "lambda": "complete"}},
        "users": [],
        "groups": [],
        "roles": [],
        "managed_policies": [],
        "s3_buckets": [],
        "lambda_functions": [],
        "external_principals": [],
    }
    base.update(sections)
    return base


def env_from(**sections: Any) -> Environment:
    return parse_environment(snapshot(**sections), "test")


def user_arn(name: str, account: str = ACCOUNT) -> str:
    return f"arn:aws:iam::{account}:user/{name}"


def role_arn(name: str, account: str = ACCOUNT) -> str:
    return f"arn:aws:iam::{account}:role/{name}"


@pytest.fixture(scope="session")
def sample_document() -> dict[str, Any]:
    return json.loads(SAMPLE_ENVIRONMENT.read_text("utf-8"))


@pytest.fixture
def sample_env(sample_document: dict[str, Any]) -> Environment:
    return parse_environment(copy.deepcopy(sample_document), "sample_environment.json")


@pytest.fixture
def tmp_json(tmp_path: Path):
    """Write a JSON document to a temporary file and return its path."""

    def _write(data: Any, name: str = "input.json") -> Path:
        path = tmp_path / name
        path.write_text(json.dumps(data), encoding="utf-8")
        return path

    return _write
