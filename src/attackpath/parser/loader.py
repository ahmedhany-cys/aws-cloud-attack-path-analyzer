"""Safe loading of input files.

Inputs are untrusted. Files are size-limited before they are read, decoded as
UTF-8 strictly, parsed with the standard ``json`` module only (no code execution,
no YAML), and checked for nesting depth so that a crafted document cannot exhaust
the interpreter stack or memory.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from attackpath.config import Limits
from attackpath.exceptions import InputError, LimitExceededError
from attackpath.models.environment import (
    Coverage,
    CoverageStatus,
    Environment,
    Metadata,
    Role,
    ServiceCoverage,
)
from attackpath.models.policy import PolicyDocument
from attackpath.parser.environment_parser import parse_environment
from attackpath.parser.policy_parser import parse_policy_document

POLICY_ONLY_ACCOUNT = "000000000000"
_NAME_SANITIZE_RE = re.compile(r"[^A-Za-z0-9+=,.@_-]")


@dataclass
class LoadedInput:
    environment: Environment
    mode: str  # "environment" or "policy-files"
    description: str
    warnings: list[str] = field(default_factory=list)


def read_json(path: Path, limits: Limits | None = None) -> Any:
    """Read and decode one JSON file within the configured safety limits."""
    limits = limits or Limits()
    if not path.is_file():
        raise InputError(f"{path}: not a file")
    size = path.stat().st_size
    if size > limits.max_input_bytes:
        raise LimitExceededError(
            f"{path}: {size} bytes exceeds the input size limit of {limits.max_input_bytes} bytes"
        )
    try:
        text = path.read_bytes().decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise InputError(
            f"{path}: file is not valid UTF-8 ({exc.reason} at byte {exc.start})"
        ) from exc
    try:
        data = json.loads(text)
    except RecursionError as exc:
        raise LimitExceededError(f"{path}: JSON nesting is too deep") from exc
    except json.JSONDecodeError as exc:
        raise InputError(
            f"{path}: invalid JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}"
        ) from exc
    _check_depth(data, limits.max_json_depth, str(path))
    return data


def classify_document(data: Any) -> str:
    """Return ``environment``, ``policy`` or ``unknown`` for a decoded document."""
    if not isinstance(data, Mapping):
        return "unknown"
    if "account_id" in data and ("users" in data or "roles" in data or "schema_version" in data):
        return "environment"
    if "Statement" in data:
        return "policy"
    return "unknown"


def load_input(path: Path, limits: Limits | None = None) -> LoadedInput:
    """Load an environment snapshot file or a directory of IAM policy documents."""
    limits = limits or Limits()
    if path.is_dir():
        return _load_policy_directory(path, limits)
    if not path.exists():
        raise InputError(f"{path}: no such file or directory")
    data = read_json(path, limits)
    kind = classify_document(data)
    warnings: list[str] = []
    if kind == "environment":
        env = parse_environment(data, path.name, limits=limits, warnings=warnings)
        return LoadedInput(
            environment=env,
            mode="environment",
            description=f"environment snapshot {path.name}",
            warnings=warnings,
        )
    if kind == "policy":
        doc = parse_policy_document(data, f"policy:{path.name}", warnings=warnings)
        env = _policy_only_environment([(path.stem, doc)], f"policy document {path.name}")
        return LoadedInput(
            environment=env,
            mode="policy-files",
            description=f"policy document {path.name}",
            warnings=warnings,
        )
    raise InputError(
        f"{path}: unrecognized document; expected an environment snapshot "
        "(with account_id/users/roles) or an IAM policy document (with Statement)"
    )


def _load_policy_directory(path: Path, limits: Limits) -> LoadedInput:
    files = sorted(p for p in path.iterdir() if p.is_file() and p.suffix.lower() == ".json")
    if not files:
        raise InputError(f"{path}: directory contains no .json files")
    if len(files) > limits.max_policy_files:
        raise LimitExceededError(
            f"{path}: {len(files)} policy files exceed the limit of {limits.max_policy_files}"
        )
    warnings: list[str] = []
    docs: list[tuple[str, PolicyDocument]] = []
    for file in files:
        data = read_json(file, limits)
        kind = classify_document(data)
        if kind == "environment":
            raise InputError(
                f"{file}: is an environment snapshot; analyze snapshot files individually, "
                "directories are reserved for standalone policy documents"
            )
        if kind != "policy":
            raise InputError(f"{file}: not an IAM policy document (missing Statement)")
        docs.append(
            (file.stem, parse_policy_document(data, f"policy:{file.name}", warnings=warnings))
        )
    env = _policy_only_environment(docs, f"{len(docs)} policy documents from {path.name}/")
    return LoadedInput(
        environment=env,
        mode="policy-files",
        description=f"{len(docs)} policy document(s) from {path}",
        warnings=warnings,
    )


def _policy_only_environment(docs: list[tuple[str, PolicyDocument]], name: str) -> Environment:
    """Wrap standalone policy documents in a synthetic environment.

    Each document becomes the inline policy of a synthetic role in a reserved account
    so that the statement-level checks can run. No trust relationships, resources or
    attachments are known, which the coverage section records explicitly.
    """
    roles: list[Role] = []
    seen: set[str] = set()
    for stem, doc in docs:
        base = _NAME_SANITIZE_RE.sub("-", stem)[:64] or "policy"
        candidate = base
        suffix = 2
        while candidate in seen:
            candidate = f"{base[:60]}-{suffix}"
            suffix += 1
        seen.add(candidate)
        arn = f"arn:aws:iam::{POLICY_ONLY_ACCOUNT}:role/{candidate}"
        roles.append(
            Role(
                name=candidate,
                arn=arn,
                account_id=POLICY_ONLY_ACCOUNT,
                trust_policy=PolicyDocument(source=f"trust:{arn}", statements=()),
                inline_policies={candidate: doc},
                description=f"synthetic principal carrying policy document {stem}",
            )
        )
    coverage = Coverage(
        services={
            "iam": ServiceCoverage(
                status=CoverageStatus.PARTIAL,
                notes=(
                    "policy-only mode: documents were analyzed as standalone policies; "
                    "trust relationships, attachments, boundaries and resources are unknown",
                ),
            ),
            "s3": ServiceCoverage(status=CoverageStatus.MISSING),
            "lambda": ServiceCoverage(status=CoverageStatus.MISSING),
        }
    )
    return Environment(
        account_id=POLICY_ONLY_ACCOUNT,
        metadata=Metadata(name=name, synthetic=True, source="policy-files"),
        coverage=coverage,
        roles=roles,
    )


def _check_depth(data: Any, max_depth: int, source: str) -> None:
    stack: list[tuple[Any, int]] = [(data, 1)]
    while stack:
        node, depth = stack.pop()
        if depth > max_depth:
            raise LimitExceededError(f"{source}: JSON nesting deeper than {max_depth} levels")
        if isinstance(node, Mapping):
            stack.extend((v, depth + 1) for v in node.values())
        elif isinstance(node, list):
            stack.extend((v, depth + 1) for v in node)
