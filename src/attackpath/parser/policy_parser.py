"""Strict parser for IAM policy documents.

AWS accepts several syntactic variants (string-or-list fields, ``NotAction``,
``NotResource``, principal maps, nested condition maps). The parser validates each
one explicitly and rejects combinations AWS itself rejects (for example ``Action``
together with ``NotAction``) instead of guessing what the author meant.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from attackpath.exceptions import InputError
from attackpath.models.policy import Condition, Effect, PolicyDocument, PrincipalSpec, Statement

KNOWN_VERSIONS = frozenset({"2012-10-17", "2008-10-17"})
_STATEMENT_KEYS = frozenset(
    {
        "Sid",
        "Effect",
        "Action",
        "NotAction",
        "Resource",
        "NotResource",
        "Principal",
        "NotPrincipal",
        "Condition",
    }
)
_PRINCIPAL_KEYS = {
    "AWS": "aws",
    "Service": "service",
    "Federated": "federated",
    "CanonicalUser": "canonical_user",
}


def parse_policy_document(
    data: Any,
    source: str,
    *,
    warnings: list[str] | None = None,
) -> PolicyDocument:
    """Parse ``data`` (decoded JSON) into a :class:`PolicyDocument`.

    ``source`` is a human-readable label (for example ``inline:role/x:Name``) that is
    carried into evidence. Non-fatal observations are appended to ``warnings``.
    """
    if not isinstance(data, Mapping):
        raise InputError(f"{source}: policy document must be a JSON object, got {_typename(data)}")

    version = data.get("Version")
    if version is not None:
        if not isinstance(version, str):
            raise InputError(f"{source}: Version must be a string")
        if version not in KNOWN_VERSIONS and warnings is not None:
            warnings.append(f"{source}: unrecognized policy Version {version!r}")
    elif warnings is not None:
        warnings.append(
            f"{source}: policy has no Version; policy variables are treated literally by AWS"
        )

    policy_id = data.get("Id")
    if policy_id is not None and not isinstance(policy_id, str):
        raise InputError(f"{source}: Id must be a string")

    if "Statement" not in data:
        raise InputError(f"{source}: policy document is missing the Statement element")
    statements_raw = data["Statement"]
    if isinstance(statements_raw, Mapping):
        statements_raw = [statements_raw]
    if not isinstance(statements_raw, list):
        raise InputError(f"{source}: Statement must be an object or a list of objects")

    statements = tuple(
        _parse_statement(index, raw, source, warnings) for index, raw in enumerate(statements_raw)
    )
    return PolicyDocument(
        source=source,
        statements=statements,
        version=version,
        policy_id=policy_id,
        raw=dict(data),
    )


def _parse_statement(index: int, raw: Any, source: str, warnings: list[str] | None) -> Statement:
    where = f"{source} statement[{index}]"
    if not isinstance(raw, Mapping):
        raise InputError(f"{where}: statement must be a JSON object, got {_typename(raw)}")

    unknown = set(raw) - _STATEMENT_KEYS
    if unknown:
        raise InputError(f"{where}: unsupported statement element(s): {', '.join(sorted(unknown))}")

    effect_raw = raw.get("Effect")
    if effect_raw == "Allow":
        effect = Effect.ALLOW
    elif effect_raw == "Deny":
        effect = Effect.DENY
    else:
        raise InputError(f"{where}: Effect must be exactly 'Allow' or 'Deny', got {effect_raw!r}")

    sid = raw.get("Sid")
    if sid is not None and not isinstance(sid, str):
        raise InputError(f"{where}: Sid must be a string")

    if "Action" in raw and "NotAction" in raw:
        raise InputError(f"{where}: Action and NotAction cannot be combined")
    if "Action" not in raw and "NotAction" not in raw:
        raise InputError(f"{where}: statement needs an Action or NotAction element")
    if "Resource" in raw and "NotResource" in raw:
        raise InputError(f"{where}: Resource and NotResource cannot be combined")
    if "Principal" in raw and "NotPrincipal" in raw:
        raise InputError(f"{where}: Principal and NotPrincipal cannot be combined")

    actions = _string_or_list(raw.get("Action"), "Action", where)
    not_actions = _string_or_list(raw.get("NotAction"), "NotAction", where)
    resources = _string_or_list(raw.get("Resource"), "Resource", where)
    not_resources = _string_or_list(raw.get("NotResource"), "NotResource", where)
    if "Action" in raw and not actions:
        raise InputError(f"{where}: Action cannot be empty")
    if "NotAction" in raw and not not_actions:
        raise InputError(f"{where}: NotAction cannot be empty")

    principal = _parse_principal(raw["Principal"], where) if "Principal" in raw else None
    not_principal = _parse_principal(raw["NotPrincipal"], where) if "NotPrincipal" in raw else None
    if not_principal is not None and effect is Effect.ALLOW and warnings is not None:
        warnings.append(
            f"{where}: NotPrincipal with Allow is discouraged by AWS and hard to reason about"
        )

    conditions = _parse_conditions(raw.get("Condition"), where)

    return Statement(
        index=index,
        effect=effect,
        sid=sid,
        actions=actions,
        not_actions=not_actions,
        resources=resources,
        not_resources=not_resources,
        principal=principal,
        not_principal=not_principal,
        conditions=conditions,
        raw=dict(raw),
    )


def _string_or_list(value: Any, name: str, where: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, list):
        out: list[str] = []
        for item in value:
            if not isinstance(item, str):
                raise InputError(f"{where}: {name} entries must be strings, got {_typename(item)}")
            out.append(item)
        return tuple(out)
    raise InputError(f"{where}: {name} must be a string or a list of strings")


def _parse_principal(value: Any, where: str) -> PrincipalSpec:
    if value == "*":
        return PrincipalSpec(wildcard=True)
    if not isinstance(value, Mapping):
        raise InputError(f"{where}: Principal must be '*' or an object")
    fields: dict[str, tuple[str, ...]] = {}
    for key, raw in value.items():
        if key not in _PRINCIPAL_KEYS:
            raise InputError(f"{where}: unsupported principal type {key!r}")
        fields[_PRINCIPAL_KEYS[key]] = _string_or_list(raw, f"Principal.{key}", where)
    spec = PrincipalSpec(
        aws=fields.get("aws", ()),
        service=fields.get("service", ()),
        federated=fields.get("federated", ()),
        canonical_user=fields.get("canonical_user", ()),
    )
    if spec.is_empty:
        raise InputError(f"{where}: Principal element is empty")
    return spec


def _parse_conditions(value: Any, where: str) -> tuple[Condition, ...]:
    if value is None:
        return ()
    if not isinstance(value, Mapping):
        raise InputError(f"{where}: Condition must be an object")
    conditions: list[Condition] = []
    for operator, block in value.items():
        if not isinstance(operator, str) or not operator:
            raise InputError(f"{where}: condition operator names must be non-empty strings")
        if not isinstance(block, Mapping):
            raise InputError(f"{where}: Condition.{operator} must be an object of key/value pairs")
        for key, raw_values in block.items():
            if not isinstance(key, str) or not key:
                raise InputError(f"{where}: condition keys must be non-empty strings")
            conditions.append(
                Condition(operator=operator, key=key, values=_condition_values(raw_values, where))
            )
    return tuple(conditions)


def _condition_values(raw: Any, where: str) -> tuple[str, ...]:
    items = raw if isinstance(raw, list) else [raw]
    values: list[str] = []
    for item in items:
        if isinstance(item, bool):
            values.append("true" if item else "false")
        elif isinstance(item, int | float):
            values.append(str(item))
        elif isinstance(item, str):
            values.append(item)
        else:
            raise InputError(f"{where}: condition values must be strings, numbers or booleans")
    return tuple(values)


def _typename(value: Any) -> str:
    return type(value).__name__
