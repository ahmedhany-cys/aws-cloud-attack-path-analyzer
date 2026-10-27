"""Amazon Resource Name parsing helpers."""

from __future__ import annotations

import re
from dataclasses import dataclass

ACCOUNT_ID_RE = re.compile(r"^\d{12}$")
_ARN_RE = re.compile(
    r"^arn:(?P<partition>[a-z][a-z-]*):(?P<service>[a-z0-9-]*):(?P<region>[a-z0-9-]*):(?P<account>\d{12}|aws|)?:(?P<resource>.+)$"
)


@dataclass(frozen=True)
class Arn:
    partition: str
    service: str
    region: str
    account: str
    resource: str

    @property
    def resource_type(self) -> str | None:
        """The ``type`` part of ``type/name`` or ``type:name`` resources, if any."""
        for sep in ("/", ":"):
            if sep in self.resource:
                return self.resource.split(sep, 1)[0]
        return None

    @property
    def resource_name(self) -> str:
        for sep in ("/", ":"):
            if sep in self.resource:
                return self.resource.split(sep, 1)[1]
        return self.resource

    def __str__(self) -> str:
        return f"arn:{self.partition}:{self.service}:{self.region}:{self.account}:{self.resource}"


def parse_arn(value: str) -> Arn | None:
    """Parse ``value`` into an :class:`Arn`, returning ``None`` when it is not an ARN."""
    match = _ARN_RE.match(value)
    if match is None:
        return None
    return Arn(
        partition=match.group("partition"),
        service=match.group("service"),
        region=match.group("region"),
        account=match.group("account") or "",
        resource=match.group("resource"),
    )


def is_account_id(value: str) -> bool:
    return ACCOUNT_ID_RE.match(value) is not None


def account_of(value: str) -> str | None:
    """Return the account id referenced by an ARN or bare account id."""
    if is_account_id(value):
        return value
    arn = parse_arn(value)
    if arn is None or not is_account_id(arn.account):
        return None
    return arn.account


def is_account_root(value: str) -> bool:
    """True for ``arn:aws:iam::123456789012:root`` or a bare 12-digit account id."""
    if is_account_id(value):
        return True
    arn = parse_arn(value)
    return arn is not None and arn.service == "iam" and arn.resource == "root"


def normalize_principal_arn(value: str) -> str:
    """Map session ARNs onto their long-lived identity.

    ``arn:aws:sts::123456789012:assumed-role/Name/session`` becomes
    ``arn:aws:iam::123456789012:role/Name`` so that trust and resource policies that
    name the role match sessions created from it.
    """
    arn = parse_arn(value)
    if arn is None:
        return value
    if arn.service == "sts" and arn.resource.startswith("assumed-role/"):
        parts = arn.resource.split("/")
        if len(parts) >= 2:
            return f"arn:{arn.partition}:iam::{arn.account}:role/{parts[1]}"
    return value


def iam_principal_kind(value: str) -> str | None:
    """Return ``user``, ``role`` or ``root`` for IAM principal ARNs."""
    arn = parse_arn(value)
    if arn is None or arn.service != "iam":
        return None
    if arn.resource == "root":
        return "root"
    rtype = arn.resource_type
    if rtype in {"user", "role"}:
        return rtype
    return None
