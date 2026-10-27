from __future__ import annotations

import pytest

from attackpath.models.arn import (
    account_of,
    iam_principal_kind,
    is_account_id,
    is_account_root,
    normalize_principal_arn,
    parse_arn,
)
from attackpath.tri import Tri, tri_all, tri_and, tri_any, tri_not, tri_or

T, F, U = Tri.TRUE, Tri.FALSE, Tri.UNKNOWN


@pytest.mark.parametrize(
    ("a", "b", "expected"),
    [(T, T, T), (T, F, F), (F, U, F), (T, U, U), (U, U, U), (F, F, F)],
)
def test_tri_and(a: Tri, b: Tri, expected: Tri) -> None:
    assert tri_and(a, b) is expected
    assert tri_and(b, a) is expected


@pytest.mark.parametrize(
    ("a", "b", "expected"),
    [(T, T, T), (T, F, T), (F, U, U), (T, U, T), (U, U, U), (F, F, F)],
)
def test_tri_or(a: Tri, b: Tri, expected: Tri) -> None:
    assert tri_or(a, b) is expected
    assert tri_or(b, a) is expected


def test_tri_not_and_identities() -> None:
    assert tri_not(T) is F and tri_not(F) is T and tri_not(U) is U
    assert tri_all([]) is T
    assert tri_any([]) is F
    assert Tri.of(True) is T and Tri.of(False) is F


def test_tri_refuses_boolean_context() -> None:
    with pytest.raises(TypeError):
        bool(Tri.UNKNOWN)


def test_parse_arn_components() -> None:
    arn = parse_arn("arn:aws:iam::111111111111:role/service/deploy")
    assert arn is not None
    assert (arn.service, arn.account, arn.resource) == (
        "iam",
        "111111111111",
        "role/service/deploy",
    )
    assert arn.resource_type == "role"
    assert arn.resource_name == "service/deploy"
    assert str(arn) == "arn:aws:iam::111111111111:role/service/deploy"


def test_parse_arn_rejects_non_arns() -> None:
    assert parse_arn("not an arn") is None
    assert parse_arn("arn:aws:s3:::bucket") is not None
    assert parse_arn("arn:aws:iam::aws:policy/AdministratorAccess") is not None


def test_account_helpers() -> None:
    assert is_account_id("123456789012")
    assert not is_account_id("12345678901")
    assert account_of("arn:aws:iam::123456789012:root") == "123456789012"
    assert account_of("123456789012") == "123456789012"
    assert account_of("arn:aws:s3:::bucket") is None
    assert is_account_root("arn:aws:iam::123456789012:root")
    assert is_account_root("123456789012")
    assert not is_account_root("arn:aws:iam::123456789012:user/alice")


def test_normalize_assumed_role_session() -> None:
    session = "arn:aws:sts::123456789012:assumed-role/deploy/session-1"
    assert normalize_principal_arn(session) == "arn:aws:iam::123456789012:role/deploy"
    assert (
        normalize_principal_arn("arn:aws:iam::123456789012:user/a")
        == "arn:aws:iam::123456789012:user/a"
    )
    assert iam_principal_kind("arn:aws:iam::123456789012:user/a") == "user"
    assert iam_principal_kind("arn:aws:iam::123456789012:root") == "root"
    assert iam_principal_kind("arn:aws:s3:::bucket") is None
