from __future__ import annotations

from attackpath.iam.principals import (
    IdentityKind,
    PrincipalIdentity,
    principal_matches,
    statement_principal_matches,
)
from attackpath.models.policy import Effect, PrincipalSpec, Statement
from attackpath.tri import Tri
from tests.conftest import ACCOUNT, OTHER_ACCOUNT, role_arn, user_arn

ALICE = PrincipalIdentity(user_arn("alice"), ACCOUNT, IdentityKind.USER)
DEPLOY = PrincipalIdentity(role_arn("deploy"), ACCOUNT, IdentityKind.ROLE)


def test_wildcard_matches_everyone_including_anonymous() -> None:
    assert principal_matches(PrincipalSpec(wildcard=True), ALICE) is Tri.TRUE
    assert principal_matches(PrincipalSpec(aws=("*",)), PrincipalIdentity.anonymous()) is Tri.TRUE


def test_account_root_matches_principals_of_that_account_only() -> None:
    spec = PrincipalSpec(aws=(f"arn:aws:iam::{ACCOUNT}:root",))
    assert principal_matches(spec, ALICE) is Tri.TRUE
    assert principal_matches(spec, PrincipalIdentity.account(ACCOUNT)) is Tri.TRUE
    assert (
        principal_matches(
            spec,
            PrincipalIdentity(user_arn("eve", OTHER_ACCOUNT), OTHER_ACCOUNT, IdentityKind.USER),
        )
        is Tri.FALSE
    )
    assert principal_matches(spec, PrincipalIdentity.anonymous()) is Tri.FALSE
    assert principal_matches(PrincipalSpec(aws=(ACCOUNT,)), ALICE) is Tri.TRUE


def test_specific_arn_and_session_normalization() -> None:
    spec = PrincipalSpec(aws=(role_arn("deploy"),))
    assert principal_matches(spec, DEPLOY) is Tri.TRUE
    session = PrincipalIdentity(
        f"arn:aws:sts::{ACCOUNT}:assumed-role/deploy/s1", ACCOUNT, IdentityKind.ROLE
    )
    assert principal_matches(spec, session) is Tri.TRUE
    assert principal_matches(spec, ALICE) is Tri.FALSE


def test_account_identity_against_specific_principal_is_unknown() -> None:
    spec = PrincipalSpec(aws=(role_arn("deploy"),))
    assert principal_matches(spec, PrincipalIdentity.account(ACCOUNT)) is Tri.UNKNOWN
    assert principal_matches(spec, PrincipalIdentity.account(OTHER_ACCOUNT)) is Tri.FALSE


def test_service_federated_and_canonical_user() -> None:
    assert (
        principal_matches(
            PrincipalSpec(service=("lambda.amazonaws.com",)),
            PrincipalIdentity.service("Lambda.amazonaws.com"),
        )
        is Tri.TRUE
    )
    assert principal_matches(PrincipalSpec(service=("lambda.amazonaws.com",)), ALICE) is Tri.FALSE
    fed = PrincipalIdentity(
        "arn:aws:iam::111111111111:saml-provider/idp", ACCOUNT, IdentityKind.FEDERATED
    )
    assert (
        principal_matches(
            PrincipalSpec(federated=("arn:aws:iam::111111111111:saml-provider/idp",)), fed
        )
        is Tri.TRUE
    )
    assert principal_matches(PrincipalSpec(canonical_user=("abc123",)), ALICE) is Tri.UNKNOWN


def test_statement_level_principal_and_not_principal() -> None:
    allow = Statement(
        index=0,
        effect=Effect.ALLOW,
        actions=("s3:GetObject",),
        principal=PrincipalSpec(aws=(user_arn("alice"),)),
    )
    assert statement_principal_matches(allow, ALICE) is Tri.TRUE
    not_principal = Statement(
        index=1,
        effect=Effect.DENY,
        actions=("s3:*",),
        not_principal=PrincipalSpec(aws=(user_arn("alice"),)),
    )
    assert statement_principal_matches(not_principal, ALICE) is Tri.FALSE
    assert statement_principal_matches(not_principal, DEPLOY) is Tri.TRUE
    assert (
        statement_principal_matches(
            Statement(index=2, effect=Effect.ALLOW, actions=("s3:*",)), ALICE
        )
        is Tri.FALSE
    )


def test_external_identity_factory() -> None:
    assert PrincipalIdentity.external("*").kind is IdentityKind.ANONYMOUS
    acct = PrincipalIdentity.external(f"arn:aws:iam::{OTHER_ACCOUNT}:root")
    assert acct.kind is IdentityKind.ACCOUNT and acct.account_id == OTHER_ACCOUNT
    role = PrincipalIdentity.external(role_arn("x", OTHER_ACCOUNT))
    assert role.kind is IdentityKind.ROLE and role.is_iam_identity
