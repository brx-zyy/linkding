import pytest
from django.contrib.auth import get_user_model
from django.test import override_settings
from mozilla_django_oidc.auth import OIDCAuthenticationBackend


@pytest.mark.django_db
@pytest.mark.parametrize("email_verified", [False, None])
@override_settings(
    OIDC_OP_AUTHORIZATION_ENDPOINT="https://idp.example.test/authorize",
    OIDC_OP_TOKEN_ENDPOINT="https://idp.example.test/token",
    OIDC_OP_USER_ENDPOINT="https://idp.example.test/userinfo",
    OIDC_OP_JWKS_ENDPOINT="https://idp.example.test/jwks",
    OIDC_RP_CLIENT_ID="linkding-test-client",
    OIDC_RP_CLIENT_SECRET="test-secret",
    OIDC_RP_SIGN_ALGO="RS256",
    OIDC_RP_SCOPES="openid email profile",
    OIDC_VERIFY_SSL=True,
    OIDC_USE_PKCE=True,
)
def test_oidc_claims_can_match_existing_account_without_verified_email(email_verified):
    """
    Probe whether Linkding's pinned OIDC backend accepts an email claim as an
    identity key when email_verified is false or absent.
    """
    victim = get_user_model().objects.create_user(
        username="existing-victim",
        email="victim@example.test",
        password="not-used-for-oidc",
    )

    claims = {
        "sub": "attacker-controlled-subject",
        "email": "victim@example.test",
    }
    if email_verified is not None:
        claims["email_verified"] = email_verified

    class StubUserInfoBackend(OIDCAuthenticationBackend):
        def get_userinfo(self, access_token, id_token, payload):
            return payload["userinfo"]

    backend = StubUserInfoBackend()

    # The configured email scope is accepted based on claim presence.
    assert backend.verify_claims(claims) is True

    # Exercise the actual default account-resolution method used after the
    # signed ID token has been verified and userinfo has been retrieved.
    authenticated_user = backend.get_or_create_user(
        "test-access-token",
        "test-id-token",
        {"userinfo": claims},
    )
    assert authenticated_user.pk == victim.pk
