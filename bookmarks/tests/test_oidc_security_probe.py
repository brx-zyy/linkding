import pytest
from django.contrib.auth import get_user_model
from mozilla_django_oidc.auth import OIDCAuthenticationBackend


@pytest.mark.django_db
@pytest.mark.parametrize("email_verified", [False, None])
def test_oidc_claims_can_match_existing_account_without_verified_email(email_verified):
    """
    Regression probe: Linkding's default OIDC backend is configured to use
    mozilla-django-oidc. Check whether an OP-supplied email claim is accepted
    as an identity key even when email_verified is false or absent.
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

    backend = OIDCAuthenticationBackend()

    # If this passes, the backend considers these claims valid for the
    # configured "openid email profile" scopes.
    assert backend.verify_claims(claims) is True

    # The default backend then resolves the identity by case-insensitive
    # email, so the claims select the pre-existing local account.
    matches = backend.filter_users_by_claims(claims)
    assert list(matches.values_list("pk", flat=True)) == [victim.pk]
