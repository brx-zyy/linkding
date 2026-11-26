from urllib.parse import parse_qs, urlparse
from unittest.mock import patch

import jwt
import pytest
from django.contrib.auth import get_user_model
from django.test import Client, override_settings
from django.urls import include, path
from mozilla_django_oidc.auth import OIDCAuthenticationBackend


urlpatterns = [
    path("oidc/", include("mozilla_django_oidc.urls")),
]


@pytest.mark.django_db
@pytest.mark.parametrize("email_verified", [False, None])
@override_settings(
    ROOT_URLCONF="bookmarks.tests.test_oidc_security_probe",
    AUTHENTICATION_BACKENDS=[
        "django.contrib.auth.backends.ModelBackend",
        "mozilla_django_oidc.auth.OIDCAuthenticationBackend",
    ],
    OIDC_OP_AUTHORIZATION_ENDPOINT="https://idp.example.test/authorize",
    OIDC_OP_TOKEN_ENDPOINT="https://idp.example.test/token",
    OIDC_OP_USER_ENDPOINT="https://idp.example.test/userinfo",
    OIDC_OP_JWKS_ENDPOINT=None,
    OIDC_RP_CLIENT_ID="linkding-test-client",
    OIDC_RP_CLIENT_SECRET="test-client-secret",
    OIDC_RP_SIGN_ALGO="HS256",
    OIDC_RP_SCOPES="openid email profile",
    OIDC_USE_NONCE=True,
    OIDC_USE_PKCE=True,
    OIDC_CREATE_USER=True,
    LOGIN_REDIRECT_URL="/",
)
def test_oidc_callback_logs_in_as_existing_user_with_unverified_email(email_verified):
    """
    End-to-end Django callback probe.

    The authorization-code token exchange and userinfo HTTP response are
    simulated as if returned by the configured OP. The ID token is genuinely
    signed and nonce-checked by mozilla-django-oidc; only the OP network
    boundary is stubbed. The callback itself performs state validation,
    authentication, account matching, and Django session login.
    """
    victim = get_user_model().objects.create_user(
        username="existing-victim",
        email="victim@example.test",
        password="not-used-for-oidc",
    )

    client = Client()
    authorize_response = client.get("/oidc/authenticate/")
    assert authorize_response.status_code == 302

    authorize_params = parse_qs(urlparse(authorize_response["Location"]).query)
    state = authorize_params["state"][0]
    nonce = authorize_params["nonce"][0]
    assert state in client.session["oidc_states"]

    id_token = jwt.encode(
        {
            "sub": "attacker-controlled-subject",
            "aud": "linkding-test-client",
            "nonce": nonce,
        },
        "test-client-secret",
        algorithm="HS256",
    )

    provider_claims = {
        "sub": "attacker-controlled-subject",
        "email": "victim@example.test",
    }
    if email_verified is not None:
        provider_claims["email_verified"] = email_verified

    with (
        patch.object(
            OIDCAuthenticationBackend,
            "get_token",
            return_value={"id_token": id_token, "access_token": "mock-access-token"},
        ),
        patch.object(
            OIDCAuthenticationBackend,
            "get_userinfo",
            return_value=provider_claims,
        ),
    ):
        callback_response = client.get(
            "/oidc/callback/",
            {"code": "mock-authorization-code", "state": state},
        )

    assert callback_response.status_code == 302
    assert client.session["_auth_user_id"] == str(victim.pk)
    assert get_user_model().objects.get(pk=victim.pk).email == "victim@example.test"
