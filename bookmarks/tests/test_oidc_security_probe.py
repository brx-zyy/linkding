import os
from html.parser import HTMLParser
from urllib.parse import parse_qs, urlparse

import pytest
import requests
from unittest.mock import patch
from django.contrib.auth import get_user_model
from django.test import Client, override_settings


class LoginFormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.action = None
        self.inputs = {}

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form" and attrs.get("id") == "kc-form-login":
            self.action = attrs.get("action")
        elif tag == "input":
            name = attrs.get("name")
            if name:
                self.inputs[name] = attrs.get("value", "")


@pytest.mark.django_db
@pytest.mark.skipif(
    not os.environ.get("OIDC_TEST_PROVIDER_URL"),
    reason="Requires the disposable Keycloak provider started by the Actions workflow",
)
@override_settings(
    ROOT_URLCONF="bookmarks.tests.test_oidc_security_probe",
    AUTHENTICATION_BACKENDS=[
        "django.contrib.auth.backends.ModelBackend",
        "mozilla_django_oidc.auth.OIDCAuthenticationBackend",
    ],
    OIDC_RP_CLIENT_ID="linkding-test-client",
    OIDC_RP_CLIENT_SECRET="linkding-probe-client-secret-32bytes",
    OIDC_RP_SIGN_ALGO="RS256",
    OIDC_RP_SCOPES="openid email profile",
    OIDC_USE_NONCE=True,
    OIDC_USE_PKCE=True,
    OIDC_VERIFY_SSL=True,
    OIDC_CREATE_USER=True,
    LOGIN_REDIRECT_URL="/",
)
def test_real_oidc_provider_unverified_email_can_take_over_existing_account():
    """
    Uses a real Keycloak OIDC authorization-code flow over HTTP.

    The OP has self-registration enabled and email verification disabled.
    Its attacker-controlled account is provisioned in the disposable realm
    with the victim's email and emailVerified=false. The test performs the
    browser login form, authorization-code exchange, signed ID-token
    validation, userinfo request, OIDC callback and Django session login.
    """
    from django.urls import include, path

    # The test module's URLConf must expose the real mozilla-django-oidc views.
    urlpatterns = [path("oidc/", include("mozilla_django_oidc.urls"))]
    globals()["urlpatterns"] = urlpatterns

    provider = os.environ["OIDC_TEST_PROVIDER_URL"].rstrip("/")
    realm = "linkding-probe"
    base = f"{provider}/realms/{realm}/protocol/openid-connect"

    with override_settings(
        OIDC_OP_AUTHORIZATION_ENDPOINT=f"{base}/auth",
        OIDC_OP_TOKEN_ENDPOINT=f"{base}/token",
        OIDC_OP_USER_ENDPOINT=f"{base}/userinfo",
        OIDC_OP_JWKS_ENDPOINT=f"{base}/certs",
    ):
        victim = get_user_model().objects.create_user(
            username="existing-victim",
            email="victim@example.test",
            password="not-used-for-oidc",
        )

        app_client = Client()
        start = app_client.get("/oidc/authenticate/")
        assert start.status_code == 302
        authorization_url = start["Location"]

        browser = requests.Session()
        login_page = browser.get(authorization_url, timeout=20)
        assert login_page.status_code == 200
        parser = LoginFormParser()
        parser.feed(login_page.text)
        assert parser.action, "Keycloak login form not found"

        form = dict(parser.inputs)
        form.update({
            "username": "attacker-controlled",
            "password": "attacker-password",
        })
        prepared_login = browser.prepare_request(
            requests.Request("POST", parser.action, data=form)
        )
        cookie_debug = {
            "cookie_header": prepared_login.headers.get("Cookie", ""),
            "cookie_paths": [
                (cookie.name, cookie.domain, cookie.path)
                for cookie in browser.cookies
            ],
        }
        cookie_header = "; ".join(
            f"{cookie.name}={cookie.value}" for cookie in browser.cookies
        )
        login_result = browser.post(
            parser.action,
            data=form,
            headers={"Cookie": cookie_header},
            allow_redirects=False,
            timeout=20,
        )
        assert login_result.status_code in (302, 303), (
            f"Keycloak did not complete login: HTTP {login_result.status_code}; "
            f"login_page={login_page.url}; action={parser.action}; "
            f"cookies={browser.cookies.get_dict()}; cookie_debug={cookie_debug}; "
            f"body={login_result.text[:1200]}"
        )

        callback_url = login_result.headers["Location"]
        callback = urlparse(callback_url)
        callback_params = parse_qs(callback.query)
        assert "code" in callback_params, callback_url

        state = callback_params["state"][0]
        assert state in app_client.session["oidc_states"]

        # Observe the real userinfo response without replacing the provider
        # request. This verifies the exact claim returned by Keycloak.
        real_get = requests.get
        observed_userinfo = {}

        def capture_userinfo(*args, **kwargs):
            response = real_get(*args, **kwargs)
            if args and args[0].rstrip("/").endswith("/userinfo"):
                observed_userinfo.update(response.json())
            return response

        with patch("requests.get", side_effect=capture_userinfo):
            callback_response = app_client.get(
                "/oidc/callback/",
                {"code": callback_params["code"][0], "state": state},
            )

        assert callback_response.status_code == 302
        assert observed_userinfo["email"] == "victim@example.test"
        assert observed_userinfo["email_verified"] is False
        assert observed_userinfo["sub"] != str(victim.pk)
        assert app_client.session["_auth_user_id"] == str(victim.pk)
        assert get_user_model().objects.get(pk=victim.pk).email == "victim@example.test"
