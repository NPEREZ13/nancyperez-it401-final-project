from unittest.mock import Mock

import pytest
from authlib.integrations.base_client.errors import OAuthError
from flask import redirect
from joserfc.errors import JoseError

from app import create_app


@pytest.fixture
def setup(monkeypatch):
    app = create_app("development")
    app.config.update(TESTING=True, SECRET_KEY="test-secret", GOOGLE_CLIENT_ID="test-id",
                      GOOGLE_CLIENT_SECRET="test-client-secret")
    google = Mock()
    monkeypatch.setattr("routes.auth.google_client", lambda: google)
    return app.test_client(), google


def test_login_redirect(setup):
    client, google = setup
    google.authorize_redirect.return_value = redirect("https://accounts.google.com/")
    response = client.get("/login/google", base_url="http://127.0.0.1:5000")
    assert response.status_code == 302
    google.authorize_redirect.assert_called_once_with(
        "http://127.0.0.1:5000/auth/google/callback"
    )


def test_missing_configuration(setup):
    client, google = setup
    client.application.config["GOOGLE_CLIENT_ID"] = None
    assert client.get("/login/google").status_code == 302
    google.authorize_redirect.assert_not_called()


def test_insecure_session_secret(setup):
    client, google = setup
    client.application.config["SECRET_KEY"] = "dev"
    assert client.get("/login/google").status_code == 302
    google.authorize_redirect.assert_not_called()


def test_successful_login_and_logout(setup):
    client, google = setup
    google.authorize_access_token.return_value = {
        "access_token": "must-not-be-stored",
        "userinfo": {"sub": "123", "email": "user@example.com", "name": "Test User",
                     "email_verified": True},
    }
    with client.session_transaction() as session:
        session["old_data"] = "discard"
    assert client.get("/auth/google/callback").status_code == 302
    with client.session_transaction() as session:
        assert session["user"]["sub"] == "123"
        assert "access_token" not in session
        assert "old_data" not in session
        csrf = session["logout_csrf"]
    page = client.get("/about")
    assert b"Test User" in page.data
    assert b"Sign out" in page.data
    assert client.get("/logout").status_code == 405
    assert client.post("/logout").status_code == 400
    assert client.post("/logout", data={"csrf_token": csrf}).status_code == 302
    with client.session_transaction() as session:
        assert "user" not in session
    assert b"Sign in with Google" in client.get("/about").data


@pytest.mark.parametrize("userinfo", [None, {}, {"sub": "123", "email": "a@b.com", "email_verified": False}])
def test_invalid_identity(setup, userinfo):
    client, google = setup
    google.authorize_access_token.return_value = {"userinfo": userinfo}
    assert client.get("/auth/google/callback").status_code == 302
    with client.session_transaction() as session:
        assert "user" not in session


@pytest.mark.parametrize("error", [OAuthError(error="access_denied"), JoseError()])
def test_provider_error(setup, error):
    client, google = setup
    google.authorize_access_token.side_effect = error
    assert client.get("/auth/google/callback?error=access_denied").status_code == 302
    with client.session_transaction() as session:
        assert "user" not in session


def test_callback_without_oauth_state():
    app = create_app("development")
    app.config.update(TESTING=True, SECRET_KEY="test-secret")
    client = app.test_client()
    assert client.get("/auth/google/callback?code=fake&state=invalid").status_code == 302
    with client.session_transaction() as session:
        assert "user" not in session
