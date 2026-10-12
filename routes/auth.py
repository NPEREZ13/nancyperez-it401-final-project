import secrets

from authlib.integrations.base_client.errors import OAuthError
from authlib.integrations.flask_client import OAuth
from joserfc.errors import JoseError
from flask import Blueprint, abort, current_app, flash, redirect, request, session, url_for
from requests.exceptions import RequestException


auth = Blueprint("auth", __name__)


def init_auth(app):
    oauth = OAuth(app)
    oauth.register(
        name="google",
        server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
        client_kwargs={"scope": "openid email profile"},
    )
    app.extensions["google_oauth"] = oauth
    app.register_blueprint(auth)


def google_client():
    return current_app.extensions["google_oauth"].create_client("google")


@auth.route("/login/google")
def login():
    config = current_app.config
    if not all(config.get(key) for key in ("GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET")):
        flash("Google sign-in is not configured. Set the Google credentials in .env.")
        return redirect(url_for("index"))
    if config.get("SECRET_KEY") == "dev" or not config.get("SECRET_KEY"):
        flash("Set a random SECRET_KEY in .env before signing in.")
        return redirect(url_for("index"))
    try:
        return google_client().authorize_redirect(
            url_for("auth.callback", _external=True)
        )
    except (OAuthError, RequestException):
        flash("Google sign-in is temporarily unavailable. Please try again.")
        return redirect(url_for("index"))


@auth.route("/auth/google/callback")
def callback():
    try:
        # Authlib validates OAuth state and the ID token, including its nonce.
        token = google_client().authorize_access_token()
        user = token.get("userinfo")
        if not user or not user.get("sub") or not user.get("email") or user.get("email_verified") is not True:
            flash("Google sign-in requires a verified email address.")
            return redirect(url_for("index"))
    except (OAuthError, JoseError, RequestException, ValueError):
        flash("Google sign-in could not be completed. Please try again.")
        return redirect(url_for("index"))

    session.clear()
    # Store only identity details, never OAuth tokens, in the signed cookie.
    session["user"] = {
        "sub": user["sub"],
        "email": user["email"],
        "name": user.get("name") or user["email"],
    }
    session["logout_csrf"] = secrets.token_urlsafe(32)
    return redirect(url_for("index"))


@auth.route("/logout", methods=["POST"])
def logout():
    expected = session.get("logout_csrf")
    supplied = request.form.get("csrf_token", "")
    if not expected or not secrets.compare_digest(expected, supplied):
        abort(400)
    session.clear()
    return redirect(url_for("index"))
