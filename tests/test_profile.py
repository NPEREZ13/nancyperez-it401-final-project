from unittest.mock import Mock, patch

from sqlalchemy.exc import SQLAlchemyError

from models import ProfileDevice, UserThreat, db
from tests.test_database import THREAT, app


def google_session(client, owner="google-test-user"):
    with client.session_transaction() as session:
        session["user"] = {"sub": owner, "name": "Test Google User", "email": "test@example.com"}
        session["owner_sub"] = owner


def csrf(client, key="profile_csrf", path="/profile"):
    assert client.get(path).status_code == 200
    with client.session_transaction() as session:
        return session[key]


def test_profile_requires_google_login(app):
    client = app.test_client()
    assert client.get("/profile").headers["Location"].endswith("/login/google")
    with client.session_transaction() as session:
        session["workspace_owner_sub"] = "browser:" + "a" * 32
    assert client.get("/profile").headers["Location"].endswith("/login/google")


def test_profile_device_crud_checks_and_isolation(app):
    client = app.test_client()
    google_session(client)
    token = csrf(client)
    response = client.post("/profile/devices", data={"csrf_token": token, "name": "My laptop", "ip_address": "8.8.8.8"}, follow_redirects=True)
    assert response.status_code == 200
    assert b"My laptop" in response.data
    with app.app_context():
        row = db.session.scalar(db.select(ProfileDevice))
        assert row.owner_sub == "google-test-user"
        record_id = row.id
    result = {"risk_class": "low", "risk_level": "Low Risk", "score": 5, "recommendation": "Monitor", "findings": []}
    with patch("routes.profile.analyze_ip", return_value=result):
        checked = client.post(f"/profile/devices/{record_id}/check", data={"csrf_token": token}, follow_redirects=True)
    assert checked.status_code == 200 and b"Low Risk" in checked.data
    assert client.post(f"/profile/devices/{record_id}/edit", data={"csrf_token": token, "name": "Renamed", "ip_address": "8.8.8.8"}).status_code == 302
    with app.app_context():
        row = db.session.get(ProfileDevice, record_id)
        assert row.result_json == result and row.checked_at is not None
    assert client.post(f"/profile/devices/{record_id}/edit", data={"csrf_token": token, "name": "Renamed", "ip_address": "1.1.1.1"}).status_code == 302
    with app.app_context():
        row = db.session.get(ProfileDevice, record_id)
        assert row.result_json is None and row.checked_at is None
    stranger = app.test_client()
    google_session(stranger, "other-google-user")
    other_token = csrf(stranger)
    assert stranger.get(f"/profile?device={record_id}").status_code == 404
    for action in ("edit", "delete", "check"):
        assert stranger.post(f"/profile/devices/{record_id}/{action}", data={"csrf_token": other_token}).status_code == 404
    assert client.post(f"/profile/devices/{record_id}/delete", data={"csrf_token": token}).status_code == 302
    with app.app_context():
        assert db.session.get(ProfileDevice, record_id) is None


def test_profile_validation_csrf_and_database_failure(app):
    client = app.test_client()
    google_session(client)
    token = csrf(client)
    assert client.post("/profile/devices", data={"name": "test", "ip_address": "8.8.8.8"}).status_code == 400
    invalid = client.post("/profile/devices", data={"csrf_token": token, "name": "test", "ip_address": "192.168.1.1"}, follow_redirects=True)
    assert b"public IP" in invalid.data
    with app.app_context():
        with patch.object(db.session, "commit", side_effect=SQLAlchemyError("private-value")):
            failed = client.post("/profile/devices", data={"csrf_token": token, "name": "test", "ip_address": "8.8.8.8"})
        assert failed.status_code == 503 and b"private-value" not in failed.data
        assert db.session.scalar(db.select(db.func.count()).select_from(ProfileDevice)) == 0


def test_workspace_preserved_on_google_login_and_claim_is_scoped(app, monkeypatch):
    client = app.test_client()
    client.get("/threats/new")
    with client.session_transaction() as session:
        token = session["threat_form_token"]
    assert client.post("/threats/new", data={**THREAT, "csrf_token": token}).status_code == 303
    with client.session_transaction() as session:
        workspace = session["workspace_owner_sub"]
    with app.app_context():
        db.session.add(UserThreat(owner_sub="other-owner", **{**THREAT, "name": "Other private threat"}))
        db.session.commit()
    google = Mock()
    google.authorize_access_token.return_value = {"userinfo": {
        "sub": "verified-google", "name": "Google User", "email": "google@example.com", "email_verified": True,
    }}
    monkeypatch.setattr("routes.auth.google_client", lambda: google)
    callback = client.get("/auth/google/callback")
    assert callback.headers["Location"].endswith("/profile")
    with client.session_transaction() as session:
        assert session["workspace_owner_sub"] == workspace
    token = csrf(client)
    assert b"Move workspace records" in client.get("/profile").data
    assert client.post("/profile/import-workspace", data={"csrf_token": token, "owner_sub": "other-owner"}).status_code == 302
    with app.app_context():
        rows = db.session.scalars(db.select(UserThreat).order_by(UserThreat.id)).all()
        assert rows[0].owner_sub == "verified-google"
        assert rows[1].owner_sub == "other-owner"
    assert THREAT["name"].encode() in client.get("/my-threats").data
    assert client.post("/profile/import-workspace", data={"csrf_token": token}).status_code == 302


def test_account_threat_edit_delete_and_isolation(app):
    client = app.test_client()
    google_session(client)
    token = csrf(client, "records_csrf", "/my-threats")
    saved = client.post("/my-threats/new", data={**THREAT, "csrf_token": token}, follow_redirects=True)
    assert saved.status_code == 200 and THREAT["name"].encode() in saved.data
    with app.app_context():
        record_id = db.session.scalar(db.select(UserThreat.id))
    assert client.post(f"/my-threats/{record_id}/edit", data={**THREAT, "name": "Edited", "csrf_token": token}).status_code == 302
    stranger = app.test_client()
    google_session(stranger, "other-account")
    other_token = csrf(stranger, "records_csrf", "/my-threats")
    assert stranger.get(f"/my-threats/{record_id}/edit").status_code == 404
    assert stranger.post(f"/my-threats/{record_id}/delete", data={"csrf_token": other_token}).status_code == 404
    assert client.post(f"/my-threats/{record_id}/delete", data={"csrf_token": token}).status_code == 302
