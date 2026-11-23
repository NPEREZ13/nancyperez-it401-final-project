from unittest.mock import patch
import pytest

from sqlalchemy.exc import SQLAlchemyError

from models import UserThreat, db
from tests.test_database import THREAT, app, client
from services.mitigation import MITIGATION_OPTIONS
from services.threat_names import THREAT_NAME_OPTIONS


def form_token(client):
    assert client.get("/threats/new").status_code == 200
    with client.session_transaction() as session:
        return session["threat_form_token"]


def test_form_saves_to_existing_account_and_redirects(app, client):
    token = form_token(client)
    response = client.post("/threats/new", data={**THREAT, "csrf_token": token})
    assert response.status_code == 303
    assert response.headers["Location"].endswith("/explore")
    page = client.get("/explore")
    assert b"Threat saved successfully" in page.data
    assert THREAT["name"].encode() in page.data
    with app.app_context():
        row = db.session.scalar(db.select(UserThreat))
        assert row.owner_sub == "Owner-A"
        assert row.to_dict()["name"] == THREAT["name"]
    # Replaying the old form cannot duplicate the record.
    assert client.post("/threats/new", data={**THREAT, "csrf_token": token}).status_code == 400


def test_browser_workspace_is_private_and_persists_across_requests(app):
    browser = app.test_client()
    token = form_token(browser)
    response = browser.post("/threats/new", data={**THREAT, "csrf_token": token}, follow_redirects=True)
    assert response.status_code == 200
    assert THREAT["name"].encode() in response.data
    with browser.session_transaction() as session:
        owner = session["workspace_owner_sub"]
    assert owner.startswith("browser:")
    with app.app_context():
        row = db.session.scalar(db.select(UserThreat))
        assert row.owner_sub == owner
        record_id = row.id
    assert browser.get("/api/threats").json["items"][0]["id"] == record_id
    stranger = app.test_client()
    assert THREAT["name"].encode() not in stranger.get("/explore").data
    assert stranger.get(f"/api/threats/{record_id}").status_code == 401
    with browser.session_transaction() as session:
        session["owner_sub"] = "verified-account"
    assert THREAT["name"].encode() not in browser.get("/explore").data


def test_form_validation_and_csrf_preserve_entries_without_inserting(app, client):
    token = form_token(client)
    for data in ({**THREAT}, {**THREAT, "csrf_token": "invalid"},
                 {**THREAT, "csrf_token": "\N{SNOWMAN}"},
                 {**THREAT, "csrf_token": token, "owner_sub": "other"},
                 {**THREAT, "csrf_token": token, "severity": "Invalid"}):
        response = client.post("/threats/new", data=data)
        assert response.status_code == 400
        assert THREAT["name"].encode() in response.data
    with app.app_context():
        assert db.session.scalar(db.select(db.func.count()).select_from(UserThreat)) == 0


def test_form_database_failure_rolls_back_and_preserves_entries(app, client):
    token = form_token(client)
    with app.app_context():
        with patch.object(db.session, "commit", side_effect=SQLAlchemyError("private-value")):
            response = client.post("/threats/new", data={**THREAT, "csrf_token": token})
        assert response.status_code == 503
        assert THREAT["name"].encode() in response.data
        assert b"private-value" not in response.data
        assert db.session.scalar(db.select(db.func.count()).select_from(UserThreat)) == 0
    assert client.post("/threats/new", data={**THREAT, "csrf_token": token}).status_code == 303


@pytest.mark.parametrize("path,token_key", [("/threats/new", "threat_form_token"), ("/my-threats/new", "records_csrf")])
def test_mitigation_options_and_other_save_the_chosen_text(app, path, token_key):
    client = app.test_client()
    with client.session_transaction() as session:
        session["user"] = {"sub": "mitigation-test", "name": "Test", "email": "test@example.com"}
    for choice, custom, expected in [
        (MITIGATION_OPTIONS[0], "Ignored old draft", MITIGATION_OPTIONS[0]),
        ("other", "Contact the incident response team.", "Contact the incident response team."),
    ]:
        page = client.get(path)
        assert page.status_code == 200 and b'Other' in page.data
        with client.session_transaction() as session:
            token = session[token_key]
        response = client.post(path, data={**THREAT, "csrf_token": token,
                                          "mitigation_choice": choice, "mitigation": custom})
        assert response.status_code in (302, 303)
        with app.app_context():
            row = db.session.scalar(db.select(UserThreat).order_by(UserThreat.id.desc()))
            assert row.mitigation == expected
            if choice == "other":
                edit = client.get(f"/my-threats/{row.id}/edit")
                assert b'value="other" selected' in edit.data
                assert custom.encode() in edit.data


@pytest.mark.parametrize("choice", ["", "not-a-preset", "other"])
def test_empty_or_invalid_mitigation_selection_is_rejected(app, client, choice):
    token = form_token(client)
    response = client.post("/threats/new", data={**THREAT, "csrf_token": token,
                                               "mitigation_choice": choice, "mitigation": ""})
    assert response.status_code == 400
    with app.app_context():
        assert db.session.scalar(db.select(db.func.count()).select_from(UserThreat)) == 0


@pytest.mark.parametrize("path,token_key", [("/threats/new", "threat_form_token"), ("/my-threats/new", "records_csrf")])
def test_threat_name_choices_and_custom_name_persist(app, path, token_key):
    client = app.test_client()
    with client.session_transaction() as session:
        session["user"] = {"sub": "name-test", "name": "Test", "email": "test@example.com"}
    for choice, custom, expected in [
        (THREAT_NAME_OPTIONS[0], "Ignored draft", THREAT_NAME_OPTIONS[0]),
        ("other", "Payroll phishing incident", "Payroll phishing incident"),
    ]:
        page = client.get(path)
        assert b'name="name_choice"' in page.data
        with client.session_transaction() as session:
            token = session[token_key]
        response = client.post(path, data={**THREAT, "csrf_token": token, "name_choice": choice, "name": custom})
        assert response.status_code in (302, 303)
        with app.app_context():
            row = db.session.scalar(db.select(UserThreat).order_by(UserThreat.id.desc()))
            assert row.name == expected
            record_id = row.id
        edited = client.get(f"/my-threats/{record_id}/edit")
        assert expected.encode() in edited.data
        if choice == "other":
            assert b'value="other" selected' in edited.data


@pytest.mark.parametrize("choice", ["", "unknown", "other"])
def test_invalid_threat_name_choices_do_not_create_records(app, client, choice):
    token = form_token(client)
    response = client.post("/threats/new", data={**THREAT, "csrf_token": token, "name_choice": choice, "name": ""})
    assert response.status_code == 400
    with app.app_context():
        assert db.session.scalar(db.select(db.func.count()).select_from(UserThreat)) == 0


def test_repeated_account_submission_inserts_only_once(app):
    client = app.test_client()
    with client.session_transaction() as session:
        session["user"] = {"sub": "duplicate-test", "name": "Test", "email": "test@example.com"}
    client.get("/my-threats/new")
    with client.session_transaction() as session:
        token = session["records_csrf"]
    payload = {**THREAT, "csrf_token": token}
    assert client.post("/my-threats/new", data=payload).status_code == 302
    repeated = client.post("/my-threats/new", data=payload, follow_redirects=True)
    assert b"No duplicate was added" in repeated.data
    with app.app_context():
        assert db.session.scalar(db.select(db.func.count()).select_from(UserThreat)) == 1
    # The same data from a freshly opened form or the API is also idempotent.
    assert client.post("/api/threats", json=THREAT).status_code == 200
    # A different incident description remains a separate record.
    assert client.post("/api/threats", json={**THREAT, "description": "A separate incident"}).status_code == 201
    with client.session_transaction() as session:
        session["user"] = {**session["user"], "sub": "another-account"}
    assert client.post("/api/threats", json=THREAT).status_code == 201
    with app.app_context():
        assert db.session.scalar(db.select(db.func.count()).select_from(UserThreat)) == 3
