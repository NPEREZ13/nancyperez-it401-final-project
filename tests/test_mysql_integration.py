"""Opt-in live tests: only UUID-owned test rows are inserted or deleted; no DDL."""

import os
import uuid
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from pathlib import Path
from unittest.mock import patch

import pytest
from sqlalchemy.exc import SQLAlchemyError

from app import create_app
from models import ProfileDevice, UserThreat, db
from tests.test_database import DEVICE, THREAT

pytestmark = pytest.mark.skipif(
    os.getenv("RUN_MYSQL_INTEGRATION") != "1", reason="Live MySQL tests require explicit opt-in"
)


@pytest.fixture
def live_app():
    app = create_app(test_config={"TESTING": True})
    owner = "it401-integration-" + uuid.uuid4().hex
    other_owner = owner + "-other"
    yield app, owner, other_owner
    with app.app_context():
        try:
            for model in (ProfileDevice, UserThreat):
                db.session.execute(db.delete(model).where(model.owner_sub.in_([owner, other_owner])))
            db.session.commit()
        except Exception:
            db.session.rollback()
            raise
        finally:
            db.session.remove()
            db.engine.dispose()


def login(client, owner):
    # Simulates only the trusted login callback; no request-supplied ownership.
    with client.session_transaction() as session:
        session["owner_sub"] = owner


@pytest.mark.parametrize("kind,payload", [("threats", THREAT), ("devices", DEVICE)])
def test_live_mysql_crud_and_isolation(live_app, kind, payload):
    app, owner, other = live_app
    client = app.test_client()
    login(client, owner)
    base = f"/api/{kind}"
    created = client.post(base, json=payload)
    assert created.status_code == 201
    record_id = created.json["id"]
    url = f"{base}/{record_id}"
    assert client.get(url).json["name"] == payload["name"]
    assert [row["id"] for row in client.get(base).json["items"]] == [record_id]
    assert client.patch(url, json={"name": "Updated isolated test"}).status_code == 200
    assert client.get(url).json["name"] == "Updated isolated test"
    assert client.put(url, json=payload).status_code == 200
    if kind == "threats":
        assert payload["name"].encode() in client.get("/explore").data
    else:
        updated = client.patch(url, json={"result_json": {"test": True}, "checked_at": "2026-10-25T17:00:00Z"})
        assert updated.status_code == 200
        assert client.get(url).json["result_json"] == {"test": True}
    login(client, other)
    assert client.get(base).json["items"] == []
    for method, kwargs in (("get", {}), ("patch", {"json": {"name": "Forbidden"}}),
                           ("put", {"json": payload}), ("delete", {"json": {}})):
        assert getattr(client, method)(url, **kwargs).status_code == 404
    login(client, owner)
    assert client.delete(url, json={}).status_code == 204
    assert client.get(url).status_code == 404

    # Flush a real INSERT, force a failure, and verify rollback removed the row.
    def fail_after_flush():
        db.session.flush()
        raise SQLAlchemyError("simulated transaction failure")
    with app.app_context(), patch.object(db.session, "commit", side_effect=fail_after_flush):
        assert client.post(base, json=payload).status_code == 503
    assert client.get(base).json["items"] == []


def test_live_mysql_import_preview_and_idempotence(live_app):
    app, owner, _ = live_app
    source = Path(app.root_path) / "data/threats.json"
    original = source.read_bytes()
    runner = app.test_cli_runner()
    args = ["import-json", "--owner-sub", owner, "--file", str(source)]
    preview = runner.invoke(args=args)
    assert preview.exit_code == 0, preview.output
    client = app.test_client()
    login(client, owner)
    assert client.get("/api/threats").json["items"] == []
    applied = runner.invoke(args=args + ["--apply"])
    assert applied.exit_code == 0, applied.output
    repeat = runner.invoke(args=args + ["--apply"])
    assert repeat.exit_code == 0, repeat.output
    assert "Imported: 0; skipped duplicates: 4" in repeat.output
    assert len(client.get("/api/threats").json["items"]) == 4
    assert source.read_bytes() == original


def test_live_mysql_threat_form(live_app):
    app, owner, other = live_app
    client = app.test_client()
    login(client, owner)
    assert client.get("/threats/new").status_code == 200
    with client.session_transaction() as session:
        token = session["threat_form_token"]
    response = client.post("/threats/new", data={**THREAT, "csrf_token": token}, follow_redirects=True)
    assert response.status_code == 200
    assert b"Threat saved successfully" in response.data
    assert THREAT["name"].encode() in response.data
    with app.app_context():
        row = db.session.scalar(db.select(UserThreat).where(UserThreat.owner_sub == owner))
        assert row is not None and row.name == THREAT["name"]
    login(client, other)
    assert THREAT["name"].encode() not in client.get("/explore").data


def test_live_google_profile_and_account_threats(live_app):
    app, owner, other = live_app
    client = app.test_client()
    with client.session_transaction() as session:
        session["user"] = {"sub": owner, "name": "Isolated profile test", "email": "test@example.com"}
        session["owner_sub"] = owner
    page = client.get("/profile")
    assert page.status_code == 200
    with client.session_transaction() as session:
        token = session["profile_csrf"]
    assert client.post("/profile/devices", data={"csrf_token": token, "name": "Isolated profile device", "ip_address": "8.8.8.8"}).status_code == 302
    with app.app_context():
        row = db.session.scalar(db.select(ProfileDevice).where(ProfileDevice.owner_sub == owner))
        assert row is not None
        device_id = row.id
    result = {"risk_class": "low", "risk_level": "Low Risk", "score": 5, "recommendation": "Synthetic test", "findings": []}
    with patch("routes.profile.analyze_ip", return_value=result):
        checked = client.post(f"/profile/devices/{device_id}/check", data={"csrf_token": token}, follow_redirects=True)
    assert checked.status_code == 200 and b"Low Risk" in checked.data
    assert client.post(f"/profile/devices/{device_id}/edit", data={"csrf_token": token, "name": "Edited profile device", "ip_address": "1.1.1.1"}).status_code == 302
    with app.app_context():
        row = db.session.get(ProfileDevice, device_id)
        assert row.name == "Edited profile device" and row.result_json is None and row.checked_at is None
    assert client.post(f"/profile/devices/{device_id}/delete", data={"csrf_token": token}).status_code == 302
    assert client.get("/my-threats").status_code == 200
    with client.session_transaction() as session:
        token = session["records_csrf"]
    assert client.post("/my-threats/new", data={**THREAT, "csrf_token": token}).status_code == 302
    assert THREAT["name"].encode() in client.get("/my-threats").data
    with app.app_context():
        record_id = db.session.scalar(db.select(UserThreat.id).where(UserThreat.owner_sub == owner))
    assert client.post(f"/my-threats/{record_id}/edit", data={**THREAT, "name": "Edited account threat", "csrf_token": token}).status_code == 302
    assert b"Edited account threat" in client.get("/my-threats").data
    with client.session_transaction() as session:
        session["user"]["sub"] = other
        session["owner_sub"] = other
    assert client.get(f"/my-threats/{record_id}/edit").status_code == 404


def test_live_concurrent_duplicate_submission(live_app):
    app, owner, _ = live_app
    barrier = Barrier(2)

    def submit():
        with app.test_client() as client:
            with client.session_transaction() as session:
                session["user"] = {"sub": owner, "name": "Test", "email": "test@example.com"}
                session["records_csrf"] = "isolated-concurrency-test"
            barrier.wait(timeout=10)
            return client.post("/my-threats/new", data={**THREAT, "csrf_token": "isolated-concurrency-test"}).status_code

    with ThreadPoolExecutor(max_workers=2) as executor:
        responses = list(executor.map(lambda _: submit(), range(2)))
    assert responses == [302, 302]
    with app.app_context():
        rows = db.session.scalars(db.select(UserThreat).where(UserThreat.owner_sub == owner)).all()
        assert len(rows) == 1


def test_live_search_pagination(live_app):
    from urllib.parse import parse_qs, urlsplit
    from tests.test_search import PageElements

    app, owner, _ = live_app
    with app.app_context():
        db.session.add_all([UserThreat(owner_sub=owner, **{
            **THREAT, "name": f"Isolated pagecheck {index:02}",
        }) for index in range(22)])
        db.session.add(UserThreat(owner_sub=owner, **{**THREAT, "name": "pagecheck"}))
        db.session.commit()
    client = app.test_client()
    login(client, owner)
    response = client.get("/explore", query_string={
        "tab": "search", "q": " PageCheck ", "severity": "High", "sort": "relevance",
    })
    assert response.status_code == 200
    assert response.data.count(b'<article class="explore-card">') == 10
    assert b"Page 1 of 3" in response.data
    assert response.data.index(b"<h2>pagecheck</h2>") < response.data.index(b"<h2>Isolated pagecheck 00</h2>")
    for expected_page, expected_count in [(2, 10), (3, 3)]:
        links = PageElements(response.get_data(as_text=True)).elements
        link = next(attrs["href"] for tag, attrs in links if tag == "a" and attrs.get("rel") == "next")
        query = parse_qs(urlsplit(link).query)
        assert query["q"] == [" PageCheck "] and query["sort"] == ["relevance"] and query["severity"] == ["High"]
        response = client.get(link)
        assert response.status_code == 200
        assert response.data.count(b'<article class="explore-card">') == expected_count
        assert f"Page {expected_page} of 3".encode() in response.data
