import json
from pathlib import Path
from unittest.mock import patch

import pytest
from sqlalchemy.exc import SQLAlchemyError

from app import create_app
from models import UserThreat, db
from services.records import PUBLIC_DEMO_OWNER


THREAT = {
    "name": "Isolated test threat", "severity": "High", "category": "Testing",
    "description": "Synthetic test record", "mitigation": "Delete after testing",
}
DEVICE = {"name": "Isolated test device", "ip_address": "192.0.2.1"}


@pytest.fixture
def app():
    application = create_app(test_config={
        "TESTING": True, "SECRET_KEY": "test-only-secret",
        "SQLALCHEMY_DATABASE_URI": "sqlite://",
    })
    with application.app_context():
        db.create_all()
    yield application
    with application.app_context():
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    client = app.test_client()
    with client.session_transaction() as session:
        session["owner_sub"] = "Owner-A"
    return client


@pytest.mark.parametrize("kind,payload", [("threats", THREAT), ("devices", DEVICE)])
def test_crud_and_owner_isolation(app, client, kind, payload):
    base = f"/api/{kind}"
    created = client.post(base, json=payload)
    assert created.status_code == 201
    record_id = created.json["id"]
    url = f"{base}/{record_id}"
    assert client.get(url).json["name"] == payload["name"]
    assert any(item["id"] == record_id for item in client.get(base).json["items"])
    assert client.patch(url, json={"name": "Updated"}).json["name"] == "Updated"
    assert client.put(url, json=payload).status_code == 200

    with client.session_transaction() as session:
        session["owner_sub"] = "owner-a"  # Case-sensitive identity.
    assert client.get(base).json == {"items": []}
    for method, kwargs in (("get", {}), ("patch", {"json": {"name": "Stolen"}}),
                           ("put", {"json": payload}), ("delete", {"json": {}})):
        assert getattr(client, method)(url, **kwargs).status_code == 404
    assert b"Isolated test threat" not in client.get("/explore").data

    with client.session_transaction() as session:
        session["owner_sub"] = "Owner-A"
    assert client.delete(url, json={}).status_code == 204
    assert client.get(url).status_code == 404


@pytest.mark.parametrize("kind,payload", [
    ("threats", {**THREAT, "owner_sub": "other"}),
    ("threats", {**THREAT, "name": " "}),
    ("threats", {**THREAT, "severity": "invalid"}),
    ("threats", {**THREAT, "name": "x" * 121}),
    ("threats", {**THREAT, "description": "😀" * 17000}),
    ("threats", {"name": "missing fields"}),
    ("threats", []),
    ("devices", {**DEVICE, "ip_address": "999.1.1.1"}),
    ("devices", {**DEVICE, "created_at": "2026-01-01"}),
    ("devices", {**DEVICE, "checked_at": "invalid"}),
    ("devices", {**DEVICE, "result_json": float("nan")}),
])
def test_invalid_inputs_do_not_insert(app, client, kind, payload):
    response = client.post(f"/api/{kind}", data=json.dumps(payload, ensure_ascii=False), content_type="application/json")
    assert response.status_code == 400
    assert client.get(f"/api/{kind}").json == {"items": []}


def test_device_json_null_and_utc_datetime(client):
    response = client.post("/api/devices", json={
        **DEVICE, "ip_address": "2001:db8::1", "result_json": {"safe": True},
        "checked_at": "2026-10-25T10:00:00-07:00",
    })
    assert response.status_code == 201
    assert response.json["checked_at"] == "2026-10-25T17:00:00"
    assert response.json["created_at"]
    url = f'/api/devices/{response.json["id"]}'
    response = client.patch(url, json={"result_json": None, "checked_at": None})
    assert response.json["result_json"] is None
    assert response.json["checked_at"] is None


def test_anonymous_access_and_request_owner_spoofing(app):
    client = app.test_client()
    assert client.get("/explore").status_code == 200
    assert b"private workspace" in client.get("/explore").data
    assert client.get("/api/threats?owner_sub=Owner-A", headers={"X-Owner-Sub": "Owner-A"}).status_code == 401
    assert client.post("/api/devices", json=DEVICE).status_code == 401


def test_writes_require_json_and_reject_cross_site(client):
    assert client.post("/api/threats", data=THREAT).status_code == 415
    assert client.post("/api/threats", json=THREAT, headers={"Sec-Fetch-Site": "cross-site"}).status_code == 403


def test_failed_commit_rolls_back_and_hides_exception(app, client):
    with app.app_context():
        with patch.object(db.session, "commit", side_effect=SQLAlchemyError("private-value")):
            with patch.object(db.session, "rollback", wraps=db.session.rollback) as rollback:
                response = client.post("/api/threats", json=THREAT)
                assert response.status_code == 503
                assert b"private-value" not in response.data
                rollback.assert_called_once()
        assert db.session.scalar(db.select(db.func.count()).select_from(UserThreat)) == 0
    assert client.post("/api/threats", json=THREAT).status_code == 201


def test_import_preview_apply_and_repeat(app):
    runner = app.test_cli_runner()
    source = str(Path(app.root_path) / "data/threats.json")
    before = Path(source).read_bytes()
    args = ["import-json", "--owner-sub", "migration-test", "--file", source]
    assert runner.invoke(args=args).exit_code == 0
    with app.app_context():
        assert db.session.scalar(db.select(db.func.count()).select_from(UserThreat)) == 0
    first = runner.invoke(args=args + ["--apply"])
    assert first.exit_code == 0, first.output
    repeat = runner.invoke(args=args + ["--apply"])
    assert repeat.exit_code == 0, repeat.output
    assert "Imported: 0; skipped duplicates: 4" in repeat.output
    with app.app_context():
        assert db.session.scalar(db.select(db.func.count()).select_from(UserThreat)) == 4
        record = db.session.scalar(db.select(UserThreat))
        assert "Primary target:" in record.description
        assert "Legacy ID:" in record.description
    assert Path(source).read_bytes() == before


def test_import_invalid_file_is_atomic(app, tmp_path):
    source = tmp_path / "invalid.json"
    source.write_text(json.dumps([THREAT, {**THREAT, "severity": "invalid"}]))
    result = app.test_cli_runner().invoke(args=[
        "import-json", "--owner-sub", "migration-test", "--file", str(source), "--apply",
    ])
    assert result.exit_code != 0
    with app.app_context():
        assert db.session.scalar(db.select(db.func.count()).select_from(UserThreat)) == 0


def test_public_population_rerun_display_and_private_isolation(app):
    runner = app.test_cli_runner()
    source = str(Path(app.root_path) / "data/threats.json")
    args = ["import-json", "--public-demo", "--file", source]
    assert runner.invoke(args=args).exit_code == 0
    anonymous = app.test_client()
    assert b"BlackCat Ransomware" not in anonymous.get("/explore").data
    first = runner.invoke(args=args + ["--apply"])
    assert first.exit_code == 0, first.output
    assert "Imported: 4" in first.output
    repeat = runner.invoke(args=args + ["--apply"])
    assert repeat.exit_code == 0, repeat.output
    assert "Imported: 0; skipped duplicates: 4" in repeat.output
    response = anonymous.get("/explore")
    assert response.status_code == 200
    assert b"BlackCat Ransomware" in response.data
    assert b"Migrated demo intelligence" in response.data
    filtered = anonymous.get("/explore?severity=High")
    assert b"Cloud Credential Phishing" in filtered.data
    assert b"BlackCat Ransomware" not in filtered.data
    assert anonymous.get("/api/threats").status_code == 401

    private = app.test_client()
    with private.session_transaction() as session:
        session["owner_sub"] = "private-user"
    assert private.post("/api/threats", json=THREAT).status_code == 201
    assert b"Isolated test threat" in private.get("/explore").data
    assert b"BlackCat Ransomware" not in private.get("/explore").data
    assert b"Isolated test threat" not in anonymous.get("/explore").data

    with private.session_transaction() as session:
        session["owner_sub"] = PUBLIC_DEMO_OWNER
    assert private.post("/api/threats", json=THREAT).status_code == 401


def test_public_import_rejects_ambiguous_or_owned_data(app, tmp_path):
    runner = app.test_cli_runner()
    assert runner.invoke(args=["import-json"]).exit_code != 0
    assert runner.invoke(args=["import-json", "--public-demo", "--owner-sub", "user"]).exit_code != 0
    assert runner.invoke(args=["import-json", "--owner-sub", PUBLIC_DEMO_OWNER]).exit_code != 0
    source = tmp_path / "owned.json"
    source.write_text(json.dumps([{**THREAT, "owner_sub": "private-user"}]))
    assert runner.invoke(args=["import-json", "--public-demo", "--file", str(source), "--apply"]).exit_code != 0
    with app.app_context():
        assert db.session.scalar(db.select(db.func.count()).select_from(UserThreat)) == 0
