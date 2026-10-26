import pytest
from pathlib import Path

from app import create_app
from models import db
from services.migration import import_threats


@pytest.fixture
def client():
    app = create_app("development", {
        "TESTING": True, "SECRET_KEY": "test-only-secret",
        "SQLALCHEMY_DATABASE_URI": "sqlite://",
    })
    with app.app_context():
        db.create_all()
        import_threats(db.session, "test-owner", Path(app.root_path) / "data/threats.json")
        db.session.commit()
    with app.test_client() as client:
        with client.session_transaction() as session:
            session["owner_sub"] = "test-owner"
        yield client
    with app.app_context():
        db.session.remove()
        db.drop_all()


def test_index(client):
    response = client.get("/")
    assert response.status_code == 200


def test_about(client):
    response = client.get("/about")
    assert response.status_code == 200
    assert b"Threat intelligence" in response.data


def test_threat_briefs(client):
    response = client.get("/menu")
    assert response.status_code == 200
    assert b"Threat briefs" in response.data


def test_explore_loads_database_threat_data(client):
    response = client.get("/explore")
    assert response.status_code == 200
    assert b"Explore intelligence" in response.data
    assert b"BlackCat Ransomware" in response.data


def test_explore_filters_by_severity(client):
    response = client.get("/explore", query_string={"severity": "High"})

    assert response.status_code == 200
    assert b"Cloud Credential Phishing" in response.data
    assert b"Business Email Compromise" in response.data
    assert b"BlackCat Ransomware" not in response.data


def test_explore_combines_search_and_category_filters(client):
    response = client.get(
        "/explore",
        query_string={"q": "cloud", "category": "Credential Theft"},
    )

    assert response.status_code == 200
    assert b"Cloud Credential Phishing" in response.data
    assert b"Business Email Compromise" not in response.data


def test_explore_shows_message_when_no_threats_match(client):
    response = client.get("/explore", query_string={"q": "not-a-real-threat"})

    assert response.status_code == 200
    assert b"No matching threats" in response.data
