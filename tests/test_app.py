import pytest

from app import create_app


@pytest.fixture
def client():
    app = create_app("development")
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


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


def test_explore_loads_json_threat_data(client):
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
