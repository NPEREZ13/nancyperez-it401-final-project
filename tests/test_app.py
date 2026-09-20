import pytest

from app import create_app


BREACH_FIXTURES = [
    {
        "entity": "Alpha Health",
        "year": "2024",
        "records_affected": "100,000",
        "organization_type": "healthcare",
        "breach_method": "hacked",
    },
    {
        "entity": "Beta Bank",
        "year": "2023",
        "records_affected": "50,000",
        "organization_type": "financial",
        "breach_method": "poor security",
    },
]


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(
        "routes.main.get_breach_records",
        lambda: list(BREACH_FIXTURES),
    )
    app = create_app("development")
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_index(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"Data Breach Intelligence" in response.data
    assert b"Alpha Health" in response.data


def test_dashboard_filters_breaches(client):
    response = client.get(
        "/",
        query_string={"breach_q": "beta", "breach_year": "2023"},
    )

    assert response.status_code == 200
    assert b"Beta Bank" in response.data
    assert b"Alpha Health" not in response.data


def test_dashboard_limits_initial_breach_records(client, monkeypatch):
    records = [
        {
            "entity": f"Organization {number}",
            "year": "2024",
            "records_affected": "Unknown",
            "organization_type": "technology",
            "breach_method": "hacked",
        }
        for number in range(20)
    ]
    monkeypatch.setattr("routes.main.get_breach_records", lambda: records)

    response = client.get("/")

    assert response.status_code == 200
    assert b"15</strong> displayed" in response.data
    assert b"Organization 14" in response.data
    assert b"Organization 15" not in response.data


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


def test_ip_analysis_page_loads(client):
    response = client.get("/analyze-ip")

    assert response.status_code == 200
    assert b"Analyze an IP address" in response.data
    assert b"Checking threat intelligence" in response.data
    assert b"ip_checker.js" in response.data


def test_ip_analysis_rejects_invalid_address(client):
    response = client.post("/analyze-ip", data={"ip_address": "not-an-ip"})

    assert response.status_code == 200
    assert b"Enter a valid IPv4 or IPv6 address" in response.data


def test_ip_analysis_rejects_empty_address(client):
    response = client.post("/analyze-ip", data={"ip_address": ""})

    assert response.status_code == 200
    assert b"Enter a valid IPv4 or IPv6 address" in response.data


def test_ip_analysis_rejects_private_address(client):
    response = client.post("/analyze-ip", data={"ip_address": "10.0.0.1"})

    assert response.status_code == 200
    assert b"Enter a public IP address" in response.data


def test_ip_analysis_displays_api_findings(client, monkeypatch):
    def fake_analyze_ip(value, api_key):
        return {
            "ip": value,
            "score": 82,
            "risk_level": "High Risk",
            "risk_class": "high",
            "findings": [("Known attacker", True), ("VPN", False)],
            "detected_count": 1,
            "cloud_provider": "",
            "recommendation": "Block or quarantine traffic from this IP.",
        }

    monkeypatch.setattr("routes.main.analyze_ip", fake_analyze_ip)
    response = client.post("/analyze-ip", data={"ip_address": "2001:db8::1"})

    assert response.status_code == 200
    assert b"High Risk" in response.data
    assert b"82" in response.data
    assert b"Known attacker" in response.data
    assert b"Block or quarantine" in response.data


def test_ip_analysis_displays_service_error(client, monkeypatch):
    from services.ip_threat import IPThreatError

    def fail_analysis(value, api_key):
        raise IPThreatError("API Freaks rejected the API key. Check your configuration.")

    monkeypatch.setattr("routes.main.analyze_ip", fail_analysis)
    response = client.post("/analyze-ip", data={"ip_address": "8.8.8.8"})

    assert response.status_code == 200
    assert b"API Freaks rejected the API key" in response.data


def test_dashboard_displays_scraping_error(client, monkeypatch):
    from services.data_breaches import BreachScrapeError

    def fail_scrape():
        raise BreachScrapeError("Data breach intelligence is temporarily unavailable.")

    monkeypatch.setattr("routes.main.get_breach_records", fail_scrape)
    response = client.get("/")

    assert response.status_code == 200
    assert b"Data breach intelligence is temporarily unavailable" in response.data
