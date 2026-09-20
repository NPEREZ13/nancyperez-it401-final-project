import pytest
import requests

from services import ip_threat


def security_payload(score=5, **overrides):
    security = {
        "threat_score": score,
        "is_vpn": False,
        "is_proxy": False,
        "is_tor": False,
        "is_anonymous": False,
        "is_known_attacker": False,
        "is_bot": False,
        "is_spam": False,
        "is_cloud_provider": False,
        "cloud_provider_name": "",
    }
    security.update(overrides)
    return {"ip": "8.8.8.8", "security": security}


class FakeResponse:
    def __init__(self, status_code=200, payload=None, json_error=None, content=b"json"):
        self.status_code = status_code
        self.payload = payload
        self.json_error = json_error
        self.content = content

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError()

    def json(self):
        if self.json_error:
            raise self.json_error
        return self.payload


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (0, "Low Risk"),
        (19, "Low Risk"),
        (20, "Medium Risk"),
        (74, "Medium Risk"),
        (75, "High Risk"),
        (100, "High Risk"),
    ],
)
def test_classify_risk_boundaries(score, expected):
    assert ip_threat.classify_risk(score) == expected


def test_normalize_ip_accepts_public_ipv4_and_ipv6():
    assert ip_threat.normalize_ip(" 8.8.8.8 ") == "8.8.8.8"
    assert (
        ip_threat.normalize_ip("2001:4860:4860:0:0:0:0:8888")
        == "2001:4860:4860::8888"
    )


@pytest.mark.parametrize("address", ["10.0.0.1", "127.0.0.1", "192.0.2.1", "::1"])
def test_normalize_ip_rejects_non_public_addresses(address):
    with pytest.raises(ValueError, match="public IP address"):
        ip_threat.normalize_ip(address)


def test_analyze_ip_calls_api_with_only_requested_fields(monkeypatch):
    captured = {}

    def fake_get(url, **kwargs):
        captured["url"] = url
        captured.update(kwargs)
        return FakeResponse(
            payload=security_payload(
                is_cloud_provider=True,
                cloud_provider_name="Google LLC",
            )
        )

    monkeypatch.setattr(ip_threat.requests, "get", fake_get)
    result = ip_threat.analyze_ip("8.8.8.8", "secret-key")

    assert captured["url"] == ip_threat.API_URL
    assert captured["params"] == {
        "ip": "8.8.8.8",
        "fields": ",".join(ip_threat.API_FIELDS),
    }
    assert captured["headers"]["X-apiKey"] == "secret-key"
    assert "secret-key" not in str(captured["params"])
    assert result["score"] == 5
    assert result["risk_level"] == "Low Risk"
    assert result["detected_count"] == 1
    assert result["cloud_provider"] == "Google LLC"
    assert "monitor" in result["recommendation"].lower()


def test_analyze_ip_requires_api_key():
    with pytest.raises(ip_threat.IPThreatError, match="APIFREAKS_API_KEY"):
        ip_threat.analyze_ip("8.8.8.8", None)


@pytest.mark.parametrize("value", ["", "   "])
def test_analyze_ip_rejects_empty_address(value):
    with pytest.raises(ValueError, match="valid IPv4 or IPv6"):
        ip_threat.analyze_ip(value, "secret-key")


def test_analyze_ip_handles_network_failure(monkeypatch):
    def fail_request(*args, **kwargs):
        raise requests.ConnectionError()

    monkeypatch.setattr(ip_threat.requests, "get", fail_request)

    with pytest.raises(ip_threat.IPThreatError, match="could not be reached"):
        ip_threat.analyze_ip("8.8.8.8", "secret-key")


@pytest.mark.parametrize(
    ("status_code", "message"),
    [
        (400, "could not process"),
        (401, "rejected the API key"),
        (403, "denied this request"),
        (429, "Too many lookups"),
        (500, "temporarily unavailable"),
    ],
)
def test_analyze_ip_handles_http_errors(monkeypatch, status_code, message):
    monkeypatch.setattr(
        ip_threat.requests,
        "get",
        lambda *args, **kwargs: FakeResponse(status_code=status_code),
    )

    with pytest.raises(ip_threat.IPThreatError, match=message):
        ip_threat.analyze_ip("8.8.8.8", "secret-key")


def test_analyze_ip_handles_malformed_json(monkeypatch):
    monkeypatch.setattr(
        ip_threat.requests,
        "get",
        lambda *args, **kwargs: FakeResponse(json_error=ValueError("bad JSON")),
    )

    with pytest.raises(ip_threat.IPThreatError, match="malformed JSON"):
        ip_threat.analyze_ip("8.8.8.8", "secret-key")


@pytest.mark.parametrize(
    "response",
    [
        FakeResponse(status_code=204, content=b""),
        FakeResponse(content=b"   "),
        FakeResponse(payload={}, content=b"{}"),
        FakeResponse(payload=None, content=b"null"),
        FakeResponse(payload=[], content=b"[]"),
    ],
)
def test_analyze_ip_handles_empty_response(monkeypatch, response):
    monkeypatch.setattr(
        ip_threat.requests,
        "get",
        lambda *args, **kwargs: response,
    )

    with pytest.raises(ip_threat.IPThreatError, match="empty response"):
        ip_threat.analyze_ip("8.8.8.8", "secret-key")


def test_analyze_ip_handles_malformed_security_fields(monkeypatch):
    malformed = security_payload(is_vpn="false")
    monkeypatch.setattr(
        ip_threat.requests,
        "get",
        lambda *args, **kwargs: FakeResponse(payload=malformed),
    )

    with pytest.raises(ip_threat.IPThreatError, match="malformed is_vpn"):
        ip_threat.analyze_ip("8.8.8.8", "secret-key")


def test_analyze_ip_rejects_malformed_threat_score(monkeypatch):
    malformed = security_payload(score="high")
    monkeypatch.setattr(
        ip_threat.requests,
        "get",
        lambda *args, **kwargs: FakeResponse(payload=malformed),
    )

    with pytest.raises(ip_threat.IPThreatError, match="malformed threat score"):
        ip_threat.analyze_ip("8.8.8.8", "secret-key")


def test_high_risk_recommendation_calls_for_blocking():
    result = ip_threat.extract_result(
        security_payload(score=82, is_known_attacker=True),
        "8.8.8.8",
    )

    assert result["risk_level"] == "High Risk"
    assert "Block or quarantine" in result["recommendation"]
