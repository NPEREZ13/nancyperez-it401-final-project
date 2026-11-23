import pytest
import requests

from services import ai_service
from services.ai_service import (
    AiConfigurationError, AiProviderError, AiRateLimitError, AiRefusalError,
    AiResponseError, AiService, AiTimeoutError,
)
from services.summary_prompt import build_summary_prompt


def prompt_package():
    return build_summary_prompt("Summarize phishing", {
        "records": [{"record_id": 7, "name": "Cloud phishing"}],
        "retrieval": {"covers_subset": False},
        "limitations": [],
    })


def completed_payload(text=None, model="gpt-test-2026-11-01", content=None):
    if content is None:
        content = [{
            "type": "output_text",
            "text": text or (
                '{"summary":"Supported overview.","key_findings":['
                '{"finding":"Supported finding.","supporting_record_ids":[7]}],'
                '"limitations":[]}'
            ),
        }]
    return {
        "status": "completed",
        "model": model,
        "output": [{"type": "message", "content": content}],
    }


class FakeResponse:
    def __init__(self, status_code=200, payload=None, json_error=None):
        self.status_code = status_code
        self.payload = payload
        self.json_error = json_error

    def json(self):
        if self.json_error:
            raise self.json_error
        return self.payload


def test_openai_responses_request_uses_strict_schema_and_backend_secret(monkeypatch):
    captured = {}

    def fake_post(url, **kwargs):
        captured["url"] = url
        captured.update(kwargs)
        return FakeResponse(payload=completed_payload())

    monkeypatch.setattr(ai_service.requests, "post", fake_post)
    result = AiService("secret-key", "configured-model", 12).generate_summary(
        prompt_package()
    )

    assert captured["url"] == ai_service.RESPONSES_URL
    assert captured["headers"]["Authorization"] == "Bearer secret-key"
    assert "secret-key" not in str(captured["json"])
    assert captured["json"]["model"] == "configured-model"
    assert captured["json"]["store"] is False
    assert captured["json"]["text"]["format"]["type"] == "json_schema"
    assert captured["json"]["text"]["format"]["strict"] is True
    assert captured["json"]["text"]["format"]["schema"]["additionalProperties"] is False
    assert captured["timeout"] == 12
    assert result.model_identifier == "gpt-test-2026-11-01"
    assert result.output["key_findings"][0]["supporting_record_ids"] == [7]


@pytest.mark.parametrize("api_key,model", [(None, "model"), ("key", None), ("", "model")])
def test_missing_provider_configuration_never_calls_network(monkeypatch, api_key, model):
    called = False

    def fake_post(*args, **kwargs):
        nonlocal called
        called = True

    monkeypatch.setattr(ai_service.requests, "post", fake_post)
    with pytest.raises(AiConfigurationError):
        AiService(api_key, model).generate_summary(prompt_package())
    assert called is False


def test_rate_limit_is_classified_and_not_retried(monkeypatch):
    calls = 0

    def rate_limited(*args, **kwargs):
        nonlocal calls
        calls += 1
        return FakeResponse(status_code=429, payload={"error": "private provider text"})

    monkeypatch.setattr(ai_service.requests, "post", rate_limited)
    with pytest.raises(AiRateLimitError):
        AiService("key", "model").generate_summary(prompt_package())
    assert calls == 1


def test_timeout_is_bounded_and_classified(monkeypatch):
    monkeypatch.setattr(
        ai_service.requests,
        "post",
        lambda *args, **kwargs: (_ for _ in ()).throw(requests.Timeout()),
    )
    with pytest.raises(AiTimeoutError):
        AiService("key", "model", 5).generate_summary(prompt_package())
    with pytest.raises(AiConfigurationError):
        AiService("key", "model", 61).generate_summary(prompt_package())


@pytest.mark.parametrize("response,error", [
    (FakeResponse(status_code=500, payload={}), AiProviderError),
    (FakeResponse(payload=None), AiResponseError),
    (FakeResponse(payload={"status": "incomplete", "model": "model"}), AiResponseError),
    (FakeResponse(payload=completed_payload(text="not json")), AiResponseError),
])
def test_provider_and_malformed_outputs_are_rejected(monkeypatch, response, error):
    monkeypatch.setattr(ai_service.requests, "post", lambda *args, **kwargs: response)
    with pytest.raises(error):
        AiService("key", "model").generate_summary(prompt_package())


def test_provider_refusal_is_detected(monkeypatch):
    response = FakeResponse(payload=completed_payload(content=[{
        "type": "refusal", "refusal": "Cannot comply",
    }]))
    monkeypatch.setattr(ai_service.requests, "post", lambda *args, **kwargs: response)

    with pytest.raises(AiRefusalError):
        AiService("key", "model").generate_summary(prompt_package())
