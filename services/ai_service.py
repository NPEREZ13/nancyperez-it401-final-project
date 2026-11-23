"""Backend-only OpenAI Responses API client for structured threat summaries."""

import json
from dataclasses import dataclass

import requests


RESPONSES_URL = "https://api.openai.com/v1/responses"
DEFAULT_TIMEOUT_SECONDS = 20
MAX_TIMEOUT_SECONDS = 60
MAX_OUTPUT_TOKENS = 1_600


class AiServiceError(RuntimeError):
    """Base class for safe provider failure classification."""


class AiConfigurationError(AiServiceError):
    pass


class AiRateLimitError(AiServiceError):
    pass


class AiTimeoutError(AiServiceError):
    pass


class AiRefusalError(AiServiceError):
    pass


class AiProviderError(AiServiceError):
    pass


class AiResponseError(AiServiceError):
    pass


@dataclass(frozen=True)
class GenerationResult:
    output: object
    model_identifier: str


class AiService:
    """Call OpenAI with strict Structured Outputs and no automatic retries."""

    def __init__(self, api_key=None, model=None, timeout_seconds=DEFAULT_TIMEOUT_SECONDS):
        self.api_key = api_key
        self.model = model
        self.timeout_seconds = timeout_seconds

    def _configuration(self):
        if not isinstance(self.api_key, str) or not self.api_key.strip():
            raise AiConfigurationError("OPENAI_API_KEY is not configured.")
        if not isinstance(self.model, str) or not self.model.strip():
            raise AiConfigurationError("OPENAI_MODEL is not configured.")
        try:
            timeout = float(self.timeout_seconds)
        except (TypeError, ValueError) as error:
            raise AiConfigurationError("OPENAI_TIMEOUT_SECONDS is invalid.") from error
        if not 1 <= timeout <= MAX_TIMEOUT_SECONDS:
            raise AiConfigurationError(
                f"OPENAI_TIMEOUT_SECONDS must be between 1 and {MAX_TIMEOUT_SECONDS}."
            )
        return self.api_key.strip(), self.model.strip(), timeout

    @staticmethod
    def _extract_output_text(payload):
        text_parts = []
        output_items = payload.get("output")
        if not isinstance(output_items, list):
            raise AiResponseError("The provider response omitted its output items.")
        for item in output_items:
            if not isinstance(item, dict) or item.get("type") != "message":
                continue
            content_items = item.get("content")
            if not isinstance(content_items, list):
                continue
            for content in content_items:
                if not isinstance(content, dict):
                    continue
                if content.get("type") == "refusal":
                    raise AiRefusalError("The model refused the request.")
                if content.get("type") == "output_text" and isinstance(content.get("text"), str):
                    text_parts.append(content["text"])
        output_text = "".join(text_parts).strip()
        if not output_text:
            raise AiResponseError("The provider returned no structured output text.")
        return output_text

    def generate_summary(self, prompt_package):
        api_key, model, timeout = self._configuration()
        try:
            messages = prompt_package["messages"]
            schema = prompt_package["required_output_schema"]
        except (KeyError, TypeError) as error:
            raise AiResponseError("The prompt package is incomplete.") from error

        request_body = {
            "model": model,
            "input": messages,
            "text": {
                "format": {
                    "type": "json_schema",
                    "name": "threat_summary",
                    "description": "A source-grounded ThreatLense summary with record citations.",
                    "strict": True,
                    "schema": schema,
                }
            },
            "max_output_tokens": MAX_OUTPUT_TOKENS,
            "store": False,
        }
        try:
            response = requests.post(
                RESPONSES_URL,
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
                json=request_body,
                timeout=timeout,
            )
        except requests.Timeout as error:
            raise AiTimeoutError("The model request timed out.") from error
        except requests.RequestException as error:
            raise AiProviderError("The model provider could not be reached.") from error

        if response.status_code == 429:
            raise AiRateLimitError("The model provider rate limit was reached.")
        if response.status_code in (401, 403):
            raise AiConfigurationError("The model provider rejected the credentials or access.")
        if response.status_code >= 400:
            raise AiProviderError("The model provider returned an unsuccessful status.")
        try:
            payload = response.json()
        except (requests.exceptions.JSONDecodeError, ValueError) as error:
            raise AiResponseError("The model provider returned malformed JSON.") from error
        if not isinstance(payload, dict):
            raise AiResponseError("The model provider returned an unexpected response.")
        if payload.get("error"):
            raise AiProviderError("The model provider reported an error.")
        if payload.get("status") != "completed":
            raise AiResponseError("The model response was incomplete.")

        actual_model = payload.get("model")
        if not isinstance(actual_model, str) or not actual_model.strip():
            raise AiResponseError("The model response omitted its model identifier.")
        output_text = self._extract_output_text(payload)
        try:
            output = json.loads(output_text)
        except (TypeError, ValueError) as error:
            raise AiResponseError("The structured model output was not valid JSON.") from error
        return GenerationResult(output=output, model_identifier=actual_model.strip())
