import requests


class ApiService:
    """Thin wrapper around outbound HTTP calls to external APIs."""

    def __init__(self, base_url, api_key=None, timeout=10):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

    def _headers(self):
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def get(self, path, params=None):
        response = requests.get(
            f"{self.base_url}/{path.lstrip('/')}",
            headers=self._headers(),
            params=params,
            timeout=self.timeout,
        )
        response.raise_for_status()
        return response.json()

    def post(self, path, payload=None):
        response = requests.post(
            f"{self.base_url}/{path.lstrip('/')}",
            headers=self._headers(),
            json=payload,
            timeout=self.timeout,
        )
        response.raise_for_status()
        return response.json()
