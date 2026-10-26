"""Client and helpers for the API Freaks IP Threat Intelligence API."""

from ipaddress import ip_address

import requests


API_URL = "https://api.apifreaks.com/v1.0/ip/security"
REQUEST_TIMEOUT_SECONDS = 10
API_FIELDS = (
    "ip",
    "security.threat_score",
    "security.is_vpn",
    "security.is_proxy",
    "security.is_tor",
    "security.is_anonymous",
    "security.is_known_attacker",
    "security.is_bot",
    "security.is_spam",
    "security.is_cloud_provider",
    "security.cloud_provider_name",
)
SECURITY_FLAGS = (
    ("Known attacker", "is_known_attacker"),
    ("Tor exit node", "is_tor"),
    ("Proxy", "is_proxy"),
    ("VPN", "is_vpn"),
    ("Anonymous", "is_anonymous"),
    ("Bot activity", "is_bot"),
    ("Spam activity", "is_spam"),
    ("Cloud provider", "is_cloud_provider"),
)


class IPThreatError(Exception):
    """Raised when an IP threat lookup cannot be completed."""


def normalize_ip(value):
    """Validate and return the canonical form of a public IPv4 or IPv6 address."""
    try:
        address = ip_address(value.strip())
    except (AttributeError, ValueError) as exc:
        raise ValueError("Enter a valid IPv4 or IPv6 address.") from exc

    # API Freaks provides internet threat intelligence, so addresses that cannot
    # be routed publicly (private, reserved, loopback, etc.) are rejected locally.
    if not address.is_global:
        raise ValueError(
            "Enter a public IP address. Private, reserved, loopback, and link-local "
            "addresses cannot be analyzed."
        )

    return address.compressed


def classify_risk(score):
    """Map API Freaks' score to the three risk levels shown by ThreatLense."""
    if score < 20:
        return "Low Risk"
    if score < 75:
        return "Medium Risk"
    return "High Risk"


def build_recommendation(risk_level, detected_flags):
    """Create a short next-step recommendation from the score and findings."""
    if risk_level == "High Risk":
        return (
            "Block or quarantine traffic from this IP and investigate related "
            "activity before allowing access."
        )
    if risk_level == "Medium Risk":
        return (
            "Require additional verification, review related logs, and monitor "
            "this IP before allowing sensitive actions."
        )
    if any(detected_flags.values()):
        return (
            "Use standard controls and monitor this IP; one or more security "
            "signals were detected despite the low score."
        )
    return "Allow with standard security controls and continue routine monitoring."


def extract_result(payload, normalized_ip):
    """Extract and validate only the fields used by the results display."""
    # JSON processing and field extraction happen here. Treat missing or wrongly
    # typed values as malformed data instead of silently showing a safe result.
    if not isinstance(payload, dict) or not isinstance(payload.get("security"), dict):
        raise IPThreatError("The service returned malformed security data.")

    security = payload["security"]
    score = security.get("threat_score")
    if isinstance(score, bool) or not isinstance(score, int):
        raise IPThreatError("The service returned a malformed threat score.")

    if not 0 <= score <= 100:
        raise IPThreatError("The service returned a threat score outside 0 to 100.")

    detected_flags = {}
    for _, field_name in SECURITY_FLAGS:
        value = security.get(field_name)
        if not isinstance(value, bool):
            raise IPThreatError(
                f"The service returned a malformed {field_name} finding."
            )
        detected_flags[field_name] = value

    cloud_provider = security.get("cloud_provider_name", "")
    if cloud_provider is None:
        cloud_provider = ""
    if not isinstance(cloud_provider, str):
        raise IPThreatError("The service returned a malformed cloud provider name.")

    findings = [
        (label, detected_flags[field_name])
        for label, field_name in SECURITY_FLAGS
    ]
    risk_level = classify_risk(score)
    return {
        "ip": str(payload.get("ip") or normalized_ip),
        "score": score,
        "risk_level": risk_level,
        "risk_class": risk_level.split()[0].lower(),
        "findings": findings,
        "detected_count": sum(detected_flags.values()),
        "cloud_provider": cloud_provider,
        "recommendation": build_recommendation(risk_level, detected_flags),
    }


def analyze_ip(value, api_key):
    """Validate a public IP address and retrieve its threat profile."""
    normalized_ip = normalize_ip(value)

    if not api_key:
        raise IPThreatError(
            "IP analysis is not configured. Add APIFREAKS_API_KEY to your .env file."
        )

    # The API request occurs only on the server. The secret key is sent in the
    # X-apiKey header and is never included in a query string or frontend code.
    try:
        response = requests.get(
            API_URL,
            params={"ip": normalized_ip, "fields": ",".join(API_FIELDS)},
            headers={"X-apiKey": api_key, "Accept": "application/json"},
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
    except requests.RequestException as exc:
        raise IPThreatError(
            "The threat intelligence service could not be reached. Try again shortly."
        ) from exc

    # HTTP and API error handling is kept here so the route only displays safe,
    # user-friendly messages rather than upstream response bodies.
    if response.status_code == 400:
        raise IPThreatError("API Freaks could not process this IP address.")
    if response.status_code == 401:
        raise IPThreatError("API Freaks rejected the API key. Check your configuration.")
    if response.status_code == 402:
        raise IPThreatError("The API Freaks account has no available credits.")
    if response.status_code in (403, 423):
        raise IPThreatError("API Freaks denied this request. Check the account access settings.")
    if response.status_code == 429:
        raise IPThreatError("Too many lookups were requested. Wait a moment and try again.")
    if response.status_code >= 500:
        raise IPThreatError("The threat intelligence service is temporarily unavailable.")

    try:
        response.raise_for_status()
    except requests.RequestException as exc:
        raise IPThreatError(
            "The threat intelligence service could not complete the request."
        ) from exc

    raw_content = getattr(response, "content", None)
    if response.status_code == 204 or (
        isinstance(raw_content, (bytes, str)) and not raw_content.strip()
    ):
        raise IPThreatError("The threat intelligence service returned an empty response.")

    try:
        payload = response.json()
    except (requests.exceptions.JSONDecodeError, ValueError) as exc:
        raise IPThreatError("The service returned malformed JSON.") from exc

    if payload is None or payload == "" or payload == {} or payload == []:
        raise IPThreatError("The threat intelligence service returned an empty response.")

    return extract_result(payload, normalized_ip)
