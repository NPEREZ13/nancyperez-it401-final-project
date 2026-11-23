"""Owner-scoped persistence and input validation shared by HTTP and import code."""

import ipaddress
import json
import re
from datetime import datetime, timezone

from flask import session

from models import db

PUBLIC_DEMO_OWNER = "threatlense:public-demo:v1"


def account_owner():
    user = session.get("user")
    value = user.get("sub") if isinstance(user, dict) else None
    if (isinstance(value, str) and value and value != PUBLIC_DEMO_OWNER
            and not value.startswith("browser:") and len(value) <= 255
            and value == value.strip() and value.isascii() and value.isprintable()):
        return value
    return None


def current_owner():
    if account_owner():
        return account_owner()
    # Account identity comes from a verified login callback, never request fields.
    value = session.get("owner_sub")
    if (isinstance(value, str) and value and value != PUBLIC_DEMO_OWNER and value == value.strip()
            and len(value) <= 255 and value.isascii() and value.isprintable()):
        return value
    # A browser workspace is a separate, server-generated identity, not a login.
    workspace = session.get("workspace_owner_sub")
    if isinstance(workspace, str) and re.fullmatch(r"browser:[0-9a-f]{32}", workspace):
        return workspace
    return None


def browser_owner():
    value = session.get("workspace_owner_sub")
    return value if isinstance(value, str) and re.fullmatch(r"browser:[0-9a-f]{32}", value) else None


def owned_query(model, owner):
    return db.select(model).where(model.owner_sub == owner)


def validate_record(kind, data, partial=False):
    if not isinstance(data, dict):
        raise ValueError("Expected a JSON object.")
    limits = ({"name": 120, "severity": 10, "category": 80,
               "description": 65535, "mitigation": 65535} if kind == "threats"
              else {"name": 80, "ip_address": 45})
    allowed = set(limits) | (set() if kind == "threats" else {"result_json", "checked_at"})
    if set(data) - allowed:
        raise ValueError("Unknown or read-only fields supplied.")
    if not data:
        raise ValueError("Supply at least one field.")
    if not partial and set(limits) - set(data):
        raise ValueError("Missing required fields: " + ", ".join(sorted(set(limits) - set(data))))
    cleaned = {}
    for key, limit in limits.items():
        if key not in data:
            continue
        value = data[key]
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{key} must be a nonempty string.")
        value = value.strip()
        if len(value) > limit or (key in ("description", "mitigation") and len(value.encode("utf-8")) > limit):
            raise ValueError(f"{key} exceeds its database length limit.")
        cleaned[key] = value
    if "severity" in cleaned:
        canonical = {v.casefold(): v for v in ("Critical", "High", "Medium", "Low", "Info")}
        if cleaned["severity"].casefold() not in canonical:
            raise ValueError("severity must be Critical, High, Medium, Low, or Info.")
        cleaned["severity"] = canonical[cleaned["severity"].casefold()]
    if "ip_address" in cleaned:
        try:
            cleaned["ip_address"] = str(ipaddress.ip_address(cleaned["ip_address"]))
        except ValueError:
            raise ValueError("ip_address must be a valid IPv4 or IPv6 address.") from None
    if "result_json" in data:
        try:
            encoded = json.dumps(data["result_json"], allow_nan=False)
        except (TypeError, ValueError):
            raise ValueError("result_json must contain valid JSON.") from None
        if len(encoded.encode("utf-8")) > 65535:
            raise ValueError("result_json exceeds 65535 bytes.")
        cleaned["result_json"] = data["result_json"]
    if "checked_at" in data:
        value = data["checked_at"]
        if value is not None:
            try:
                value = datetime.fromisoformat(value.replace("Z", "+00:00"))
                if value.tzinfo:
                    value = value.astimezone(timezone.utc).replace(tzinfo=None)
                if value.year < 1000:
                    raise ValueError()
            except (ValueError, TypeError, AttributeError):
                raise ValueError("checked_at must be an ISO datetime or null.") from None
        cleaned["checked_at"] = value
    return cleaned
