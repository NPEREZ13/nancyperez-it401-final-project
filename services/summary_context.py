"""Build bounded, ranked, privacy-conscious context for threat summaries."""

import json
import re
from urllib.parse import urlsplit, urlunsplit

from services.search_service import SORT_OPTIONS, paginated_threats, process_query


MAX_CONTEXT_RECORDS = 5
MAX_CONTEXT_BYTES = 12_000
MAX_CONTEXT_FIELD_CHARACTERS = 3_500
MAX_USER_REQUEST_CHARACTERS = 2_000

_EMAIL = re.compile(r"(?<![\w.+-])[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}(?![\w.-])")
_SSN = re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")
_SECRET = re.compile(
    r"(?i)\b(api[ _-]?key|password|passwd|secret|access[ _-]?token|authorization)"
    r"\b\s*[:=]\s*(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)"
)
_PRIVATE_KEY = re.compile(
    r"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----",
    re.DOTALL,
)


class SummaryContextError(ValueError):
    """Raised when a summary request cannot produce safe retrieval context."""


def _sanitize_text(value):
    """Remove common credential/PII forms before text reaches a model."""
    if value is None:
        return None
    text = str(value)
    text = _PRIVATE_KEY.sub("[redacted private key]", text)
    text = _SECRET.sub(lambda match: f"{match.group(1)}=[redacted credential]", text)
    text = _EMAIL.sub("[redacted email]", text)
    return _SSN.sub("[redacted personal identifier]", text)


def _bounded_text(value):
    text = _sanitize_text(value)
    if text is None or len(text) <= MAX_CONTEXT_FIELD_CHARACTERS:
        return text, False
    marker = " [truncated for context limit]"
    return text[:MAX_CONTEXT_FIELD_CHARACTERS - len(marker)] + marker, True


def _safe_source_url(value):
    """Keep a public HTTP(S) source location while discarding credentials/query data."""
    if not value:
        return None
    try:
        parsed = urlsplit(str(value).strip())
        port = parsed.port
    except ValueError:
        return None
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return None
    host = parsed.hostname
    if port:
        host += f":{port}"
    return urlunsplit((parsed.scheme, host, parsed.path, "", ""))


def _context_record(record):
    """Project only summary-relevant fields; absent source fields remain null."""
    projected = {
        "record_id": record["id"],
        "name": record.get("name"),
        "description": record.get("description"),
        "severity": record.get("severity"),
        "category": record.get("category"),
        "target": record.get("target"),
        "mitigation": record.get("mitigation"),
        "source_url": _safe_source_url(record.get("source_url")),
        "source_published_at": record.get("source_published_at"),
        "source_updated_at": record.get("source_updated_at"),
    }
    truncated_fields = []
    for field in (
        "name", "description", "severity", "category", "target", "mitigation",
        "source_published_at", "source_updated_at",
    ):
        projected[field], truncated = _bounded_text(projected[field])
        if truncated:
            truncated_fields.append(field)
    projected["truncated_fields"] = truncated_fields
    return projected


def _encoded_size(records):
    return len(json.dumps(
        records, ensure_ascii=False, separators=(",", ":"), sort_keys=True,
    ).encode("utf-8"))


def build_summary_context(
    owner,
    user_request,
    *,
    retrieval_parameters=None,
    max_records=MAX_CONTEXT_RECORDS,
    max_context_bytes=MAX_CONTEXT_BYTES,
):
    """Retrieve a relevance-ranked prefix and return the exact model context.

    The existing retrieval service remains the source of matching and ranking.
    Lower-ranked records are omitted once either the five-record ceiling or the
    serialized-record byte ceiling is reached; records are never reordered.
    """
    if not owner:
        raise SummaryContextError("An authenticated owner is required.")
    if not isinstance(user_request, str) or not user_request.strip():
        raise SummaryContextError("Enter a threat-summary request.")
    user_request = user_request.strip()
    if len(user_request) > MAX_USER_REQUEST_CHARACTERS:
        raise SummaryContextError(
            f"The request exceeds {MAX_USER_REQUEST_CHARACTERS} characters."
        )
    if not 1 <= max_records <= MAX_CONTEXT_RECORDS:
        raise SummaryContextError(
            f"Context may include between 1 and {MAX_CONTEXT_RECORDS} records."
        )
    if not 2 <= max_context_bytes <= MAX_CONTEXT_BYTES:
        raise SummaryContextError(
            f"Context may not exceed {MAX_CONTEXT_BYTES} UTF-8 bytes."
        )

    parameters = retrieval_parameters or {}
    retrieval_query = parameters.get("q", user_request)
    query = process_query(retrieval_query)
    if query.is_empty:
        raise SummaryContextError("Enter a keyword or phrase before summarizing.")
    order = parameters.get("sort", "relevance")
    if order not in SORT_OPTIONS:
        order = "relevance"
    severity = str(parameters.get("severity", "")).strip()
    category = str(parameters.get("category", "")).strip()
    try:
        requested_page = int(parameters.get("page", 1))
    except (TypeError, ValueError):
        requested_page = 1
    retrieval = paginated_threats(
        owner,
        query,
        order,
        severity=severity,
        category=category,
        requested_page=requested_page,
        searching=True,
    )
    selected = []
    byte_limit_reached = False
    for record in retrieval.items[:max_records]:
        candidate = [*selected, _context_record(record)]
        if _encoded_size(candidate) > max_context_bytes:
            byte_limit_reached = True
            break
        selected = candidate

    selected_count = len(selected)
    is_subset = retrieval.total > selected_count
    limitations = []
    if is_subset:
        limitations.append(
            f"This summary context includes {selected_count} of "
            f"{retrieval.total} matching records."
        )
    if byte_limit_reached:
        limitations.append(
            f"Lower-ranked records were omitted to keep retrieved records within "
            f"{max_context_bytes} UTF-8 bytes."
        )
    truncated = [
        str(record["record_id"])
        for record in selected
        if record["truncated_fields"]
    ]
    if truncated:
        limitations.append(
            "Long fields were explicitly truncated in record(s): " + ", ".join(truncated) + "."
        )
    if not selected:
        limitations.append("No matching records were available to summarize.")

    return {
        "records": selected,
        "retrieval": {
            "query": query.original,
            "severity": severity,
            "category": category,
            "sort": order,
            "page": retrieval.page,
            "page_result_count": len(retrieval.items),
            "total_matching_records": retrieval.total,
            "selected_record_count": selected_count,
            "selected_record_limit": max_records,
            "context_size_bytes": _encoded_size(selected),
            "context_size_limit_bytes": max_context_bytes,
            "covers_subset": is_subset,
        },
        "limitations": limitations,
    }
