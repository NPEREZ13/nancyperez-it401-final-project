"""Scrape and normalize public data-breach records from Wikipedia."""

import re
from threading import Lock
from time import monotonic

import requests
from bs4 import BeautifulSoup


SOURCE_URL = "https://en.wikipedia.org/wiki/List_of_data_breaches"
REQUEST_TIMEOUT_SECONDS = 15
CACHE_TTL_SECONDS = 3600
FAILURE_CACHE_TTL_SECONDS = 60
USER_AGENT = "ThreatLense/1.0 (educational cybersecurity dashboard)"

_cache = {
    "loaded_at": 0.0,
    "records": None,
    "failed_at": 0.0,
    "error_message": None,
}
_cache_lock = Lock()


class BreachScrapeError(Exception):
    """Raised when breach records cannot be downloaded or parsed."""


def clean_cell(cell):
    """Remove citations and normalize whitespace and missing values."""
    if cell is None:
        return "Unknown"

    # Citation elements are removed before text extraction so raw footnote
    # markers and HTML never enter the structured records.
    for citation in cell.select(
        "sup.reference, .reference, span.sortkey, span[style*='display:none']"
    ):
        citation.decompose()

    value = cell.get_text(" ", strip=True)
    value = re.sub(r"\[\s*\d+(?:\s*,\s*\d+)*\s*\]", "", value)
    value = re.sub(r"\s+", " ", value).strip()
    value = re.sub(r"\s+([,.;:!?])", r"\1", value)

    if not value or value.casefold() in {
        "?",
        "-",
        "–",
        "—",
        "n/a",
        "na",
        "none",
        "unknown",
        "tbc",
    }:
        return "Unknown"
    return value


def parse_breach_tables(html):
    """Convert Wikipedia's breach tables into a list of five-field dictionaries."""
    soup = BeautifulSoup(html, "html.parser")
    records = []
    tables = soup.select("table.wikitable")
    if not tables:
        raise BreachScrapeError(
            "Wikipedia's data breach tables could not be found. The page structure may have changed."
        )

    matching_table_count = 0

    for table in tables:
        header_row = table.find("tr")
        if header_row is None:
            continue

        headers = [clean_cell(cell) for cell in header_row.find_all(["th", "td"])]
        normalized_headers = [header.casefold() for header in headers]

        # Company tables use Entity; government tables use Agency.
        entity_header = "entity" if "entity" in normalized_headers else "agency"
        required_headers = {
            "entity": entity_header,
            "year": "year",
            "records_affected": "records",
            "organization_type": "organization type",
            "breach_method": "method",
        }
        if not all(header in normalized_headers for header in required_headers.values()):
            continue
        matching_table_count += 1

        indexes = {
            output_name: normalized_headers.index(source_name)
            for output_name, source_name in required_headers.items()
        }

        for row in table.find_all("tr")[1:]:
            cells = row.find_all(["th", "td"], recursive=False)
            if not cells or max(indexes.values()) >= len(cells):
                continue

            record = {
                field: clean_cell(cells[index])
                for field, index in indexes.items()
            }
            if all(value == "Unknown" for value in record.values()):
                continue
            records.append(record)

    if matching_table_count == 0:
        raise BreachScrapeError(
            "Wikipedia's breach tables are missing expected columns. The page structure may have changed."
        )
    if not records:
        raise BreachScrapeError(
            "Wikipedia's breach tables contained no usable records."
        )

    # Remove exact duplicates that can appear across multiple source tables.
    unique_records = []
    seen = set()
    for record in records:
        identity = tuple(record.values())
        if identity not in seen:
            seen.add(identity)
            unique_records.append(record)

    # Put recent incidents first while keeping unknown/nonstandard years last.
    unique_records.sort(
        key=lambda record: (
            int(record["year"]) if record["year"].isdigit() else -1,
            record["entity"].casefold(),
        ),
        reverse=True,
    )
    return unique_records


def _download_breach_records():
    try:
        response = requests.get(
            SOURCE_URL,
            headers={"User-Agent": USER_AGENT},
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
    except requests.RequestException as exc:
        raise BreachScrapeError(
            "Data breach intelligence is temporarily unavailable."
        ) from exc

    try:
        return parse_breach_tables(response.content)
    except BreachScrapeError:
        raise
    except Exception as exc:
        raise BreachScrapeError("Wikipedia returned data that could not be read.") from exc


def get_breach_records():
    """Return cached structured records, refreshing them at most once per hour."""
    now = monotonic()
    with _cache_lock:
        if (
            _cache["records"] is not None
            and now - _cache["loaded_at"] < CACHE_TTL_SECONDS
        ):
            return list(_cache["records"])

        if (
            _cache["error_message"] is not None
            and now - _cache["failed_at"] < FAILURE_CACHE_TTL_SECONDS
        ):
            raise BreachScrapeError(_cache["error_message"])

        try:
            records = _download_breach_records()
        except BreachScrapeError as exc:
            _cache["failed_at"] = now
            _cache["error_message"] = str(exc)
            raise

        _cache["records"] = records
        _cache["loaded_at"] = now
        _cache["failed_at"] = 0.0
        _cache["error_message"] = None
        return list(records)


def clear_breach_cache():
    """Clear cached records (primarily useful for tests)."""
    with _cache_lock:
        _cache["loaded_at"] = 0.0
        _cache["records"] = None
        _cache["failed_at"] = 0.0
        _cache["error_message"] = None
