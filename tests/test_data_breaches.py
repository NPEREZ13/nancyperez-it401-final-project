import pytest
import requests

from services import data_breaches


SAMPLE_HTML = b"""
<html><body>
<table class="wikitable sortable">
  <tr><th>Government</th><th>Agency</th><th>Year</th><th>Records</th><th>Organization type</th><th>Method</th><th>Sources</th></tr>
  <tr>
    <td>United States</td><td> Example   Agency <sup class="reference">[1]</sup> , Division</td>
    <td>2024</td><td> 50,000 </td><td> Government </td><td> hacked </td><td>[1]</td>
  </tr>
  <tr><td></td><td></td><td></td><td></td><td></td><td></td><td></td></tr>
</table>
<table class="wikitable">
  <tr><th>Entity</th><th>Year</th><th>Records</th><th>Organization type</th><th>Method</th><th>Sources</th></tr>
  <tr><td>Example Company <sup class="reference">[22]</sup></td><td>2023</td><td></td><td>Tech</td><td>?</td><td>[22]</td></tr>
</table>
</body></html>
"""


def test_parse_breach_tables_cleans_and_structures_records():
    records = data_breaches.parse_breach_tables(SAMPLE_HTML)

    assert records == [
        {
            "entity": "Example Agency, Division",
            "year": "2024",
            "records_affected": "50,000",
            "organization_type": "Government",
            "breach_method": "hacked",
        },
        {
            "entity": "Example Company",
            "year": "2023",
            "records_affected": "Unknown",
            "organization_type": "Tech",
            "breach_method": "Unknown",
        },
    ]
    assert "<" not in str(records)
    assert "[22]" not in str(records)


def test_parse_breach_tables_rejects_missing_tables():
    with pytest.raises(data_breaches.BreachScrapeError, match="could not be found"):
        data_breaches.parse_breach_tables(b"<html><body>No table</body></html>")


def test_parse_breach_tables_rejects_missing_columns():
    html = b"<table class='wikitable'><tr><th>Name</th><th>Date</th></tr></table>"

    with pytest.raises(data_breaches.BreachScrapeError, match="missing expected columns"):
        data_breaches.parse_breach_tables(html)


def test_parse_breach_tables_rejects_empty_results():
    html = b"""
    <table class='wikitable'>
      <tr><th>Entity</th><th>Year</th><th>Records</th><th>Organization type</th><th>Method</th></tr>
    </table>
    """

    with pytest.raises(data_breaches.BreachScrapeError, match="no usable records"):
        data_breaches.parse_breach_tables(html)


def test_get_breach_records_uses_cache(monkeypatch):
    calls = []

    def fake_download():
        calls.append(True)
        return [{"entity": "Cached"}]

    data_breaches.clear_breach_cache()
    monkeypatch.setattr(data_breaches, "_download_breach_records", fake_download)

    assert data_breaches.get_breach_records() == [{"entity": "Cached"}]
    assert data_breaches.get_breach_records() == [{"entity": "Cached"}]
    assert len(calls) == 1
    data_breaches.clear_breach_cache()


def test_download_handles_network_failure(monkeypatch):
    def fail_request(*args, **kwargs):
        raise requests.ConnectionError()

    monkeypatch.setattr(data_breaches.requests, "get", fail_request)

    with pytest.raises(data_breaches.BreachScrapeError, match="temporarily unavailable"):
        data_breaches._download_breach_records()


def test_get_breach_records_temporarily_caches_failure(monkeypatch):
    calls = []

    def fail_download():
        calls.append(True)
        raise data_breaches.BreachScrapeError("Source unavailable")

    data_breaches.clear_breach_cache()
    monkeypatch.setattr(data_breaches, "_download_breach_records", fail_download)

    for _ in range(2):
        with pytest.raises(data_breaches.BreachScrapeError, match="Source unavailable"):
            data_breaches.get_breach_records()

    assert len(calls) == 1
    data_breaches.clear_breach_cache()
