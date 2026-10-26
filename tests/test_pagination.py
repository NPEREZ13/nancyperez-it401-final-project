import re
from urllib.parse import parse_qs, urlsplit

import pytest
from sqlalchemy import event

from models import UserThreat, db
from tests.test_database import THREAT, app, client
from tests.test_search import PageElements


@pytest.fixture
def records(app):
    with app.app_context():
        for index in reversed(range(23)):
            db.session.add(UserThreat(owner_sub="Owner-A", **{
                **THREAT, "name": f"Incident {index:02}", "description": "Investigating a shared secret leak.",
                "category": "Credential Theft",
            }))
        db.session.add(UserThreat(owner_sub="Owner-A", **{
            **THREAT, "name": "shared secret", "category": "Credential Theft",
        }))
        db.session.add(UserThreat(owner_sub="Owner-A", **{
            **THREAT, "name": "Excluded low severity", "description": "shared secret", "severity": "Low",
        }))
        db.session.add(UserThreat(owner_sub="other-user", **{
            **THREAT, "name": "Another account shared secret", "category": "Credential Theft",
        }))
        db.session.commit()


def titles(response):
    return re.findall(r'<article class="explore-card">.*?<h2>(.*?)</h2>', response.get_data(as_text=True), re.S)


def page_link(response, relation):
    return next(attrs["href"] for tag, attrs in PageElements(response.get_data(as_text=True)).elements
                if tag == "a" and attrs.get("rel") == relation)


def test_pagination_preserves_query_filters_sort_and_has_no_overlaps(client, records):
    original = "  SHARED secret  "
    first = client.get("/explore", query_string={
        "tab": "search", "q": original, "severity": "High",
        "category": "Credential Theft", "sort": "alphabetical",
    })
    assert titles(first) == [f"Incident {index:02}" for index in range(10)]
    assert "Showing <strong>1–10</strong> of 24 results" in first.get_data(as_text=True)
    assert b"Page 1 of 3" in first.data
    next_url = page_link(first, "next")
    assert parse_qs(urlsplit(next_url).query) == {
        "tab": ["search"], "q": [original], "severity": ["High"],
        "category": ["Credential Theft"], "sort": ["alphabetical"], "page": ["2"],
    }
    second = client.get(next_url)
    assert titles(second) == [f"Incident {index:02}" for index in range(10, 20)]
    assert b"Page 2 of 3" in second.data
    assert titles(client.get(page_link(second, "prev"))) == titles(first)
    third = client.get(page_link(second, "next"))
    assert titles(third) == ["Incident 20", "Incident 21", "Incident 22", "shared secret"]
    assert "21–24" in third.get_data(as_text=True)
    assert b"Page 3 of 3" in third.data
    assert b'rel="next"' not in third.data
    assert b'rel="prev"' not in first.data
    assert len(set(titles(first) + titles(second) + titles(third))) == 24


def test_ranking_happens_before_pagination(client, records):
    first = client.get("/explore?tab=search&q=shared+secret&severity=High&category=Credential+Theft&sort=relevance")
    assert titles(first)[0] == "shared secret"
    assert len(titles(first)) == 10
    second = client.get(page_link(first, "next"))
    assert "shared secret" not in titles(second)


@pytest.mark.parametrize("page,expected", [("invalid", 1), ("0", 1), ("-1", 1), ("999999999", 3)])
def test_invalid_and_out_of_range_pages_are_clamped(client, records, page, expected):
    response = client.get("/explore", query_string={
        "tab": "search", "q": "shared secret", "severity": "High", "category": "Credential Theft", "page": page,
    })
    assert response.status_code == 200
    assert f"Page {expected} of 3" in response.get_data(as_text=True)
    assert 0 < len(titles(response)) <= 10


def test_large_result_set_uses_bounded_reads_and_renders_ten(app, client):
    with app.app_context():
        for index in range(123):
            db.session.add(UserThreat(owner_sub="Owner-A", **{**THREAT, "name": f"Batch incident {index:03}"}))
        db.session.commit()
        statements = []

        def capture(connection, cursor, statement, parameters, context, executemany):
            if statement.lstrip().upper().startswith("SELECT"):
                statements.append((statement, parameters))

        event.listen(db.engine, "before_cursor_execute", capture)
        try:
            response = client.get("/explore?tab=search&q=Batch&sort=alphabetical&page=12")
        finally:
            event.remove(db.engine, "before_cursor_execute", capture)
    assert len(titles(response)) == 10
    assert titles(response)[0] == "Batch incident 110"
    assert b"Page 12 of 13" in response.data
    assert len(statements) == 3  # Two candidate batches, then one display-page fetch.
    assert all("LIMIT" in sql.upper() for sql, _ in statements)
    assert 100 in statements[0][1] and 10 in statements[-1][1]


def test_zero_results_has_no_pagination_navigation(client):
    response = client.get("/explore?tab=search&q=missing&page=999")
    assert b"No matching threats" in response.data
    assert b'aria-label="Results pages"' not in response.data
