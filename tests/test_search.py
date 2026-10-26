from html.parser import HTMLParser
from urllib.parse import parse_qs, urlsplit
import pytest
from sqlalchemy import event

from models import UserThreat, db
from services.records import PUBLIC_DEMO_OWNER
from tests.test_database import THREAT, app, client


class PageElements(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.elements = []
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        self.elements.append((tag, dict(attrs)))


def test_search_tab_has_get_form_and_preserves_phrase(app, client):
    with app.app_context():
        for owner, name in [("Owner-A", "My payroll incident"), ("other-user", "Other user's private incident"), (PUBLIC_DEMO_OWNER, "Public sample incident")]:
            db.session.add(UserThreat(owner_sub=owner, **{
                **THREAT, "name": name, "description": "Observed password reset scams.",
            }))
        db.session.commit()
    response = client.get("/explore", query_string={
        "tab": "search", "q": "password reset", "collection": "demo",
    })
    assert response.status_code == 200
    assert parse_qs(urlsplit(response.request.url).query)["q"] == ["password reset"]
    elements = PageElements(response.get_data(as_text=True)).elements
    assert any(tag == "form" and attrs.get("method") == "get"
               and attrs.get("action") == "/explore" and attrs.get("role") == "search"
               for tag, attrs in elements)
    assert any(tag == "input" and attrs.get("type") == "search"
               and attrs.get("name") == "q" and attrs.get("value") == "password reset"
               for tag, attrs in elements)
    assert b"Search threats</button>" in response.data
    assert b"My payroll incident" in response.data
    assert b"Other user" not in response.data
    assert b"Public sample incident" not in response.data


def test_new_search_clears_previous_query_and_keeps_search_tab(client):
    response = client.get("/explore?tab=search&q=not-a-real-threat")
    assert b"No matching threats" in response.data
    elements = PageElements(response.get_data(as_text=True)).elements
    assert any(tag == "a" and attrs.get("href") == "/explore?tab=search"
               for tag, attrs in elements)
    fresh = client.get("/explore?tab=search")
    assert b"Start a search" in fresh.data
    assert b'name="q"' in fresh.data
    assert b'value=""' in fresh.data


def test_anonymous_search_does_not_search_public_or_private_records(app):
    with app.app_context():
        for owner in ("private-user", PUBLIC_DEMO_OWNER):
            db.session.add(UserThreat(owner_sub=owner, **THREAT))
        db.session.commit()
    anonymous = app.test_client()
    response = anonymous.get("/explore?tab=search&q=Isolated&collection=demo")
    assert response.status_code == 200
    assert THREAT["name"].encode() not in response.data
    assert b"Your saved threats are private" in response.data
    assert b"Sign in with Google" in response.data


def test_search_query_is_escaped(client):
    response = client.get("/explore", query_string={"tab": "search", "q": '<script>alert("test")</script>'})
    assert b'<script>alert("test")</script>' not in response.data
    elements = PageElements(response.get_data(as_text=True)).elements
    assert any(tag == "input" and attrs.get("name") == "q"
               and attrs.get("value") == '<script>alert("test")</script>'
               for tag, attrs in elements)


@pytest.mark.parametrize("original", ["  PaSsWoRd ReSeT  ", "PASSWORD RESET", "password reset"])
def test_query_is_trimmed_casefolded_and_original_is_displayed(app, client, original):
    with app.app_context():
        db.session.add(UserThreat(owner_sub="Owner-A", **{
            **THREAT, "description": "Investigate the password reset incident.",
        }))
        db.session.commit()
    response = client.get("/explore", query_string={"tab": "search", "q": original})
    assert response.status_code == 200
    assert THREAT["name"].encode() in response.data
    assert parse_qs(urlsplit(response.request.url).query)["q"] == [original]
    elements = PageElements(response.get_data(as_text=True)).elements
    assert any(tag == "input" and attrs.get("name") == "q" and attrs.get("value") == original
               for tag, attrs in elements)


@pytest.mark.parametrize("query", ["", "   ", "\t\r\n"])
def test_empty_submitted_queries_show_validation_and_no_results(app, client, query):
    with app.app_context():
        db.session.add(UserThreat(owner_sub="Owner-A", **THREAT))
        db.session.commit()
    response = client.get("/explore", query_string={"tab": "search", "q": query})
    assert response.status_code == 200
    assert b"Enter a keyword or phrase before searching." in response.data
    assert THREAT["name"].encode() not in response.data


def test_unicode_case_handling_is_consistent(app, client):
    with app.app_context():
        db.session.add(UserThreat(owner_sub="Owner-A", **{**THREAT, "name": "Straße incident"}))
        db.session.commit()
    response = client.get("/explore?tab=search&q=STRASSE")
    assert "Straße incident" in response.get_data(as_text=True)


def test_sql_like_search_is_literal_and_ownership_uses_bound_parameters(app, client):
    query = "x' OR 1=1 --"
    with app.app_context():
        db.session.add(UserThreat(owner_sub="Owner-A", **THREAT))
        db.session.commit()
        statements = []

        def capture(connection, cursor, statement, parameters, context, executemany):
            statements.append((statement, parameters))

        event.listen(db.engine, "before_cursor_execute", capture)
        try:
            response = client.get("/explore", query_string={"tab": "search", "q": query})
        finally:
            event.remove(db.engine, "before_cursor_execute", capture)
        assert response.status_code == 200
        assert b"No matching threats" in response.data
        assert THREAT["name"].encode() not in response.data
        assert statements and all(query not in sql and "Owner-A" not in sql for sql, _ in statements)
        assert any("Owner-A" in params for _, params in statements)
        assert db.session.scalar(db.select(db.func.count()).select_from(UserThreat)) == 1


@pytest.mark.parametrize("order,expected", [
    ("relevance", ["Phishing", "Z phishing investigation", "B category-only alert", "A background alert"]),
    ("alphabetical", ["A background alert", "B category-only alert", "Phishing", "Z phishing investigation"]),
    ("invalid-sort", ["Phishing", "Z phishing investigation", "B category-only alert", "A background alert"]),
])
def test_result_ordering_and_selected_option(app, client, order, expected):
    with app.app_context():
        records = [
            {"name": "A background alert", "description": "Observed phishing activity."},
            {"name": "Z phishing investigation"},
            {"name": "Phishing"},
            {"name": "B category-only alert", "category": "Phishing"},
        ]
        for record in records:
            db.session.add(UserThreat(owner_sub="Owner-A", **{**THREAT, **record}))
        db.session.add(UserThreat(owner_sub="other-user", **{**THREAT, "name": "Other private phishing incident"}))
        db.session.commit()
    original = "  PhIsHiNg  "
    response = client.get("/explore", query_string={
        "tab": "search", "q": original, "sort": order, "severity": "High",
    })
    assert response.status_code == 200
    positions = [response.data.index(f"<h2>{name}</h2>".encode()) for name in expected]
    assert positions == sorted(positions)
    assert b"Other private phishing incident" not in response.data
    chosen = "relevance" if order == "invalid-sort" else order
    elements = PageElements(response.get_data(as_text=True)).elements
    assert any(tag == "option" and attrs.get("value") == chosen and "selected" in attrs
               for tag, attrs in elements)
    assert any(tag == "select" and attrs.get("name") == "sort" for tag, attrs in elements)
    assert any(tag == "input" and attrs.get("name") == "q" and attrs.get("value") == original
               for tag, attrs in elements)
    assert parse_qs(urlsplit(response.request.url).query)["sort"] == [order]


def test_relevance_ties_use_alphabetical_order_and_stay_stable(app, client):
    with app.app_context():
        for name in ("Zulu case", "Alpha case"):
            db.session.add(UserThreat(owner_sub="Owner-A", **{
                **THREAT, "name": name, "description": "Observed phishing activity.",
            }))
        db.session.commit()
    for _ in range(2):
        response = client.get("/explore?tab=search&q=phishing&sort=relevance")
        assert response.data.index(b"<h2>Alpha case</h2>") < response.data.index(b"<h2>Zulu case</h2>")
