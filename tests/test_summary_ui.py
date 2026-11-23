from unittest.mock import patch

from sqlalchemy.exc import SQLAlchemyError

from services.ai_service import AiServiceError, GenerationResult
from models import StoredIntelligence, UserThreat, db
from tests.test_database import THREAT, app, client


def _seed(app, owner="Owner-A"):
    with app.app_context():
        db.session.add_all([
            UserThreat(owner_sub=owner, **{
                **THREAT,
                "name": "Cloud phishing alert",
                "severity": "High",
                "category": "Phishing",
                "description": "Observed <script>alert('source')</script> login lure.",
            }),
            UserThreat(owner_sub=owner, **{
                **THREAT,
                "name": "Low phishing notice",
                "severity": "Low",
                "category": "Phishing",
            }),
        ])
        db.session.commit()


def _tokens(client, query="phishing", **parameters):
    response = client.get("/explore", query_string={
        "tab": "search", "q": query, **parameters,
    })
    assert response.status_code == 200
    with client.session_transaction() as session:
        return response, session["summary_csrf"], session["summary_submission_token"]


def _payload(csrf, submission, **overrides):
    return {
        "csrf_token": csrf,
        "submission_token": submission,
        "q": "phishing",
        "severity": "",
        "category": "",
        "sort": "relevance",
        "page": "1",
        **overrides,
    }


def _use_successful_generator(app):
    class GroundedGenerator:
        def generate_summary(self, prompt_package):
            records = prompt_package["retrieved_context"]["records"]
            return GenerationResult(
                output={
                    "summary": "The supplied records describe phishing activity.",
                    "key_findings": [{
                        "finding": record["description"],
                        "supporting_record_ids": [record["record_id"]],
                    } for record in records],
                    "limitations": [],
                },
                model_identifier="test-hosted-model-2026-11-01",
            )
    app.extensions["summary_generator"] = GroundedGenerator()


def test_search_action_generates_saved_escaped_summary_with_preserved_state(app, client):
    _seed(app)
    _use_successful_generator(app)
    search, csrf, submission = _tokens(
        client, severity="High", category="Phishing", sort="alphabetical",
    )
    assert b"Summarize results" in search.data
    assert b"12,000-byte context limit" in search.data
    assert b'name="severity" value="High"' in search.data

    response = client.post("/summaries/generate", data=_payload(
        csrf,
        submission,
        severity="High",
        category="Phishing",
        sort="alphabetical",
    ))

    assert response.status_code == 303
    assert "/summaries/" in response.headers["Location"]
    detail = client.get(response.headers["Location"])
    assert detail.status_code == 200
    assert b"Generated summary" in detail.data
    assert b"not an original threat record" in detail.data
    assert b"test-hosted-model-2026-11-01" in detail.data
    assert b"Key findings" in detail.data
    assert b"Supporting records" in detail.data
    assert b"View validated structured JSON" in detail.data
    assert b"<script>alert('source')</script>" not in detail.data
    assert b"&lt;script&gt;alert" in detail.data

    with app.app_context():
        stored = db.session.scalar(db.select(StoredIntelligence))
        assert stored.owner_sub == "Owner-A"
        retrieval = stored.context_snapshot["retrieval"]
        assert retrieval["query"] == "phishing"
        assert retrieval["severity"] == "High"
        assert retrieval["category"] == "Phishing"
        assert retrieval["sort"] == "alphabetical"
        assert retrieval["page"] == 1
        assert len(stored.source_record_ids) == 1
        assert stored.context_snapshot["records"][0]["severity"] == "High"

    history = client.get("/summaries")
    assert history.status_code == 200
    assert b"Summarize the current ThreatLense search results for: phishing" in history.data


def test_generation_rejects_repeated_or_browser_supplied_record_content(app, client):
    _seed(app)
    _use_successful_generator(app)
    _, csrf, submission = _tokens(client)
    payload = _payload(csrf, submission)

    first = client.post("/summaries/generate", data=payload)
    assert first.status_code == 303
    assert client.post("/summaries/generate", data=payload).status_code == 400

    _, csrf, submission = _tokens(client)
    untrusted = _payload(csrf, submission, description="Browser supplied record text")
    assert client.post("/summaries/generate", data=untrusted).status_code == 400
    with app.app_context():
        assert db.session.scalar(
            db.select(db.func.count()).select_from(StoredIntelligence)
        ) == 1


def test_generation_no_results_returns_to_same_search_without_storing(app, client):
    class MustNotBeCalled:
        def generate_summary(self, prompt_package):
            raise AssertionError("Provider must not be called for empty retrieval")

    _seed(app)
    app.extensions["summary_generator"] = MustNotBeCalled()
    _, csrf, submission = _tokens(client, query="no-such-threat", severity="High")

    response = client.post("/summaries/generate", data=_payload(
        csrf, submission, q="no-such-threat", severity="High",
    ), follow_redirects=True)

    assert response.status_code == 200
    assert b"No matching source records are available to summarize" in response.data
    assert b'name="q"' in response.data
    assert b'value="no-such-threat"' in response.data
    with app.app_context():
        assert db.session.scalar(
            db.select(db.func.count()).select_from(StoredIntelligence)
        ) == 0


def test_provider_failure_is_safe_and_does_not_store(app, client):
    class FailingGenerator:
        def generate_summary(self, prompt_package):
            raise AiServiceError("secret provider response")

    _seed(app)
    app.extensions["summary_generator"] = FailingGenerator()
    _, csrf, submission = _tokens(client)

    response = client.post(
        "/summaries/generate",
        data=_payload(csrf, submission),
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"summary service could not complete" in response.data
    assert b"secret provider response" not in response.data
    with app.app_context():
        assert db.session.scalar(
            db.select(db.func.count()).select_from(StoredIntelligence)
        ) == 0


def test_missing_api_key_preserves_search_and_does_not_store(app, client):
    _seed(app)
    _, csrf, submission = _tokens(client)

    response = client.post(
        "/summaries/generate",
        data=_payload(csrf, submission),
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"summarization is not configured" in response.data
    assert b"Cloud phishing alert" in response.data
    with app.app_context():
        assert db.session.scalar(
            db.select(db.func.count()).select_from(StoredIntelligence)
        ) == 0


def test_invalid_model_output_is_not_persisted(app, client):
    class InvalidGenerator:
        def generate_summary(self, prompt_package):
            return GenerationResult(
                output={"summary": "Missing required fields"},
                model_identifier="test-model",
            )

    _seed(app)
    app.extensions["summary_generator"] = InvalidGenerator()
    _, csrf, submission = _tokens(client)
    response = client.post(
        "/summaries/generate", data=_payload(csrf, submission), follow_redirects=True,
    )

    assert b"did not pass validation" in response.data
    with app.app_context():
        assert db.session.scalar(
            db.select(db.func.count()).select_from(StoredIntelligence)
        ) == 0


def test_database_read_failure_returns_to_search(app, client):
    _seed(app)
    _use_successful_generator(app)
    _, csrf, submission = _tokens(client)
    with patch(
        "services.summary_generation.build_summary_context",
        side_effect=SQLAlchemyError("private database detail"),
    ):
        response = client.post(
            "/summaries/generate", data=_payload(csrf, submission), follow_redirects=True,
        )

    assert b"Threat records could not be retrieved" in response.data
    assert b"Cloud phishing alert" in response.data
    assert b"private database detail" not in response.data


def test_valid_generation_save_failure_is_distinguished_and_rolled_back(app, client):
    _seed(app)
    _use_successful_generator(app)
    _, csrf, submission = _tokens(client)
    with patch(
        "services.summary_generation.store_validated_summary",
        side_effect=SQLAlchemyError("private write detail"),
    ):
        response = client.post(
            "/summaries/generate", data=_payload(csrf, submission), follow_redirects=True,
        )

    assert b"valid summary was generated but could not be saved" in response.data
    assert b"No stored result is available" in response.data
    assert b"private write detail" not in response.data
    with app.app_context():
        assert db.session.scalar(
            db.select(db.func.count()).select_from(StoredIntelligence)
        ) == 0


def test_summary_history_and_detail_are_owner_scoped(app, client):
    _seed(app)
    _use_successful_generator(app)
    _, csrf, submission = _tokens(client)
    created = client.post("/summaries/generate", data=_payload(csrf, submission))
    summary_url = created.headers["Location"]

    other = app.test_client()
    with other.session_transaction() as session:
        session["owner_sub"] = "other-owner"

    assert other.get(summary_url).status_code == 404
    assert b"Cloud phishing alert" not in other.get("/summaries").data


def test_generation_requires_valid_csrf(app, client):
    _seed(app)
    _tokens(client)

    response = client.post("/summaries/generate", data=_payload("wrong", "wrong"))

    assert response.status_code == 400
