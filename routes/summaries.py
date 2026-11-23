"""Owner-scoped generation, history, and detail views for A5 summaries."""

import json
import secrets

from flask import (
    Blueprint, abort, current_app, flash, redirect, render_template, request,
    session, url_for,
)

from models import StoredIntelligence, db
from services.ai_service import (
    AiConfigurationError, AiProviderError, AiRateLimitError, AiRefusalError, AiServiceError,
    AiResponseError, AiTimeoutError,
)
from services.records import current_owner, owned_query
from services.summary_context import SummaryContextError
from services.summary_generation import (
    EmptySummaryContextError, InvalidGeneratedSummaryError,
    SummaryPersistenceError, SummaryRetrievalError, generate_and_store_summary,
)


summaries = Blueprint("summaries", __name__, url_prefix="/summaries")

_GENERATION_FIELDS = {
    "csrf_token", "submission_token", "q", "severity", "category", "sort", "page",
}


def ensure_summary_form_tokens():
    """Create tokens while rendering Search; POST validation stays in this blueprint."""
    if current_owner():
        session.setdefault("summary_csrf", secrets.token_urlsafe(32))
        session.setdefault("summary_submission_token", secrets.token_urlsafe(32))


def _search_parameters(form):
    return {
        "q": form.get("q", ""),
        "severity": form.get("severity", ""),
        "category": form.get("category", ""),
        "sort": form.get("sort", "relevance"),
        "page": form.get("page", "1"),
    }


def _results_url(parameters):
    return url_for("explore", tab="search", **parameters)


@summaries.before_request
def protect():
    if not current_owner():
        flash("Sign in or create a private workspace before generating summaries.", "error")
        return redirect(url_for("explore", tab="search"))
    if request.method == "POST":
        csrf_token = request.form.get("csrf_token", "")
        expected_csrf = session.get("summary_csrf")
        submission_token = request.form.get("submission_token", "")
        expected_submission = session.get("summary_submission_token")
        if (
            not expected_csrf
            or not csrf_token.isascii()
            or not secrets.compare_digest(expected_csrf, csrf_token)
            or not expected_submission
            or not submission_token.isascii()
            or not secrets.compare_digest(expected_submission, submission_token)
        ):
            abort(400)
        # Consume before generation. Refreshing Search creates a new token, while
        # a repeated POST with this token is rejected.
        session.pop("summary_submission_token", None)


@summaries.post("/generate")
def generate():
    if set(request.form) - _GENERATION_FIELDS:
        abort(400)
    parameters = _search_parameters(request.form)
    return_url = _results_url(parameters)
    query = parameters["q"]
    if not query.strip():
        flash("Run a keyword search before requesting a summary.", "error")
        return redirect(return_url)

    user_request = f"Summarize the current ThreatLense search results for: {query.strip()}"
    generator = current_app.extensions["summary_generator"]
    try:
        workflow = generate_and_store_summary(
            owner=current_owner(),
            user_request=user_request,
            retrieval_parameters=parameters,
            generator=generator,
        )
    except SummaryContextError as error:
        flash(str(error), "error")
        return redirect(return_url)
    except EmptySummaryContextError:
        flash("No matching source records are available to summarize.", "error")
        return redirect(return_url)
    except SummaryRetrievalError as error:
        current_app.logger.error("Summary retrieval failed (%s)", type(error).__name__)
        flash("Threat records could not be retrieved. Your existing search results remain available.", "error")
        return redirect(return_url)
    except AiConfigurationError as error:
        current_app.logger.error("Summary provider configuration failed (%s)", type(error).__name__)
        flash("Threat summarization is not configured. Ask an administrator to check the model settings.", "error")
        return redirect(return_url)
    except AiRateLimitError as error:
        current_app.logger.error("Summary provider rate limited (%s)", type(error).__name__)
        flash("The summary service is temporarily busy. Wait a moment and try again.", "error")
        return redirect(return_url)
    except AiTimeoutError as error:
        current_app.logger.error("Summary provider timed out (%s)", type(error).__name__)
        flash("Summary generation timed out. Your search results are unchanged; try again.", "error")
        return redirect(return_url)
    except AiRefusalError as error:
        current_app.logger.error("Summary provider refused request (%s)", type(error).__name__)
        flash("The model could not summarize these records. No summary was saved.", "error")
        return redirect(return_url)
    except (AiProviderError, AiResponseError) as error:
        current_app.logger.error("Summary provider failed (%s)", type(error).__name__)
        flash("The summary service could not complete this request. Please try again.", "error")
        return redirect(return_url)
    except AiServiceError as error:
        current_app.logger.error("Summary service failed (%s)", type(error).__name__)
        flash("The summary service could not complete this request. Please try again.", "error")
        return redirect(return_url)
    except InvalidGeneratedSummaryError as error:
        current_app.logger.error("Generated summary validation failed (%s)", type(error).__name__)
        flash("The generated summary did not pass validation. Please try again.", "error")
        return redirect(return_url)
    except SummaryPersistenceError as error:
        current_app.logger.error("Valid summary persistence failed (%s)", type(error).__name__)
        flash("A valid summary was generated but could not be saved. No stored result is available; your search results are unchanged.", "error")
        return redirect(return_url)

    flash("Summary generated and saved.", "success")
    return redirect(url_for("summaries.detail", summary_id=workflow.stored.id), code=303)


@summaries.get("")
def history():
    records = db.session.scalars(
        owned_query(StoredIntelligence, current_owner())
        .order_by(StoredIntelligence.generated_at_utc.desc(), StoredIntelligence.id.desc())
    ).all()
    return render_template("summary_history.html", summaries=records)


@summaries.get("/<int:summary_id>")
def detail(summary_id):
    stored = db.session.scalar(
        owned_query(StoredIntelligence, current_owner())
        .where(StoredIntelligence.id == summary_id)
    )
    if stored is None:
        abort(404)
    context = stored.context_snapshot if isinstance(stored.context_snapshot, dict) else {}
    retrieval = context.get("retrieval", {})
    results_url = url_for(
        "explore",
        tab="search",
        q=retrieval.get("query", ""),
        severity=retrieval.get("severity", ""),
        category=retrieval.get("category", ""),
        sort=retrieval.get("sort", "relevance"),
        page=retrieval.get("page", 1),
    )
    output = stored.generated_output if isinstance(stored.generated_output, dict) else {}
    return render_template(
        "summary_detail.html",
        stored=stored,
        output=output,
        context=context,
        results_url=results_url,
        output_json=json.dumps(output, ensure_ascii=False, indent=2, sort_keys=True),
    )
