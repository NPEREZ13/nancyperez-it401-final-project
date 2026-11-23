"""Persist only validated A5 summary output and its audit context."""

from copy import deepcopy
from datetime import datetime, timezone

from sqlalchemy.exc import SQLAlchemyError

from models import StoredIntelligence, db
from services.summary_validation import (
    SummaryOutputError, ValidatedSummary, nonempty_text,
)


def store_validated_summary(
    *,
    owner,
    validated_output,
    model_identifier,
    prompt_package,
    generated_at=None,
):
    """Save a validated result against the exact package supplied to the provider."""
    if not isinstance(validated_output, ValidatedSummary):
        raise SummaryOutputError("validated_output must be a ValidatedSummary.")
    if not isinstance(owner, str) or not owner:
        raise SummaryOutputError("A trusted owner is required.")
    if not isinstance(prompt_package, dict):
        raise SummaryOutputError("prompt_package must be an object.")
    try:
        user_request = prompt_package["user_request"]
        prompt_version = prompt_package["prompt_version"]
        supplied_context = prompt_package["retrieved_context"]
    except KeyError as error:
        raise SummaryOutputError(
            f"prompt_package is missing {error.args[0]}."
        ) from error
    user_request = nonempty_text(user_request, "user_request", 2_000)
    prompt_version = nonempty_text(prompt_version, "prompt_version", 64)
    model_identifier = nonempty_text(model_identifier, "model_identifier", 160)
    if not isinstance(supplied_context, dict):
        raise SummaryOutputError("supplied_context must be an object.")

    if generated_at is None:
        generated_at = datetime.now(timezone.utc)
    if not isinstance(generated_at, datetime) or generated_at.tzinfo is None:
        raise SummaryOutputError("generated_at must be a timezone-aware UTC datetime.")
    generated_at_utc = generated_at.astimezone(timezone.utc).replace(tzinfo=None)
    context_snapshot = deepcopy(supplied_context)
    source_record_ids = [
        record["record_id"] for record in context_snapshot.get("records", [])
    ]

    stored = StoredIntelligence(
        owner_sub=owner,
        user_request=user_request,
        generated_output=deepcopy(validated_output.data),
        prompt_version=prompt_version,
        model_identifier=model_identifier,
        generated_at_utc=generated_at_utc,
        source_record_ids=source_record_ids,
        context_snapshot=context_snapshot,
    )
    db.session.add(stored)
    try:
        db.session.commit()
    except SQLAlchemyError:
        db.session.rollback()
        raise
    return stored
