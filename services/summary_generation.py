"""Orchestrate retrieval, prompting, hosted generation, validation, and storage."""

from dataclasses import dataclass

from sqlalchemy.exc import SQLAlchemyError

from models import db
from services.summary_context import SummaryContextError, build_summary_context
from services.summary_prompt import build_summary_prompt
from services.summary_storage import store_validated_summary
from services.summary_validation import SummaryOutputError, validate_generated_output


class SummaryWorkflowError(RuntimeError):
    pass


class EmptySummaryContextError(SummaryWorkflowError):
    pass


class SummaryRetrievalError(SummaryWorkflowError):
    pass


class InvalidGeneratedSummaryError(SummaryWorkflowError):
    pass


class SummaryPersistenceError(SummaryWorkflowError):
    """A valid generation exists in memory but was not stored."""


@dataclass(frozen=True)
class SummaryWorkflowResult:
    stored: object


def generate_and_store_summary(
    *, owner, user_request, retrieval_parameters, generator,
):
    """Execute the A5 workflow without relying on browser-supplied record content."""
    try:
        context = build_summary_context(
            owner,
            user_request,
            retrieval_parameters=retrieval_parameters,
        )
    except SummaryContextError:
        raise
    except SQLAlchemyError as error:
        db.session.rollback()
        raise SummaryRetrievalError("Threat retrieval failed.") from error
    if not context["records"]:
        # This check deliberately occurs before prompt construction/provider access.
        raise EmptySummaryContextError("No matching source records are available.")

    prompt_package = build_summary_prompt(user_request, context)
    generated = generator.generate_summary(prompt_package)
    try:
        validated = validate_generated_output(generated.output, context)
    except SummaryOutputError as error:
        raise InvalidGeneratedSummaryError("Generated output failed validation.") from error

    try:
        stored = store_validated_summary(
            owner=owner,
            validated_output=validated,
            model_identifier=generated.model_identifier,
            prompt_package=prompt_package,
        )
    except SummaryOutputError as error:
        raise InvalidGeneratedSummaryError("Generated output failed storage validation.") from error
    except SQLAlchemyError as error:
        db.session.rollback()
        raise SummaryPersistenceError(
            "A valid summary was generated but could not be saved."
        ) from error
    return SummaryWorkflowResult(stored=stored)
