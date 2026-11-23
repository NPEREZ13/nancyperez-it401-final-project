"""Application-level validation for structured threat-summary output."""

import json
from copy import deepcopy
from dataclasses import dataclass


MAX_SUMMARY_CHARACTERS = 10_000
MAX_FINDINGS = 20
MAX_FINDING_CHARACTERS = 2_000
MAX_LIMITATIONS = 30
MAX_LIMITATION_CHARACTERS = 1_000


class SummaryOutputError(ValueError):
    """Raised when generated output does not satisfy the stored schema."""


@dataclass(frozen=True)
class ValidatedSummary:
    """Marker type ensuring persistence receives application-validated output."""

    data: dict


def nonempty_text(value, field, limit):
    if not isinstance(value, str) or not value.strip():
        raise SummaryOutputError(f"{field} must be a nonempty string.")
    value = value.strip()
    if len(value) > limit:
        raise SummaryOutputError(f"{field} exceeds {limit} characters.")
    return value


def _parse_output(output):
    if isinstance(output, str):
        try:
            output = json.loads(output)
        except (TypeError, ValueError) as error:
            raise SummaryOutputError("Generated output is not valid JSON.") from error
    if not isinstance(output, dict):
        raise SummaryOutputError("Generated output must be a JSON object.")
    return output


def validate_generated_output(output, supplied_context):
    """Validate shape and citations; this does not prove factual accuracy."""
    if not isinstance(supplied_context, dict):
        raise SummaryOutputError("supplied_context must be an object.")
    output = _parse_output(output)
    required = {"summary", "key_findings", "limitations"}
    if set(output) != required:
        raise SummaryOutputError(
            "Generated output must contain only summary, key_findings, and limitations."
        )

    summary = nonempty_text(output["summary"], "summary", MAX_SUMMARY_CHARACTERS)
    supplied_ids = {
        record.get("record_id")
        for record in supplied_context.get("records", [])
        if isinstance(record, dict)
        and isinstance(record.get("record_id"), int)
        and not isinstance(record.get("record_id"), bool)
    }

    raw_findings = output["key_findings"]
    if (
        not isinstance(raw_findings, list)
        or not raw_findings
        or len(raw_findings) > MAX_FINDINGS
    ):
        raise SummaryOutputError(
            f"key_findings must be a nonempty list of at most {MAX_FINDINGS} items."
        )
    findings = []
    for index, finding in enumerate(raw_findings):
        if not isinstance(finding, dict) or set(finding) != {
            "finding", "supporting_record_ids",
        }:
            raise SummaryOutputError(
                f"key_findings[{index}] must contain only finding and supporting_record_ids."
            )
        text = nonempty_text(
            finding["finding"],
            f"key_findings[{index}].finding",
            MAX_FINDING_CHARACTERS,
        )
        record_ids = finding["supporting_record_ids"]
        if (
            not isinstance(record_ids, list)
            or not record_ids
            or len(record_ids) > 5
            or any(not isinstance(value, int) or isinstance(value, bool) for value in record_ids)
            or len(record_ids) != len(set(record_ids))
        ):
            raise SummaryOutputError(
                f"key_findings[{index}].supporting_record_ids must be a nonempty "
                "list of at most 5 unique integer IDs."
            )
        unknown = set(record_ids) - supplied_ids
        if unknown:
            raise SummaryOutputError(
                f"key_findings[{index}] cites records that were not supplied: "
                + ", ".join(str(value) for value in sorted(unknown))
                + "."
            )
        findings.append({"finding": text, "supporting_record_ids": record_ids})

    raw_limitations = output["limitations"]
    if not isinstance(raw_limitations, list) or len(raw_limitations) > MAX_LIMITATIONS:
        raise SummaryOutputError(
            f"limitations must be a list of at most {MAX_LIMITATIONS} items."
        )
    limitations = [
        nonempty_text(value, f"limitations[{index}]", MAX_LIMITATION_CHARACTERS)
        for index, value in enumerate(raw_limitations)
    ]
    for limitation in supplied_context.get("limitations", []):
        limitation = nonempty_text(
            limitation, "retrieval limitation", MAX_LIMITATION_CHARACTERS,
        )
        if limitation not in limitations:
            limitations.append(limitation)
    if len(limitations) > MAX_LIMITATIONS:
        raise SummaryOutputError(
            f"Combined limitations exceed the {MAX_LIMITATIONS}-item limit."
        )

    return ValidatedSummary(deepcopy({
        "summary": summary,
        "key_findings": findings,
        "limitations": limitations,
    }))
