"""Focused grounding review; schema validity alone is not factual verification."""

from services.summary_validation import validate_generated_output


CONTEXT = {
    "records": [
        {
            "record_id": 11,
            "name": "Cloud phishing",
            "description": "A login lure targeted cloud accounts.",
        },
        {
            "record_id": 12,
            "name": "Edge scanning",
            "description": "Scanning targeted exposed edge devices.",
        },
    ],
    "limitations": [],
}


def test_review_fixture_findings_are_traceable_to_their_cited_records():
    candidate = {
        "summary": "The supplied records describe phishing and edge-device scanning.",
        "key_findings": [
            {
                "finding": "Cloud phishing used a login lure against cloud accounts.",
                "supporting_record_ids": [11],
            },
            {
                "finding": "Edge scanning targeted exposed edge devices.",
                "supporting_record_ids": [12],
            },
        ],
        "limitations": [],
    }
    validated = validate_generated_output(candidate, CONTEXT).data
    sources = {record["record_id"]: record for record in CONTEXT["records"]}

    # This evaluation fixture performs a human-authored grounding expectation:
    # every finding must reuse a distinctive fact from each record it cites.
    expected_terms = {11: "cloud accounts", 12: "edge devices"}
    for finding in validated["key_findings"]:
        for record_id in finding["supporting_record_ids"]:
            assert record_id in sources
            assert expected_terms[record_id] in finding["finding"].casefold()


def test_schema_and_citation_validation_do_not_prove_factual_accuracy():
    unsupported_but_well_shaped = {
        "summary": "The supplied records predict an unrelated event.",
        "key_findings": [{
            "finding": "An unsupported event will occur tomorrow.",
            "supporting_record_ids": [11],
        }],
        "limitations": [],
    }

    # This passes structural validation because ID 11 exists. The test documents
    # why prompt grounding and factual evaluation remain necessary.
    validated = validate_generated_output(unsupported_but_well_shaped, CONTEXT)
    assert validated.data["key_findings"][0]["supporting_record_ids"] == [11]
    assert "tomorrow" not in CONTEXT["records"][0]["description"]
