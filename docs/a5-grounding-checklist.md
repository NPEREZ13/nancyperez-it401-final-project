# A5 Manual Grounding Checklist

Use this checklist when reviewing a generated ThreatLense summary. Passing JSON-schema and citation validation is necessary, but it does not prove that a model claim is factually supported.

## Generation identity

- [ ] Record the stored-summary ID.
- [ ] Confirm the generation timestamp, prompt version, and actual model identifier are present.
- [ ] Confirm the displayed user request matches the request saved with the generation.

## Retrieval coverage

- [ ] Compare `selected_record_count` with `total_matching_records` in the stored context.
- [ ] Note whether `covers_subset` is true.
- [ ] Review every context-limit or truncation message before judging completeness.
- [ ] Confirm the query, severity/category filters, sort order, and page match the intended search.

## Finding-by-finding review

For every key finding:

- [ ] Confirm every cited ID exists in the exact stored `context_snapshot.records` list.
- [ ] Open each cited snapshot record; do not rely only on the current editable threat row.
- [ ] Identify the exact name, description, severity, category, target, mitigation, URL, or date supporting the finding.
- [ ] Mark the finding unsupported if the cited record merely concerns the same topic but does not support the specific claim.
- [ ] Check that severity, dates, affected targets, and causal language were not inferred from missing values.
- [ ] Check that instructions or prompt-like text inside a source record were treated as data rather than followed.

## Overall summary review

- [ ] Map every material summary claim to at least one supplied record.
- [ ] Check for contradictions between the summary and any selected record.
- [ ] Confirm absent source URLs, dates, targets, or other context are acknowledged rather than invented.
- [ ] Confirm the summary introduces no unsupported current events, threat activity, mitigation, or recommendation.
- [ ] Confirm subset coverage is not described as a complete account of all matching records.

## Review outcome

| Field | Reviewer entry |
| --- | --- |
| Stored-summary ID | |
| Reviewer and UTC date | |
| Grounded findings / total findings | |
| Unsupported or overstated claims | |
| Missing or truncated evidence | |
| Outcome (`pass`, `needs revision`, `do not use`) | |

If any material claim is unsupported, treat the summary as unverified. Retain the stored output and context for evaluation, but do not present schema validity or valid citations as proof that hallucinations were prevented.
