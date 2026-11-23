-- Additive A5 migration. Safe for existing data: no table is dropped or replaced.
CREATE TABLE IF NOT EXISTS stored_intelligence (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    owner_sub VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    user_request TEXT NOT NULL,
    generated_output JSON NOT NULL,
    prompt_version VARCHAR(64) NOT NULL,
    model_identifier VARCHAR(160) NOT NULL,
    generated_at_utc DATETIME(6) NOT NULL,
    source_record_ids JSON NOT NULL,
    context_snapshot JSON NOT NULL,
    PRIMARY KEY (id),
    KEY idx_intelligence_owner_generated (owner_sub, generated_at_utc)
);
