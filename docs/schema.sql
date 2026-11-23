-- Reference/bootstrap schema for a NEW development database.
-- Existing Aiven threat/device tables are already provisioned: do not drop or recreate them.
-- Apply migrations/20261122_01_add_stored_intelligence.sql to an existing A5 database.
-- IF NOT EXISTS preserves existing tables; it does not migrate mismatched schemas.
-- No search-history/telemetry table is implemented in this version.

CREATE TABLE IF NOT EXISTS profile_devices (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    owner_sub VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    name VARCHAR(80) NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    result_json JSON NULL,
    checked_at DATETIME NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_devices_owner (owner_sub)
);

CREATE TABLE IF NOT EXISTS user_threats (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    owner_sub VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    name VARCHAR(120) NOT NULL,
    severity VARCHAR(10) NOT NULL,
    category VARCHAR(80) NOT NULL,
    description TEXT NOT NULL,
    mitigation TEXT NOT NULL,
    PRIMARY KEY (id),
    KEY idx_threats_owner (owner_sub)
);

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
