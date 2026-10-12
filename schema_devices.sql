CREATE TABLE IF NOT EXISTS profile_devices (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    owner_sub VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    name VARCHAR(80) NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    result_json JSON NULL,
    checked_at DATETIME NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_devices_owner (owner_sub)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
