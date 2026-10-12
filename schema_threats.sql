CREATE TABLE IF NOT EXISTS user_threats (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    owner_sub VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    name VARCHAR(120) NOT NULL,
    severity VARCHAR(10) NOT NULL,
    category VARCHAR(80) NOT NULL,
    description TEXT NOT NULL,
    mitigation TEXT NOT NULL,
    INDEX idx_threats_owner (owner_sub)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
