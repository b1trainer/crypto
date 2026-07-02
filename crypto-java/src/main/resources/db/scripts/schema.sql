CREATE TABLE IF NOT EXISTS documents (
    id          BIGINT PRIMARY KEY AUTO_INCREMENT,
    name        VARCHAR(255) NOT NULL UNIQUE,
    content_type VARCHAR(100),
    data        BLOB,
    size        BIGINT,
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS cryptedDocuments (
    id          BIGINT PRIMARY KEY AUTO_INCREMENT,
    document_id BIGINT,
    document_name VARCHAR(255) NOT NULL UNIQUE,
    operation_type VARCHAR(50) NOT NULL,
    data        BLOB,
    size        BIGINT,
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS operations_log (
    id          BIGINT PRIMARY KEY AUTO_INCREMENT,
    operation_type VARCHAR(50) NOT NULL,
    status      VARCHAR(20) DEFAULT 'SUCCESS',
    details     TEXT,
    duration_ms BIGINT,
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
