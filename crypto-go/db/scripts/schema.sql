CREATE TABLE IF NOT EXISTS documents (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE,
    content_type TEXT,
    data        BLOB,
    size        INTEGER,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS cryptedDocuments (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    document_id INTEGER,
    document_name TEXT NOT NULL UNIQUE,
    operation_type TEXT NOT NULL,
    data        BLOB,
    size        INTEGER,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS operations_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    operation_type TEXT NOT NULL,
    status      TEXT DEFAULT 'SUCCESS',
    details     TEXT,
    duration_ms INTEGER,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);
