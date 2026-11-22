CREATE TABLE IF NOT EXISTS audit_sessions (
    session_id TEXT PRIMARY KEY,
    started_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ended_at TIMESTAMP,
    command TEXT NOT NULL,
    exit_code INTEGER
);

CREATE TABLE IF NOT EXISTS audit_events (
    event_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    http_method TEXT NOT NULL,
    host TEXT NOT NULL,
    port INTEGER NOT NULL,
    path_sanitized TEXT NOT NULL,
    action TEXT NOT NULL,
    injected_key_name TEXT,
    scrub_count INTEGER NOT NULL DEFAULT 0,
    http_status INTEGER NOT NULL,
    latency_ms REAL NOT NULL,
    details TEXT,
    FOREIGN KEY(session_id) REFERENCES audit_sessions(session_id)
);

CREATE INDEX IF NOT EXISTS idx_audit_events_session ON audit_events(session_id);
CREATE INDEX IF NOT EXISTS idx_audit_events_host ON audit_events(host);
CREATE INDEX IF NOT EXISTS idx_audit_events_action ON audit_events(action);
CREATE INDEX IF NOT EXISTS idx_audit_events_timestamp ON audit_events(timestamp);
