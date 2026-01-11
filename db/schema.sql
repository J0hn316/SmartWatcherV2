-- Audit table: one row per observed file event
CREATE TABLE IF NOT EXISTS audit_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,

  -- when the event was recorded (UTC)
  event_time TEXT NOT NULL,

  -- event type: created, modified, moved, deleted, etc.
  event_type TEXT NOT NULL,

  -- paths (old/new for moves/renames)
  src_path TEXT,
  dest_path TEXT,

  -- file metadata (optional but useful)
  file_size_bytes INTEGER,
  sha256 TEXT,

  -- extra context as JSON string (future-proofing)
  extra_json TEXT
);

-- Helpful indexes for searching
CREATE INDEX IF NOT EXISTS idx_audit_events_time
  ON audit_events(event_time);

CREATE INDEX IF NOT EXISTS idx_audit_events_type
  ON audit_events(event_type);

CREATE INDEX IF NOT EXISTS idx_audit_events_src_path
  ON audit_events(src_path);