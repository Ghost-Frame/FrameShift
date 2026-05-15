-- Schema version 1: memories with FTS5 full-text search and tag filtering.

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS memories (
    id          TEXT PRIMARY KEY NOT NULL,
    text        TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER,
    metadata    TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_memories_created_at ON memories (created_at);

CREATE TABLE IF NOT EXISTS memory_tags (
    memory_id TEXT NOT NULL REFERENCES memories(id) ON DELETE CASCADE,
    tag       TEXT NOT NULL,
    PRIMARY KEY (memory_id, tag)
);

CREATE INDEX IF NOT EXISTS idx_memory_tags_tag ON memory_tags (tag);

CREATE VIRTUAL TABLE IF NOT EXISTS memories_fts USING fts5 (
    text,
    content='memories',
    content_rowid='rowid'
);

-- Keep memories_fts in sync with the memories table.

CREATE TRIGGER IF NOT EXISTS memories_fts_insert
AFTER INSERT ON memories BEGIN
    INSERT INTO memories_fts (rowid, text) VALUES (new.rowid, new.text);
END;

CREATE TRIGGER IF NOT EXISTS memories_fts_update
AFTER UPDATE ON memories BEGIN
    INSERT INTO memories_fts (memories_fts, rowid, text) VALUES ('delete', old.rowid, old.text);
    INSERT INTO memories_fts (rowid, text) VALUES (new.rowid, new.text);
END;

CREATE TRIGGER IF NOT EXISTS memories_fts_delete
AFTER DELETE ON memories BEGIN
    INSERT INTO memories_fts (memories_fts, rowid, text) VALUES ('delete', old.rowid, old.text);
END;
