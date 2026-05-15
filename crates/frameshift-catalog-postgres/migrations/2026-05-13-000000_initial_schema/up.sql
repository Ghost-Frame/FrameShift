-- Initial schema for the frameshift catalog.
--
-- Tables are created in dependency order: authors first (no foreign keys),
-- then packs and pack_versions (reference authors), then handles (reference authors).
-- All timestamps are TIMESTAMPTZ to avoid silent timezone bugs.

-- Authors: one row per registered Ed25519 keypair + handle pair.
CREATE TABLE authors (
    -- Raw 32-byte Ed25519 public key; primary identifier for all author operations.
    pubkey        BYTEA        NOT NULL PRIMARY KEY,
    -- Unique human-readable handle chosen by the author (e.g. "alice").
    -- Case-sensitive at the DB level; the server layer is responsible for
    -- normalizing handles (e.g. lowercasing) before insert.
    handle        TEXT         NOT NULL UNIQUE,
    -- Optional display name; NULL means the author did not supply one.
    -- Empty strings are rejected at the application layer before insert.
    display_name  TEXT,
    -- UTC timestamp when this author record was first created.
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    -- JSON array of OAuth provider links [{provider, subject, linked_at}, ...].
    -- Stored opaquely; parsed by the application layer.
    oauth_links   JSONB        NOT NULL DEFAULT '[]'
);

-- Packs: one row per named persona pack; tracks the mutable "head" metadata.
CREATE TABLE packs (
    -- Globally unique pack name (e.g. "my-persona").
    name              TEXT        NOT NULL PRIMARY KEY,
    -- Ed25519 pubkey of the current pack owner; references authors(pubkey).
    current_author    BYTEA       NOT NULL REFERENCES authors(pubkey),
    -- Array of tag strings for search and discovery (e.g. {"roleplay","assistant"}).
    tags              TEXT[]      NOT NULL DEFAULT '{}',
    -- Short human-readable description of the pack.
    description       TEXT        NOT NULL DEFAULT '',
    -- UTC timestamp when this pack was first registered.
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Semver string of the most-recently published version; NULL until first version.
    latest_version    TEXT,
    -- Cumulative download count across all versions; monotonically increasing.
    total_downloads   BIGINT      NOT NULL DEFAULT 0
);

-- Pack versions: immutable append-only version history.
-- Status is the only mutable field (Active -> Tombstone transition only).
CREATE TABLE pack_versions (
    -- The parent pack name; ON DELETE RESTRICT prevents pack deletion while versions exist.
    pack_name               TEXT        NOT NULL REFERENCES packs(name) ON DELETE RESTRICT,
    -- Semver version string (e.g. "1.2.0").
    version                 TEXT        NOT NULL,
    -- Raw 32-byte SHA-256 content hash of the pack artifact.
    content_hash            BYTEA       NOT NULL,
    -- Raw 64-byte Ed25519 signature over the canonical pack content.
    -- CHECK constraint enforces the exact byte length required by Ed25519.
    signature               BYTEA       NOT NULL CHECK (octet_length(signature) = 64),
    -- Ed25519 pubkey of the author who published this version.
    author_pubkey           BYTEA       NOT NULL REFERENCES authors(pubkey),
    -- Raw 32-byte SHA-256 hash of the previous version in the history chain.
    -- NULL for the first version of a pack. Catalog does NOT validate existence;
    -- transparency log infrastructure enforces lineage separately.
    parent_hash             BYTEA,
    -- JSON object describing requested capabilities (schema defined by pack runtime).
    capability_manifest_json JSONB      NOT NULL,
    -- Integer identifying the pack schema format used at publication time.
    schema_version          INTEGER     NOT NULL,
    -- SPDX license identifier (e.g. "MIT", "Apache-2.0").
    license                 TEXT        NOT NULL,
    -- UTC timestamp when this version was published.
    published_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- JSON object representing publication status.
    -- Wire shape: {"kind":"active"} or {"kind":"tombstone","reason":"...","recorded_at":"..."}.
    status                  JSONB       NOT NULL DEFAULT '{"kind":"active"}',
    -- Size of the pack artifact in bytes as stored in the object store.
    size_bytes              BIGINT      NOT NULL,
    -- Composite primary key: a pack can have at most one row per version string.
    PRIMARY KEY (pack_name, version)
);

-- Handles: handle-to-pubkey mapping table, separate from authors.handle.
-- This table supports handle ownership transfers without changing the authors row.
-- The authors.handle column reflects the initial registration; handles.pubkey
-- reflects the current owner after any transfers.
CREATE TABLE handles (
    -- The handle string; globally unique.
    handle      TEXT        NOT NULL PRIMARY KEY,
    -- Current owner's Ed25519 pubkey.
    pubkey      BYTEA       NOT NULL REFERENCES authors(pubkey),
    -- UTC timestamp of the most recent ownership update.
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
