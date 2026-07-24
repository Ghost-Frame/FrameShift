-- Add the non-public persistence primitive for exact, one-time publication intents.
-- HTTP routes, quarantine storage, moderation, and public promotion remain out of scope.

ALTER TABLE publisher_keys
    ADD CONSTRAINT publisher_keys_id_publisher_unique UNIQUE (id, publisher_id);

CREATE TABLE publication_intents (
    id UUID PRIMARY KEY,
    account_id UUID NOT NULL,
    publisher_id UUID NOT NULL,
    publisher_key_id UUID NOT NULL,
    archive_hash BYTEA NOT NULL,
    manifest_hash BYTEA NOT NULL,
    file_inventory_hash BYTEA NOT NULL,
    scan_schema_version INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    CONSTRAINT publication_intents_membership_fk
        FOREIGN KEY (account_id, publisher_id)
        REFERENCES publisher_memberships (account_id, publisher_id),
    CONSTRAINT publication_intents_publisher_key_fk
        FOREIGN KEY (publisher_key_id, publisher_id)
        REFERENCES publisher_keys (id, publisher_id),
    CONSTRAINT publication_intents_archive_hash_length
        CHECK (octet_length(archive_hash) = 32),
    CONSTRAINT publication_intents_manifest_hash_length
        CHECK (octet_length(manifest_hash) = 32),
    CONSTRAINT publication_intents_inventory_hash_length
        CHECK (octet_length(file_inventory_hash) = 32),
    CONSTRAINT publication_intents_scan_schema_positive
        CHECK (scan_schema_version > 0),
    CONSTRAINT publication_intents_expiry_order
        CHECK (expires_at > created_at),
    CONSTRAINT publication_intents_consumption_window
        CHECK (
            consumed_at IS NULL
            OR (consumed_at >= created_at AND consumed_at < expires_at)
        )
);

CREATE INDEX publication_intents_publisher_time_idx
    ON publication_intents (publisher_id, created_at DESC);
CREATE INDEX publication_intents_open_expiry_idx
    ON publication_intents (expires_at)
    WHERE consumed_at IS NULL;
