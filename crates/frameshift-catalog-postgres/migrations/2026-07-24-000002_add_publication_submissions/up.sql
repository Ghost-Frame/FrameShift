-- Persist only the internal quarantine boundary for Phase 5C2.
-- HTTP routes, object movement, moderation decisions, and public promotion remain out of scope.

ALTER TABLE publication_intents
    ADD CONSTRAINT publication_intents_submission_binding_unique
    UNIQUE (
        id,
        account_id,
        publisher_id,
        publisher_key_id,
        archive_hash,
        manifest_hash,
        file_inventory_hash,
        scan_schema_version
    );

CREATE TABLE publication_submissions (
    id UUID PRIMARY KEY,
    intent_id UUID NOT NULL UNIQUE,
    account_id UUID NOT NULL,
    publisher_id UUID NOT NULL,
    publisher_key_id UUID NOT NULL,
    archive_hash BYTEA NOT NULL,
    manifest_hash BYTEA NOT NULL,
    file_inventory_hash BYTEA NOT NULL,
    scan_schema_version INTEGER NOT NULL,
    scan_report JSONB NOT NULL,
    state TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT publication_submissions_intent_binding_fk
        FOREIGN KEY (
            intent_id,
            account_id,
            publisher_id,
            publisher_key_id,
            archive_hash,
            manifest_hash,
            file_inventory_hash,
            scan_schema_version
        )
        REFERENCES publication_intents (
            id,
            account_id,
            publisher_id,
            publisher_key_id,
            archive_hash,
            manifest_hash,
            file_inventory_hash,
            scan_schema_version
        ),
    CONSTRAINT publication_submissions_archive_hash_length
        CHECK (octet_length(archive_hash) = 32),
    CONSTRAINT publication_submissions_manifest_hash_length
        CHECK (octet_length(manifest_hash) = 32),
    CONSTRAINT publication_submissions_inventory_hash_length
        CHECK (octet_length(file_inventory_hash) = 32),
    CONSTRAINT publication_submissions_scan_schema_positive
        CHECK (scan_schema_version > 0),
    CONSTRAINT publication_submissions_scan_report_object
        CHECK (jsonb_typeof(scan_report) = 'object'),
    CONSTRAINT publication_submissions_initial_state
        CHECK (state = 'quarantined'),
    CONSTRAINT publication_submissions_timestamp_order
        CHECK (updated_at >= created_at)
);

CREATE INDEX publication_submissions_publisher_time_idx
    ON publication_submissions (publisher_id, created_at DESC);
