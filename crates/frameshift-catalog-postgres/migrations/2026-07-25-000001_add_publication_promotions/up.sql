-- Atomically bind approved quarantine submissions to active catalog versions.

ALTER TABLE publication_submissions
    DROP CONSTRAINT publication_submissions_review_state;

ALTER TABLE publication_submissions
    ADD CONSTRAINT publication_submissions_review_state
    CHECK (
        state IN (
            'quarantined',
            'needs_review',
            'approved',
            'rejected',
            'promoted'
        )
    );

CREATE TABLE publication_promotions (
    id UUID PRIMARY KEY,
    submission_id UUID NOT NULL UNIQUE REFERENCES publication_submissions(id),
    actor_account_id UUID NOT NULL REFERENCES accounts(id),
    pack_name TEXT NOT NULL,
    version TEXT NOT NULL,
    content_hash BYTEA NOT NULL,
    request_id UUID NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT publication_promotions_pack_version_fk
        FOREIGN KEY (pack_name, version)
        REFERENCES pack_versions (pack_name, version),
    CONSTRAINT publication_promotions_content_hash_length
        CHECK (octet_length(content_hash) = 32)
);

CREATE INDEX publication_promotions_actor_time_idx
    ON publication_promotions (actor_account_id, created_at, id);

CREATE FUNCTION reject_publication_promotion_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'publication promotions are immutable';
END
$$;

CREATE TRIGGER publication_promotions_immutable
BEFORE UPDATE OR DELETE ON publication_promotions
FOR EACH ROW EXECUTE FUNCTION reject_publication_promotion_mutation();
