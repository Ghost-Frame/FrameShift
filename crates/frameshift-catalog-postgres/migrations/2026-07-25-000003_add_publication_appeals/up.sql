-- Add immutable publisher appeals and administrator resolutions.
-- Appeals bind to an unchanged submission and its original moderation decision.

ALTER TABLE publication_moderation_decisions
    ADD CONSTRAINT publication_moderation_decision_submission_unique
    UNIQUE (id, submission_id);

ALTER TABLE publication_submissions
    ADD CONSTRAINT publication_submission_publisher_unique
    UNIQUE (id, publisher_id);

CREATE TABLE publication_appeals (
    id UUID PRIMARY KEY,
    decision_id UUID NOT NULL UNIQUE,
    submission_id UUID NOT NULL,
    publisher_id UUID NOT NULL,
    actor_account_id UUID NOT NULL REFERENCES accounts(id),
    statement TEXT NOT NULL,
    request_id UUID NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT publication_appeal_decision_submission_fk
        FOREIGN KEY (decision_id, submission_id)
        REFERENCES publication_moderation_decisions (id, submission_id),
    CONSTRAINT publication_appeal_submission_publisher_fk
        FOREIGN KEY (submission_id, publisher_id)
        REFERENCES publication_submissions (id, publisher_id),
    CONSTRAINT publication_appeal_statement_bounded CHECK (
        char_length(statement) <= 4000
        AND btrim(statement) <> ''
    )
);

CREATE INDEX publication_appeals_publisher_time_idx
    ON publication_appeals (publisher_id, created_at DESC, id DESC);

CREATE INDEX publication_appeals_global_time_idx
    ON publication_appeals (created_at DESC, id DESC);

CREATE TABLE publication_appeal_resolutions (
    id UUID PRIMARY KEY,
    appeal_id UUID NOT NULL UNIQUE REFERENCES publication_appeals(id),
    actor_account_id UUID NOT NULL REFERENCES accounts(id),
    disposition TEXT NOT NULL CHECK (disposition IN ('uphold', 'overturn')),
    rationale TEXT NOT NULL,
    separation_exception_reason TEXT,
    request_id UUID NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT publication_appeal_resolution_rationale_bounded CHECK (
        char_length(rationale) <= 4000
        AND btrim(rationale) <> ''
    ),
    CONSTRAINT publication_appeal_separation_exception_bounded CHECK (
        separation_exception_reason IS NULL
        OR (
            char_length(separation_exception_reason) <= 1000
            AND btrim(separation_exception_reason) <> ''
        )
    )
);

CREATE FUNCTION reject_publication_appeal_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'publication appeal evidence is immutable';
END
$$;

CREATE TRIGGER publication_appeals_immutable
BEFORE UPDATE OR DELETE ON publication_appeals
FOR EACH ROW EXECUTE FUNCTION reject_publication_appeal_mutation();

CREATE TRIGGER publication_appeal_resolutions_immutable
BEFORE UPDATE OR DELETE ON publication_appeal_resolutions
FOR EACH ROW EXECUTE FUNCTION reject_publication_appeal_mutation();
