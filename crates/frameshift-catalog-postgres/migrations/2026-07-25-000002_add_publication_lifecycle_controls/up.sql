-- Add atomic owner and administrator publication lifecycle controls.
-- Released catalog rows and object bytes remain retained.

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
            'promoted',
            'withdrawn'
        )
    );

CREATE TABLE publication_lifecycle_decisions (
    id UUID PRIMARY KEY,
    action TEXT NOT NULL CHECK (
        action IN (
            'withdraw_submission',
            'suspend_publisher',
            'tombstone_release'
        )
    ),
    actor_account_id UUID NOT NULL REFERENCES accounts(id),
    publisher_id UUID REFERENCES publisher_profiles(id),
    submission_id UUID REFERENCES publication_submissions(id),
    pack_name TEXT,
    version TEXT,
    from_state TEXT NOT NULL,
    to_state TEXT NOT NULL,
    reason_code TEXT NOT NULL,
    request_id UUID NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT publication_lifecycle_reason_code_shape CHECK (
        reason_code ~ '^[a-z0-9][a-z0-9_.-]{0,63}$'
    ),
    CONSTRAINT publication_lifecycle_release_fk
        FOREIGN KEY (pack_name, version)
        REFERENCES pack_versions (pack_name, version),
    CONSTRAINT publication_lifecycle_target_shape CHECK (
        (
            action = 'withdraw_submission'
            AND publisher_id IS NOT NULL
            AND submission_id IS NOT NULL
            AND pack_name IS NULL
            AND version IS NULL
        )
        OR (
            action = 'suspend_publisher'
            AND publisher_id IS NOT NULL
            AND submission_id IS NULL
            AND pack_name IS NULL
            AND version IS NULL
        )
        OR (
            action = 'tombstone_release'
            AND submission_id IS NULL
            AND pack_name IS NOT NULL
            AND version IS NOT NULL
        )
    ),
    CONSTRAINT publication_lifecycle_transition CHECK (
        (
            action = 'withdraw_submission'
            AND from_state IN ('quarantined', 'needs_review', 'approved')
            AND to_state = 'withdrawn'
        )
        OR (
            action = 'suspend_publisher'
            AND from_state IN ('pending', 'approved')
            AND to_state = 'suspended'
        )
        OR (
            action = 'tombstone_release'
            AND from_state = 'active'
            AND to_state = 'tombstone'
        )
    )
);

CREATE UNIQUE INDEX publication_lifecycle_withdrawal_target_unique
    ON publication_lifecycle_decisions (submission_id)
    WHERE action = 'withdraw_submission';

CREATE UNIQUE INDEX publication_lifecycle_suspension_target_unique
    ON publication_lifecycle_decisions (publisher_id)
    WHERE action = 'suspend_publisher';

CREATE UNIQUE INDEX publication_lifecycle_tombstone_target_unique
    ON publication_lifecycle_decisions (pack_name, version)
    WHERE action = 'tombstone_release';

CREATE INDEX publication_lifecycle_publisher_time_idx
    ON publication_lifecycle_decisions (publisher_id, created_at DESC, id DESC)
    WHERE publisher_id IS NOT NULL;

CREATE INDEX publication_lifecycle_global_time_idx
    ON publication_lifecycle_decisions (created_at DESC, id DESC);

CREATE FUNCTION reject_publication_lifecycle_decision_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'publication lifecycle decisions are immutable';
END
$$;

CREATE TRIGGER publication_lifecycle_decisions_immutable
BEFORE UPDATE OR DELETE ON publication_lifecycle_decisions
FOR EACH ROW EXECUTE FUNCTION reject_publication_lifecycle_decision_mutation();
