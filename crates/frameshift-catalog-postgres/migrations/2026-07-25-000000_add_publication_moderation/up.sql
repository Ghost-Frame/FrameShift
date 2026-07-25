-- Add the route-free D4 moderation authority and review evidence substrate.
-- Approval remains non-public; this migration adds no promotion or active state.

CREATE TABLE account_platform_roles (
    account_id UUID NOT NULL REFERENCES accounts(id),
    role TEXT NOT NULL CHECK (role IN ('moderator', 'administrator')),
    state TEXT NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'revoked')),
    assigned_by_account_id UUID NOT NULL REFERENCES accounts(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (account_id, role),
    CONSTRAINT account_platform_roles_timestamp_order
        CHECK (updated_at >= created_at)
);

CREATE INDEX account_platform_roles_active_role_idx
    ON account_platform_roles (role, account_id)
    WHERE state = 'active';

ALTER TABLE publication_submissions
    DROP CONSTRAINT publication_submissions_initial_state;

ALTER TABLE publication_submissions
    ADD CONSTRAINT publication_submissions_review_state
    CHECK (state IN ('quarantined', 'needs_review', 'approved', 'rejected'));

CREATE TABLE publication_moderation_decisions (
    id UUID PRIMARY KEY,
    submission_id UUID NOT NULL REFERENCES publication_submissions(id),
    actor_account_id UUID NOT NULL REFERENCES accounts(id),
    action TEXT NOT NULL
        CHECK (action IN ('approve', 'request_changes', 'reject')),
    from_state TEXT NOT NULL
        CHECK (from_state IN ('quarantined', 'needs_review')),
    to_state TEXT NOT NULL
        CHECK (to_state IN ('needs_review', 'approved', 'rejected')),
    reason_code TEXT NOT NULL,
    private_explanation TEXT,
    request_id UUID NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT publication_moderation_reason_code_shape CHECK (
        reason_code ~ '^[a-z0-9][a-z0-9_.-]{0,63}$'
    ),
    CONSTRAINT publication_moderation_private_explanation_bounded CHECK (
        private_explanation IS NULL
        OR (
            char_length(private_explanation) <= 2000
            AND btrim(private_explanation) <> ''
        )
    ),
    CONSTRAINT publication_moderation_action_transition CHECK (
        (action = 'approve' AND to_state = 'approved')
        OR (action = 'request_changes' AND to_state = 'needs_review')
        OR (action = 'reject' AND to_state = 'rejected')
    )
);

CREATE INDEX publication_moderation_submission_time_idx
    ON publication_moderation_decisions (submission_id, created_at, id);

CREATE INDEX publication_moderation_actor_time_idx
    ON publication_moderation_decisions (actor_account_id, created_at, id);

CREATE FUNCTION reject_publication_moderation_decision_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'publication moderation decisions are immutable';
END
$$;

CREATE TRIGGER publication_moderation_decisions_immutable
BEFORE UPDATE OR DELETE ON publication_moderation_decisions
FOR EACH ROW EXECUTE FUNCTION reject_publication_moderation_decision_mutation();
