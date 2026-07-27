-- Durable applications for the invite-only first-party account system.
-- Applications are deliberately separate from accounts and credentials.

CREATE TABLE account_invite_requests (
    id UUID PRIMARY KEY,
    normalized_email TEXT NOT NULL UNIQUE,
    display_name TEXT,
    intent TEXT NOT NULL CHECK (
        intent IN (
            'publish_personas',
            'premium_features',
            'team_evaluation',
            'contribute',
            'other'
        )
    ),
    statement TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (
        status IN ('pending', 'reviewing', 'invited', 'declined')
    ),
    consented_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT account_invite_email_normalized CHECK (
        normalized_email = lower(btrim(normalized_email))
    ),
    CONSTRAINT account_invite_email_not_blank CHECK (normalized_email <> ''),
    CONSTRAINT account_invite_email_length CHECK (
        octet_length(normalized_email) <= 320
    ),
    CONSTRAINT account_invite_display_name_length CHECK (
        display_name IS NULL
        OR (
            btrim(display_name) <> ''
            AND octet_length(display_name) <= 400
        )
    ),
    CONSTRAINT account_invite_statement_length CHECK (
        btrim(statement) <> ''
        AND octet_length(statement) <= 8000
    ),
    CONSTRAINT account_invite_timestamps_consistent CHECK (
        consented_at <= created_at
        AND updated_at >= created_at
    )
);

CREATE INDEX account_invite_requests_review_queue_idx
    ON account_invite_requests (status, created_at, id);
