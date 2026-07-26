-- Bound moderation queue aggregates to unresolved publication rows.

CREATE INDEX publication_submissions_unresolved_created_at_idx
    ON publication_submissions (created_at)
    WHERE state IN ('quarantined', 'needs_review');
