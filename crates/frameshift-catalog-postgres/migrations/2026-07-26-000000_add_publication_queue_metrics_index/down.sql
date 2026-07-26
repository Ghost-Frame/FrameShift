-- Remove the review-queue aggregate index.

DROP INDEX IF EXISTS publication_submissions_unresolved_created_at_idx;
