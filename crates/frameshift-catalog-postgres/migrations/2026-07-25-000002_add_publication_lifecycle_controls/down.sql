-- Lifecycle decisions are immutable authorization and audit evidence.
-- Reversal requires an explicit retention and recovery review.
DO $$
BEGIN
    RAISE EXCEPTION
        'publication lifecycle migration is expand-only and cannot be rolled back automatically';
END
$$;
