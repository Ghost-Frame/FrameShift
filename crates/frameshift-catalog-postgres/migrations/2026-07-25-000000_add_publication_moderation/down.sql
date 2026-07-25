-- Moderation decisions and role assignments are authorization and audit
-- evidence. Reversal requires an explicit retention and recovery review.
DO $$
BEGIN
    RAISE EXCEPTION
        'publication moderation migration is expand-only and cannot be rolled back automatically';
END
$$;
