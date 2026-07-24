-- This migration is intentionally expand-only because publication submissions
-- are authorization and audit evidence. Reversing it requires an explicit,
-- separately reviewed retention and recovery procedure.
DO $$
BEGIN
    RAISE EXCEPTION
        'publication submission migration is expand-only and cannot be rolled back automatically';
END
$$;
