-- First-party credentials and sessions contain security-sensitive user data.
-- This expand-only migration intentionally refuses destructive rollback.
DO $$
BEGIN
    RAISE EXCEPTION
        'local account auth migration is forward-only; preserve credential and session records';
END
$$;
