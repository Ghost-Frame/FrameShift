-- Invite applications contain private applicant data and review history.
-- This expand-only migration intentionally refuses destructive rollback.
DO $$
BEGIN
    RAISE EXCEPTION
        'account invite request migration is forward-only; preserve applicant records';
END
$$;
