-- Authentication credentials, replay evidence, MFA state, authorization
-- codes, and audit rows are security records. Destructive rollback would
-- silently invalidate incident evidence and live credentials, so it is
-- intentionally refused.
DO $$
BEGIN
    RAISE EXCEPTION
        'account authentication hardening migration is forward-only; preserve credential, replay, MFA, authorization-code, and audit records';
END
$$;
