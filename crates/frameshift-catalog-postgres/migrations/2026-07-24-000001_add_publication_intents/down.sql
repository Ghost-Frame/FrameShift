-- Publication intents are immutable security evidence. This expand-only
-- migration intentionally has no destructive automatic rollback.
DO $$
BEGIN
    RAISE EXCEPTION 'publication intent persistence is an irreversible expand-only migration';
END
$$;
