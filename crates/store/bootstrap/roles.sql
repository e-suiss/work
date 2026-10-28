-- T-8 T-36 OP-12 P-17 Access OP-12 Access OP-17 Access OP-55 Access OP-73
DO $$
DECLARE
    r text;
BEGIN
    FOREACH r IN ARRAY ARRAY[
        'work_owner',
        'work_app',
        'work_sequencer',
        'work_checkpointer',
        'work_publisher',
        'work_erasure',
        'work_archive',
        'work_deriver',
        'work_reconciler'
    ] LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = r) THEN
            EXECUTE pg_catalog.format('CREATE ROLE %I NOLOGIN', r);
        END IF;
        EXECUTE pg_catalog.format(
            'ALTER ROLE %I NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT',
            r
        );
    END LOOP;
END
$$;

-- T-80
GRANT SET ON PARAMETER app.outbox_scan TO work_owner;
