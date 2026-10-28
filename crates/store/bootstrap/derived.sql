-- OP-2 T-8 T-11 T-36 Access OP-12
REVOKE ALL ON SCHEMA public FROM PUBLIC;
DO $$
BEGIN
    EXECUTE pg_catalog.format('REVOKE ALL ON DATABASE %I FROM PUBLIC', pg_catalog.current_database());
    EXECUTE pg_catalog.format(
        'GRANT CONNECT ON DATABASE %I TO work_app, work_deriver, work_reconciler',
        pg_catalog.current_database()
    );
END
$$;
