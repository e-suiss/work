-- Access OP-12 Access OP-17 Access OP-55 Access OP-66 Access OP-73 Access OP-76 T-36
-- squawk-ignore-file ban-create-domain-with-constraint
SET LOCAL ROLE work_owner;
SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '5min';

ALTER DEFAULT PRIVILEGES REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES REVOKE ALL ON SEQUENCES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

CREATE SCHEMA ledger AUTHORIZATION work_owner;
REVOKE ALL ON SCHEMA ledger FROM PUBLIC;
GRANT USAGE ON SCHEMA ledger TO work_app, work_sequencer, work_checkpointer, work_publisher, work_erasure, work_archive, work_deriver, work_reconciler;

-- P-67 OQ-34
CREATE DOMAIN ledger.digest32 AS bytea
    CHECK (pg_catalog.octet_length(VALUE) = 32);

-- P-11
CREATE DOMAIN ledger.log_pos AS bigint
    CHECK (VALUE >= 0);

-- P-27 P-67 T-36
CREATE DOMAIN ledger.ms_time AS timestamptz
    CHECK (VALUE = pg_catalog.date_trunc('milliseconds', VALUE));

-- Access OP-66
CREATE DOMAIN ledger.ident AS text
    CHECK (VALUE ~ '^[a-z][a-z0-9_]{0,63}$');

-- P-42 Access OP-67
CREATE DOMAIN ledger.traceparent AS text
    CHECK (
        VALUE ~ '^[0-9a-f]{2}-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$'
        AND pg_catalog.left(VALUE, 2) <> 'ff'
        AND pg_catalog.substr(VALUE, 4, 32) <> pg_catalog.repeat('0', 32)
        AND pg_catalog.substr(VALUE, 37, 16) <> pg_catalog.repeat('0', 16)
    );

-- Access T26 Access TI-RT10
CREATE DOMAIN ledger.event_id AS text
    CHECK (VALUE ~ '^[!-~]{1,255}$');

-- Access T26
CREATE DOMAIN ledger.event_type AS text
    CHECK (VALUE ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$' AND pg_catalog.octet_length(VALUE) <= 255);

-- T-13 T-36 Access OP-12 Access OP-18
CREATE FUNCTION ledger.current_ledger_id() RETURNS bytea
    LANGUAGE sql STABLE PARALLEL SAFE
AS $$
    SELECT pg_catalog.decode(NULLIF(pg_catalog.current_setting('app.ledger_id', true), ''), 'hex')
$$;
REVOKE ALL ON FUNCTION ledger.current_ledger_id() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ledger.current_ledger_id() TO work_app, work_sequencer, work_checkpointer, work_publisher, work_erasure, work_archive, work_deriver, work_reconciler;

-- Access OP-17 Access OP-73
CREATE FUNCTION ledger.reject_mutation() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog
AS $$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = 'insufficient_privilege',
        MESSAGE = format('physical_mutation_forbidden: %s on %I.%I', TG_OP, TG_TABLE_SCHEMA, TG_TABLE_NAME);
END
$$;
REVOKE ALL ON FUNCTION ledger.reject_mutation() FROM PUBLIC;

-- Access OP-17 Access OP-73
CREATE FUNCTION ledger.guard_table(t regclass, mode text) RETURNS void
    LANGUAGE plpgsql
    SET search_path = pg_catalog
AS $$
DECLARE
    owner_role name;
BEGIN
    IF mode NOT IN ('append_only', 'mutable', 'job_queue') THEN
        RAISE EXCEPTION 'unknown guard mode %', mode;
    END IF;
    SELECT pg_get_userbyid(relowner) INTO owner_role FROM pg_class WHERE oid = t;
    EXECUTE format(
        'CREATE TRIGGER reject_truncate BEFORE TRUNCATE ON %s FOR EACH STATEMENT EXECUTE FUNCTION ledger.reject_mutation()',
        t
    );
    EXECUTE format('REVOKE DELETE, TRUNCATE ON %s FROM %I', t, owner_role);
    IF mode = 'append_only' THEN
        EXECUTE format(
            'CREATE TRIGGER reject_update_delete BEFORE UPDATE OR DELETE ON %s FOR EACH ROW EXECUTE FUNCTION ledger.reject_mutation()',
            t
        );
    ELSIF mode = 'mutable' THEN
        EXECUTE format(
            'CREATE TRIGGER reject_delete BEFORE DELETE ON %s FOR EACH ROW EXECUTE FUNCTION ledger.reject_mutation()',
            t
        );
    ELSE
        EXECUTE format(
            'CREATE TRIGGER reject_update BEFORE UPDATE ON %s FOR EACH ROW EXECUTE FUNCTION ledger.reject_mutation()',
            t
        );
    END IF;
END
$$;
REVOKE ALL ON FUNCTION ledger.guard_table(regclass, text) FROM PUBLIC;

-- T-13 T-36 Access OP-12
CREATE FUNCTION ledger.apply_ledger_scope(t regclass) RETURNS void
    LANGUAGE plpgsql
    SET search_path = pg_catalog
AS $$
BEGIN
    EXECUTE format('ALTER TABLE %s ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %s FORCE ROW LEVEL SECURITY', t);
    EXECUTE format(
        'CREATE POLICY granted_roles ON %s AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true)',
        t
    );
    EXECUTE format(
        'CREATE POLICY ledger_scope ON %s AS RESTRICTIVE FOR ALL TO PUBLIC '
        'USING (ledger_id = ledger.current_ledger_id()) WITH CHECK (ledger_id = ledger.current_ledger_id())',
        t
    );
END
$$;
REVOKE ALL ON FUNCTION ledger.apply_ledger_scope(regclass) FROM PUBLIC;
