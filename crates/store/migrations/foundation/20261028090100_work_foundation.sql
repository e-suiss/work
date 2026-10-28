-- T-36 OP-12 Access OP-12 Access OP-17 Access OP-66 Access OP-73
-- squawk-ignore-file ban-create-domain-with-constraint
SET LOCAL ROLE work_owner;
SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '5min';

CREATE SCHEMA work AUTHORIZATION work_owner;
REVOKE ALL ON SCHEMA work FROM PUBLIC;
GRANT USAGE ON SCHEMA work TO work_app, work_sequencer, work_checkpointer, work_publisher, work_erasure, work_archive, work_deriver, work_reconciler;

-- P-67 OP-13
CREATE DOMAIN work.party_ref AS text
    CHECK (pg_catalog.octet_length(VALUE) BETWEEN 1 AND 255);

-- P-11 P-71 P-85
CREATE DOMAIN work.reason_code AS text
    CHECK (VALUE ~ '^[a-z][a-z0-9_]*(:[a-z][a-z0-9_]*)?(:https://[a-z0-9.-]+(:[0-9]+)?/[!-~]*)?$');

-- P-70
CREATE DOMAIN work.type_uri AS text
    CHECK (VALUE ~ '^https://[a-z0-9.-]+(:[0-9]+)?/[!-~]*$');

-- P-72
CREATE DOMAIN work.snake_name AS text
    CHECK (VALUE ~ '^[a-z][a-z0-9_]{0,63}$');

-- OP-14
CREATE DOMAIN work.retention_class AS text
    CHECK (VALUE IN (
        'work_record', 'work_evidence', 'work_draft', 'agent_trace',
        'audit', 'traffic', 'dsr_log', 'erasure_log'
    ));

-- OP-12 T-36 Access OP-73
CREATE FUNCTION work.ensure_monthly_partitions(parent regclass, months_back integer, months_ahead integer)
    RETURNS void
    LANGUAGE plpgsql
    SET search_path = pg_catalog
    SET timezone = 'UTC'
AS $$
DECLARE
    base  timestamptz := (date_trunc('month', now() AT TIME ZONE 'UTC')) AT TIME ZONE 'UTC';
    lo    timestamptz;
    hi    timestamptz;
    part  text;
    owner_role name;
    label text;
    i     integer;
BEGIN
    SELECT pg_get_userbyid(relowner), obj_description(oid, 'pg_class')
      INTO owner_role, label
      FROM pg_class WHERE oid = parent;
    FOR i IN (0 - months_back) .. months_ahead LOOP
        lo := base + make_interval(months => i);
        hi := base + make_interval(months => i + 1);
        part := format('%s_p%s', parent::text, to_char(lo AT TIME ZONE 'UTC', 'YYYYMM'));
        IF to_regclass(part) IS NOT NULL THEN
            CONTINUE;
        END IF;
        EXECUTE format('CREATE TABLE %s PARTITION OF %s FOR VALUES FROM (%L) TO (%L)', part, parent, lo, hi);
        EXECUTE format(
            'CREATE TRIGGER reject_truncate BEFORE TRUNCATE ON %s FOR EACH STATEMENT EXECUTE FUNCTION ledger.reject_mutation()',
            part
        );
        EXECUTE format('REVOKE ALL ON %s FROM PUBLIC', part);
        EXECUTE format('REVOKE DELETE, TRUNCATE ON %s FROM %I', part, owner_role);
        PERFORM ledger.apply_ledger_scope(part::regclass);
        EXECUTE format('COMMENT ON TABLE %s IS %L', part, label);
    END LOOP;
END
$$;
REVOKE ALL ON FUNCTION work.ensure_monthly_partitions(regclass, integer, integer) FROM PUBLIC;
