-- OP-35 OP-34 OP-12 OP-38 T-36 Access OP-73
SET LOCAL ROLE work_owner;
SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '5min';

-- OP-35
CREATE TABLE work.partition_archive (
    ledger_id      ledger.digest32 NOT NULL,
    cold_partition text            NOT NULL,
    object_key     text            NOT NULL,
    copy_digest    ledger.digest32 NOT NULL,
    row_count      bigint          NOT NULL,
    verified_at    timestamptz     NOT NULL DEFAULT pg_catalog.now(),
    CONSTRAINT partition_archive_pk PRIMARY KEY (ledger_id, cold_partition),
    CONSTRAINT partition_archive_partition_ck
        CHECK (cold_partition ~ '^work\.(idempotency_key|inbound_seen)_p[0-9]{6}$'),
    CONSTRAINT partition_archive_key_ck
        CHECK (pg_catalog.octet_length(object_key) BETWEEN 1 AND 512),
    CONSTRAINT partition_archive_rows_ck CHECK (row_count >= 1)
);

SELECT ledger.guard_table('work.partition_archive', 'append_only');
SELECT ledger.apply_ledger_scope('work.partition_archive');

REVOKE ALL ON work.partition_archive FROM PUBLIC, work_app, work_sequencer, work_checkpointer, work_publisher, work_erasure, work_archive;
GRANT SELECT, INSERT ON work.partition_archive TO work_archive;

COMMENT ON TABLE work.partition_archive IS 'label=OPERATIONAL; home=canonical; guard=append_only; erasure=none';

-- OP-35 T-80
CREATE FUNCTION work.partition_ledgers(part regclass)
    RETURNS SETOF ledger.digest32
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = pg_catalog, pg_temp
    SET timezone = 'UTC'
AS $$
DECLARE
    parent regclass;
    upper_bound timestamptz;
BEGIN
    SELECT h.inhparent::regclass INTO parent FROM pg_inherits h WHERE h.inhrelid = part;
    IF parent IS NULL OR parent NOT IN ('work.idempotency_key'::regclass, 'work.inbound_seen'::regclass) THEN
        RAISE EXCEPTION USING ERRCODE = 'invalid_parameter_value', MESSAGE = 'not_an_archivable_partition';
    END IF;
    SELECT substring(pg_get_expr(c.relpartbound, c.oid) FROM 'TO \(''([^'']+)''\)')::timestamptz
      INTO upper_bound
      FROM pg_class c WHERE c.oid = part;
    IF upper_bound IS NULL OR upper_bound > now() - interval '30 days' THEN
        RAISE EXCEPTION USING ERRCODE = 'object_in_use', MESSAGE = 'partition_still_hot';
    END IF;
    EXECUTE format('ALTER TABLE %s NO FORCE ROW LEVEL SECURITY', part);
    RETURN QUERY EXECUTE format('SELECT DISTINCT t.ledger_id FROM %s t ORDER BY 1', part);
    EXECUTE format('ALTER TABLE %s FORCE ROW LEVEL SECURITY', part);
END
$$;
REVOKE ALL ON FUNCTION work.partition_ledgers(regclass) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION work.partition_ledgers(regclass) TO work_archive;

-- OP-35 OP-8 OP-12 Access OP-73
CREATE OR REPLACE FUNCTION work.drop_archived_partition(part regclass, manifest ledger.digest32)
    RETURNS bigint
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = pg_catalog, pg_temp
    SET timezone = 'UTC'
AS $$
DECLARE
    parent regclass;
    upper_bound timestamptz;
    actual bytea;
    total bigint;
    scope text;
    slice record;
BEGIN
    SELECT h.inhparent::regclass INTO parent FROM pg_inherits h WHERE h.inhrelid = part;
    IF parent IS NULL OR parent NOT IN ('work.idempotency_key'::regclass, 'work.inbound_seen'::regclass) THEN
        RAISE EXCEPTION USING ERRCODE = 'invalid_parameter_value', MESSAGE = 'not_an_archivable_partition';
    END IF;
    SELECT substring(pg_get_expr(c.relpartbound, c.oid) FROM 'TO \(''([^'']+)''\)')::timestamptz
      INTO upper_bound
      FROM pg_class c WHERE c.oid = part;
    IF upper_bound IS NULL OR upper_bound > now() - interval '30 days' THEN
        RAISE EXCEPTION USING ERRCODE = 'object_in_use', MESSAGE = 'partition_still_hot';
    END IF;
    EXECUTE format('ALTER TABLE %s DETACH PARTITION %s', parent, part);
    EXECUTE format('ALTER TABLE %s NO FORCE ROW LEVEL SECURITY', part);
    EXECUTE format(
        'SELECT coalesce(sum(s.n), 0)::bigint, '
        'sha256(convert_to(coalesce(string_agg(encode(s.l, ''hex'') || '':'' || s.n || '':'' || encode(s.d, ''hex''), '
        'E''\n'' ORDER BY s.l), ''''), ''UTF8'')) '
        'FROM (SELECT t.ledger_id::bytea AS l, count(*) AS n, '
        'sha256(convert_to(string_agg(t::text, E''\n'' ORDER BY t::text COLLATE "C"), ''UTF8'')) AS d '
        'FROM %s t GROUP BY t.ledger_id) s',
        part
    ) INTO total, actual;
    IF actual <> manifest THEN
        RAISE EXCEPTION USING ERRCODE = 'data_exception', MESSAGE = 'archive_manifest_mismatch';
    END IF;
    scope := coalesce(current_setting('app.ledger_id', true), '');
    FOR slice IN EXECUTE format(
        'SELECT t.ledger_id::bytea AS l, count(*) AS n, '
        'sha256(convert_to(string_agg(t::text, E''\n'' ORDER BY t::text COLLATE "C"), ''UTF8'')) AS d '
        'FROM %s t GROUP BY t.ledger_id',
        part
    ) LOOP
        PERFORM set_config('app.ledger_id', encode(slice.l, 'hex'), true);
        PERFORM 1 FROM work.partition_archive a
         WHERE a.ledger_id = slice.l AND a.cold_partition = part::text
           AND a.row_count = slice.n AND a.copy_digest = slice.d;
        IF NOT FOUND THEN
            RAISE EXCEPTION USING ERRCODE = 'data_exception', MESSAGE = 'archive_record_missing';
        END IF;
    END LOOP;
    PERFORM set_config('app.ledger_id', scope, true);
    EXECUTE format('DROP TABLE %s', part);
    RETURN total;
END
$$;
REVOKE ALL ON FUNCTION work.drop_archived_partition(regclass, ledger.digest32) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION work.drop_archived_partition(regclass, ledger.digest32) TO work_archive;
