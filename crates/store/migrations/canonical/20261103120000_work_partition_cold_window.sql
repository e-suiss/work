-- OP-38 OP-35 OP-36 OP-32 OP-49 T-36 Access OP-73
SET LOCAL ROLE work_owner;
SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '5min';

-- OP-38 OP-32
CREATE FUNCTION work.partition_is_cold(upper_bound timestamptz, as_of timestamptz)
    RETURNS boolean
    LANGUAGE sql IMMUTABLE STRICT
    SET search_path = pg_catalog, pg_temp
    SET timezone = 'UTC'
AS $$
    SELECT upper_bound <= as_of - interval '30 days' - interval '250 milliseconds'
$$;
REVOKE ALL ON FUNCTION work.partition_is_cold(timestamptz, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION work.partition_is_cold(timestamptz, timestamptz) TO work_archive;

-- OP-35 T-80
CREATE OR REPLACE FUNCTION work.partition_ledgers(part regclass)
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
    IF upper_bound IS NULL OR NOT work.partition_is_cold(upper_bound, now()) THEN
        RAISE EXCEPTION USING ERRCODE = 'object_in_use', MESSAGE = 'partition_still_hot';
    END IF;
    EXECUTE format('ALTER TABLE %s NO FORCE ROW LEVEL SECURITY', part);
    RETURN QUERY EXECUTE format('SELECT DISTINCT t.ledger_id FROM %s t ORDER BY 1', part);
    EXECUTE format('ALTER TABLE %s FORCE ROW LEVEL SECURITY', part);
END
$$;

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
    IF upper_bound IS NULL OR NOT work.partition_is_cold(upper_bound, now()) THEN
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
