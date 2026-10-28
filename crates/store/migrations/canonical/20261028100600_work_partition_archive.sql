-- OP-8 OP-12 T-36 Access OP-73
SET LOCAL ROLE work_owner;
SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '5min';

-- OP-12 Access OP-73
CREATE FUNCTION work.partition_slice(part regclass)
    RETURNS TABLE (ledger_id ledger.digest32, row_count bigint, slice_digest ledger.digest32)
    LANGUAGE plpgsql STABLE
    SET search_path = pg_catalog
AS $$
DECLARE
    parent regclass;
BEGIN
    SELECT h.inhparent::regclass INTO parent FROM pg_inherits h WHERE h.inhrelid = part;
    IF parent IS NULL OR parent NOT IN ('work.idempotency_key'::regclass, 'work.inbound_seen'::regclass) THEN
        RAISE EXCEPTION USING ERRCODE = 'invalid_parameter_value', MESSAGE = 'not_an_archivable_partition';
    END IF;
    RETURN QUERY EXECUTE format(
        'SELECT t.ledger_id, count(*), '
        'sha256(convert_to(string_agg(t::text, E''\n'' ORDER BY t::text COLLATE "C"), ''UTF8''))::ledger.digest32 '
        'FROM %s t WHERE t.tableoid = %s GROUP BY t.ledger_id',
        parent, part::oid
    );
END
$$;
REVOKE ALL ON FUNCTION work.partition_slice(regclass) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION work.partition_slice(regclass) TO work_archive;

-- OP-8 OP-12 Access OP-73
CREATE FUNCTION work.drop_archived_partition(part regclass, manifest ledger.digest32)
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
    EXECUTE format('DROP TABLE %s', part);
    RETURN total;
END
$$;
REVOKE ALL ON FUNCTION work.drop_archived_partition(regclass, ledger.digest32) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION work.drop_archived_partition(regclass, ledger.digest32) TO work_archive;

GRANT SELECT ON work.idempotency_key, work.inbound_seen TO work_archive;
