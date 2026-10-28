-- T-83 T-82 T-80 T-79 T-13 T-17 T-21 OP-12 OP-34 Access OP-12
-- squawk-ignore-file ban-drop-function
SET LOCAL ROLE work_owner;
SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '5min';

-- T-83
DROP FUNCTION ledger.outbox_ledgers(bigint);

-- T-83 T-82 T-80 OP-34 Access OP-12
CREATE FUNCTION ledger.outbox_ledgers(after_ledger ledger.digest32, max_ledgers bigint)
    RETURNS SETOF ledger.digest32
    LANGUAGE sql STABLE
    SECURITY DEFINER
    SET search_path = pg_catalog, pg_temp
    SET app.outbox_scan = 'on'
AS $$
    SELECT DISTINCT o.ledger_id FROM ledger.outbox o
     WHERE after_ledger IS NULL OR o.ledger_id > after_ledger
     ORDER BY o.ledger_id
     LIMIT GREATEST(COALESCE(max_ledgers, 0), 0)
$$;
REVOKE ALL ON FUNCTION ledger.outbox_ledgers(ledger.digest32, bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION ledger.outbox_ledgers(ledger.digest32, bigint) FROM work_owner;
GRANT EXECUTE ON FUNCTION ledger.outbox_ledgers(ledger.digest32, bigint) TO work_publisher, work_deriver;

-- T-82 T-21 T-13
GRANT SELECT ON ledger.outbox, ledger.log TO work_deriver;
