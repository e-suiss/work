-- T-80 T-79 T-13 T-17 OP-12 OP-34 Access OP-12 Access OP-73
SET LOCAL ROLE work_owner;
SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '5min';

-- T-80 T-13 OP-34
ALTER POLICY ledger_scope ON ledger.outbox
    USING (
        ledger_id = ledger.current_ledger_id()
        OR (CURRENT_USER = 'work_owner' AND pg_catalog.current_setting('app.outbox_scan', true) = 'on')
    );

-- T-80 T-17 OP-34 Access OP-12
CREATE FUNCTION ledger.outbox_ledgers(max_ledgers bigint)
    RETURNS SETOF ledger.digest32
    LANGUAGE sql STABLE STRICT
    SECURITY DEFINER
    SET search_path = pg_catalog, pg_temp
    SET app.outbox_scan = 'on'
AS $$
    SELECT DISTINCT o.ledger_id FROM ledger.outbox o ORDER BY o.ledger_id LIMIT max_ledgers
$$;
REVOKE ALL ON FUNCTION ledger.outbox_ledgers(bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION ledger.outbox_ledgers(bigint) FROM work_owner;
GRANT EXECUTE ON FUNCTION ledger.outbox_ledgers(bigint) TO work_publisher;
