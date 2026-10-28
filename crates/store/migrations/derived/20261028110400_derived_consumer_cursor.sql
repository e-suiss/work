-- OP-39 T-21 T-18 T-14 T-36 Access OP-73
SET LOCAL ROLE work_owner;
SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '5min';

-- OP-39 T-21
CREATE TABLE derived.consumer_cursor (
    ledger_id      ledger.digest32  NOT NULL,
    consumer_group text             NOT NULL,
    pos            ledger.log_pos   NOT NULL,
    event_id       ledger.event_id  NOT NULL,
    CONSTRAINT consumer_cursor_pk PRIMARY KEY (ledger_id, consumer_group),
    CONSTRAINT consumer_cursor_group_ck CHECK (consumer_group ~ '^[a-z0-9_]{1,64}$')
) WITH (fillfactor = 70);

-- OP-39 Access OP-73
CREATE FUNCTION derived.consumer_cursor_guard() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog
AS $$
BEGIN
    IF NEW.ledger_id <> OLD.ledger_id OR NEW.consumer_group <> OLD.consumer_group THEN
        RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'consumer_cursor_identity_immutable';
    END IF;
    IF (NEW.pos, NEW.event_id) < (OLD.pos, OLD.event_id) THEN
        RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'consumer_cursor_regressed';
    END IF;
    RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION derived.consumer_cursor_guard() FROM PUBLIC;

CREATE TRIGGER consumer_cursor_guard
    BEFORE UPDATE ON derived.consumer_cursor
    FOR EACH ROW EXECUTE FUNCTION derived.consumer_cursor_guard();

SELECT ledger.guard_table('derived.consumer_cursor', 'mutable');
SELECT ledger.apply_ledger_scope('derived.consumer_cursor');

REVOKE ALL ON derived.consumer_cursor FROM PUBLIC;
GRANT SELECT, INSERT ON derived.consumer_cursor TO work_deriver;
GRANT UPDATE (pos, event_id) ON derived.consumer_cursor TO work_deriver;

COMMENT ON TABLE derived.consumer_cursor IS 'label=OPERATIONAL; home=derived; guard=mutable; erasure=none';
