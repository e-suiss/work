-- P-100 P-11 OP-5 Access T6
-- squawk-ignore-file ban-drop-not-null, constraint-missing-not-valid
SET LOCAL ROLE work_owner;
SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '5min';

-- P-100
ALTER TABLE ledger.log
    ALTER COLUMN prev DROP NOT NULL,
    ADD CONSTRAINT log_genesis_prev_ck CHECK ((pos = 0) = (prev IS NULL));

-- P-100 OP-5 OP-6 P-11 Access T6
CREATE OR REPLACE FUNCTION ledger.log_before_insert() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog
AS $$
DECLARE
    h record;
    p record;
BEGIN
    SELECT pos, epoch INTO h FROM ledger.head WHERE ledger_id = NEW.ledger_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'ledger_head_missing';
    END IF;
    IF NEW.epoch <> h.epoch THEN
        RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'stale_epoch';
    END IF;
    IF NEW.pos <= h.pos THEN
        RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'position_reused';
    END IF;
    IF (NEW.pos = 0) <> (NEW.prev IS NULL) THEN
        RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'prev_only_absent_at_genesis';
    END IF;
    IF NEW.pos > 0 THEN
        SELECT leaf_hash, recorded_at INTO p
          FROM ledger.log
         WHERE ledger_id = NEW.ledger_id AND pos = NEW.pos - 1;
        IF NOT FOUND THEN
            RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'position_gap';
        END IF;
        IF NEW.prev IS DISTINCT FROM p.leaf_hash THEN
            RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'prev_mismatch';
        END IF;
        IF NEW.recorded_at < p.recorded_at THEN
            RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'recorded_at_regressed';
        END IF;
    END IF;
    RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION ledger.log_before_insert() FROM PUBLIC;
