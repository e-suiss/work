-- T-85 P-100 OP-5 OP-10 Access T6 Access FA-2
-- squawk-ignore-file adding-required-field, constraint-missing-not-valid
SET LOCAL ROLE work_owner;
SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '5min';

-- T-85
ALTER TABLE ledger.head
    ADD COLUMN frontier bytea NOT NULL,
    ADD CONSTRAINT head_frontier_ck CHECK (
        pg_catalog.octet_length(frontier) = 32 * pg_catalog.bit_count((pos + 1)::bit(64))
    );

-- T-85 OP-5 OP-10 Access T6 Access FA-2
CREATE OR REPLACE FUNCTION ledger.head_guard() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog
AS $$
DECLARE
    l record;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.pos <> -1 THEN
            RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'head_must_start_empty';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.ledger_id <> OLD.ledger_id THEN
        RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'head_identity_immutable';
    END IF;
    IF NEW.epoch < OLD.epoch THEN
        RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'epoch_regressed';
    END IF;
    IF NEW.epoch > OLD.epoch THEN
        IF NEW.pos <> OLD.pos
           OR NEW.head_leaf IS DISTINCT FROM OLD.head_leaf
           OR NEW.head_recorded_at IS DISTINCT FROM OLD.head_recorded_at
           OR NEW.frontier <> OLD.frontier THEN
            RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'fence_must_not_append';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.pos < OLD.pos THEN
        RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'position_regressed';
    END IF;
    IF NEW.pos = OLD.pos THEN
        IF NEW.head_leaf IS DISTINCT FROM OLD.head_leaf
           OR NEW.head_recorded_at IS DISTINCT FROM OLD.head_recorded_at
           OR NEW.frontier <> OLD.frontier THEN
            RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'head_rewritten';
        END IF;
        RETURN NEW;
    END IF;
    SELECT leaf_hash, recorded_at, epoch INTO l
      FROM ledger.log
     WHERE ledger_id = NEW.ledger_id AND pos = NEW.pos;
    IF NOT FOUND
       OR l.leaf_hash <> NEW.head_leaf
       OR l.recorded_at <> NEW.head_recorded_at
       OR l.epoch <> NEW.epoch THEN
        RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'head_does_not_match_log';
    END IF;
    RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION ledger.head_guard() FROM PUBLIC;

-- T-85 P-100
CREATE FUNCTION ledger.head_opened() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog
AS $$
BEGIN
    PERFORM 1 FROM ledger.head WHERE ledger_id = NEW.ledger_id AND pos >= 0;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'ledger_not_opened';
    END IF;
    RETURN NULL;
END
$$;
REVOKE ALL ON FUNCTION ledger.head_opened() FROM PUBLIC;

CREATE CONSTRAINT TRIGGER head_opened
    AFTER INSERT ON ledger.head
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION ledger.head_opened();

-- T-85
GRANT UPDATE (frontier) ON ledger.head TO work_sequencer;
