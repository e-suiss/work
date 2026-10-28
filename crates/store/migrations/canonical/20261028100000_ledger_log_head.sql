-- OP-5 OP-9 P-5 P-11 P-23 T-36 Access OP-12 Access OP-17 Access T6 Access T7 Access FA-2 Access TI-RT11
SET LOCAL ROLE work_owner;
SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '5min';

-- OP-5 OP-9 Access T6 Access FA-2
CREATE TABLE ledger.head (
    ledger_id        ledger.digest32 NOT NULL,
    pos              bigint          NOT NULL,
    epoch            bigint          NOT NULL,
    head_leaf        ledger.digest32,
    head_recorded_at ledger.ms_time,
    CONSTRAINT head_pk PRIMARY KEY (ledger_id),
    CONSTRAINT head_pos_ck CHECK (pos >= -1),
    CONSTRAINT head_epoch_ck CHECK (epoch >= 0),
    CONSTRAINT head_empty_ck CHECK (
        (pos = -1) = (head_leaf IS NULL) AND (pos = -1) = (head_recorded_at IS NULL)
    )
) WITH (fillfactor = 70);

-- OP-2 P-5 P-11 P-79 Access TI-RT11
CREATE TABLE ledger.log (
    ledger_id      ledger.digest32 NOT NULL,
    pos            ledger.log_pos  NOT NULL,
    epoch          bigint          NOT NULL,
    record_id      ledger.digest32 NOT NULL,
    recorded_at    ledger.ms_time  NOT NULL,
    prev           ledger.digest32 NOT NULL,
    leaf_hash      ledger.digest32 NOT NULL,
    record_bytes   bytea           NOT NULL,
    envelope_bytes bytea           NOT NULL,
    CONSTRAINT log_pk PRIMARY KEY (ledger_id, pos),
    CONSTRAINT log_record_uq UNIQUE (ledger_id, record_id),
    CONSTRAINT log_head_fk FOREIGN KEY (ledger_id) REFERENCES ledger.head (ledger_id),
    CONSTRAINT log_epoch_ck CHECK (epoch >= 0),
    CONSTRAINT log_bytes_ck CHECK (
        pg_catalog.octet_length(record_bytes) > 0 AND pg_catalog.octet_length(envelope_bytes) > 0
    )
);

-- OP-5 OP-6 P-11 Access T6
CREATE FUNCTION ledger.log_before_insert() RETURNS trigger
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
    IF NEW.pos > 0 THEN
        SELECT leaf_hash, recorded_at INTO p
          FROM ledger.log
         WHERE ledger_id = NEW.ledger_id AND pos = NEW.pos - 1;
        IF NOT FOUND THEN
            RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'position_gap';
        END IF;
        IF NEW.prev <> p.leaf_hash THEN
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

CREATE TRIGGER log_before_insert
    BEFORE INSERT ON ledger.log
    FOR EACH ROW EXECUTE FUNCTION ledger.log_before_insert();

-- OP-5 Access T7
CREATE FUNCTION ledger.log_head_advanced() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog
AS $$
BEGIN
    PERFORM 1 FROM ledger.head
     WHERE ledger_id = NEW.ledger_id AND pos >= NEW.pos AND epoch = NEW.epoch;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'head_not_advanced';
    END IF;
    RETURN NULL;
END
$$;
REVOKE ALL ON FUNCTION ledger.log_head_advanced() FROM PUBLIC;

CREATE CONSTRAINT TRIGGER log_head_advanced
    AFTER INSERT ON ledger.log
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION ledger.log_head_advanced();

-- OP-5 OP-10 Access T6 Access FA-2
CREATE FUNCTION ledger.head_guard() RETURNS trigger
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
           OR NEW.head_recorded_at IS DISTINCT FROM OLD.head_recorded_at THEN
            RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'fence_must_not_append';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.pos < OLD.pos THEN
        RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'position_regressed';
    END IF;
    IF NEW.pos = OLD.pos THEN
        IF NEW.head_leaf IS DISTINCT FROM OLD.head_leaf
           OR NEW.head_recorded_at IS DISTINCT FROM OLD.head_recorded_at THEN
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

CREATE TRIGGER head_guard
    BEFORE INSERT OR UPDATE ON ledger.head
    FOR EACH ROW EXECUTE FUNCTION ledger.head_guard();

SELECT ledger.guard_table('ledger.head', 'mutable');
SELECT ledger.guard_table('ledger.log', 'append_only');

SELECT ledger.apply_ledger_scope('ledger.head');
SELECT ledger.apply_ledger_scope('ledger.log');

REVOKE ALL ON ledger.head, ledger.log FROM PUBLIC, work_app, work_sequencer, work_checkpointer, work_publisher, work_erasure, work_archive;
GRANT SELECT ON ledger.head, ledger.log TO work_app, work_sequencer, work_checkpointer, work_publisher, work_erasure;
GRANT INSERT ON ledger.head, ledger.log TO work_sequencer;
GRANT UPDATE (pos, epoch, head_leaf, head_recorded_at) ON ledger.head TO work_sequencer;

COMMENT ON TABLE ledger.head IS 'label=SYNC-DERIVED; home=canonical; guard=mutable; erasure=none';
COMMENT ON TABLE ledger.log IS 'label=CANONICAL; home=canonical; guard=append_only; erasure=pseudonymous_skeleton';
