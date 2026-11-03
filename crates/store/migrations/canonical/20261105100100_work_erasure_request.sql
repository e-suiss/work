-- P-111 P-25 OP-45 OP-14 Access OP-78
-- squawk-ignore-file adding-foreign-key-constraint, constraint-missing-not-valid, disallowed-unique-constraint
SET LOCAL ROLE work_owner;
SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '5min';

-- P-111 OP-45
ALTER TABLE work.erasure_log ADD COLUMN request_pos ledger.log_pos;
ALTER TABLE work.erasure_log
    ADD CONSTRAINT erasure_log_request_fk FOREIGN KEY (ledger_id, request_pos)
        REFERENCES ledger.log (ledger_id, pos),
    ADD CONSTRAINT erasure_log_request_ck CHECK ((cause = 'redaction') = (request_pos IS NOT NULL)) NOT VALID,
    ADD CONSTRAINT erasure_log_request_uq UNIQUE (ledger_id, request_pos, pos, part);

-- P-111 OP-45 OP-14 Access OP-78
CREATE OR REPLACE FUNCTION work.erasure_log_guard() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog
AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        IF NEW.ledger_id <> OLD.ledger_id OR NEW.erasure_id <> OLD.erasure_id OR NEW.dek_id <> OLD.dek_id
           OR NEW.cause <> OLD.cause OR NEW.requested_at <> OLD.requested_at
           OR NEW.pos IS DISTINCT FROM OLD.pos OR NEW.part IS DISTINCT FROM OLD.part
           OR NEW.request_pos IS DISTINCT FROM OLD.request_pos THEN
            RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'erasure_identity_immutable';
        END IF;
        IF OLD.state = 'completed' THEN
            RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'erasure_completed_is_terminal';
        END IF;
        IF OLD.settles_at IS NOT NULL AND NEW.settles_at IS DISTINCT FROM OLD.settles_at THEN
            RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'erasure_settles_at_immutable';
        END IF;
    END IF;
    IF NEW.state <> 'waiting_on_hold' THEN
        IF NEW.pos IS NULL THEN
            PERFORM 1 FROM work.body_dek
             WHERE ledger_id = NEW.ledger_id AND dek_id = NEW.dek_id AND state = 'destroyed';
            IF NOT FOUND THEN
                RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'erasure_without_destroyed_dek';
            END IF;
        ELSE
            PERFORM 1 FROM work.body_part_key
             WHERE ledger_id = NEW.ledger_id AND pos = NEW.pos AND part = NEW.part
               AND wrapped_key IS NULL;
            IF NOT FOUND THEN
                RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'erasure_without_shredded_part_key';
            END IF;
        END IF;
    END IF;
    RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION work.erasure_log_guard() FROM PUBLIC;
