-- OP-45 OP-12 OP-15 P-25 P-68 T-56 T-79 Access OP-73 Access OP-74 Access OP-145
-- squawk-ignore-file adding-foreign-key-constraint, constraint-missing-not-valid, renaming-column
SET LOCAL ROLE work_owner;
SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '5min';

-- OP-45
ALTER TABLE work.body_dek DROP CONSTRAINT body_dek_label_uq;
ALTER TABLE work.body_dek DROP CONSTRAINT body_dek_label_ck;
ALTER TABLE work.body_dek RENAME COLUMN hsm_key_label TO kek_id;
ALTER TABLE work.body_dek ADD COLUMN wrapped_key bytea;
ALTER TABLE work.body_dek
    ADD CONSTRAINT body_dek_kek_id_ck CHECK (kek_id ~ '^work\.[0-9a-f]{64}\.kek\.v[1-9][0-9]{0,8}$'),
    ADD CONSTRAINT body_dek_wrapped_ck CHECK ((state = 'active') = (wrapped_key IS NOT NULL)),
    ADD CONSTRAINT body_dek_wrapped_length_ck CHECK (wrapped_key IS NULL OR pg_catalog.octet_length(wrapped_key) = 40);

-- OP-45 OP-12 Access OP-74
CREATE OR REPLACE FUNCTION work.body_dek_guard() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.state <> 'active' THEN
            RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'dek_must_start_active';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.ledger_id <> OLD.ledger_id OR NEW.dek_id <> OLD.dek_id
       OR NEW.subject_ref <> OLD.subject_ref OR NEW.retention_class <> OLD.retention_class
       OR NEW.created_at <> OLD.created_at THEN
        RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'dek_identity_immutable';
    END IF;
    IF OLD.state = 'destroyed' THEN
        RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'dek_destroyed_is_terminal';
    END IF;
    IF NEW.state = 'active' THEN
        IF (NEW.kek_id = OLD.kek_id) <> (NEW.wrapped_key = OLD.wrapped_key) THEN
            RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'dek_rewrap_changes_kek_and_key';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.kek_id <> OLD.kek_id THEN
        RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'dek_identity_immutable';
    END IF;
    PERFORM 1 FROM work.retention_hold h
     WHERE h.ledger_id = NEW.ledger_id
       AND h.state = 'active'
       AND (h.subject_ref IS NULL OR h.subject_ref = NEW.subject_ref)
       AND (h.retention_class IS NULL OR h.retention_class = NEW.retention_class);
    IF FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'retention_hold_active';
    END IF;
    RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION work.body_dek_guard() FROM PUBLIC;

REVOKE UPDATE (state, destroyed_at) ON work.body_dek FROM work_erasure;
GRANT UPDATE (kek_id, wrapped_key, state, destroyed_at) ON work.body_dek TO work_erasure;

-- OP-45
CREATE FUNCTION work.body_part_guard() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog
AS $$
BEGIN
    PERFORM 1 FROM work.body_dek d
     WHERE d.ledger_id = NEW.ledger_id AND d.dek_id = NEW.dek_id AND d.state = 'active'
       FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'body_part_dek_not_active';
    END IF;
    RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION work.body_part_guard() FROM PUBLIC;

CREATE TRIGGER body_part_guard
    BEFORE INSERT ON work.body_part
    FOR EACH ROW EXECUTE FUNCTION work.body_part_guard();

-- OP-45 P-25 P-68
CREATE TABLE work.body_part_key (
    ledger_id   ledger.digest32   NOT NULL,
    pos         ledger.log_pos    NOT NULL,
    part        work.snake_name NOT NULL,
    wrapped_key bytea,
    shredded_at timestamptz,
    CONSTRAINT body_part_key_pk PRIMARY KEY (ledger_id, pos, part),
    CONSTRAINT body_part_key_part_fk FOREIGN KEY (ledger_id, pos, part)
        REFERENCES work.body_part (ledger_id, pos, part),
    CONSTRAINT body_part_key_shredded_ck CHECK ((shredded_at IS NULL) = (wrapped_key IS NOT NULL)),
    CONSTRAINT body_part_key_length_ck CHECK (wrapped_key IS NULL OR pg_catalog.octet_length(wrapped_key) = 40)
);

-- OP-45 OP-12 Access OP-74
CREATE FUNCTION work.body_part_key_guard() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.wrapped_key IS NULL THEN
            RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'part_key_must_start_wrapped';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.ledger_id <> OLD.ledger_id OR NEW.pos <> OLD.pos OR NEW.part <> OLD.part THEN
        RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'part_key_identity_immutable';
    END IF;
    IF OLD.wrapped_key IS NULL OR NEW.wrapped_key IS NOT NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'part_key_shred_once';
    END IF;
    PERFORM 1 FROM work.body_part p
      JOIN work.body_dek d ON d.ledger_id = p.ledger_id AND d.dek_id = p.dek_id
      JOIN work.retention_hold h ON h.ledger_id = p.ledger_id
     WHERE p.ledger_id = NEW.ledger_id AND p.pos = NEW.pos AND p.part = NEW.part
       AND h.state = 'active'
       AND (h.subject_ref IS NULL OR h.subject_ref = d.subject_ref)
       AND (h.retention_class IS NULL OR h.retention_class = p.retention_class);
    IF FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'retention_hold_active';
    END IF;
    RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION work.body_part_key_guard() FROM PUBLIC;

CREATE TRIGGER body_part_key_guard
    BEFORE INSERT OR UPDATE ON work.body_part_key
    FOR EACH ROW EXECUTE FUNCTION work.body_part_key_guard();

SELECT ledger.guard_table('work.body_part_key', 'mutable');
SELECT ledger.apply_ledger_scope('work.body_part_key');

REVOKE ALL ON work.body_part_key FROM PUBLIC;
GRANT SELECT ON work.body_part_key TO work_app, work_sequencer, work_erasure;
GRANT INSERT ON work.body_part_key TO work_sequencer;
GRANT UPDATE (wrapped_key, shredded_at) ON work.body_part_key TO work_erasure;

COMMENT ON TABLE work.body_part_key IS 'label=OPERATIONAL; home=canonical; guard=mutable; erasure=crypto_shred';

-- OP-45 OP-14 Access OP-78
ALTER TABLE work.erasure_log ADD COLUMN pos ledger.log_pos;
ALTER TABLE work.erasure_log ADD COLUMN part work.snake_name;
ALTER TABLE work.erasure_log
    ADD CONSTRAINT erasure_log_part_ck CHECK ((pos IS NULL) = (part IS NULL)),
    ADD CONSTRAINT erasure_log_part_fk FOREIGN KEY (ledger_id, pos, part)
        REFERENCES work.body_part_key (ledger_id, pos, part);

-- OP-45 OP-14 Access OP-78
CREATE OR REPLACE FUNCTION work.erasure_log_guard() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog
AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        IF NEW.ledger_id <> OLD.ledger_id OR NEW.erasure_id <> OLD.erasure_id OR NEW.dek_id <> OLD.dek_id
           OR NEW.cause <> OLD.cause OR NEW.requested_at <> OLD.requested_at
           OR NEW.pos IS DISTINCT FROM OLD.pos OR NEW.part IS DISTINCT FROM OLD.part THEN
            RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'erasure_identity_immutable';
        END IF;
        IF OLD.state = 'completed' THEN
            RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'erasure_completed_is_terminal';
        END IF;
    END IF;
    IF NEW.state = 'completed' THEN
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
