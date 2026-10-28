-- OP-12 OP-13 OP-14 OP-15 P-17 P-25 P-68 T-56 Access OP-73 Access OP-74 Access T39
SET LOCAL ROLE work_owner;
SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '5min';

-- OP-12 Access OP-74
CREATE TABLE work.retention_hold (
    ledger_id       ledger.digest32 NOT NULL,
    hold_id         uuid          NOT NULL DEFAULT pg_catalog.uuidv7(),
    hold_kind       text          NOT NULL,
    subject_ref     work.party_ref,
    retention_class work.retention_class,
    state           text          NOT NULL,
    placed_at       timestamptz   NOT NULL DEFAULT pg_catalog.now(),
    released_at     timestamptz,
    CONSTRAINT retention_hold_pk PRIMARY KEY (ledger_id, hold_id),
    CONSTRAINT retention_hold_kind_ck CHECK (hold_kind IN ('statutory', 'litigation', 'regulator')),
    CONSTRAINT retention_hold_state_ck CHECK (state IN ('active', 'released')),
    CONSTRAINT retention_hold_released_ck CHECK ((state = 'released') = (released_at IS NOT NULL))
);
CREATE INDEX retention_hold_active_ix ON work.retention_hold (ledger_id, subject_ref)
    WHERE state = 'active';

-- OP-12 OP-15 T-56 Access OP-74
CREATE TABLE work.body_dek (
    ledger_id       ledger.digest32        NOT NULL,
    dek_id          uuid                 NOT NULL DEFAULT pg_catalog.uuidv7(),
    subject_ref     work.party_ref       NOT NULL,
    retention_class work.retention_class NOT NULL,
    hsm_key_label   text                 NOT NULL,
    state           text                 NOT NULL,
    created_at      timestamptz          NOT NULL DEFAULT pg_catalog.now(),
    destroyed_at    timestamptz,
    CONSTRAINT body_dek_pk PRIMARY KEY (ledger_id, dek_id),
    CONSTRAINT body_dek_class_uq UNIQUE (ledger_id, dek_id, retention_class),
    CONSTRAINT body_dek_label_uq UNIQUE (ledger_id, hsm_key_label),
    CONSTRAINT body_dek_label_ck CHECK (hsm_key_label ~ '^[A-Za-z0-9_.:-]{1,128}$'),
    CONSTRAINT body_dek_state_ck CHECK (state IN ('active', 'destroyed')),
    CONSTRAINT body_dek_destroyed_ck CHECK ((state = 'destroyed') = (destroyed_at IS NOT NULL))
);
CREATE UNIQUE INDEX body_dek_active_uq ON work.body_dek (ledger_id, subject_ref, retention_class)
    WHERE state = 'active';

-- OP-12 Access OP-74
CREATE FUNCTION work.body_dek_guard() RETURNS trigger
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
       OR NEW.hsm_key_label <> OLD.hsm_key_label OR NEW.created_at <> OLD.created_at THEN
        RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'dek_identity_immutable';
    END IF;
    IF OLD.state = 'destroyed' THEN
        RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'dek_destroyed_is_terminal';
    END IF;
    IF NEW.state = 'destroyed' THEN
        PERFORM 1 FROM work.retention_hold h
         WHERE h.ledger_id = NEW.ledger_id
           AND h.state = 'active'
           AND (h.subject_ref IS NULL OR h.subject_ref = NEW.subject_ref)
           AND (h.retention_class IS NULL OR h.retention_class = NEW.retention_class);
        IF FOUND THEN
            RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'retention_hold_active';
        END IF;
    END IF;
    RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION work.body_dek_guard() FROM PUBLIC;

CREATE TRIGGER body_dek_guard
    BEFORE INSERT OR UPDATE ON work.body_dek
    FOR EACH ROW EXECUTE FUNCTION work.body_dek_guard();

-- OP-12
CREATE FUNCTION work.retention_hold_guard() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.state <> 'active' THEN
            RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'hold_must_start_active';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.ledger_id <> OLD.ledger_id OR NEW.hold_id <> OLD.hold_id OR NEW.hold_kind <> OLD.hold_kind
       OR NEW.subject_ref IS DISTINCT FROM OLD.subject_ref
       OR NEW.retention_class IS DISTINCT FROM OLD.retention_class
       OR NEW.placed_at <> OLD.placed_at THEN
        RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'hold_identity_immutable';
    END IF;
    IF OLD.state = 'released' THEN
        RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'hold_released_is_terminal';
    END IF;
    RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION work.retention_hold_guard() FROM PUBLIC;

CREATE TRIGGER retention_hold_guard
    BEFORE INSERT OR UPDATE ON work.retention_hold
    FOR EACH ROW EXECUTE FUNCTION work.retention_hold_guard();

-- OP-2 OP-15 P-17 P-68 T-20
CREATE TABLE work.body_part (
    ledger_id         ledger.digest32        NOT NULL,
    pos               ledger.log_pos         NOT NULL,
    part              work.snake_name      NOT NULL,
    dek_id            uuid                 NOT NULL,
    retention_class   work.retention_class NOT NULL,
    storage           text                 NOT NULL,
    nonce             bytea                NOT NULL,
    ciphertext        bytea,
    object_key        text,
    ciphertext_digest ledger.digest32        NOT NULL,
    CONSTRAINT body_part_pk PRIMARY KEY (ledger_id, pos, part),
    CONSTRAINT body_part_commitment_fk FOREIGN KEY (ledger_id, pos, part)
        REFERENCES work.body_commitment (ledger_id, pos, part),
    CONSTRAINT body_part_dek_fk FOREIGN KEY (ledger_id, dek_id, retention_class)
        REFERENCES work.body_dek (ledger_id, dek_id, retention_class),
    CONSTRAINT body_part_storage_ck CHECK (
        (storage = 'inline' AND ciphertext IS NOT NULL AND object_key IS NULL)
        OR (storage = 'object_store' AND ciphertext IS NULL AND object_key IS NOT NULL)
    ),
    CONSTRAINT body_part_nonce_ck CHECK (pg_catalog.octet_length(nonce) BETWEEN 12 AND 32),
    CONSTRAINT body_part_object_key_ck CHECK (object_key IS NULL OR (object_key ~ '^[a-z0-9/_.-]+$' AND pg_catalog.octet_length(object_key) <= 512))
);
CREATE INDEX body_part_dek_ix ON work.body_part (ledger_id, dek_id);

-- OP-12 OP-15 Access OP-73
CREATE TABLE work.body_part_tombstone (
    ledger_id     ledger.digest32   NOT NULL,
    pos           ledger.log_pos    NOT NULL,
    part          work.snake_name NOT NULL,
    cause         text            NOT NULL,
    tombstoned_at timestamptz     NOT NULL DEFAULT pg_catalog.now(),
    CONSTRAINT body_part_tombstone_pk PRIMARY KEY (ledger_id, pos, part),
    CONSTRAINT body_part_tombstone_part_fk FOREIGN KEY (ledger_id, pos, part)
        REFERENCES work.body_part (ledger_id, pos, part),
    CONSTRAINT body_part_tombstone_cause_ck CHECK (
        cause IN ('retention_expired', 'redacted', 'subject_erasure', 'tenant_closure')
    )
);

-- OP-14 Access OP-74 Access OP-78
CREATE TABLE work.erasure_log (
    ledger_id    ledger.digest32 NOT NULL,
    erasure_id   uuid          NOT NULL DEFAULT pg_catalog.uuidv7(),
    dek_id       uuid          NOT NULL,
    cause        text          NOT NULL,
    state        text          NOT NULL,
    requested_at timestamptz   NOT NULL DEFAULT pg_catalog.now(),
    completed_at timestamptz,
    CONSTRAINT erasure_log_pk PRIMARY KEY (ledger_id, erasure_id),
    CONSTRAINT erasure_log_dek_fk FOREIGN KEY (ledger_id, dek_id) REFERENCES work.body_dek (ledger_id, dek_id),
    CONSTRAINT erasure_log_cause_ck CHECK (
        cause IN ('subject_request', 'retention_expired', 'redaction', 'tenant_closure')
    ),
    CONSTRAINT erasure_log_state_ck CHECK (state IN ('waiting_on_hold', 'completed')),
    CONSTRAINT erasure_log_completed_ck CHECK ((state = 'completed') = (completed_at IS NOT NULL))
);

-- OP-14 Access OP-78
CREATE FUNCTION work.erasure_log_guard() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog
AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        IF NEW.ledger_id <> OLD.ledger_id OR NEW.erasure_id <> OLD.erasure_id OR NEW.dek_id <> OLD.dek_id
           OR NEW.cause <> OLD.cause OR NEW.requested_at <> OLD.requested_at THEN
            RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'erasure_identity_immutable';
        END IF;
        IF OLD.state = 'completed' THEN
            RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'erasure_completed_is_terminal';
        END IF;
    END IF;
    IF NEW.state = 'completed' THEN
        PERFORM 1 FROM work.body_dek
         WHERE ledger_id = NEW.ledger_id AND dek_id = NEW.dek_id AND state = 'destroyed';
        IF NOT FOUND THEN
            RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'erasure_without_destroyed_dek';
        END IF;
    END IF;
    RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION work.erasure_log_guard() FROM PUBLIC;

CREATE TRIGGER erasure_log_guard
    BEFORE INSERT OR UPDATE ON work.erasure_log
    FOR EACH ROW EXECUTE FUNCTION work.erasure_log_guard();

SELECT ledger.guard_table('work.retention_hold', 'mutable');
SELECT ledger.guard_table('work.body_dek', 'mutable');
SELECT ledger.guard_table('work.body_part', 'append_only');
SELECT ledger.guard_table('work.body_part_tombstone', 'append_only');
SELECT ledger.guard_table('work.erasure_log', 'mutable');

SELECT ledger.apply_ledger_scope('work.retention_hold');
SELECT ledger.apply_ledger_scope('work.body_dek');
SELECT ledger.apply_ledger_scope('work.body_part');
SELECT ledger.apply_ledger_scope('work.body_part_tombstone');
SELECT ledger.apply_ledger_scope('work.erasure_log');

REVOKE ALL ON work.retention_hold, work.body_dek, work.body_part,
              work.body_part_tombstone, work.erasure_log FROM PUBLIC;
GRANT SELECT ON work.retention_hold, work.body_dek, work.body_part,
                work.body_part_tombstone, work.erasure_log
    TO work_app, work_sequencer, work_erasure;
GRANT INSERT ON work.body_dek, work.body_part TO work_sequencer;
GRANT INSERT ON work.retention_hold, work.body_part_tombstone, work.erasure_log TO work_erasure;
GRANT UPDATE (state, released_at) ON work.retention_hold TO work_erasure;
GRANT UPDATE (state, destroyed_at) ON work.body_dek TO work_erasure;
GRANT UPDATE (state, completed_at) ON work.erasure_log TO work_erasure;

COMMENT ON TABLE work.retention_hold IS 'label=OPERATIONAL; home=canonical; guard=mutable; erasure=pseudonymous_skeleton';
COMMENT ON TABLE work.body_dek IS 'label=OPERATIONAL; home=canonical; guard=mutable; erasure=pseudonymous_skeleton';
COMMENT ON TABLE work.body_part IS 'label=CANONICAL; home=canonical; guard=append_only; erasure=crypto_shred';
COMMENT ON TABLE work.body_part_tombstone IS 'label=CANONICAL; home=canonical; guard=append_only; erasure=none';
COMMENT ON TABLE work.erasure_log IS 'label=OPERATIONAL; home=canonical; guard=mutable; erasure=retention_class:erasure_log';
