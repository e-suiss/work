-- RC-41 RC-42 RC-43 T-105 E-39 SEC-15 OP-4 OP-47 T-17 T-36 T-79 T-80 Access OP-12 Access OP-73
SET LOCAL ROLE work_owner;
SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '5min';

-- RC-42 T-105 E-39
CREATE TABLE work.executor_delivery (
    ledger_id       ledger.digest32 NOT NULL,
    seq             bigint          NOT NULL,
    pos             ledger.log_pos  NOT NULL,
    record_id       ledger.digest32 NOT NULL,
    addressee       text            NOT NULL,
    kind            text            NOT NULL,
    commitment      ledger.digest32 NOT NULL,
    body            bytea           NOT NULL,
    issued_at       ledger.ms_time  NOT NULL,
    doorbell        text            NOT NULL,
    attempts        bigint          NOT NULL,
    next_attempt_at ledger.ms_time  NOT NULL,
    last_error      text,
    settled_at      ledger.ms_time,
    CONSTRAINT executor_delivery_pk PRIMARY KEY (ledger_id, seq),
    CONSTRAINT executor_delivery_once_uq UNIQUE (ledger_id, pos, addressee, kind),
    CONSTRAINT executor_delivery_log_fk FOREIGN KEY (ledger_id, pos) REFERENCES ledger.log (ledger_id, pos),
    CONSTRAINT executor_delivery_seq_ck CHECK (seq >= 1),
    CONSTRAINT executor_delivery_addressee_ck CHECK (pg_catalog.octet_length(addressee) BETWEEN 1 AND 255),
    CONSTRAINT executor_delivery_kind_ck CHECK (kind IN ('commitment', 'request')),
    CONSTRAINT executor_delivery_body_ck CHECK (pg_catalog.octet_length(body) BETWEEN 1 AND 65536),
    CONSTRAINT executor_delivery_doorbell_ck CHECK (doorbell IN ('pending', 'rung', 'unrouted')),
    CONSTRAINT executor_delivery_attempts_ck CHECK (attempts >= 0),
    CONSTRAINT executor_delivery_error_ck CHECK (
        last_error IS NULL OR last_error ~ '^[a-z][a-z0-9_:-]{0,63}$'),
    CONSTRAINT executor_delivery_settled_ck CHECK ((doorbell = 'pending') = (settled_at IS NULL))
);
CREATE INDEX executor_delivery_addressee_ix ON work.executor_delivery (ledger_id, addressee, seq);
CREATE INDEX executor_delivery_due_ix ON work.executor_delivery (ledger_id, next_attempt_at)
    WHERE doorbell = 'pending';

-- RC-42 T-36
CREATE FUNCTION work.executor_delivery_guard() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog
AS $$
BEGIN
    IF NEW.ledger_id <> OLD.ledger_id OR NEW.seq <> OLD.seq OR NEW.pos <> OLD.pos
       OR NEW.record_id <> OLD.record_id OR NEW.addressee <> OLD.addressee OR NEW.kind <> OLD.kind
       OR NEW.commitment <> OLD.commitment OR NEW.body <> OLD.body OR NEW.issued_at <> OLD.issued_at THEN
        RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'executor_delivery_immutable';
    END IF;
    IF OLD.doorbell <> 'pending' THEN
        RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'executor_delivery_settled';
    END IF;
    IF NEW.attempts < OLD.attempts THEN
        RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'executor_delivery_attempts_backwards';
    END IF;
    RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION work.executor_delivery_guard() FROM PUBLIC;

CREATE TRIGGER executor_delivery_guard
    BEFORE UPDATE ON work.executor_delivery
    FOR EACH ROW EXECUTE FUNCTION work.executor_delivery_guard();

-- Access OP-73
SELECT ledger.guard_table('work.executor_delivery', 'mutable');

-- T-13 T-80 Access OP-12
SELECT ledger.apply_ledger_scope('work.executor_delivery');
ALTER POLICY ledger_scope ON work.executor_delivery
    USING (
        ledger_id = ledger.current_ledger_id()
        OR (CURRENT_USER = 'work_owner' AND pg_catalog.current_setting('app.outbox_scan', true) = 'on')
    );

-- T-80 T-83 Access OP-12
CREATE FUNCTION work.executor_delivery_ledgers(after_ledger ledger.digest32, due_ms bigint, max_ledgers bigint)
    RETURNS SETOF ledger.digest32
    LANGUAGE sql STABLE
    SECURITY DEFINER
    SET search_path = pg_catalog, pg_temp
    SET app.outbox_scan = 'on'
AS $$
    SELECT DISTINCT d.ledger_id FROM work.executor_delivery d
     WHERE d.doorbell = 'pending'
       AND d.next_attempt_at <= pg_catalog.to_timestamp(0)
           + interval '1 millisecond' * COALESCE(due_ms, 0)::double precision
       AND (after_ledger IS NULL OR d.ledger_id > after_ledger)
     ORDER BY d.ledger_id
     LIMIT GREATEST(COALESCE(max_ledgers, 0), 0)
$$;
REVOKE ALL ON FUNCTION work.executor_delivery_ledgers(ledger.digest32, bigint, bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION work.executor_delivery_ledgers(ledger.digest32, bigint, bigint) FROM work_owner;
GRANT EXECUTE ON FUNCTION work.executor_delivery_ledgers(ledger.digest32, bigint, bigint) TO work_publisher;

-- T-79 Access OP-73
REVOKE ALL ON work.executor_delivery FROM PUBLIC;
GRANT INSERT ON work.executor_delivery TO work_sequencer;
GRANT SELECT ON work.executor_delivery TO work_sequencer, work_app, work_publisher;
GRANT UPDATE (doorbell, attempts, next_attempt_at, last_error, settled_at)
    ON work.executor_delivery TO work_publisher;

COMMENT ON TABLE work.executor_delivery IS 'label=OPERATIONAL; home=canonical; guard=mutable; erasure=none';

-- SEC-15 OP-4 OP-47
CREATE TABLE work.single_use (
    ledger_id       ledger.digest32   NOT NULL,
    authority_digest ledger.digest32  NOT NULL,
    idem_key        text              NOT NULL,
    pos             ledger.log_pos    NOT NULL,
    record_id       ledger.digest32   NOT NULL,
    relies_on       ledger.digest32[] NOT NULL,
    CONSTRAINT single_use_pk PRIMARY KEY (ledger_id, authority_digest),
    CONSTRAINT single_use_key_uq UNIQUE (ledger_id, idem_key),
    CONSTRAINT single_use_pos_uq UNIQUE (ledger_id, pos),
    CONSTRAINT single_use_log_fk FOREIGN KEY (ledger_id, pos) REFERENCES ledger.log (ledger_id, pos),
    CONSTRAINT single_use_key_ck CHECK (pg_catalog.octet_length(idem_key) BETWEEN 1 AND 255),
    CONSTRAINT single_use_relies_ck CHECK (
        pg_catalog.cardinality(relies_on) <= 256
        AND pg_catalog.array_position(relies_on, NULL) IS NULL)
);

SELECT ledger.guard_table('work.single_use', 'append_only');
SELECT ledger.apply_ledger_scope('work.single_use');

REVOKE ALL ON work.single_use FROM PUBLIC;
GRANT SELECT ON work.single_use TO work_app, work_sequencer;
GRANT INSERT ON work.single_use TO work_sequencer;

COMMENT ON TABLE work.single_use IS 'label=SYNC-DERIVED; home=canonical; guard=append_only; erasure=none';
