-- E-8 E-12 T-17 T-36 T-79 T-80 OP-12 OP-34 Access OP-12 Access OP-73
SET LOCAL ROLE work_owner;
SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '5min';

-- E-8 E-12 T-17
CREATE TABLE work.claim_delivery (
    ledger_id       ledger.digest32 NOT NULL,
    record_id       ledger.digest32 NOT NULL,
    subject         bytea           NOT NULL,
    pos             ledger.log_pos  NOT NULL,
    commitment      ledger.digest32 NOT NULL,
    issuer          bytea           NOT NULL,
    domain_id       ledger.digest32 NOT NULL,
    pep             ledger.digest32 NOT NULL,
    issued_at       ledger.ms_time  NOT NULL,
    delivery        text            NOT NULL,
    attempts        bigint          NOT NULL,
    next_attempt_at ledger.ms_time  NOT NULL,
    last_error      text,
    access_claim    bytea,
    access_pos      bigint,
    replayed        boolean,
    held_reason     text,
    settled_at      ledger.ms_time,
    CONSTRAINT claim_delivery_pk PRIMARY KEY (ledger_id, record_id, subject),
    CONSTRAINT claim_delivery_log_fk FOREIGN KEY (ledger_id, pos) REFERENCES ledger.log (ledger_id, pos),
    CONSTRAINT claim_delivery_subject_ck CHECK (pg_catalog.octet_length(subject) = 16),
    CONSTRAINT claim_delivery_issuer_ck CHECK (pg_catalog.octet_length(issuer) = 16),
    CONSTRAINT claim_delivery_delivery_ck CHECK (delivery IN ('pending', 'delivered', 'quarantined')),
    CONSTRAINT claim_delivery_attempts_ck CHECK (attempts >= 0),
    CONSTRAINT claim_delivery_error_ck CHECK (
        last_error IS NULL OR last_error ~ '^[a-z][a-z0-9_:-]{0,63}$'),
    CONSTRAINT claim_delivery_reason_ck CHECK (
        held_reason IS NULL OR held_reason ~ '^[!-~]{1,128}$'),
    CONSTRAINT claim_delivery_claim_ck CHECK (
        access_claim IS NULL OR pg_catalog.octet_length(access_claim) = 16),
    CONSTRAINT claim_delivery_settled_ck CHECK (
        (delivery = 'pending') = (settled_at IS NULL)
        AND (delivery = 'pending') = (access_claim IS NULL)
        AND (delivery = 'pending') = (access_pos IS NULL)
        AND (delivery = 'delivered') = (replayed IS NOT NULL)
        AND (delivery = 'quarantined') = (held_reason IS NOT NULL)
        AND (access_pos IS NULL OR access_pos >= 0))
);
CREATE INDEX claim_delivery_due_ix ON work.claim_delivery (ledger_id, next_attempt_at)
    WHERE delivery = 'pending';

-- E-8 E-12 T-36
CREATE FUNCTION work.claim_delivery_guard() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog
AS $$
BEGIN
    IF NEW.ledger_id <> OLD.ledger_id OR NEW.record_id <> OLD.record_id OR NEW.subject <> OLD.subject
       OR NEW.pos <> OLD.pos OR NEW.commitment <> OLD.commitment OR NEW.issuer <> OLD.issuer
       OR NEW.domain_id <> OLD.domain_id OR NEW.pep <> OLD.pep OR NEW.issued_at <> OLD.issued_at THEN
        RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'claim_delivery_claim_immutable';
    END IF;
    IF OLD.delivery <> 'pending' THEN
        RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'claim_delivery_settled';
    END IF;
    IF NEW.attempts < OLD.attempts THEN
        RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'claim_delivery_attempts_backwards';
    END IF;
    RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION work.claim_delivery_guard() FROM PUBLIC;

CREATE TRIGGER claim_delivery_guard
    BEFORE UPDATE ON work.claim_delivery
    FOR EACH ROW EXECUTE FUNCTION work.claim_delivery_guard();

-- Access OP-73
SELECT ledger.guard_table('work.claim_delivery', 'mutable');

-- T-13 T-80 OP-34 Access OP-12
SELECT ledger.apply_ledger_scope('work.claim_delivery');
ALTER POLICY ledger_scope ON work.claim_delivery
    USING (
        ledger_id = ledger.current_ledger_id()
        OR (CURRENT_USER = 'work_owner' AND pg_catalog.current_setting('app.outbox_scan', true) = 'on')
    );

-- T-80 T-83 E-12 OP-34 Access OP-12
CREATE FUNCTION work.claim_delivery_ledgers(after_ledger ledger.digest32, due_ms bigint, max_ledgers bigint)
    RETURNS SETOF ledger.digest32
    LANGUAGE sql STABLE
    SECURITY DEFINER
    SET search_path = pg_catalog, pg_temp
    SET app.outbox_scan = 'on'
AS $$
    SELECT DISTINCT c.ledger_id FROM work.claim_delivery c
     WHERE c.delivery = 'pending'
       AND c.next_attempt_at <= pg_catalog.to_timestamp(0)
           + interval '1 millisecond' * COALESCE(due_ms, 0)::double precision
       AND (after_ledger IS NULL OR c.ledger_id > after_ledger)
     ORDER BY c.ledger_id
     LIMIT GREATEST(COALESCE(max_ledgers, 0), 0)
$$;
REVOKE ALL ON FUNCTION work.claim_delivery_ledgers(ledger.digest32, bigint, bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION work.claim_delivery_ledgers(ledger.digest32, bigint, bigint) FROM work_owner;
GRANT EXECUTE ON FUNCTION work.claim_delivery_ledgers(ledger.digest32, bigint, bigint) TO work_publisher;

-- T-79 Access OP-73
REVOKE ALL ON work.claim_delivery FROM PUBLIC;
GRANT INSERT ON work.claim_delivery TO work_sequencer;
GRANT SELECT ON work.claim_delivery TO work_app, work_publisher;
GRANT UPDATE (delivery, attempts, next_attempt_at, last_error, access_claim, access_pos, replayed, held_reason, settled_at)
    ON work.claim_delivery TO work_publisher;

COMMENT ON TABLE work.claim_delivery IS 'label=OPERATIONAL; home=canonical; guard=mutable; erasure=none';
