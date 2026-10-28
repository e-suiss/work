-- OP-1 OP-7 OP-8 P-28 P-29 T-11 C-4 C-40
SET LOCAL ROLE work_owner;
SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '5min';

-- OP-1 OP-7 P-28 P-29 C-40
CREATE TABLE work.item_head (
    ledger_id ledger.digest32   NOT NULL,
    item_kind text            NOT NULL,
    item_id   bytea           NOT NULL,
    version   bigint          NOT NULL,
    last_pos  ledger.log_pos    NOT NULL,
    heads     ledger.digest32[],
    CONSTRAINT item_head_pk PRIMARY KEY (ledger_id, item_kind, item_id),
    CONSTRAINT item_head_last_fk FOREIGN KEY (ledger_id, last_pos) REFERENCES ledger.log (ledger_id, pos),
    CONSTRAINT item_head_kind_ck CHECK (item_kind IN ('work', 'commitment', 'condition')),
    CONSTRAINT item_head_id_ck CHECK (
        (item_kind = 'work' AND pg_catalog.octet_length(item_id) = 16)
        OR (item_kind IN ('commitment', 'condition') AND pg_catalog.octet_length(item_id) = 32)
    ),
    CONSTRAINT item_head_version_ck CHECK (version >= 1),
    CONSTRAINT item_head_heads_ck CHECK (
        (item_kind = 'work' AND heads IS NULL)
        OR (item_kind IN ('commitment', 'condition')
            AND pg_catalog.cardinality(heads) BETWEEN 1 AND 64
            AND pg_catalog.array_position(heads, NULL) IS NULL)
    )
) WITH (fillfactor = 70);

-- P-29 OP-7
CREATE FUNCTION work.item_head_guard() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.version <> 1 THEN
            RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'item_version_must_start_at_one';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.ledger_id <> OLD.ledger_id OR NEW.item_kind <> OLD.item_kind OR NEW.item_id <> OLD.item_id THEN
        RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'item_identity_immutable';
    END IF;
    IF NEW.version <> OLD.version + 1 THEN
        RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'item_version_not_monotonic';
    END IF;
    IF NEW.last_pos <= OLD.last_pos THEN
        RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'item_position_not_monotonic';
    END IF;
    RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION work.item_head_guard() FROM PUBLIC;

CREATE TRIGGER item_head_guard
    BEFORE INSERT OR UPDATE ON work.item_head
    FOR EACH ROW EXECUTE FUNCTION work.item_head_guard();

-- OP-8 OP-12 T-32 P-54 Access OP-73
CREATE TABLE work.idempotency_key (
    ledger_id        ledger.digest32  NOT NULL,
    caller_ref       work.party_ref NOT NULL,
    idem_key         text           NOT NULL,
    request_digest   ledger.digest32  NOT NULL,
    outcome          text           NOT NULL,
    result_pos       ledger.log_pos,
    result_record_id ledger.digest32,
    reason           work.reason_code,
    created_at       timestamptz    NOT NULL DEFAULT pg_catalog.now(),
    CONSTRAINT idempotency_key_pk PRIMARY KEY (ledger_id, caller_ref, idem_key, created_at),
    CONSTRAINT idempotency_key_result_fk FOREIGN KEY (ledger_id, result_pos)
        REFERENCES ledger.log (ledger_id, pos),
    CONSTRAINT idempotency_key_key_ck CHECK (idem_key ~ '^[!-~]{1,255}$'),
    CONSTRAINT idempotency_key_outcome_ck CHECK (outcome IN ('recorded', 'rejected')),
    CONSTRAINT idempotency_key_result_ck CHECK (
        (outcome = 'recorded' AND result_pos IS NOT NULL AND result_record_id IS NOT NULL AND reason IS NULL)
        OR (outcome = 'rejected' AND result_pos IS NULL AND result_record_id IS NULL AND reason IS NOT NULL)
    )
) PARTITION BY RANGE (created_at);

-- OP-8 OP-12 P-35 FD-19 Access OP-73
CREATE TABLE work.inbound_seen (
    ledger_id     ledger.digest32 NOT NULL,
    source        text          NOT NULL,
    source_id     text          NOT NULL,
    content_digest ledger.digest32 NOT NULL,
    result_pos    ledger.log_pos,
    seen_at       timestamptz   NOT NULL DEFAULT pg_catalog.now(),
    CONSTRAINT inbound_seen_pk PRIMARY KEY (ledger_id, source, source_id, seen_at),
    CONSTRAINT inbound_seen_result_fk FOREIGN KEY (ledger_id, result_pos)
        REFERENCES ledger.log (ledger_id, pos),
    CONSTRAINT inbound_seen_source_ck CHECK (source ~ '^[!-~]+$' AND pg_catalog.octet_length(source) <= 1024),
    CONSTRAINT inbound_seen_id_ck CHECK (source_id ~ '^[!-~]+$' AND pg_catalog.octet_length(source_id) <= 1024)
) PARTITION BY RANGE (seen_at);

-- OP-1
CREATE TABLE work.one_time_flag (
    ledger_id     ledger.digest32   NOT NULL,
    flag_kind     work.snake_name NOT NULL,
    flag_key      ledger.digest32   NOT NULL,
    consumed_pos  ledger.log_pos    NOT NULL,
    CONSTRAINT one_time_flag_pk PRIMARY KEY (ledger_id, flag_kind, flag_key),
    CONSTRAINT one_time_flag_pos_fk FOREIGN KEY (ledger_id, consumed_pos)
        REFERENCES ledger.log (ledger_id, pos)
);

SELECT ledger.guard_table('work.item_head', 'mutable');
SELECT ledger.guard_table('work.idempotency_key', 'append_only');
SELECT ledger.guard_table('work.inbound_seen', 'append_only');
SELECT ledger.guard_table('work.one_time_flag', 'append_only');

SELECT ledger.apply_ledger_scope('work.item_head');
SELECT ledger.apply_ledger_scope('work.idempotency_key');
SELECT ledger.apply_ledger_scope('work.inbound_seen');
SELECT ledger.apply_ledger_scope('work.one_time_flag');

REVOKE ALL ON work.item_head, work.idempotency_key, work.inbound_seen, work.one_time_flag FROM PUBLIC;
GRANT SELECT ON work.item_head, work.idempotency_key, work.inbound_seen, work.one_time_flag
    TO work_app, work_sequencer;
GRANT INSERT ON work.item_head, work.idempotency_key, work.inbound_seen, work.one_time_flag
    TO work_sequencer;
GRANT UPDATE (version, last_pos, heads) ON work.item_head TO work_sequencer;

COMMENT ON TABLE work.item_head IS 'label=SYNC-DERIVED; home=canonical; guard=mutable; erasure=none';
COMMENT ON TABLE work.idempotency_key IS 'label=SYNC-DERIVED; home=canonical; guard=append_only; erasure=pseudonymous_skeleton';
COMMENT ON TABLE work.inbound_seen IS 'label=SYNC-DERIVED; home=canonical; guard=append_only; erasure=none';
COMMENT ON TABLE work.one_time_flag IS 'label=SYNC-DERIVED; home=canonical; guard=append_only; erasure=none';

-- OP-12 Access OP-73
SELECT work.ensure_monthly_partitions('work.idempotency_key', 1, 3);
SELECT work.ensure_monthly_partitions('work.inbound_seen', 1, 3);
