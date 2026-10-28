-- OP-2 OP-4 P-20 T-7 SEC-32 Access T16 Access T21 Access TI-13
SET LOCAL ROLE work_owner;
SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '5min';

-- OP-2 OP-4 P-20
CREATE TABLE ledger.checkpoint (
    ledger_id   ledger.digest32 NOT NULL,
    size        bigint          NOT NULL,
    root        ledger.digest32 NOT NULL,
    head_leaf   ledger.digest32 NOT NULL,
    issued_at   ledger.ms_time  NOT NULL,
    signed_note bytea           NOT NULL,
    CONSTRAINT checkpoint_pk PRIMARY KEY (ledger_id, size),
    CONSTRAINT checkpoint_head_fk FOREIGN KEY (ledger_id) REFERENCES ledger.head (ledger_id),
    CONSTRAINT checkpoint_size_ck CHECK (size >= 1),
    CONSTRAINT checkpoint_note_ck CHECK (pg_catalog.octet_length(signed_note) > 0)
);

-- P-20 OP-4
CREATE FUNCTION ledger.checkpoint_matches_log() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog
AS $$
BEGIN
    PERFORM 1 FROM ledger.log
     WHERE ledger_id = NEW.ledger_id AND pos = NEW.size - 1
       AND leaf_hash = NEW.head_leaf AND recorded_at <= NEW.issued_at;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'checkpoint_does_not_match_log';
    END IF;
    RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION ledger.checkpoint_matches_log() FROM PUBLIC;

CREATE TRIGGER checkpoint_matches_log
    BEFORE INSERT ON ledger.checkpoint
    FOR EACH ROW EXECUTE FUNCTION ledger.checkpoint_matches_log();

-- OP-4 Access T21
CREATE TABLE ledger.replica_progress (
    ledger_id     ledger.digest32 NOT NULL,
    replica_id    ledger.ident    NOT NULL,
    mirrored_size bigint          NOT NULL,
    updated_at    timestamptz     NOT NULL DEFAULT pg_catalog.now(),
    CONSTRAINT replica_progress_pk PRIMARY KEY (ledger_id, replica_id),
    CONSTRAINT replica_progress_head_fk FOREIGN KEY (ledger_id) REFERENCES ledger.head (ledger_id),
    CONSTRAINT replica_progress_size_ck CHECK (mirrored_size >= 0)
) WITH (fillfactor = 70);

-- OP-4 Access T21
CREATE FUNCTION ledger.replica_progress_guard() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog
AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        IF NEW.ledger_id <> OLD.ledger_id OR NEW.replica_id <> OLD.replica_id THEN
            RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'replica_identity_immutable';
        END IF;
        IF NEW.mirrored_size < OLD.mirrored_size THEN
            RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'replica_progress_regressed';
        END IF;
    END IF;
    PERFORM 1 FROM ledger.head
     WHERE ledger_id = NEW.ledger_id AND pos + 1 >= NEW.mirrored_size;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'replica_ahead_of_head';
    END IF;
    RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION ledger.replica_progress_guard() FROM PUBLIC;

CREATE TRIGGER replica_progress_guard
    BEFORE INSERT OR UPDATE ON ledger.replica_progress
    FOR EACH ROW EXECUTE FUNCTION ledger.replica_progress_guard();

-- OP-4 P-20 SEC-32
CREATE TABLE ledger.checkpoint_cosignature (
    ledger_id   ledger.digest32 NOT NULL,
    size        bigint          NOT NULL,
    witness_id  ledger.ident    NOT NULL,
    cosign_kind text            NOT NULL,
    cosigned_at ledger.ms_time  NOT NULL,
    signature   bytea           NOT NULL,
    CONSTRAINT checkpoint_cosignature_pk PRIMARY KEY (ledger_id, size, witness_id),
    CONSTRAINT checkpoint_cosignature_checkpoint_fk FOREIGN KEY (ledger_id, size)
        REFERENCES ledger.checkpoint (ledger_id, size),
    CONSTRAINT checkpoint_cosignature_kind_ck CHECK (cosign_kind IN ('witness', 'rfc3161')),
    CONSTRAINT checkpoint_cosignature_sig_ck CHECK (pg_catalog.octet_length(signature) > 0)
);

-- OP-4 Access T21
CREATE FUNCTION ledger.cosignature_after_mirror() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog
AS $$
BEGIN
    PERFORM 1 FROM ledger.replica_progress
     WHERE ledger_id = NEW.ledger_id AND mirrored_size >= NEW.size;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'witnessed_before_mirrored';
    END IF;
    RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION ledger.cosignature_after_mirror() FROM PUBLIC;

CREATE TRIGGER cosignature_after_mirror
    BEFORE INSERT ON ledger.checkpoint_cosignature
    FOR EACH ROW EXECUTE FUNCTION ledger.cosignature_after_mirror();

SELECT ledger.guard_table('ledger.checkpoint', 'append_only');
SELECT ledger.guard_table('ledger.replica_progress', 'mutable');
SELECT ledger.guard_table('ledger.checkpoint_cosignature', 'append_only');

SELECT ledger.apply_ledger_scope('ledger.checkpoint');
SELECT ledger.apply_ledger_scope('ledger.replica_progress');
SELECT ledger.apply_ledger_scope('ledger.checkpoint_cosignature');

-- OP-4
CREATE VIEW ledger.record_durability WITH (security_invoker = true, security_barrier = true) AS
SELECT l.ledger_id,
       l.pos,
       l.record_id,
       w.witnessed,
       i.included,
       CASE WHEN w.witnessed THEN 'witnessed'
            WHEN i.included THEN 'included'
            ELSE 'recorded' END AS durability
  FROM ledger.log l
 CROSS JOIN LATERAL (
       SELECT EXISTS (SELECT 1 FROM ledger.checkpoint c
                       WHERE c.ledger_id = l.ledger_id AND c.size > l.pos) AS included
 ) i
 CROSS JOIN LATERAL (
       SELECT EXISTS (SELECT 1 FROM ledger.checkpoint_cosignature s
                       WHERE s.ledger_id = l.ledger_id AND s.size > l.pos) AS witnessed
 ) w;

REVOKE ALL ON ledger.checkpoint, ledger.replica_progress, ledger.checkpoint_cosignature,
              ledger.record_durability FROM PUBLIC, work_app, work_sequencer, work_checkpointer, work_publisher, work_erasure, work_archive;
GRANT SELECT ON ledger.checkpoint, ledger.replica_progress, ledger.checkpoint_cosignature,
                ledger.record_durability
    TO work_app, work_sequencer, work_checkpointer, work_publisher, work_erasure;
GRANT INSERT ON ledger.checkpoint, ledger.replica_progress, ledger.checkpoint_cosignature
    TO work_checkpointer;
GRANT UPDATE (mirrored_size, updated_at) ON ledger.replica_progress TO work_checkpointer;

COMMENT ON TABLE ledger.checkpoint IS 'label=CANONICAL; home=canonical; guard=append_only; erasure=none';
COMMENT ON TABLE ledger.replica_progress IS 'label=OPERATIONAL; home=canonical; guard=mutable; erasure=none';
COMMENT ON TABLE ledger.checkpoint_cosignature IS 'label=CANONICAL; home=canonical; guard=append_only; erasure=none';
COMMENT ON VIEW ledger.record_durability IS 'label=DERIVED; home=canonical; guard=view; erasure=none';
