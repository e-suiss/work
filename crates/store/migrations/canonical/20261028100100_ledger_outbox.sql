-- OP-3 T-17 T-21 P-35 P-42 Access OP-73 Access T26 Access TI-6 Access TI-RT10
SET LOCAL ROLE work_owner;
SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '5min';

-- T-17 P-42 Access OP-73 Access T26
CREATE TABLE ledger.outbox (
    ledger_id   ledger.digest32    NOT NULL,
    pos         ledger.log_pos     NOT NULL,
    event_id    ledger.event_id    NOT NULL,
    event_type  ledger.event_type  NOT NULL,
    traceparent ledger.traceparent NOT NULL,
    created_at  timestamptz        NOT NULL DEFAULT pg_catalog.now(),
    CONSTRAINT outbox_pk PRIMARY KEY (ledger_id, pos, event_id),
    CONSTRAINT outbox_log_fk FOREIGN KEY (ledger_id, pos) REFERENCES ledger.log (ledger_id, pos)
);

SELECT ledger.guard_table('ledger.outbox', 'job_queue');
SELECT ledger.apply_ledger_scope('ledger.outbox');

REVOKE ALL ON ledger.outbox FROM PUBLIC, work_app, work_sequencer, work_checkpointer, work_publisher, work_erasure, work_archive;
GRANT INSERT ON ledger.outbox TO work_sequencer;
GRANT SELECT, DELETE ON ledger.outbox TO work_publisher;

COMMENT ON TABLE ledger.outbox IS 'label=SYNC-DERIVED; home=canonical; guard=job_queue; erasure=none';
