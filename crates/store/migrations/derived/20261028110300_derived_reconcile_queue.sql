-- OP-12 T-12 Access OP-73
SET LOCAL ROLE work_owner;
SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '5min';

-- OP-12 T-12 Access OP-73
CREATE TABLE derived.reconcile_queue (
    ledger_id   ledger.digest32 NOT NULL,
    queue_id    uuid          NOT NULL DEFAULT pg_catalog.uuidv7(),
    key_kind    text          NOT NULL,
    key_id      ledger.digest32 NOT NULL,
    cause       text          NOT NULL,
    not_before  timestamptz   NOT NULL DEFAULT pg_catalog.now(),
    enqueued_at timestamptz   NOT NULL DEFAULT pg_catalog.now(),
    CONSTRAINT reconcile_queue_pk PRIMARY KEY (ledger_id, queue_id),
    CONSTRAINT reconcile_queue_kind_ck CHECK (key_kind IN ('commitment', 'condition')),
    CONSTRAINT reconcile_queue_cause_ck CHECK (cause IN ('outbox_signal', 'timer_due', 'full_scan'))
);
CREATE INDEX reconcile_queue_ready_ix ON derived.reconcile_queue (ledger_id, not_before);

SELECT ledger.guard_table('derived.reconcile_queue', 'job_queue');
SELECT ledger.apply_ledger_scope('derived.reconcile_queue');

REVOKE ALL ON derived.reconcile_queue FROM PUBLIC;
GRANT SELECT ON derived.reconcile_queue TO work_app, work_deriver, work_reconciler;
GRANT INSERT ON derived.reconcile_queue TO work_deriver, work_reconciler;
GRANT DELETE ON derived.reconcile_queue TO work_reconciler;

COMMENT ON TABLE derived.reconcile_queue IS 'label=OPERATIONAL; home=derived; guard=job_queue; erasure=none';
