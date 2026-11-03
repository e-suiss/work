-- P-110 OP-28 OP-1 P-100 T-85 Access OP-56
SET LOCAL ROLE work_owner;
SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '5min';

-- P-110 OP-28
CREATE TABLE ledger.version_activation (
    ledger_id ledger.digest32 NOT NULL,
    pos       ledger.log_pos  NOT NULL,
    CONSTRAINT version_activation_pk PRIMARY KEY (ledger_id, pos),
    CONSTRAINT version_activation_log_fk FOREIGN KEY (ledger_id, pos) REFERENCES ledger.log (ledger_id, pos)
);

-- P-110 P-100
ALTER TABLE ledger.log NO FORCE ROW LEVEL SECURITY;
INSERT INTO ledger.version_activation (ledger_id, pos)
SELECT ledger_id, pos FROM ledger.log WHERE pos = 0;
ALTER TABLE ledger.log FORCE ROW LEVEL SECURITY;

SELECT ledger.guard_table('ledger.version_activation', 'append_only');
SELECT ledger.apply_ledger_scope('ledger.version_activation');

REVOKE ALL ON ledger.version_activation FROM PUBLIC;
GRANT SELECT ON ledger.version_activation TO work_app, work_sequencer;
GRANT INSERT ON ledger.version_activation TO work_sequencer;

COMMENT ON TABLE ledger.version_activation IS 'label=SYNC-DERIVED; home=canonical; guard=append_only; erasure=none';
