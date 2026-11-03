-- OP-9 OP-10 OP-28 T-28 T-85 C-35 Access CMP-26 Access T28 Access OP-73
SET LOCAL ROLE work_owner;
SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '5min';

-- OP-9 C-35
CREATE TABLE ledger.ledger_cell (
    ledger_id ledger.digest32 NOT NULL,
    cell      text            NOT NULL,
    CONSTRAINT ledger_cell_pk PRIMARY KEY (ledger_id),
    CONSTRAINT ledger_cell_head_fk FOREIGN KEY (ledger_id) REFERENCES ledger.head (ledger_id),
    CONSTRAINT ledger_cell_cell_ck CHECK (cell ~ '^[a-z0-9][a-z0-9-]{0,62}$')
);

-- OP-9 Access CMP-26
CREATE TABLE work.placement (
    ledger_id ledger.digest32 NOT NULL,
    cell      text            NOT NULL,
    CONSTRAINT placement_pk PRIMARY KEY (ledger_id),
    CONSTRAINT placement_cell_ck CHECK (cell ~ '^[a-z0-9][a-z0-9-]{0,62}$')
);

-- OP-10 T-28 T-85 Access T28
CREATE TABLE ledger.sequencer_lease (
    ledger_id   ledger.digest32 NOT NULL,
    holder      bytea           NOT NULL,
    epoch       bigint          NOT NULL,
    acquired_at timestamptz     NOT NULL,
    expires_at  timestamptz     NOT NULL,
    released_at timestamptz,
    CONSTRAINT sequencer_lease_pk PRIMARY KEY (ledger_id),
    CONSTRAINT sequencer_lease_head_fk FOREIGN KEY (ledger_id) REFERENCES ledger.head (ledger_id),
    CONSTRAINT sequencer_lease_holder_ck CHECK (pg_catalog.octet_length(holder) = 16),
    CONSTRAINT sequencer_lease_epoch_ck CHECK (epoch >= 1),
    CONSTRAINT sequencer_lease_window_ck CHECK (expires_at > acquired_at)
);

SELECT ledger.guard_table('ledger.ledger_cell', 'append_only');
SELECT ledger.guard_table('work.placement', 'mutable');
SELECT ledger.guard_table('ledger.sequencer_lease', 'mutable');

SELECT ledger.apply_ledger_scope('ledger.ledger_cell');
SELECT ledger.apply_ledger_scope('work.placement');
SELECT ledger.apply_ledger_scope('ledger.sequencer_lease');

REVOKE ALL ON ledger.ledger_cell, work.placement, ledger.sequencer_lease FROM PUBLIC;
GRANT SELECT ON ledger.ledger_cell, work.placement, ledger.sequencer_lease TO work_app, work_sequencer;
GRANT INSERT ON ledger.ledger_cell, work.placement, ledger.sequencer_lease TO work_sequencer;
GRANT UPDATE (holder, epoch, acquired_at, expires_at, released_at) ON ledger.sequencer_lease
    TO work_sequencer;

COMMENT ON TABLE ledger.ledger_cell IS 'label=OPERATIONAL; home=canonical; guard=append_only; erasure=none';
COMMENT ON TABLE work.placement IS 'label=OPERATIONAL; home=canonical; guard=mutable; erasure=none';
COMMENT ON TABLE ledger.sequencer_lease IS 'label=OPERATIONAL; home=canonical; guard=mutable; erasure=none';
