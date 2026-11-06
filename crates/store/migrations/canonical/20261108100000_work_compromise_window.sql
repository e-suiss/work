-- SEC-36 T-36 Access OP-73
SET LOCAL ROLE work_owner;
SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '5min';

-- SEC-36
CREATE TABLE work.record_signer (
    ledger_id   ledger.digest32 NOT NULL,
    pos         ledger.log_pos  NOT NULL,
    tenant      text            NOT NULL,
    recorded_at ledger.ms_time  NOT NULL,
    kid         bytea,
    author      work.party_ref,
    CONSTRAINT record_signer_pk PRIMARY KEY (ledger_id, pos),
    CONSTRAINT record_signer_log_fk FOREIGN KEY (ledger_id, pos) REFERENCES ledger.log (ledger_id, pos),
    CONSTRAINT record_signer_tenant_ck CHECK (tenant ~ '^tnt_[A-Za-z0-9_-]{1,64}$'),
    CONSTRAINT record_signer_kid_ck CHECK (kid IS NULL OR pg_catalog.octet_length(kid) = 32),
    CONSTRAINT record_signer_one_ck CHECK ((kid IS NULL) <> (author IS NULL))
);
CREATE INDEX record_signer_tenant_ix ON work.record_signer (tenant, recorded_at);

-- SEC-36 C-4
CREATE TABLE work.compromise_notice (
    ledger_id    ledger.digest32 NOT NULL,
    event_digest ledger.digest32 NOT NULL,
    pos          ledger.log_pos  NOT NULL,
    window_from  ledger.ms_time  NOT NULL,
    window_to    ledger.ms_time  NOT NULL,
    kids         bytea[]         NOT NULL,
    party        work.party_ref,
    CONSTRAINT compromise_notice_pk PRIMARY KEY (ledger_id, event_digest),
    CONSTRAINT compromise_notice_log_fk FOREIGN KEY (ledger_id, pos) REFERENCES ledger.log (ledger_id, pos),
    CONSTRAINT compromise_notice_window_ck CHECK (window_from <= window_to),
    CONSTRAINT compromise_notice_kids_ck CHECK (pg_catalog.cardinality(kids) BETWEEN 1 AND 256)
);
CREATE INDEX compromise_notice_pos_ix ON work.compromise_notice (ledger_id, pos);

SELECT ledger.guard_table('work.record_signer', 'append_only');
SELECT ledger.guard_table('work.compromise_notice', 'append_only');

-- SEC-36 T-36
ALTER TABLE work.record_signer ENABLE ROW LEVEL SECURITY;
ALTER TABLE work.record_signer FORCE ROW LEVEL SECURITY;
CREATE POLICY granted_roles ON work.record_signer AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true);
SELECT ledger.apply_ledger_scope('work.compromise_notice');

-- SEC-36 Access OP-73
REVOKE ALL ON work.record_signer, work.compromise_notice FROM PUBLIC;
GRANT SELECT ON work.record_signer TO work_access, work_sequencer;
GRANT SELECT ON work.compromise_notice TO work_app, work_sequencer;
GRANT INSERT ON work.record_signer, work.compromise_notice TO work_sequencer;

COMMENT ON TABLE work.record_signer IS 'label=OPERATIONAL; home=canonical; guard=append_only; erasure=pseudonymous_skeleton';
COMMENT ON TABLE work.compromise_notice IS 'label=SYNC-DERIVED; home=canonical; guard=append_only; erasure=pseudonymous_skeleton';
