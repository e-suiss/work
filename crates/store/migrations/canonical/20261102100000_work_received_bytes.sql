-- T-90 P-5 P-21 P-75 OP-13 OP-31
-- squawk-ignore-file adding-foreign-key-constraint, constraint-missing-not-valid
SET LOCAL ROLE work_owner;
SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '5min';

-- T-90 P-5
CREATE TABLE work.received_bytes (
    ledger_id ledger.digest32 NOT NULL,
    digest    ledger.digest32 NOT NULL,
    kind      text            NOT NULL,
    bytes     bytea           NOT NULL,
    first_pos ledger.log_pos  NOT NULL,
    CONSTRAINT received_bytes_pk PRIMARY KEY (ledger_id, digest),
    CONSTRAINT received_bytes_first_fk FOREIGN KEY (ledger_id, first_pos)
        REFERENCES ledger.log (ledger_id, pos),
    CONSTRAINT received_bytes_digest_ck CHECK (digest = pg_catalog.sha256(bytes)),
    CONSTRAINT received_bytes_length_ck CHECK (pg_catalog.octet_length(bytes) BETWEEN 1 AND 262144),
    CONSTRAINT received_bytes_kind_ck CHECK (kind IN (
        'cose_sign1', 'access_decision_receipt', 'access_portable_authority_proof',
        'access_approval_act_statement', 'access_eligibility_check', 'access_auth_context',
        'webauthn_assertion', 'foreign_record'
    ))
);

-- T-90 P-75
CREATE TABLE work.log_received (
    ledger_id ledger.digest32 NOT NULL,
    pos       ledger.log_pos  NOT NULL,
    role      text            NOT NULL,
    digest    ledger.digest32 NOT NULL,
    CONSTRAINT log_received_pk PRIMARY KEY (ledger_id, pos, role, digest),
    CONSTRAINT log_received_log_fk FOREIGN KEY (ledger_id, pos) REFERENCES ledger.log (ledger_id, pos),
    CONSTRAINT log_received_bytes_fk FOREIGN KEY (ledger_id, digest)
        REFERENCES work.received_bytes (ledger_id, digest),
    CONSTRAINT log_received_role_ck CHECK (role IN (
        'author_signature', 'authority_proof', 'auth_context', 'webauthn_assertion', 'federated_source',
        'presenter_signature'
    ))
);
CREATE INDEX log_received_digest_ix ON work.log_received (ledger_id, digest);

-- T-90 P-75
ALTER TABLE work.record_header
    ADD CONSTRAINT record_header_proof_fk FOREIGN KEY (ledger_id, proof_commit)
        REFERENCES work.received_bytes (ledger_id, digest);

SELECT ledger.guard_table('work.received_bytes', 'append_only');
SELECT ledger.guard_table('work.log_received', 'append_only');

SELECT ledger.apply_ledger_scope('work.received_bytes');
SELECT ledger.apply_ledger_scope('work.log_received');

REVOKE ALL ON work.received_bytes, work.log_received FROM PUBLIC;
GRANT SELECT ON work.received_bytes, work.log_received
    TO work_app, work_sequencer, work_checkpointer, work_publisher, work_erasure;
GRANT INSERT ON work.received_bytes, work.log_received TO work_sequencer;

COMMENT ON TABLE work.received_bytes IS 'label=CANONICAL; home=canonical; guard=append_only; erasure=pseudonymous_skeleton';
COMMENT ON TABLE work.log_received IS 'label=CANONICAL; home=canonical; guard=append_only; erasure=none';
