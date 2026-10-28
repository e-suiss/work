-- OP-2 OP-9 OP-13 OP-27 P-5 P-11 P-21 P-75 P-79 T-36
SET LOCAL ROLE work_owner;
SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '5min';

-- OP-2 OP-13 P-5 P-12 P-21 P-75 P-79
CREATE TABLE work.record_header (
    ledger_id                ledger.digest32 NOT NULL,
    pos                      ledger.log_pos  NOT NULL,
    kind                     text            NOT NULL,
    record_type              work.type_uri   NOT NULL,
    author                   work.party_ref  NOT NULL,
    author_actor_type        text            NOT NULL,
    author_actor_type_source text            NOT NULL,
    occurred_at              ledger.ms_time,
    ingest                   text            NOT NULL,
    ingest_reason            work.reason_code,
    proof_commit             ledger.digest32,
    auth_context_ref         ledger.digest32,
    protocol_major           bigint          NOT NULL,
    protocol_minor           bigint          NOT NULL,
    schema_digest            ledger.digest32 NOT NULL,
    CONSTRAINT record_header_pk PRIMARY KEY (ledger_id, pos),
    CONSTRAINT record_header_log_fk FOREIGN KEY (ledger_id, pos) REFERENCES ledger.log (ledger_id, pos),
    CONSTRAINT record_header_kind_ck CHECK (kind IN ('act', 'declaration', 'claim')),
    CONSTRAINT record_header_occurred_ck CHECK (kind = 'declaration' OR occurred_at IS NOT NULL),
    CONSTRAINT record_header_actor_type_ck CHECK (
        author_actor_type IN ('human', 'agent', 'system', 'machine', 'organization')
    ),
    CONSTRAINT record_header_actor_source_ck CHECK (
        author_actor_type_source IN ('access_binding', 'declared_unverified')
    ),
    CONSTRAINT record_header_ingest_ck CHECK (ingest IN ('admitted', 'quarantined', 'rejected')),
    CONSTRAINT record_header_ingest_reason_ck CHECK ((ingest = 'admitted') = (ingest_reason IS NULL)),
    CONSTRAINT record_header_proof_ck CHECK (proof_commit IS NOT NULL OR auth_context_ref IS NOT NULL),
    CONSTRAINT record_header_protocol_ck CHECK (protocol_major >= 1 AND protocol_minor >= 0)
);

-- OP-27
CREATE TABLE work.ledger_profile (
    ledger_id          ledger.digest32 NOT NULL,
    durability_profile text            NOT NULL,
    CONSTRAINT ledger_profile_pk PRIMARY KEY (ledger_id),
    CONSTRAINT ledger_profile_head_fk FOREIGN KEY (ledger_id) REFERENCES ledger.head (ledger_id),
    CONSTRAINT ledger_profile_durability_ck CHECK (durability_profile IN ('quorum', 'single-node'))
);

-- C-8 INV-1 OP-9 P-67
CREATE TABLE work.work_root (
    ledger_id ledger.digest32 NOT NULL,
    work_id   uuid          NOT NULL,
    first_pos ledger.log_pos NOT NULL,
    CONSTRAINT work_root_pk PRIMARY KEY (ledger_id, work_id),
    CONSTRAINT work_root_first_fk FOREIGN KEY (ledger_id, first_pos) REFERENCES ledger.log (ledger_id, pos)
);

-- C-34 OP-9 OP-13 P-10
CREATE TABLE work.log_concerns (
    ledger_id ledger.digest32 NOT NULL,
    work_id   uuid          NOT NULL,
    pos       ledger.log_pos NOT NULL,
    CONSTRAINT log_concerns_pk PRIMARY KEY (ledger_id, work_id, pos),
    CONSTRAINT log_concerns_log_fk FOREIGN KEY (ledger_id, pos) REFERENCES ledger.log (ledger_id, pos),
    CONSTRAINT log_concerns_work_fk FOREIGN KEY (ledger_id, work_id) REFERENCES work.work_root (ledger_id, work_id)
);
CREATE INDEX log_concerns_pos_ix ON work.log_concerns (ledger_id, pos);

-- OP-13 P-28 P-81
CREATE TABLE work.log_basis (
    ledger_id       ledger.digest32 NOT NULL,
    pos             ledger.log_pos NOT NULL,
    basis_record_id ledger.digest32 NOT NULL,
    CONSTRAINT log_basis_pk PRIMARY KEY (ledger_id, pos, basis_record_id),
    CONSTRAINT log_basis_log_fk FOREIGN KEY (ledger_id, pos) REFERENCES ledger.log (ledger_id, pos)
);
CREATE INDEX log_basis_target_ix ON work.log_basis (ledger_id, basis_record_id);

-- OP-13 P-14 P-24 P-73
CREATE TABLE work.log_relation (
    ledger_id    ledger.digest32 NOT NULL,
    pos          ledger.log_pos NOT NULL,
    ordinal      bigint        NOT NULL,
    rel          text          NOT NULL,
    source_kind  text          NOT NULL,
    source_bytes bytea,
    source_text  text,
    target_kind  text          NOT NULL,
    target_bytes bytea,
    target_text  text,
    qualifier    work.type_uri,
    CONSTRAINT log_relation_pk PRIMARY KEY (ledger_id, pos, ordinal),
    CONSTRAINT log_relation_log_fk FOREIGN KEY (ledger_id, pos) REFERENCES ledger.log (ledger_id, pos),
    CONSTRAINT log_relation_ordinal_ck CHECK (ordinal BETWEEN 0 AND 255),
    CONSTRAINT log_relation_rel_ck CHECK (rel IN (
        'engaged_in', 'concerns', 'part_of', 'serves',
        'supersedes', 'derived_from', 'on_behalf_of', 'references'
    )),
    CONSTRAINT log_relation_source_ck CHECK (
        (source_kind = 'self' AND source_bytes IS NULL AND source_text IS NULL)
        OR (source_kind IN ('record', 'evidence') AND pg_catalog.octet_length(source_bytes) = 32 AND source_text IS NULL)
        OR (source_kind = 'work' AND pg_catalog.octet_length(source_bytes) = 16 AND source_text IS NULL)
        OR (source_kind IN ('party', 'external') AND source_bytes IS NULL
            AND pg_catalog.octet_length(source_text) BETWEEN 1 AND 1024)
    ),
    CONSTRAINT log_relation_target_ck CHECK (
        (target_kind IN ('record', 'evidence') AND pg_catalog.octet_length(target_bytes) = 32 AND target_text IS NULL)
        OR (target_kind = 'work' AND pg_catalog.octet_length(target_bytes) = 16 AND target_text IS NULL)
        OR (target_kind IN ('party', 'external') AND target_bytes IS NULL
            AND pg_catalog.octet_length(target_text) BETWEEN 1 AND 1024)
    )
);
CREATE INDEX log_relation_target_ix ON work.log_relation (ledger_id, rel, target_kind, target_bytes);

-- OP-13 OP-15 P-17 P-68
CREATE TABLE work.body_commitment (
    ledger_id ledger.digest32   NOT NULL,
    pos       ledger.log_pos   NOT NULL,
    part      work.snake_name NOT NULL,
    part_commit ledger.digest32 NOT NULL,
    CONSTRAINT body_commitment_pk PRIMARY KEY (ledger_id, pos, part),
    CONSTRAINT body_commitment_log_fk FOREIGN KEY (ledger_id, pos) REFERENCES ledger.log (ledger_id, pos)
);

SELECT ledger.guard_table('work.record_header', 'append_only');
SELECT ledger.guard_table('work.ledger_profile', 'append_only');
SELECT ledger.guard_table('work.work_root', 'append_only');
SELECT ledger.guard_table('work.log_concerns', 'append_only');
SELECT ledger.guard_table('work.log_basis', 'append_only');
SELECT ledger.guard_table('work.log_relation', 'append_only');
SELECT ledger.guard_table('work.body_commitment', 'append_only');

SELECT ledger.apply_ledger_scope('work.record_header');
SELECT ledger.apply_ledger_scope('work.ledger_profile');
SELECT ledger.apply_ledger_scope('work.work_root');
SELECT ledger.apply_ledger_scope('work.log_concerns');
SELECT ledger.apply_ledger_scope('work.log_basis');
SELECT ledger.apply_ledger_scope('work.log_relation');
SELECT ledger.apply_ledger_scope('work.body_commitment');

REVOKE ALL ON work.record_header, work.ledger_profile, work.work_root, work.log_concerns,
              work.log_basis, work.log_relation, work.body_commitment FROM PUBLIC;
GRANT SELECT ON work.record_header, work.ledger_profile, work.work_root, work.log_concerns,
                work.log_basis, work.log_relation, work.body_commitment
    TO work_app, work_sequencer, work_checkpointer, work_publisher, work_erasure;
GRANT INSERT ON work.record_header, work.ledger_profile, work.work_root, work.log_concerns,
                work.log_basis, work.log_relation, work.body_commitment
    TO work_sequencer;

COMMENT ON TABLE work.record_header IS 'label=CANONICAL; home=canonical; guard=append_only; erasure=pseudonymous_skeleton';
COMMENT ON TABLE work.ledger_profile IS 'label=SYNC-DERIVED; home=canonical; guard=append_only; erasure=none';
COMMENT ON TABLE work.work_root IS 'label=SYNC-DERIVED; home=canonical; guard=append_only; erasure=none';
COMMENT ON TABLE work.log_concerns IS 'label=CANONICAL; home=canonical; guard=append_only; erasure=none';
COMMENT ON TABLE work.log_basis IS 'label=CANONICAL; home=canonical; guard=append_only; erasure=none';
COMMENT ON TABLE work.log_relation IS 'label=CANONICAL; home=canonical; guard=append_only; erasure=pseudonymous_skeleton';
COMMENT ON TABLE work.body_commitment IS 'label=CANONICAL; home=canonical; guard=append_only; erasure=none';
