-- T-81 P-29 P-35 T-17 OP-34 Access OP-73
-- squawk-ignore-file adding-required-field, constraint-missing-not-valid
SET LOCAL ROLE work_owner;
SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '5min';

-- T-81 P-29
ALTER TABLE ledger.outbox
    ADD COLUMN item_kind text NOT NULL,
    ADD COLUMN item_id bytea NOT NULL,
    ADD COLUMN version bigint NOT NULL,
    ADD CONSTRAINT outbox_item_kind_ck CHECK (item_kind IN ('work', 'commitment', 'condition')),
    ADD CONSTRAINT outbox_item_id_ck CHECK (
        (item_kind = 'work' AND pg_catalog.octet_length(item_id) = 16)
        OR (item_kind IN ('commitment', 'condition') AND pg_catalog.octet_length(item_id) = 32)
    ),
    ADD CONSTRAINT outbox_version_ck CHECK (version >= 1);
