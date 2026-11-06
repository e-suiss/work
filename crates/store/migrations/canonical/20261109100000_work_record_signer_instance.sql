-- SEC-36 P-116 Access OP-73
SET LOCAL ROLE work_owner;
SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '5min';

-- SEC-36 P-116
ALTER TABLE work.record_signer ADD COLUMN instance bytea;
ALTER TABLE work.record_signer
    ADD CONSTRAINT record_signer_instance_ck
        CHECK (instance IS NULL OR (kid IS NULL AND pg_catalog.octet_length(instance) = 16)) NOT VALID;
