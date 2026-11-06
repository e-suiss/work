-- T-101 E-17 T-36 Access OP-73
SET LOCAL ROLE work_owner;
SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '5min';

-- T-101 E-17
ALTER TABLE work.approval_return ADD COLUMN contribution bytea;
ALTER TABLE work.approval_return
    ADD CONSTRAINT approval_return_contribution_ck
        CHECK (contribution IS NULL OR pg_catalog.octet_length(contribution) = 32) NOT VALID;

-- T-101 E-17 Access OP-73
CREATE OR REPLACE FUNCTION work.approval_return_guard() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.used_at IS NOT NULL THEN
            RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'approval_return_issued_used';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.used_at IS NOT NULL OR NEW.used_at IS NULL
       OR (NEW.handle, NEW.tenant, NEW.party, NEW.digest, NEW.ledger, NEW.contribution, NEW.issued_at, NEW.expires_at)
          IS DISTINCT FROM
          (OLD.handle, OLD.tenant, OLD.party, OLD.digest, OLD.ledger, OLD.contribution, OLD.issued_at, OLD.expires_at) THEN
        RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'approval_return_used_once';
    END IF;
    RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION work.approval_return_guard() FROM PUBLIC;
