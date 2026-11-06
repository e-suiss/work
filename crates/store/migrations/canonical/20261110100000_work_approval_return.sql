-- T-101 E-17 T-36 Access OP-73
SET LOCAL ROLE work_owner;
SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '5min';

-- T-101 E-17
CREATE TABLE work.approval_return (
    handle      text        NOT NULL,
    tenant      text        NOT NULL,
    party       bytea       NOT NULL,
    digest      bytea       NOT NULL,
    ledger      bytea       NOT NULL,
    issued_at   timestamptz NOT NULL,
    expires_at  timestamptz NOT NULL,
    used_at     timestamptz,
    CONSTRAINT approval_return_pk PRIMARY KEY (handle),
    CONSTRAINT approval_return_handle_ck CHECK (handle ~ '^[A-Za-z0-9_-]{43}$'),
    CONSTRAINT approval_return_tenant_ck CHECK (tenant ~ '^tnt_[A-Za-z0-9_-]{1,64}$'),
    CONSTRAINT approval_return_party_ck CHECK (pg_catalog.octet_length(party) = 16),
    CONSTRAINT approval_return_digest_ck CHECK (pg_catalog.octet_length(digest) = 32),
    CONSTRAINT approval_return_ledger_ck CHECK (pg_catalog.octet_length(ledger) = 32),
    CONSTRAINT approval_return_expiry_ck CHECK (issued_at <= expires_at),
    CONSTRAINT approval_return_used_ck CHECK (used_at IS NULL OR used_at >= issued_at)
);

-- T-101 E-17 Access OP-73
CREATE FUNCTION work.approval_return_guard() RETURNS trigger
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
       OR (NEW.handle, NEW.tenant, NEW.party, NEW.digest, NEW.ledger, NEW.issued_at, NEW.expires_at)
          IS DISTINCT FROM
          (OLD.handle, OLD.tenant, OLD.party, OLD.digest, OLD.ledger, OLD.issued_at, OLD.expires_at) THEN
        RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'approval_return_used_once';
    END IF;
    RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION work.approval_return_guard() FROM PUBLIC;

CREATE TRIGGER approval_return_guard
    BEFORE INSERT OR UPDATE ON work.approval_return
    FOR EACH ROW EXECUTE FUNCTION work.approval_return_guard();

-- T-101 T-36 Access OP-73
SELECT ledger.guard_table('work.approval_return', 'mutable');

-- T-101 T-36
ALTER TABLE work.approval_return ENABLE ROW LEVEL SECURITY;
ALTER TABLE work.approval_return FORCE ROW LEVEL SECURITY;
CREATE POLICY granted_roles ON work.approval_return AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true);

-- T-101 Access OP-73
REVOKE ALL ON work.approval_return FROM PUBLIC;
GRANT SELECT, INSERT ON work.approval_return TO work_access;
GRANT UPDATE (used_at) ON work.approval_return TO work_access;

COMMENT ON TABLE work.approval_return IS 'label=OPERATIONAL; home=canonical; guard=mutable; erasure=none';
