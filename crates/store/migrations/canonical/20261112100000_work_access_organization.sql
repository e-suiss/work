-- E-3 T-96 T-102 T-36 Access OP-73 Access OP-149
SET LOCAL ROLE work_owner;
SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '5min';

-- E-3 T-96
CREATE TABLE work.access_organization (
    tenant        text        NOT NULL,
    organization  uuid        NOT NULL,
    origin        text        NOT NULL,
    access_pos    bigint,
    access_idx    bigint,
    changed_at    timestamptz,
    mapped_at     timestamptz NOT NULL,
    updated_at    timestamptz NOT NULL,
    CONSTRAINT access_organization_pk PRIMARY KEY (tenant, organization),
    CONSTRAINT access_organization_tenant_ck CHECK (tenant ~ '^tnt_[A-Za-z0-9_-]{1,64}$'),
    CONSTRAINT access_organization_origin_ck CHECK (origin IN ('event', 'snapshot')),
    CONSTRAINT access_organization_position_ck CHECK (
        (access_pos IS NULL) = (access_idx IS NULL)
        AND (access_pos IS NULL OR (access_pos >= 0 AND access_idx >= 0))),
    CONSTRAINT access_organization_time_ck CHECK (mapped_at <= updated_at)
);

-- E-3 T-102
CREATE FUNCTION work.access_organization_guard() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        RETURN NEW;
    END IF;
    IF NEW.tenant <> OLD.tenant OR NEW.organization <> OLD.organization OR NEW.origin <> OLD.origin
       OR NEW.mapped_at <> OLD.mapped_at THEN
        RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'access_organization_identity_immutable';
    END IF;
    IF NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'access_organization_time_backwards';
    END IF;
    IF OLD.access_pos IS NOT NULL
       AND (NEW.access_pos IS NULL OR (NEW.access_pos, NEW.access_idx) < (OLD.access_pos, OLD.access_idx)) THEN
        RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'access_organization_position_backwards';
    END IF;
    RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION work.access_organization_guard() FROM PUBLIC;

CREATE TRIGGER access_organization_guard
    BEFORE INSERT OR UPDATE ON work.access_organization
    FOR EACH ROW EXECUTE FUNCTION work.access_organization_guard();

-- E-3 T-36 Access OP-73
SELECT ledger.guard_table('work.access_organization', 'mutable');

-- E-3 T-36
ALTER TABLE work.access_organization ENABLE ROW LEVEL SECURITY;
ALTER TABLE work.access_organization FORCE ROW LEVEL SECURITY;
CREATE POLICY granted_roles ON work.access_organization AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true);

-- E-3 T-79 Access OP-73
REVOKE ALL ON work.access_organization FROM PUBLIC;
GRANT SELECT ON work.access_organization TO work_app, work_access;
GRANT INSERT, UPDATE ON work.access_organization TO work_access;

COMMENT ON TABLE work.access_organization IS 'label=OPERATIONAL; home=canonical; guard=mutable; erasure=none';
