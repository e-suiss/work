-- T-103 T-96 P-115 P-116 T-102 T-36 Access OP-73 Access OP-149
SET LOCAL ROLE work_owner;
SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '5min';

GRANT USAGE ON SCHEMA work TO work_access;

-- T-103 P-115
CREATE TABLE work.access_realm (
    tenant        text        NOT NULL,
    realm         uuid        NOT NULL,
    issuer        text        NOT NULL,
    slug          text        NOT NULL,
    domain        bytea,
    party         bytea,
    instance      bytea,
    kid           text,
    state         text        NOT NULL,
    refusal_code  text,
    failed_runs   bigint      NOT NULL DEFAULT 0,
    paired_at     timestamptz,
    updated_at    timestamptz NOT NULL,
    CONSTRAINT access_realm_pk PRIMARY KEY (tenant, realm),
    CONSTRAINT access_realm_tenant_ck CHECK (tenant ~ '^tnt_[A-Za-z0-9_-]{1,64}$'),
    CONSTRAINT access_realm_issuer_ck CHECK (issuer ~ '^https://' AND pg_catalog.octet_length(issuer) <= 2048),
    CONSTRAINT access_realm_slug_ck CHECK (pg_catalog.octet_length(slug) BETWEEN 1 AND 255),
    CONSTRAINT access_realm_domain_ck CHECK (domain IS NULL OR pg_catalog.octet_length(domain) = 32),
    CONSTRAINT access_realm_party_ck CHECK (party IS NULL OR pg_catalog.octet_length(party) = 16),
    CONSTRAINT access_realm_instance_ck CHECK (instance IS NULL OR pg_catalog.octet_length(instance) = 16),
    CONSTRAINT access_realm_kid_ck CHECK (kid IS NULL OR kid ~ '^[A-Za-z0-9_-]{43}$'),
    CONSTRAINT access_realm_state_ck CHECK (state IN ('unpaired', 'paired', 'refused', 'retired')),
    CONSTRAINT access_realm_paired_ck CHECK (
        (state = 'paired') = (party IS NOT NULL AND instance IS NOT NULL AND kid IS NOT NULL AND paired_at IS NOT NULL)
        OR state = 'retired'),
    CONSTRAINT access_realm_refused_ck CHECK ((state = 'refused') = (refusal_code IS NOT NULL) OR state = 'retired'),
    CONSTRAINT access_realm_refusal_ck CHECK (refusal_code IS NULL OR pg_catalog.octet_length(refusal_code) BETWEEN 1 AND 128),
    CONSTRAINT access_realm_failed_ck CHECK (failed_runs >= 0)
);
CREATE UNIQUE INDEX access_realm_domain_uq ON work.access_realm (domain)
    WHERE domain IS NOT NULL AND state <> 'retired';
CREATE INDEX access_realm_issuer_ix ON work.access_realm (issuer)
    WHERE state <> 'retired';

-- T-103
CREATE FUNCTION work.access_realm_guard() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        RETURN NEW;
    END IF;
    IF NEW.tenant <> OLD.tenant OR NEW.realm <> OLD.realm OR NEW.slug <> OLD.slug
       OR NEW.issuer <> OLD.issuer THEN
        RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'access_realm_identity_immutable';
    END IF;
    IF OLD.domain IS NOT NULL AND NEW.domain IS DISTINCT FROM OLD.domain THEN
        RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'access_realm_domain_immutable';
    END IF;
    IF NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'access_realm_time_backwards';
    END IF;
    RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION work.access_realm_guard() FROM PUBLIC;

CREATE TRIGGER access_realm_guard
    BEFORE INSERT OR UPDATE ON work.access_realm
    FOR EACH ROW EXECUTE FUNCTION work.access_realm_guard();

-- T-103 T-102
CREATE TABLE work.access_event_stream (
    singleton     boolean     NOT NULL DEFAULT true,
    stream_id     uuid,
    state         text        NOT NULL,
    checked_at    timestamptz NOT NULL,
    recreated     bigint      NOT NULL DEFAULT 0,
    CONSTRAINT access_event_stream_pk PRIMARY KEY (singleton),
    CONSTRAINT access_event_stream_singleton_ck CHECK (singleton),
    CONSTRAINT access_event_stream_state_ck CHECK (state IN ('enabled', 'paused', 'disabled', 'unreachable', 'missing')),
    CONSTRAINT access_event_stream_missing_ck CHECK ((state = 'missing') = (stream_id IS NULL)),
    CONSTRAINT access_event_stream_recreated_ck CHECK (recreated >= 0)
);

-- T-103
CREATE FUNCTION work.access_event_stream_guard() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        RETURN NEW;
    END IF;
    IF NEW.checked_at < OLD.checked_at OR NEW.recreated < OLD.recreated THEN
        RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'access_event_stream_backwards';
    END IF;
    RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION work.access_event_stream_guard() FROM PUBLIC;

CREATE TRIGGER access_event_stream_guard
    BEFORE INSERT OR UPDATE ON work.access_event_stream
    FOR EACH ROW EXECUTE FUNCTION work.access_event_stream_guard();

-- T-103 T-36 Access OP-73
SELECT ledger.guard_table('work.access_realm', 'mutable');
SELECT ledger.guard_table('work.access_event_stream', 'mutable');

-- T-103 T-36
ALTER TABLE work.access_realm ENABLE ROW LEVEL SECURITY;
ALTER TABLE work.access_realm FORCE ROW LEVEL SECURITY;
CREATE POLICY granted_roles ON work.access_realm AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true);
ALTER TABLE work.access_event_stream ENABLE ROW LEVEL SECURITY;
ALTER TABLE work.access_event_stream FORCE ROW LEVEL SECURITY;
CREATE POLICY granted_roles ON work.access_event_stream AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true);

-- T-103 T-79 Access OP-73
REVOKE ALL ON work.access_realm, work.access_event_stream FROM PUBLIC;
GRANT SELECT ON work.access_realm, work.access_event_stream TO work_app, work_access;
GRANT INSERT, UPDATE ON work.access_realm, work.access_event_stream TO work_access;

COMMENT ON TABLE work.access_realm IS 'label=OPERATIONAL; home=canonical; guard=mutable; erasure=none';
COMMENT ON TABLE work.access_event_stream IS 'label=OPERATIONAL; home=canonical; guard=mutable; erasure=none';
