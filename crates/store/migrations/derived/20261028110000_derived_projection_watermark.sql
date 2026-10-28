-- OP-2 OP-11 T-10 T-14 T-36 Access OP-73
SET LOCAL ROLE work_owner;
SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '5min';

CREATE SCHEMA derived AUTHORIZATION work_owner;
REVOKE ALL ON SCHEMA derived FROM PUBLIC;
GRANT USAGE ON SCHEMA derived TO work_app, work_deriver, work_reconciler;

-- OP-1 OP-11 T-14 T-36
CREATE TABLE derived.projection_watermark (
    ledger_id           ledger.digest32   NOT NULL,
    projection          work.snake_name NOT NULL,
    version             bigint          NOT NULL,
    state               text            NOT NULL,
    applied_through_pos bigint          NOT NULL,
    updated_at          timestamptz     NOT NULL DEFAULT pg_catalog.now(),
    CONSTRAINT projection_watermark_pk PRIMARY KEY (ledger_id, projection, version),
    CONSTRAINT projection_watermark_version_ck CHECK (version >= 1),
    CONSTRAINT projection_watermark_state_ck CHECK (state IN ('building', 'live', 'archived')),
    CONSTRAINT projection_watermark_pos_ck CHECK (applied_through_pos >= -1)
) WITH (fillfactor = 70);
CREATE UNIQUE INDEX projection_watermark_live_uq ON derived.projection_watermark (ledger_id, projection)
    WHERE state = 'live';

-- OP-11 T-14 Access OP-73
CREATE FUNCTION derived.projection_watermark_guard() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.state <> 'building' THEN
            RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'projection_must_start_building';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.ledger_id <> OLD.ledger_id OR NEW.projection <> OLD.projection OR NEW.version <> OLD.version THEN
        RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'projection_identity_immutable';
    END IF;
    IF NEW.applied_through_pos < OLD.applied_through_pos THEN
        RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'projection_watermark_regressed';
    END IF;
    IF NOT ((OLD.state = NEW.state AND NEW.state <> 'archived')
            OR (OLD.state = 'building' AND NEW.state IN ('live', 'archived'))
            OR (OLD.state = 'live' AND NEW.state = 'archived')) THEN
        RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'projection_state_transition';
    END IF;
    RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION derived.projection_watermark_guard() FROM PUBLIC;

CREATE TRIGGER projection_watermark_guard
    BEFORE INSERT OR UPDATE ON derived.projection_watermark
    FOR EACH ROW EXECUTE FUNCTION derived.projection_watermark_guard();

SELECT ledger.guard_table('derived.projection_watermark', 'mutable');
SELECT ledger.apply_ledger_scope('derived.projection_watermark');

REVOKE ALL ON derived.projection_watermark FROM PUBLIC;
GRANT SELECT ON derived.projection_watermark TO work_app, work_deriver, work_reconciler;
GRANT INSERT ON derived.projection_watermark TO work_deriver;
GRANT UPDATE (state, applied_through_pos, updated_at) ON derived.projection_watermark TO work_deriver;

COMMENT ON TABLE derived.projection_watermark IS 'label=OPERATIONAL; home=derived; guard=mutable; erasure=none';
