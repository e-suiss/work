-- OP-14 OP-12 OP-45 Access OP-74 Access OP-147
-- squawk-ignore-file changing-column-type, adding-required-field, constraint-missing-not-valid, ban-drop-constraint, ban-drop-default
SET LOCAL ROLE work_owner;
SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '5min';

-- OP-14 Access OP-147
ALTER TABLE work.retention_hold DROP CONSTRAINT retention_hold_kind_ck;
ALTER TABLE work.retention_hold ALTER COLUMN hold_id DROP DEFAULT;
ALTER TABLE work.retention_hold ALTER COLUMN hold_id TYPE text USING hold_id::text;
ALTER TABLE work.retention_hold ALTER COLUMN placed_at DROP DEFAULT;
ALTER TABLE work.retention_hold ADD COLUMN scope text NOT NULL;
ALTER TABLE work.retention_hold ADD COLUMN retention_classes work.snake_name[];
ALTER TABLE work.retention_hold ADD COLUMN suspicious_activity boolean NOT NULL DEFAULT false;
ALTER TABLE work.retention_hold
    ADD CONSTRAINT retention_hold_kind_ck CHECK (hold_kind IN ('litigation', 'regulator', 'law_enforcement')),
    ADD CONSTRAINT retention_hold_id_ck CHECK (pg_catalog.octet_length(hold_id) BETWEEN 1 AND 255),
    ADD CONSTRAINT retention_hold_scope_ck CHECK (scope IN ('subject', 'classes', 'tenant')),
    ADD CONSTRAINT retention_hold_subject_ck CHECK ((scope = 'subject') = (subject_ref IS NOT NULL)),
    ADD CONSTRAINT retention_hold_classes_ck CHECK ((scope = 'classes') = (retention_classes IS NOT NULL)),
    ADD CONSTRAINT retention_hold_class_deprecated_ck CHECK (retention_class IS NULL);

-- OP-14 OP-12 Access OP-74 Access OP-147
CREATE FUNCTION work.retention_held(bytea, text, text) RETURNS boolean
    LANGUAGE sql
    STABLE
    SET search_path = pg_catalog
AS $$
    SELECT EXISTS (
        SELECT 1 FROM work.retention_hold h
         WHERE h.ledger_id = $1
           AND ((h.scope = 'classes' AND pg_catalog.cardinality(h.retention_classes) = 0)
                OR ((h.released_at IS NULL OR pg_catalog.now() < h.released_at)
                    AND (h.scope = 'tenant'
                         OR (h.scope = 'subject' AND h.subject_ref = $2)
                         OR (h.scope = 'classes' AND $3 = ANY (h.retention_classes::text[])))))
    )
$$;
REVOKE ALL ON FUNCTION work.retention_held(bytea, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION work.retention_held(bytea, text, text) TO work_erasure;

-- OP-14 OP-12 Access OP-147
CREATE OR REPLACE FUNCTION work.retention_hold_guard() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        RETURN NEW;
    END IF;
    IF NEW.ledger_id <> OLD.ledger_id OR NEW.hold_id <> OLD.hold_id OR NEW.hold_kind <> OLD.hold_kind
       OR NEW.scope <> OLD.scope
       OR NEW.subject_ref IS DISTINCT FROM OLD.subject_ref
       OR NEW.retention_classes IS DISTINCT FROM OLD.retention_classes
       OR NEW.suspicious_activity <> OLD.suspicious_activity
       OR NEW.placed_at <> OLD.placed_at THEN
        RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'hold_identity_immutable';
    END IF;
    IF OLD.state = 'released' THEN
        RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'hold_released_is_terminal';
    END IF;
    RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION work.retention_hold_guard() FROM PUBLIC;

-- OP-45 OP-12 OP-14 Access OP-74 Access OP-147
CREATE OR REPLACE FUNCTION work.body_dek_guard() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.state <> 'active' THEN
            RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'dek_must_start_active';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.ledger_id <> OLD.ledger_id OR NEW.dek_id <> OLD.dek_id
       OR NEW.subject_ref <> OLD.subject_ref OR NEW.retention_class <> OLD.retention_class
       OR NEW.created_at <> OLD.created_at THEN
        RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'dek_identity_immutable';
    END IF;
    IF OLD.state = 'destroyed' THEN
        RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'dek_destroyed_is_terminal';
    END IF;
    IF NEW.state = 'active' THEN
        IF (NEW.kek_id = OLD.kek_id) <> (NEW.wrapped_key = OLD.wrapped_key) THEN
            RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'dek_rewrap_changes_kek_and_key';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.kek_id <> OLD.kek_id THEN
        RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'dek_identity_immutable';
    END IF;
    IF work.retention_held(NEW.ledger_id, NEW.subject_ref, NEW.retention_class) THEN
        RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'retention_hold_active';
    END IF;
    RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION work.body_dek_guard() FROM PUBLIC;

-- OP-45 OP-12 OP-14 Access OP-74 Access OP-147
CREATE OR REPLACE FUNCTION work.body_part_key_guard() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.wrapped_key IS NULL THEN
            RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'part_key_must_start_wrapped';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.ledger_id <> OLD.ledger_id OR NEW.pos <> OLD.pos OR NEW.part <> OLD.part THEN
        RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'part_key_identity_immutable';
    END IF;
    IF OLD.wrapped_key IS NULL OR NEW.wrapped_key IS NOT NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'part_key_shred_once';
    END IF;
    PERFORM 1 FROM work.body_part p
      JOIN work.body_dek d ON d.ledger_id = p.ledger_id AND d.dek_id = p.dek_id
     WHERE p.ledger_id = NEW.ledger_id AND p.pos = NEW.pos AND p.part = NEW.part
       AND work.retention_held(p.ledger_id, d.subject_ref, p.retention_class);
    IF FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'retention_hold_active';
    END IF;
    RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION work.body_part_key_guard() FROM PUBLIC;
