-- OP-2 T-15 OP-12 OP-17
SET LOCAL ROLE work_owner;
SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '5min';

-- T-15 OP-2
CREATE TABLE derived.timer_v1 (
    ledger_id    ledger.digest32   NOT NULL,
    timer_id     uuid            NOT NULL DEFAULT pg_catalog.uuidv7(),
    family       text            NOT NULL,
    timer_kind   work.snake_name NOT NULL,
    item_kind    text            NOT NULL,
    item_id      bytea           NOT NULL,
    basis_pos    ledger.log_pos    NOT NULL,
    due_at       ledger.ms_time    NOT NULL,
    state        text            NOT NULL,
    settled_at   timestamptz,
    CONSTRAINT timer_v1_pk PRIMARY KEY (ledger_id, timer_id),
    CONSTRAINT timer_v1_key_uq UNIQUE (ledger_id, item_kind, item_id, family, timer_kind, basis_pos),
    CONSTRAINT timer_v1_family_ck CHECK (family IN ('commitment_clock', 'budget', 'lease', 'return_review')),
    CONSTRAINT timer_v1_item_kind_ck CHECK (item_kind IN ('work', 'commitment', 'condition')),
    CONSTRAINT timer_v1_item_id_ck CHECK (
        (item_kind = 'work' AND pg_catalog.octet_length(item_id) = 16)
        OR (item_kind IN ('commitment', 'condition') AND pg_catalog.octet_length(item_id) = 32)
    ),
    CONSTRAINT timer_v1_state_ck CHECK (state IN ('pending', 'fired', 'superseded')),
    CONSTRAINT timer_v1_settled_ck CHECK ((state = 'pending') = (settled_at IS NULL))
);
CREATE INDEX timer_v1_due_ix ON derived.timer_v1 (ledger_id, due_at) WHERE state = 'pending';

-- T-15
CREATE FUNCTION derived.timer_v1_guard() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.state <> 'pending' THEN
            RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'timer_must_start_pending';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.ledger_id <> OLD.ledger_id OR NEW.timer_id <> OLD.timer_id OR NEW.family <> OLD.family
       OR NEW.timer_kind <> OLD.timer_kind OR NEW.item_kind <> OLD.item_kind OR NEW.item_id <> OLD.item_id
       OR NEW.basis_pos <> OLD.basis_pos OR NEW.due_at <> OLD.due_at THEN
        RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'timer_identity_immutable';
    END IF;
    IF OLD.state <> 'pending' THEN
        RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'timer_settled_is_terminal';
    END IF;
    RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION derived.timer_v1_guard() FROM PUBLIC;

CREATE TRIGGER timer_v1_guard
    BEFORE INSERT OR UPDATE ON derived.timer_v1
    FOR EACH ROW EXECUTE FUNCTION derived.timer_v1_guard();

SELECT ledger.guard_table('derived.timer_v1', 'mutable');
SELECT ledger.apply_ledger_scope('derived.timer_v1');

REVOKE ALL ON derived.timer_v1 FROM PUBLIC;
GRANT SELECT ON derived.timer_v1 TO work_app, work_deriver, work_reconciler;
GRANT INSERT ON derived.timer_v1 TO work_deriver;
GRANT UPDATE (state, settled_at) ON derived.timer_v1 TO work_deriver, work_reconciler;

COMMENT ON TABLE derived.timer_v1 IS 'label=DERIVED; home=derived; guard=mutable; erasure=none';
