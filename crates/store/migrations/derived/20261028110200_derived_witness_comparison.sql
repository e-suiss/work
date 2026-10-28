-- OP-2 OP-4 SEC-32
SET LOCAL ROLE work_owner;
SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '5min';

-- OP-2 SEC-32
CREATE TABLE derived.witness_comparison_v1 (
    ledger_id     ledger.digest32   NOT NULL,
    witness_id    work.snake_name NOT NULL,
    observed_size bigint          NOT NULL,
    observed_root ledger.digest32   NOT NULL,
    observed_at   timestamptz     NOT NULL DEFAULT pg_catalog.now(),
    verdict       text            NOT NULL,
    decided_at    timestamptz,
    CONSTRAINT witness_comparison_v1_pk PRIMARY KEY (ledger_id, witness_id, observed_size, observed_root),
    CONSTRAINT witness_comparison_v1_size_ck CHECK (observed_size >= 1),
    CONSTRAINT witness_comparison_v1_verdict_ck CHECK (verdict IN ('pending', 'consistent', 'inconsistent')),
    CONSTRAINT witness_comparison_v1_decided_ck CHECK ((verdict = 'pending') = (decided_at IS NULL))
);

-- SEC-32
CREATE FUNCTION derived.witness_comparison_v1_guard() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog
AS $$
BEGIN
    IF NEW.ledger_id <> OLD.ledger_id OR NEW.witness_id <> OLD.witness_id
       OR NEW.observed_size <> OLD.observed_size OR NEW.observed_root <> OLD.observed_root
       OR NEW.observed_at <> OLD.observed_at THEN
        RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'observation_immutable';
    END IF;
    IF OLD.verdict <> 'pending' THEN
        RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'verdict_is_terminal';
    END IF;
    RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION derived.witness_comparison_v1_guard() FROM PUBLIC;

CREATE TRIGGER witness_comparison_v1_guard
    BEFORE UPDATE ON derived.witness_comparison_v1
    FOR EACH ROW EXECUTE FUNCTION derived.witness_comparison_v1_guard();

SELECT ledger.guard_table('derived.witness_comparison_v1', 'mutable');
SELECT ledger.apply_ledger_scope('derived.witness_comparison_v1');

REVOKE ALL ON derived.witness_comparison_v1 FROM PUBLIC;
GRANT SELECT ON derived.witness_comparison_v1 TO work_app, work_deriver;
GRANT INSERT ON derived.witness_comparison_v1 TO work_deriver;
GRANT UPDATE (verdict, decided_at) ON derived.witness_comparison_v1 TO work_deriver;

COMMENT ON TABLE derived.witness_comparison_v1 IS 'label=DERIVED; home=derived; guard=mutable; erasure=none';
