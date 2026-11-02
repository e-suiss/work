-- OP-4 OP-33 OP-46 T-78
SET LOCAL ROLE work_owner;
SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '5min';

-- OP-46
CREATE OR REPLACE VIEW ledger.record_durability WITH (security_invoker = true, security_barrier = true) AS
SELECT l.ledger_id,
       l.pos,
       l.record_id,
       w.witnessed,
       i.included,
       CASE WHEN w.witnessed THEN 'witnessed'
            WHEN i.included THEN 'included'
            ELSE 'recorded' END AS durability
  FROM ledger.log l
 CROSS JOIN LATERAL (
       SELECT EXISTS (SELECT 1 FROM ledger.checkpoint c
                       WHERE c.ledger_id = l.ledger_id AND c.size > l.pos) AS included
 ) i
 CROSS JOIN LATERAL (
       SELECT EXISTS (
              SELECT 1
                FROM ledger.checkpoint c
               CROSS JOIN LATERAL (
                     SELECT pg_catalog.regexp_match(
                                pg_catalog.split_part(pg_catalog.encode(c.signed_note, 'escape'), E'\n\n', 1),
                                '^[^\n]+\n[0-9]+\n[^\n]+\ndurability (?:quorum|single-node)\ntime_sources (?:independent|dependent)\nwitness independent ([1-9][0-9]{0,2})$'
                            ) AS m
               ) p
               WHERE c.ledger_id = l.ledger_id AND c.size > l.pos
                 AND p.m IS NOT NULL
                 AND p.m[1]::integer <= 255
                 AND ((SELECT pg_catalog.count(DISTINCT s.witness_id) FROM ledger.checkpoint_cosignature s
                        WHERE s.ledger_id = c.ledger_id AND s.size = c.size AND s.cosign_kind = 'witness')
                      >= p.m[1]::integer
                      OR EXISTS (SELECT 1 FROM ledger.checkpoint_cosignature s
                                  WHERE s.ledger_id = c.ledger_id AND s.size = c.size AND s.cosign_kind = 'rfc3161'))
       ) AS witnessed
 ) w;

COMMENT ON VIEW ledger.record_durability IS 'label=DERIVED; home=canonical; guard=view; erasure=none';
