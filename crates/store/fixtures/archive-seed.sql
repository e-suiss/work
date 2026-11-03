-- OP-35 OP-37 OP-38
SET ROLE work_owner;
SELECT work.ensure_monthly_partitions('work.idempotency_key', 4, 0);
SELECT work.ensure_monthly_partitions('work.inbound_seen', 4, 0);
RESET ROLE;
INSERT INTO work.idempotency_key (ledger_id, caller_ref, idem_key, request_digest, outcome, reason, created_at)
SELECT decode(v.l, 'hex'), 'party:bob', 'req-' || i, decode(repeat('78', 32), 'hex'), 'rejected', 'conflict',
       (date_trunc('month', now() AT TIME ZONE 'UTC') - interval '3 months' + interval '1 day' + i * interval '1 minute') AT TIME ZONE 'UTC'
  FROM (VALUES (repeat('a1', 32)), (repeat('b2', 32))) AS v (l), generate_series(1, 3) AS i;
INSERT INTO work.inbound_seen (ledger_id, source, source_id, content_digest, seen_at)
SELECT decode(repeat('a1', 32), 'hex'), 'https://partner.example', 'evt-' || i, decode(repeat('79', 32), 'hex'),
       (date_trunc('month', now() AT TIME ZONE 'UTC') - interval '3 months' + interval '1 day' + i * interval '1 minute') AT TIME ZONE 'UTC'
  FROM generate_series(1, 2) AS i;
