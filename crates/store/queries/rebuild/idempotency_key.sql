-- T-10 OP-8 OP-36 T-91
SELECT ROW(k.idem_key, k.result_pos)::text AS "row!" FROM work.idempotency_key k
JOIN ledger.log l ON l.ledger_id = k.ledger_id AND l.pos = k.result_pos
WHERE k.ledger_id = $1 AND k.outcome = 'recorded'
AND (l.record_id <> k.result_record_id OR l.recorded_at <> k.created_at)
