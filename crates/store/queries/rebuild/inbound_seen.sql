-- T-10 OP-8 OP-38 T-91
SELECT ROW(i.source, i.source_id, i.result_pos)::text AS "row!" FROM work.inbound_seen i
JOIN ledger.log l ON l.ledger_id = i.ledger_id AND l.pos = i.result_pos
WHERE i.ledger_id = $1
AND (l.record_id <> i.content_digest OR l.recorded_at <> i.seen_at)
