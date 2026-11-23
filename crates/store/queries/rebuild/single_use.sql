-- T-10 SEC-15 OP-47
SELECT ROW(s.authority_digest, s.idem_key, s.pos)::text AS "row!" FROM work.single_use s
LEFT JOIN ledger.log l ON l.ledger_id = s.ledger_id AND l.pos = s.pos
LEFT JOIN work.body_commitment b ON b.ledger_id = s.ledger_id AND b.pos = s.pos AND b.part = 'definition'
WHERE s.ledger_id = $1
AND (l.record_id IS DISTINCT FROM s.record_id OR b.part IS NULL)
