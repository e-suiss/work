-- OP-1 T-11 T-90
SELECT r.pos AS "pos!", r.role AS "role!", b.kind AS "kind!", b.bytes AS "bytes!"
FROM work.log_received r
JOIN work.received_bytes b ON b.ledger_id = r.ledger_id AND b.digest = r.digest
WHERE r.ledger_id = $1 AND r.pos BETWEEN $2 AND $3
ORDER BY r.pos, r.role, r.digest
