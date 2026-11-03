-- T-10 OP-1 T-90
SELECT ROW(digest, kind, first_pos)::text AS "row!" FROM work.received_bytes
WHERE ledger_id = $1
