-- T-10 OP-1 T-90
SELECT ROW(pos, role, digest)::text AS "row!" FROM work.log_received WHERE ledger_id = $1
