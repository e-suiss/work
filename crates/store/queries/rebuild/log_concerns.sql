-- T-10 OP-1
SELECT ROW(work_id, pos)::text AS "row!" FROM work.log_concerns WHERE ledger_id = $1
