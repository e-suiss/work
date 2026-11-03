-- T-10 OP-1
SELECT ROW(work_id, first_pos)::text AS "row!" FROM work.work_root WHERE ledger_id = $1
