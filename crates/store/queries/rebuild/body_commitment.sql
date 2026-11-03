-- T-10 OP-1
SELECT ROW(pos, part, part_commit)::text AS "row!" FROM work.body_commitment
WHERE ledger_id = $1
