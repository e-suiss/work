-- T-10 OP-1
SELECT ROW(pos, basis_record_id)::text AS "row!" FROM work.log_basis WHERE ledger_id = $1
