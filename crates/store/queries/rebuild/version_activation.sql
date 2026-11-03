-- T-10 OP-1 P-110
SELECT ROW(pos)::text AS "row!" FROM ledger.version_activation WHERE ledger_id = $1
