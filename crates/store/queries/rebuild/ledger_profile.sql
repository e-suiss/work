-- T-10 OP-1
SELECT ROW(durability_profile)::text AS "row!" FROM work.ledger_profile WHERE ledger_id = $1
