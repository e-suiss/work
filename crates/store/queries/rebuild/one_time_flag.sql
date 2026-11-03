-- T-10 OP-1
SELECT ROW(flag_kind, flag_key, consumed_pos)::text AS "row!" FROM work.one_time_flag
WHERE ledger_id = $1
