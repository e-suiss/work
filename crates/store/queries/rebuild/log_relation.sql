-- T-10 OP-1
SELECT ROW(pos, ordinal, rel, source_kind, source_bytes, source_text, target_kind,
           target_bytes, target_text, qualifier)::text AS "row!"
FROM work.log_relation WHERE ledger_id = $1
