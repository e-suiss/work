-- T-10 OP-1 T-89
SELECT ROW(item_kind, item_id, version, last_pos, heads)::text AS "row!" FROM work.item_head
WHERE ledger_id = $1
