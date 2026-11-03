-- T-10 OP-1
SELECT ROW(pos, head_leaf, (extract(epoch FROM head_recorded_at) * 1000)::bigint,
           frontier)::text AS "row!"
FROM ledger.head WHERE ledger_id = $1
