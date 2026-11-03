-- T-10 OP-1 T-90
SELECT ROW(pos, record_id, (extract(epoch FROM recorded_at) * 1000)::bigint, prev,
           leaf_hash, pg_catalog.sha256(record_bytes), pg_catalog.sha256(envelope_bytes))::text
       AS "row!"
FROM ledger.log WHERE ledger_id = $1
