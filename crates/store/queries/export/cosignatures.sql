-- P-2 P-20 T-10 OP-33
SELECT size AS "size!", witness_id::text AS "witness_id!",
       (extract(epoch FROM cosigned_at) * 1000)::bigint AS "at!",
       signature AS "signature!"
FROM ledger.checkpoint_cosignature
WHERE ledger_id = $1 AND cosign_kind = 'witness'
ORDER BY size, witness_id
