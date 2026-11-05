-- P-2 P-20 T-10
SELECT size AS "size!", root::bytea AS "root!", head_leaf::bytea AS "head_leaf!",
       (extract(epoch FROM issued_at) * 1000)::bigint AS "issued_at!",
       signed_note AS "signed_note!"
FROM ledger.checkpoint WHERE ledger_id = $1 ORDER BY size
