-- T-10 OP-1 SEC-36
SELECT ROW(event_digest, pos, (extract(epoch FROM window_from) * 1000)::bigint,
           (extract(epoch FROM window_to) * 1000)::bigint, kids, party)::text AS "row!"
FROM work.compromise_notice WHERE ledger_id = $1
