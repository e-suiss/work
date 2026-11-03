-- T-10 OP-1
SELECT ROW(pos, kind, record_type, author, author_actor_type, author_actor_type_source,
           (extract(epoch FROM occurred_at) * 1000)::bigint, ingest, ingest_reason, proof_commit,
           auth_context_ref, protocol_major, protocol_minor, schema_digest)::text AS "row!"
FROM work.record_header WHERE ledger_id = $1
