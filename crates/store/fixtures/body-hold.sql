-- OP-45 OP-12 OP-14 Access OP-74 Access OP-147
INSERT INTO work.retention_hold (ledger_id, hold_id, hold_kind, scope, subject_ref, placed_at, state)
SELECT ledger_id, 'hld_fixture', 'litigation', 'subject', 'party:acme:alice', now(), 'active' FROM ledger.head;
