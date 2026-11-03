-- OP-45 OP-12 Access OP-74
INSERT INTO work.retention_hold (ledger_id, hold_kind, subject_ref, state)
SELECT ledger_id, 'litigation', 'party:acme:alice', 'active' FROM ledger.head;
