-- OP-1 T-11 T-89
UPDATE work.item_head h
   SET version = h.version + 1,
       last_pos = (SELECT max(l.pos) FROM ledger.log l WHERE l.ledger_id = h.ledger_id)
 WHERE h.last_pos < (SELECT max(l.pos) FROM ledger.log l WHERE l.ledger_id = h.ledger_id);
INSERT INTO work.log_concerns (ledger_id, work_id, pos)
SELECT ledger_id, work_id, 0 FROM work.work_root;
INSERT INTO work.one_time_flag (ledger_id, flag_kind, flag_key, consumed_pos)
SELECT ledger_id, 'forged_flag', decode(repeat('0f', 32), 'hex'), 1 FROM ledger.head;
