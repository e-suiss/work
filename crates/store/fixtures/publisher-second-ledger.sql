-- T-80 OP-34 P-98
INSERT INTO ledger.head (ledger_id, pos, epoch) VALUES (decode(repeat('cd', 32), 'hex'), -1, 0);
INSERT INTO ledger.log (ledger_id, pos, epoch, record_id, recorded_at, prev, leaf_hash, record_bytes, envelope_bytes)
VALUES (decode(repeat('cd', 32), 'hex'), 0, 0, decode(repeat('04', 32), 'hex'), '2026-10-23T11:00:00.000Z',
        decode(repeat('00', 32), 'hex'), decode(repeat('21', 32), 'hex'), '\xd2', '\xa0');
INSERT INTO ledger.outbox (ledger_id, pos, event_id, event_type, traceparent, item_kind, item_id, version)
VALUES (decode(repeat('cd', 32), 'hex'), 0, 'evt-m0', 'work.opened', '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01', 'work', decode(repeat('0c', 16), 'hex'), 1);
UPDATE ledger.head
   SET pos = 0, head_leaf = decode(repeat('21', 32), 'hex'), head_recorded_at = '2026-10-23T11:00:00.000Z'
 WHERE ledger_id = decode(repeat('cd', 32), 'hex') AND pos = -1 AND epoch = 0;
