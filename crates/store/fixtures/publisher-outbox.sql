-- T-17 OP-34 P-42 T-81
INSERT INTO ledger.head (ledger_id, pos, epoch) VALUES (decode(repeat('ab', 32), 'hex'), -1, 0);
INSERT INTO ledger.log (ledger_id, pos, epoch, record_id, recorded_at, prev, leaf_hash, record_bytes, envelope_bytes)
VALUES (decode(repeat('ab', 32), 'hex'), 0, 0, decode(repeat('01', 32), 'hex'), '2026-10-23T10:00:00.123Z',
        decode(repeat('00', 32), 'hex'), decode(repeat('11', 32), 'hex'), '\xd2', '\xa0'),
       (decode(repeat('ab', 32), 'hex'), 1, 0, decode(repeat('02', 32), 'hex'), '2026-10-23T10:00:01.000Z',
        decode(repeat('11', 32), 'hex'), decode(repeat('12', 32), 'hex'), '\xd2', '\xa0'),
       (decode(repeat('ab', 32), 'hex'), 2, 0, decode(repeat('03', 32), 'hex'), '2026-10-23T10:00:02.500Z',
        decode(repeat('12', 32), 'hex'), decode(repeat('13', 32), 'hex'), '\xd2', '\xa0');
INSERT INTO ledger.outbox (ledger_id, pos, event_id, event_type, traceparent, item_kind, item_id, version)
VALUES (decode(repeat('ab', 32), 'hex'), 0, 'evt-0', 'work.opened', '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01', 'work', decode(repeat('0b', 16), 'hex'), 1),
       (decode(repeat('ab', 32), 'hex'), 0, 'evt-1', 'commitment.requested', '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01', 'commitment', decode(repeat('0a', 32), 'hex'), 1),
       (decode(repeat('ab', 32), 'hex'), 1, 'evt-2', 'commitment.promised', '00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01', 'commitment', decode(repeat('0a', 32), 'hex'), 2),
       (decode(repeat('ab', 32), 'hex'), 2, 'evt-3', 'commitment.declined', '00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01', 'commitment', decode(repeat('0a', 32), 'hex'), 3);
UPDATE ledger.head
   SET pos = 2, head_leaf = decode(repeat('13', 32), 'hex'), head_recorded_at = '2026-10-23T10:00:02.500Z'
 WHERE ledger_id = decode(repeat('ab', 32), 'hex') AND pos = -1 AND epoch = 0;
