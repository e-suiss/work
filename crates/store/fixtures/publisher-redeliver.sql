-- T-76 OP-34
INSERT INTO ledger.outbox (ledger_id, pos, event_id, event_type, traceparent)
VALUES (decode(repeat('ab', 32), 'hex'), 0, 'evt-0', 'work.opened', '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01');
