-- OP-45 OP-12 Access OP-74
UPDATE work.retention_hold SET state = 'released', released_at = now() WHERE state = 'active';
