-- OP-28 T-36
SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '5min';
CREATE INDEX IF NOT EXISTS work_title_idx ON work.work (title);
