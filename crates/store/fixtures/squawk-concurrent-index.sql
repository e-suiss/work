-- no-transaction
-- OP-28 T-36
SET lock_timeout = '10s';
SET statement_timeout = '5min';
CREATE INDEX CONCURRENTLY IF NOT EXISTS work_title_idx ON work.work (title);
