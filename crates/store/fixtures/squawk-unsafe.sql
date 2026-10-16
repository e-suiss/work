-- T-36
CREATE INDEX work_title_idx ON work (title);
ALTER TABLE work RENAME COLUMN title TO name;
