-- T-20
SELECT (extract(epoch FROM clock_timestamp()) * 1000)::bigint;
