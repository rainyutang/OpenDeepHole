-- PostgreSQL 16 / psql. Catalog diagnostics by default; no application startup.
-- Usage: psql -X -d SERVICE_OR_DATABASE -f scripts/diagnose_postgres_storage.sql
-- Optional application data sampling: add -v details=1 (prefer a restored copy).
-- For a different application schema: add -v app_schema=your_schema.
-- Credentials belong in libpq service configuration / .pgpass, not this file.
-- Monitoring views may require pg_monitor / pg_read_all_stats.
\set ON_ERROR_STOP on
\pset pager off
\timing on
\if :{?app_schema}
\else
  \set app_schema public
\endif
\if :{?details}
\else
  \set details 0
\endif

SET default_transaction_read_only = on;
SET statement_timeout = '10s';
SET lock_timeout = '1s';

-- Autocommit keeps each observation short; this is not a consistent snapshot.
SELECT now() AS observed_at, version() AS postgres_version,
       current_database() AS database_name,
       pg_database_size(current_database()) AS database_bytes,
       pg_size_pretty(pg_database_size(current_database())) AS database_size,
       pg_is_in_recovery() AS is_replica;

SELECT name, setting, unit, source
FROM pg_settings
WHERE name IN (
    'max_connections', 'shared_buffers', 'work_mem', 'maintenance_work_mem',
    'autovacuum', 'autovacuum_max_workers', 'autovacuum_naptime',
    'autovacuum_vacuum_threshold', 'autovacuum_vacuum_scale_factor',
    'autovacuum_analyze_threshold', 'autovacuum_analyze_scale_factor',
    'default_toast_compression', 'track_counts', 'track_io_timing',
    'max_wal_size', 'max_slot_wal_keep_size', 'archive_mode'
)
ORDER BY name;

-- total_bytes includes TOAST and indexes; do not add toast_bytes to it again.
-- heap_main_bytes excludes FSM/VM; sizes are not a bloat measurement.
SELECT c.relname AS table_name, c.reltuples::bigint AS estimated_rows,
       pg_relation_size(c.oid) AS heap_main_bytes,
       CASE WHEN c.reltoastrelid = 0 THEN 0
            ELSE pg_total_relation_size(c.reltoastrelid) END AS toast_total_bytes,
       pg_indexes_size(c.oid) AS table_indexes_bytes,
       pg_total_relation_size(c.oid) AS total_bytes,
       pg_size_pretty(pg_total_relation_size(c.oid)) AS total_size,
       c.reloptions AS table_options, toast.reloptions AS toast_options
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
LEFT JOIN pg_class toast ON toast.oid = c.reltoastrelid
WHERE n.nspname = :'app_schema' AND c.relkind IN ('r', 'm')
ORDER BY total_bytes DESC;

-- Include each application's TOAST relation in the churn/vacuum inspection.
SELECT root.relname AS application_table, st.schemaname, st.relname,
       st.n_live_tup, st.n_dead_tup, st.n_tup_ins, st.n_tup_upd,
       st.n_tup_del, st.n_tup_hot_upd, st.n_mod_since_analyze,
       st.seq_scan, st.idx_scan, st.last_autovacuum, st.last_autoanalyze,
       st.last_vacuum, st.last_analyze
FROM pg_class root
JOIN pg_namespace ns ON ns.oid = root.relnamespace
JOIN pg_stat_all_tables st ON st.relid IN (root.oid, root.reltoastrelid)
WHERE ns.nspname = :'app_schema' AND root.relkind IN ('r', 'm')
ORDER BY st.n_dead_tup DESC;

SELECT t.relname AS table_name, i.relname AS index_name,
       pg_relation_size(i.oid) AS index_bytes,
       x.indisprimary, x.indisunique, x.indisvalid,
       stats.idx_scan, stats.idx_tup_read, stats.idx_tup_fetch,
       pg_get_indexdef(i.oid) AS index_definition
FROM pg_index x
JOIN pg_class i ON i.oid = x.indexrelid
JOIN pg_class t ON t.oid = x.indrelid
JOIN pg_namespace n ON n.oid = t.relnamespace
LEFT JOIN pg_stat_user_indexes stats ON stats.indexrelid = i.oid
WHERE n.nspname = :'app_schema'
ORDER BY index_bytes DESC;

SELECT rel.relname AS child_table, con.conname,
       pg_get_constraintdef(con.oid) AS foreign_key_definition
FROM pg_constraint con
JOIN pg_class rel ON rel.oid = con.conrelid
JOIN pg_namespace ns ON ns.oid = rel.relnamespace
WHERE ns.nspname = :'app_schema' AND con.contype = 'f'
ORDER BY child_table, con.conname;

-- Legacy table/column discovery, including tables absent from current code.
SELECT table_name, column_name, data_type
FROM information_schema.columns
WHERE table_schema = :'app_schema'
ORDER BY table_name, ordinal_position;

-- Exclude query text: prompts, project contents, tokens and SQL literals are
-- unnecessary for the first diagnostic report. Capture selected EXPLAINs later.
SELECT pid, state, wait_event_type, wait_event,
       now() - xact_start AS transaction_age,
       now() - query_start AS query_age,
       pg_blocking_pids(pid) AS blocking_pids
FROM pg_stat_activity
WHERE datname = current_database() AND pid <> pg_backend_pid()
ORDER BY xact_start NULLS LAST;

SELECT datname, numbackends, xact_commit, xact_rollback, blks_read, blks_hit,
       temp_files, temp_bytes, deadlocks, blk_read_time, blk_write_time, stats_reset
FROM pg_stat_database WHERE datname = current_database();

-- WAL statistics are cluster-wide cumulative counters, not a disk-size total.
SELECT wal_records, wal_fpi, wal_bytes, wal_buffers_full, stats_reset
FROM pg_stat_wal;

SELECT slot_type, active, xmin, catalog_xmin, wal_status,
       pg_wal_lsn_diff(
           CASE WHEN pg_is_in_recovery() THEN pg_last_wal_replay_lsn()
                ELSE pg_current_wal_lsn() END,
           restart_lsn
       ) AS retained_wal_bytes
FROM pg_replication_slots;

SELECT archived_count, failed_count, last_archived_time, last_failed_time, stats_reset
FROM pg_stat_archiver;

-- Skip pg_stat_statements unless both extension and preload are configured.
SELECT EXISTS (
    SELECT 1 FROM pg_extension WHERE extname = 'pg_stat_statements'
) AND current_setting('shared_preload_libraries') LIKE '%pg_stat_statements%'
AS have_pgss \gset
\if :have_pgss
  SELECT format(
    'SELECT queryid, calls, total_exec_time, mean_exec_time, rows, '
    'shared_blks_read, shared_blks_hit, temp_blks_written, wal_bytes '
    'FROM %I.pg_stat_statements WHERE dbid = '
    '(SELECT oid FROM pg_database WHERE datname = current_database()) '
    'ORDER BY total_exec_time DESC LIMIT 30', n.nspname
  )
  FROM pg_extension e JOIN pg_namespace n ON n.oid = e.extnamespace
  WHERE e.extname = 'pg_stat_statements'
  \gexec
\else
  \echo 'pg_stat_statements unavailable; no extension/config changes were made.'
\endif

\if :details
  -- These scans can consume I/O even though they are read-only. Each statement
  -- has a 10 s limit; ON_ERROR_STOP exits at the first timeout or permission error.
  -- Small tables can yield zero sampled rows; do not extrapolate sample totals.
  SELECT format(
    'SELECT %L AS table_name, %L AS column_name, count(*) AS sampled_rows, '
    'coalesce(sum(octet_length(%I)), 0) AS sampled_logical_bytes, '
    'max(octet_length(%I)) AS max_sampled_logical_bytes '
    'FROM (SELECT %I FROM %I.%I TABLESAMPLE SYSTEM (1) '
    'REPEATABLE (20260907) LIMIT 200) AS sample',
    c.relname, a.attname, a.attname, a.attname, a.attname, n.nspname, c.relname
  )
  FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace
  JOIN pg_attribute a ON a.attrelid = c.oid
  WHERE n.nspname = :'app_schema' AND c.relkind = 'r'
    AND a.attnum > 0 AND NOT a.attisdropped
    AND a.atttypid IN ('text'::regtype, 'varchar'::regtype)
    AND (c.relname, a.attname) IN (
      ('scans', 'opencode_pool'), ('scans', 'current_candidate'),
      ('scan_candidates', 'audit_result'), ('scan_candidates', 'metadata'),
      ('vulnerabilities', 'vulnerability_report'), ('vulnerabilities', 'ai_analysis'),
      ('vulnerabilities', 'function_source'), ('vulnerabilities', 'output_source'),
      ('fp_review_results', 'stage_outputs'), ('fp_review_results', 'vulnerability_report'),
      ('fp_review_stage_outputs', 'markdown'), ('threat_analysis', 'content'),
      ('skill_reports', 'content'), ('vulnerability_validations', 'intermediate_output'),
      ('vulnerability_validations', 'output_sections'), ('vulnerability_validations', 'artifacts'),
      ('opencode_task_reports', 'task_json'), ('scan_stream_events', 'data_json'),
      ('agent_commands', 'payload_json'), ('agent_resume_manifests', 'payload_json')
    )
  ORDER BY c.relname, a.attname
  \gexec

  -- Generate only queries whose parent/child tables exist in the chosen schema.
  SELECT format(
    'SELECT count(*) AS orphan_fp_review_jobs FROM %I.fp_review_jobs j '
    'WHERE NOT EXISTS (SELECT 1 FROM %I.scans s WHERE s.scan_id = j.scan_id)',
    :'app_schema', :'app_schema'
  )
  WHERE to_regclass(format('%I.fp_review_jobs', :'app_schema')) IS NOT NULL
    AND to_regclass(format('%I.scans', :'app_schema')) IS NOT NULL
  \gexec

  SELECT format(
    'SELECT status, count(*) AS commands, sum(octet_length(payload_json)) '
    'AS logical_payload_bytes, min(created_at) AS oldest, max(created_at) AS newest '
    'FROM %I.agent_commands GROUP BY status', :'app_schema'
  )
  WHERE to_regclass(format('%I.agent_commands', :'app_schema')) IS NOT NULL
  \gexec

  SELECT format(
    'SELECT event_type, count(*) AS events, sum(octet_length(data_json)) '
    'AS logical_payload_bytes, min(created_at) AS oldest, max(created_at) AS newest '
    'FROM %I.scan_stream_events GROUP BY event_type', :'app_schema'
  )
  WHERE to_regclass(format('%I.scan_stream_events', :'app_schema')) IS NOT NULL
  \gexec
\endif
