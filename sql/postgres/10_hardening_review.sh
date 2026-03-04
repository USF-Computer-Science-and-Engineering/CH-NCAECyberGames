#!/usr/bin/env bash
# =============================================================================
# postgres/10_hardening_review.sh — PostgreSQL Hardening Configuration Review
# =============================================================================
# Reviews current PostgreSQL settings and compares them against
# security-hardened recommendations. Generates ALTER SYSTEM SET statements
# but does NOT apply them automatically.
# =============================================================================
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${SCRIPT_DIR}/../common/lib.sh"
NCAE_SCRIPT_NAME="10_hardening_review.sh"

ensure_pg_defaults

REPORT_FILE="${SCRIPT_DIR}/10_hardening_report.txt"

run_pg_sql() {
    psql -X -A --no-psqlrc --pset pager=off <<'EOSQL'

\echo '═══════════════════════════════════════════════════════════════'
\echo '  POSTGRESQL HARDENING CONFIGURATION REVIEW'
\echo '═══════════════════════════════════════════════════════════════'
\echo ''

-- ---------------------------------------------------------------------------
-- 1. Authentication & Password Settings
-- ---------------------------------------------------------------------------
\echo '── 1. Authentication & Password Settings ──'

SELECT
    name,
    setting,
    CASE
        WHEN name = 'password_encryption' AND setting = 'scram-sha-256' THEN 'OK'
        WHEN name = 'password_encryption' AND setting = 'md5' THEN 'WEAK — use scram-sha-256'
        WHEN name = 'password_encryption' THEN 'REVIEW — unexpected value'
        ELSE 'INFO'
    END AS recommendation,
    CASE
        WHEN name = 'password_encryption' AND setting != 'scram-sha-256'
            THEN 'ALTER SYSTEM SET password_encryption = ''scram-sha-256'';'
        ELSE NULL
    END AS remediation
FROM pg_settings
WHERE name IN ('password_encryption')
ORDER BY name;

-- ---------------------------------------------------------------------------
-- 2. Logging Settings
-- ---------------------------------------------------------------------------
\echo ''
\echo '── 2. Logging Settings ──'

SELECT
    name,
    setting,
    CASE
        WHEN name = 'logging_collector' AND setting = 'on' THEN 'OK'
        WHEN name = 'logging_collector' AND setting = 'off' THEN 'WARN — enable logging_collector'
        WHEN name = 'log_connections' AND setting = 'on' THEN 'OK'
        WHEN name = 'log_connections' AND setting = 'off' THEN 'WARN — enable for audit trail'
        WHEN name = 'log_disconnections' AND setting = 'on' THEN 'OK'
        WHEN name = 'log_disconnections' AND setting = 'off' THEN 'WARN — enable for audit trail'
        WHEN name = 'log_statement' AND setting = 'ddl' THEN 'OK (minimum ddl)'
        WHEN name = 'log_statement' AND setting = 'all' THEN 'OK (verbose)'
        WHEN name = 'log_statement' AND setting = 'none' THEN 'WARN — set to at least ddl'
        WHEN name = 'log_duration' AND setting = 'on' THEN 'OK'
        WHEN name = 'log_min_duration_statement' AND setting::int >= 0 AND setting::int <= 1000 THEN 'OK'
        WHEN name = 'log_min_duration_statement' AND setting = '-1' THEN 'WARN — disabled; set to 1000ms or less'
        WHEN name = 'log_line_prefix' AND setting LIKE '%u%' AND setting LIKE '%d%' AND setting LIKE '%t%' THEN 'OK — includes user/db/time'
        WHEN name = 'log_line_prefix' THEN 'WARN — should include %%u, %%d, %%t at minimum'
        WHEN name = 'log_directory' THEN 'INFO'
        WHEN name = 'log_filename' THEN 'INFO'
        WHEN name = 'log_rotation_age' THEN 'INFO'
        WHEN name = 'log_rotation_size' THEN 'INFO'
        ELSE 'REVIEW'
    END AS recommendation
FROM pg_settings
WHERE name IN (
    'logging_collector', 'log_connections', 'log_disconnections',
    'log_statement', 'log_duration', 'log_min_duration_statement',
    'log_line_prefix', 'log_directory', 'log_filename',
    'log_rotation_age', 'log_rotation_size'
)
ORDER BY name;

-- Generate remediation for logging
SELECT 'ALTER SYSTEM SET ' || name || ' = ''on'';' AS remediation_logging
FROM pg_settings
WHERE name IN ('logging_collector', 'log_connections', 'log_disconnections')
  AND setting = 'off';

SELECT 'ALTER SYSTEM SET log_statement = ''ddl'';' AS remediation_log_statement
WHERE EXISTS (SELECT 1 FROM pg_settings WHERE name = 'log_statement' AND setting = 'none');

-- ---------------------------------------------------------------------------
-- 3. SSL / TLS Configuration
-- ---------------------------------------------------------------------------
\echo ''
\echo '── 3. SSL / TLS Configuration ──'

SELECT
    name,
    setting,
    CASE
        WHEN name = 'ssl' AND setting = 'on' THEN 'OK — SSL enabled'
        WHEN name = 'ssl' AND setting = 'off' THEN 'CRITICAL — SSL is DISABLED'
        WHEN name = 'ssl_min_protocol_version' AND setting IN ('TLSv1.2','TLSv1.3') THEN 'OK'
        WHEN name = 'ssl_min_protocol_version' THEN 'WARN — should be TLSv1.2 or higher'
        WHEN name = 'ssl_cert_file' THEN 'INFO — ' || setting
        WHEN name = 'ssl_key_file' THEN 'INFO — ' || setting
        WHEN name = 'ssl_ca_file' AND setting = '' THEN 'WARN — no CA file set; client cert verification not possible'
        WHEN name = 'ssl_ca_file' THEN 'OK — CA file: ' || setting
        WHEN name = 'ssl_ciphers' THEN 'INFO'
        ELSE 'REVIEW'
    END AS recommendation
FROM pg_settings
WHERE name LIKE 'ssl%'
ORDER BY name;

-- ---------------------------------------------------------------------------
-- 4. Network / Listener Configuration
-- ---------------------------------------------------------------------------
\echo ''
\echo '── 4. Network / Listener Configuration ──'

SELECT
    name,
    setting,
    CASE
        WHEN name = 'listen_addresses' AND setting = '*' THEN 'WARN — listening on ALL interfaces'
        WHEN name = 'listen_addresses' AND setting = '0.0.0.0' THEN 'WARN — listening on all IPv4'
        WHEN name = 'listen_addresses' AND setting = 'localhost' THEN 'OK — localhost only'
        WHEN name = 'listen_addresses' THEN 'INFO — ' || setting
        WHEN name = 'port' THEN 'INFO — port ' || setting
        WHEN name = 'unix_socket_permissions' AND setting::int <= 770 THEN 'OK'
        WHEN name = 'unix_socket_permissions' AND setting::int > 770 THEN 'WARN — too permissive; use 0770 or stricter'
        ELSE 'REVIEW'
    END AS recommendation
FROM pg_settings
WHERE name IN ('listen_addresses', 'port', 'unix_socket_permissions', 'unix_socket_directories')
ORDER BY name;

-- ---------------------------------------------------------------------------
-- 5. Shared Preload Libraries
-- ---------------------------------------------------------------------------
\echo ''
\echo '── 5. Shared Preload Libraries ──'

SELECT
    name,
    setting,
    CASE
        WHEN setting = '' THEN 'INFO — no preloaded libraries'
        WHEN setting LIKE '%pg_stat_statements%' THEN 'OK — pg_stat_statements loaded'
        ELSE 'REVIEW — check if all libraries are expected: ' || setting
    END AS recommendation
FROM pg_settings
WHERE name = 'shared_preload_libraries';

-- Flag suspicious libraries (non-standard / potentially malicious)
SELECT
    'SUSPICIOUS LIBRARY' AS alert,
    unnest(string_to_array(setting, ',')) AS library_name
FROM pg_settings
WHERE name = 'shared_preload_libraries'
  AND setting != ''
  AND (
      setting LIKE '%shell%'
      OR setting LIKE '%exec%'
      OR setting LIKE '%hook%'
      OR setting LIKE '%inject%'
      OR setting LIKE '%backdoor%'
      OR setting LIKE '%rootkit%'
  );

-- ---------------------------------------------------------------------------
-- 6. Row Level Security (RLS) Usage
-- ---------------------------------------------------------------------------
\echo ''
\echo '── 6. Row Level Security (RLS) Usage ──'

SELECT
    n.nspname AS schema_name,
    c.relname AS table_name,
    c.relrowsecurity AS rls_enabled,
    c.relforcerowsecurity AS rls_forced,
    CASE
        WHEN c.relrowsecurity THEN 'OK — RLS enabled'
        ELSE 'INFO — RLS not enabled on this table'
    END AS status
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind = 'r'
  AND n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
ORDER BY n.nspname, c.relname;

-- Summarize RLS
SELECT
    COUNT(*) FILTER (WHERE relrowsecurity) AS tables_with_rls,
    COUNT(*) FILTER (WHERE NOT relrowsecurity) AS tables_without_rls,
    COUNT(*) AS total_tables
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind = 'r'
  AND n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast');

-- ---------------------------------------------------------------------------
-- 7. Extensions Installed
-- ---------------------------------------------------------------------------
\echo ''
\echo '── 7. Extensions Installed ──'

SELECT
    e.extname,
    e.extversion,
    n.nspname AS schema,
    CASE
        WHEN e.extname IN ('dblink', 'postgres_fdw', 'file_fdw', 'pg_cron',
                           'plpythonu', 'plperlu', 'pltclu', 'adminpack',
                           'pg_execute_server_program') THEN 'HIGH RISK — review necessity'
        WHEN e.extname IN ('pgcrypto', 'pg_stat_statements', 'pg_trgm', 'uuid-ossp',
                           'citext', 'hstore', 'ltree') THEN 'LOW RISK — common extension'
        ELSE 'REVIEW — ' || e.extname
    END AS risk_assessment
FROM pg_extension e
JOIN pg_namespace n ON n.oid = e.extnamespace
ORDER BY
    CASE WHEN e.extname IN ('dblink','postgres_fdw','file_fdw','pg_cron','plpythonu','plperlu','pltclu','adminpack') THEN 0 ELSE 1 END,
    e.extname;

-- ---------------------------------------------------------------------------
-- 8. Additional Security Parameters
-- ---------------------------------------------------------------------------
\echo ''
\echo '── 8. Additional Security Parameters ──'

SELECT
    name,
    setting,
    CASE
        WHEN name = 'track_activities' AND setting = 'on' THEN 'OK'
        WHEN name = 'track_activities' AND setting = 'off' THEN 'WARN — enable for monitoring'
        WHEN name = 'log_lock_waits' AND setting = 'on' THEN 'OK'
        WHEN name = 'log_lock_waits' AND setting = 'off' THEN 'WARN — enable to detect lock contention'
        WHEN name = 'log_temp_files' AND setting::int >= 0 THEN 'OK — logging temp files > ' || setting || ' bytes'
        WHEN name = 'log_temp_files' AND setting = '-1' THEN 'WARN — not logging temp files'
        WHEN name = 'log_checkpoints' AND setting = 'on' THEN 'OK'
        WHEN name = 'log_checkpoints' AND setting = 'off' THEN 'WARN — enable for performance audit'
        ELSE 'INFO'
    END AS recommendation
FROM pg_settings
WHERE name IN (
    'track_activities', 'log_lock_waits', 'log_temp_files',
    'log_checkpoints', 'idle_in_transaction_session_timeout',
    'statement_timeout', 'lock_timeout'
)
ORDER BY name;

-- ---------------------------------------------------------------------------
-- 9. Restart-Required Changes Summary
-- ---------------------------------------------------------------------------
\echo ''
\echo '── 9. Pending Restart / Reload Summary ──'

SELECT
    name,
    setting,
    pending_restart,
    context,
    CASE
        WHEN context = 'postmaster' THEN 'REQUIRES SERVER RESTART to take effect'
        WHEN context = 'sighup' THEN 'Requires pg_reload_conf() or SIGHUP'
        WHEN context = 'superuser' THEN 'Takes effect for new sessions'
        WHEN context = 'user' THEN 'Takes effect for new sessions'
        ELSE context
    END AS apply_method
FROM pg_settings
WHERE pending_restart = true
ORDER BY name;

-- ---------------------------------------------------------------------------
-- SUMMARY: Generate remediation script (DO NOT auto-apply)
-- ---------------------------------------------------------------------------
\echo ''
\echo '── REMEDIATION STATEMENTS (review before applying) ──'
\echo '-- These ALTER SYSTEM SET statements are SUGGESTIONS.'
\echo '-- Apply only after review. Use: psql -f <this_file> and then'
\echo '-- call SELECT pg_reload_conf(); for sighup-level changes.'
\echo '-- For postmaster-level changes, a server restart is required.'
\echo ''

-- Collect all recommended ALTER SYSTEM statements
SELECT '-- Password encryption' AS comment
WHERE EXISTS (SELECT 1 FROM pg_settings WHERE name = 'password_encryption' AND setting != 'scram-sha-256');
SELECT 'ALTER SYSTEM SET password_encryption = ''scram-sha-256'';' AS stmt
WHERE EXISTS (SELECT 1 FROM pg_settings WHERE name = 'password_encryption' AND setting != 'scram-sha-256');

SELECT '-- Enable SSL' AS comment
WHERE EXISTS (SELECT 1 FROM pg_settings WHERE name = 'ssl' AND setting = 'off');
SELECT 'ALTER SYSTEM SET ssl = ''on'';' AS stmt
WHERE EXISTS (SELECT 1 FROM pg_settings WHERE name = 'ssl' AND setting = 'off');

SELECT '-- Enable logging' AS comment
WHERE EXISTS (SELECT 1 FROM pg_settings WHERE name = 'logging_collector' AND setting = 'off');
SELECT 'ALTER SYSTEM SET logging_collector = ''on'';' AS stmt
WHERE EXISTS (SELECT 1 FROM pg_settings WHERE name = 'logging_collector' AND setting = 'off');
SELECT 'ALTER SYSTEM SET log_connections = ''on'';' AS stmt
WHERE EXISTS (SELECT 1 FROM pg_settings WHERE name = 'log_connections' AND setting = 'off');
SELECT 'ALTER SYSTEM SET log_disconnections = ''on'';' AS stmt
WHERE EXISTS (SELECT 1 FROM pg_settings WHERE name = 'log_disconnections' AND setting = 'off');

SELECT '-- Set log_statement to ddl minimum' AS comment
WHERE EXISTS (SELECT 1 FROM pg_settings WHERE name = 'log_statement' AND setting = 'none');
SELECT 'ALTER SYSTEM SET log_statement = ''ddl'';' AS stmt
WHERE EXISTS (SELECT 1 FROM pg_settings WHERE name = 'log_statement' AND setting = 'none');

SELECT '-- Enable log_duration' AS comment
WHERE EXISTS (SELECT 1 FROM pg_settings WHERE name = 'log_duration' AND setting = 'off');
SELECT 'ALTER SYSTEM SET log_duration = ''on'';' AS stmt
WHERE EXISTS (SELECT 1 FROM pg_settings WHERE name = 'log_duration' AND setting = 'off');

SELECT '-- Set SSL minimum protocol' AS comment
WHERE EXISTS (SELECT 1 FROM pg_settings WHERE name = 'ssl_min_protocol_version' AND setting NOT IN ('TLSv1.2','TLSv1.3'));
SELECT 'ALTER SYSTEM SET ssl_min_protocol_version = ''TLSv1.2'';' AS stmt
WHERE EXISTS (SELECT 1 FROM pg_settings WHERE name = 'ssl_min_protocol_version' AND setting NOT IN ('TLSv1.2','TLSv1.3'));

\echo ''
\echo '-- To apply sighup-level changes without restart:'
\echo '-- SELECT pg_reload_conf();'
\echo ''
\echo '-- To check which changes need a restart:'
\echo '-- SELECT name, setting FROM pg_settings WHERE pending_restart;'
\echo ''
\echo '═══════════════════════════════════════════════════════════════'
\echo '  HARDENING REVIEW COMPLETE'
\echo '═══════════════════════════════════════════════════════════════'

EOSQL
}

run_section "PostgreSQL Hardening Review" run_pg_sql | tee "$REPORT_FILE"

print_summary

log_info "Report saved to: ${REPORT_FILE}"
