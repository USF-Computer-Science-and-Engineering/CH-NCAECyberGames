#!/usr/bin/env bash
# =============================================================================
# postgres/40_insecure_defaults_and_objects.sh — PostgreSQL Insecure Defaults & Risky Objects
# =============================================================================
# Checks for insecure defaults, dangerous functions, untrusted languages,
# risky extensions, foreign data wrappers, event triggers, and more.
# =============================================================================
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${SCRIPT_DIR}/../common/lib.sh"
NCAE_SCRIPT_NAME="40_insecure_defaults_and_objects.sh"
REPORT_FILE="${SCRIPT_DIR}/40_insecure_defaults_report.txt"

ensure_pg_defaults

run_pg_sql() {
    psql -X -A --no-psqlrc --pset pager=off <<'EOSQL'

\echo '═══════════════════════════════════════════════════════════════'
\echo '  POSTGRESQL INSECURE DEFAULTS & RISKY OBJECTS AUDIT'
\echo '═══════════════════════════════════════════════════════════════'

-- ---------------------------------------------------------------------------
-- 1. Template Database Security Settings
-- ---------------------------------------------------------------------------
\echo ''
\echo '── 1. Template & Default Database Settings ──'

SELECT
    datname,
    pg_catalog.pg_get_userbyid(datdba) AS owner,
    datallowconn,
    datistemplate,
    pg_encoding_to_char(encoding) AS encoding,
    datcollate,
    datacl,
    CASE
        WHEN datname = 'template0' AND datallowconn THEN 'WARN — template0 allows connections'
        WHEN datname = 'template1' AND datacl IS NOT NULL
            AND datacl::text LIKE '%=CTc/%' THEN 'REVIEW — template1 has explicit ACLs'
        ELSE 'INFO'
    END AS concern
FROM pg_database
ORDER BY datname;

-- ---------------------------------------------------------------------------
-- 2. pg_hba.conf Patterns (if pg_hba_file_rules view is available, PG >= 10)
-- ---------------------------------------------------------------------------
\echo ''
\echo '── 2. pg_hba.conf Authentication Rules ──'
\echo '   (Requires pg_hba_file_rules view, PG >= 10; errors here are expected on older versions)'

-- This will error gracefully on PG < 10
SELECT
    line_number,
    type,
    database,
    user_name,
    address,
    netmask,
    auth_method,
    CASE
        WHEN auth_method = 'trust' THEN 'CRITICAL — trust authentication (no password required!)'
        WHEN auth_method = 'md5' THEN 'WARN — md5 auth; upgrade to scram-sha-256'
        WHEN auth_method = 'password' THEN 'CRITICAL — cleartext password auth!'
        WHEN auth_method = 'peer' AND type = 'local' THEN 'OK — peer auth on local'
        WHEN auth_method = 'scram-sha-256' THEN 'OK'
        WHEN auth_method = 'cert' THEN 'OK — certificate auth'
        WHEN auth_method = 'gss' OR auth_method = 'sspi' THEN 'OK — Kerberos/SSPI'
        WHEN auth_method = 'ldap' THEN 'INFO — LDAP auth'
        WHEN auth_method = 'radius' THEN 'INFO — RADIUS auth'
        WHEN auth_method = 'reject' THEN 'OK — explicit reject'
        ELSE 'REVIEW — ' || auth_method
    END AS assessment,
    CASE
        WHEN address = '0.0.0.0/0' OR address = '::/0'
            THEN 'WARN — open to ALL addresses'
        WHEN address LIKE '%/0' THEN 'WARN — very broad network mask'
        ELSE 'OK'
    END AS network_scope
FROM pg_hba_file_rules
ORDER BY line_number;

-- ---------------------------------------------------------------------------
-- 3. SECURITY DEFINER Functions (potential privilege escalation)
-- ---------------------------------------------------------------------------
\echo ''
\echo '── 3. SECURITY DEFINER Functions ──'

SELECT
    n.nspname AS schema_name,
    p.proname AS function_name,
    pg_catalog.pg_get_userbyid(p.proowner) AS owner,
    pg_catalog.pg_get_function_arguments(p.oid) AS arguments,
    l.lanname AS language,
    CASE
        WHEN pg_catalog.pg_get_userbyid(p.proowner) = 'postgres'
            OR r.rolsuper THEN 'HIGH — SECURITY DEFINER owned by superuser'
        ELSE 'MEDIUM — SECURITY DEFINER owned by ' || pg_catalog.pg_get_userbyid(p.proowner)
    END AS risk,
    CASE
        WHEN has_function_privilege('PUBLIC', p.oid, 'EXECUTE')
            THEN 'CRITICAL — PUBLIC can execute this SECURITY DEFINER function'
        ELSE 'INFO — restricted execute'
    END AS public_access
FROM pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace
JOIN pg_language l ON l.oid = p.prolang
JOIN pg_roles r ON r.oid = p.proowner
WHERE p.prosecdef = true
  AND n.nspname NOT IN ('pg_catalog', 'information_schema')
ORDER BY risk DESC, n.nspname, p.proname;

-- ---------------------------------------------------------------------------
-- 4. Procedural Languages (flag untrusted)
-- ---------------------------------------------------------------------------
\echo ''
\echo '── 4. Installed Procedural Languages ──'

SELECT
    l.lanname,
    l.lanpltrusted,
    pg_catalog.pg_get_userbyid(l.lanowner) AS owner,
    CASE
        WHEN NOT l.lanpltrusted THEN 'HIGH RISK — untrusted language (can execute OS commands)'
        WHEN l.lanname IN ('plpythonu', 'plperlu', 'pltclu', 'plpython3u')
            THEN 'HIGH RISK — untrusted language variant'
        WHEN l.lanname IN ('plpgsql', 'sql') THEN 'OK — standard trusted language'
        ELSE 'REVIEW'
    END AS risk_assessment
FROM pg_language l
ORDER BY l.lanpltrusted, l.lanname;

-- ---------------------------------------------------------------------------
-- 5. Extensions Enabling OS/Network Interaction
-- ---------------------------------------------------------------------------
\echo ''
\echo '── 5. Risky Extensions ──'

SELECT
    e.extname,
    e.extversion,
    n.nspname AS schema,
    CASE
        WHEN e.extname = 'dblink' THEN 'HIGH — enables cross-database/server queries & network access'
        WHEN e.extname = 'postgres_fdw' THEN 'HIGH — foreign data wrapper to other PG servers'
        WHEN e.extname = 'file_fdw' THEN 'HIGH — can read arbitrary files on server'
        WHEN e.extname = 'adminpack' THEN 'HIGH — admin functions including file I/O'
        WHEN e.extname = 'pg_cron' THEN 'MEDIUM — scheduled job execution'
        WHEN e.extname IN ('plpythonu', 'plperlu', 'pltclu') THEN 'CRITICAL — untrusted PL with OS access'
        WHEN e.extname = 'pg_execute_server_program' THEN 'CRITICAL — can execute OS programs'
        WHEN e.extname = 'lo' THEN 'MEDIUM — large object management'
        WHEN e.extname = 'pg_read_server_files' THEN 'HIGH — can read server files'
        WHEN e.extname = 'pg_write_server_files' THEN 'CRITICAL — can write server files'
        ELSE 'LOW'
    END AS risk_level
FROM pg_extension e
JOIN pg_namespace n ON n.oid = e.extnamespace
WHERE e.extname IN (
    'dblink', 'postgres_fdw', 'file_fdw', 'adminpack', 'pg_cron',
    'plpythonu', 'plperlu', 'pltclu', 'pg_execute_server_program',
    'lo', 'pg_read_server_files', 'pg_write_server_files',
    'mysql_fdw', 'oracle_fdw', 'tds_fdw', 'multicorn'
)
ORDER BY risk_level DESC, e.extname;

-- Also list ALL extensions for completeness
\echo ''
\echo '── All Installed Extensions ──'
SELECT extname, extversion FROM pg_extension ORDER BY extname;

-- ---------------------------------------------------------------------------
-- 6. Foreign Data Wrappers & Foreign Servers
-- ---------------------------------------------------------------------------
\echo ''
\echo '── 6. Foreign Data Wrappers ──'

SELECT
    fdw.fdwname AS wrapper_name,
    pg_catalog.pg_get_userbyid(fdw.fdwowner) AS owner,
    srv.srvname AS server_name,
    srv.srvtype,
    srv.srvoptions,
    'REVIEW — FDW can access external resources' AS concern
FROM pg_foreign_data_wrapper fdw
LEFT JOIN pg_foreign_server srv ON srv.srvfdw = fdw.oid
ORDER BY fdw.fdwname;

-- Foreign server user mappings (may reveal connection patterns)
SELECT
    srv.srvname,
    um.umuser::regrole AS local_role,
    'User mapping exists — review for credential exposure' AS concern
FROM pg_user_mapping um
JOIN pg_foreign_server srv ON srv.oid = um.umserver
ORDER BY srv.srvname;

-- ---------------------------------------------------------------------------
-- 7. Event Triggers
-- ---------------------------------------------------------------------------
\echo ''
\echo '── 7. Event Triggers ──'

SELECT
    evtname,
    evtevent,
    evtowner::regrole AS owner,
    evtenabled,
    evtfoid::regproc AS function,
    CASE
        WHEN evtenabled = 'D' THEN 'INFO — disabled'
        WHEN evtevent IN ('ddl_command_start', 'ddl_command_end') THEN 'REVIEW — DDL event trigger'
        WHEN evtevent = 'sql_drop' THEN 'REVIEW — DROP event trigger'
        WHEN evtevent = 'table_rewrite' THEN 'REVIEW — table rewrite trigger'
        ELSE 'REVIEW'
    END AS concern
FROM pg_event_trigger
ORDER BY evtname;

-- ---------------------------------------------------------------------------
-- 8. Background Workers (pg_stat_activity suspicious entries)
-- ---------------------------------------------------------------------------
\echo ''
\echo '── 8. Background Workers / Suspicious Activity ──'

SELECT
    pid,
    usename,
    application_name,
    client_addr,
    backend_type,
    state,
    query_start,
    LEFT(query, 200) AS query_preview
FROM pg_stat_activity
WHERE backend_type NOT IN ('autovacuum launcher', 'autovacuum worker',
                            'background writer', 'checkpointer',
                            'walwriter', 'walsender', 'walreceiver',
                            'logical replication launcher', 'client backend')
  AND backend_type != 'background worker' -- show unusual ones
ORDER BY backend_type, pid;

-- Also check for unknown background workers
SELECT
    pid,
    usename,
    application_name,
    backend_type,
    state,
    LEFT(query, 200) AS query_preview,
    'REVIEW — background worker' AS concern
FROM pg_stat_activity
WHERE backend_type = 'background worker'
ORDER BY pid;

-- ---------------------------------------------------------------------------
-- 9. Shared Preload Libraries (suspicious patterns)
-- ---------------------------------------------------------------------------
\echo ''
\echo '── 9. Loaded Libraries Check ──'

SELECT
    name, setting,
    CASE
        WHEN setting LIKE '%passwordcheck%' THEN 'INFO — password check module'
        WHEN setting LIKE '%auth_delay%' THEN 'OK — brute force protection'
        WHEN setting LIKE '%pg_stat_statements%' THEN 'OK — query statistics'
        WHEN setting LIKE '%auto_explain%' THEN 'OK — query plan logging'
        WHEN setting LIKE '%pg_cron%' THEN 'REVIEW — job scheduler'
        ELSE 'REVIEW — verify: ' || setting
    END AS assessment
FROM pg_settings
WHERE name IN ('shared_preload_libraries', 'session_preload_libraries', 'local_preload_libraries')
  AND setting != '';

-- ---------------------------------------------------------------------------
-- SUMMARY
-- ---------------------------------------------------------------------------
\echo ''
\echo '── INSECURE DEFAULTS SUMMARY ──'

SELECT 'SECURITY DEFINER functions (user schemas)' AS check_item,
    COUNT(*)::text AS count
FROM pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE p.prosecdef AND n.nspname NOT IN ('pg_catalog','information_schema')
UNION ALL
SELECT 'Untrusted languages',
    COUNT(*)::text
FROM pg_language WHERE NOT lanpltrusted AND lanname NOT IN ('internal','c')
UNION ALL
SELECT 'Foreign data wrappers',
    COUNT(*)::text
FROM pg_foreign_data_wrapper
UNION ALL
SELECT 'Event triggers',
    COUNT(*)::text
FROM pg_event_trigger
UNION ALL
SELECT 'High-risk extensions',
    COUNT(*)::text
FROM pg_extension
WHERE extname IN ('dblink','postgres_fdw','file_fdw','adminpack','pg_cron',
    'plpythonu','plperlu','pltclu','pg_execute_server_program',
    'pg_read_server_files','pg_write_server_files');

\echo ''
\echo '═══════════════════════════════════════════════════════════════'
\echo '  INSECURE DEFAULTS & OBJECTS AUDIT COMPLETE'
\echo '═══════════════════════════════════════════════════════════════'

EOSQL
}

run_section "PostgreSQL Insecure Defaults & Objects" run_pg_sql | tee "$REPORT_FILE"

print_summary

log_info "Report saved to: ${REPORT_FILE}"
