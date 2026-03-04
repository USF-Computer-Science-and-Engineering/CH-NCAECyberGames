#!/usr/bin/env bash
# =============================================================================
# postgres/31_privilege_audit.sh — PostgreSQL Privilege & Grant Audit
# =============================================================================
# Examines object ownership, PUBLIC grants, database-level grants,
# schema-level grants, and function/table grants to identify over-privileged
# configurations.
# =============================================================================
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${SCRIPT_DIR}/../common/lib.sh"
NCAE_SCRIPT_NAME="31_privilege_audit.sh"
REPORT_FILE="${SCRIPT_DIR}/31_privilege_report.txt"

ensure_pg_defaults

run_pg_sql() {
    psql -X -A --no-psqlrc --pset pager=off <<'EOSQL'

\echo '═══════════════════════════════════════════════════════════════'
\echo '  POSTGRESQL PRIVILEGE & GRANT AUDIT'
\echo '═══════════════════════════════════════════════════════════════'

-- ---------------------------------------------------------------------------
-- 1. Database-Level Grants (CONNECT, CREATE, TEMP)
-- ---------------------------------------------------------------------------
\echo ''
\echo '── 1. Database-Level Grants ──'

SELECT
    d.datname AS database,
    r.rolname AS grantee,
    CASE WHEN has_database_privilege(r.oid, d.oid, 'CONNECT') THEN 'Y' ELSE 'N' END AS connect,
    CASE WHEN has_database_privilege(r.oid, d.oid, 'CREATE')  THEN 'Y' ELSE 'N' END AS "create",
    CASE WHEN has_database_privilege(r.oid, d.oid, 'TEMP')    THEN 'Y' ELSE 'N' END AS temp,
    CASE
        WHEN r.rolname = 'PUBLIC' AND has_database_privilege(r.oid, d.oid, 'CONNECT')
            THEN 'WARN — PUBLIC can connect'
        ELSE 'INFO'
    END AS concern
FROM pg_database d
CROSS JOIN (
    SELECT oid, rolname FROM pg_roles
    UNION ALL
    SELECT 0::oid, 'PUBLIC'
) r
WHERE NOT d.datistemplate
  AND (
    has_database_privilege(r.oid, d.oid, 'CONNECT')
    OR has_database_privilege(r.oid, d.oid, 'CREATE')
    OR has_database_privilege(r.oid, d.oid, 'TEMP')
  )
ORDER BY d.datname, r.rolname;

-- ---------------------------------------------------------------------------
-- 2. PUBLIC Grants on Schemas
-- ---------------------------------------------------------------------------
\echo ''
\echo '── 2. PUBLIC Grants on Schemas ──'

SELECT
    n.nspname AS schema_name,
    CASE WHEN has_schema_privilege('PUBLIC', n.oid, 'USAGE')  THEN 'Y' ELSE 'N' END AS public_usage,
    CASE WHEN has_schema_privilege('PUBLIC', n.oid, 'CREATE') THEN 'Y' ELSE 'N' END AS public_create,
    CASE
        WHEN has_schema_privilege('PUBLIC', n.oid, 'CREATE')
            THEN 'CRITICAL — PUBLIC has CREATE on schema ' || n.nspname
        WHEN has_schema_privilege('PUBLIC', n.oid, 'USAGE') AND n.nspname != 'public'
            THEN 'WARN — PUBLIC has USAGE on non-public schema'
        ELSE 'INFO'
    END AS concern
FROM pg_namespace n
WHERE n.nspname NOT LIKE 'pg_%'
  AND n.nspname != 'information_schema'
ORDER BY n.nspname;

-- ---------------------------------------------------------------------------
-- 3. PUBLIC Grants on Tables
-- ---------------------------------------------------------------------------
\echo ''
\echo '── 3. PUBLIC Grants on Tables (sample — first 50) ──'

SELECT
    n.nspname AS schema_name,
    c.relname AS table_name,
    CASE WHEN has_table_privilege('PUBLIC', c.oid, 'SELECT') THEN 'Y' ELSE 'N' END AS public_select,
    CASE WHEN has_table_privilege('PUBLIC', c.oid, 'INSERT') THEN 'Y' ELSE 'N' END AS public_insert,
    CASE WHEN has_table_privilege('PUBLIC', c.oid, 'UPDATE') THEN 'Y' ELSE 'N' END AS public_update,
    CASE WHEN has_table_privilege('PUBLIC', c.oid, 'DELETE') THEN 'Y' ELSE 'N' END AS public_delete,
    'WARN — PUBLIC has direct grants' AS concern
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind IN ('r', 'v', 'm')
  AND n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
  AND (
    has_table_privilege('PUBLIC', c.oid, 'SELECT')
    OR has_table_privilege('PUBLIC', c.oid, 'INSERT')
    OR has_table_privilege('PUBLIC', c.oid, 'UPDATE')
    OR has_table_privilege('PUBLIC', c.oid, 'DELETE')
  )
ORDER BY n.nspname, c.relname
LIMIT 50;

-- ---------------------------------------------------------------------------
-- 4. PUBLIC Grants on Functions
-- ---------------------------------------------------------------------------
\echo ''
\echo '── 4. PUBLIC Grants on Functions (EXECUTE) — sample ──'
\echo '   (By default PG grants EXECUTE on functions to PUBLIC)'

SELECT
    n.nspname AS schema_name,
    p.proname AS function_name,
    pg_catalog.pg_get_userbyid(p.proowner) AS owner,
    CASE
        WHEN p.prosecdef THEN 'SECURITY DEFINER — HIGH RISK with PUBLIC EXECUTE'
        ELSE 'SECURITY INVOKER'
    END AS security_type,
    'PUBLIC has EXECUTE' AS concern
FROM pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
  AND has_function_privilege('PUBLIC', p.oid, 'EXECUTE')
  AND p.prosecdef = true  -- Focus on SECURITY DEFINER functions
ORDER BY n.nspname, p.proname
LIMIT 50;

-- ---------------------------------------------------------------------------
-- 5. Objects Owned by Non-Admin / Unexpected Roles
-- ---------------------------------------------------------------------------
\echo ''
\echo '── 5. Objects Owned by Non-Superuser Roles ──'

SELECT
    n.nspname AS schema_name,
    c.relkind AS object_type,
    c.relname AS object_name,
    pg_catalog.pg_get_userbyid(c.relowner) AS owner,
    r.rolsuper AS owner_is_super,
    CASE
        WHEN NOT r.rolsuper AND c.relkind = 'r' THEN 'REVIEW — table owned by non-superuser'
        WHEN NOT r.rolsuper AND c.relkind = 'v' THEN 'REVIEW — view owned by non-superuser'
        WHEN NOT r.rolsuper AND c.relkind = 'f' THEN 'WARN — foreign table owned by non-superuser'
        ELSE 'INFO'
    END AS concern
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
JOIN pg_roles r ON r.oid = c.relowner
WHERE n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
  AND c.relkind IN ('r', 'v', 'm', 'f', 'S')
  AND NOT r.rolsuper
ORDER BY n.nspname, c.relname
LIMIT 100;

-- ---------------------------------------------------------------------------
-- 6. Column-Level Privileges (non-default)
-- ---------------------------------------------------------------------------
\echo ''
\echo '── 6. Column-Level Privileges ──'

SELECT
    table_schema,
    table_name,
    column_name,
    grantee,
    privilege_type,
    is_grantable,
    CASE
        WHEN grantee = 'PUBLIC' THEN 'WARN — PUBLIC column grant'
        WHEN is_grantable = 'YES' THEN 'WARN — WITH GRANT OPTION on column'
        ELSE 'INFO'
    END AS concern
FROM information_schema.column_privileges
WHERE table_schema NOT IN ('pg_catalog', 'information_schema')
  AND grantor != grantee
ORDER BY table_schema, table_name, column_name
LIMIT 50;

-- ---------------------------------------------------------------------------
-- 7. Default Privileges That May Over-Grant
-- ---------------------------------------------------------------------------
\echo ''
\echo '── 7. Default Privileges (ALTER DEFAULT PRIVILEGES) ──'

SELECT
    pg_catalog.pg_get_userbyid(d.defaclrole) AS role,
    d.defaclnamespace::regnamespace AS schema,
    CASE d.defaclobjtype
        WHEN 'r' THEN 'TABLE'
        WHEN 'S' THEN 'SEQUENCE'
        WHEN 'f' THEN 'FUNCTION'
        WHEN 'T' THEN 'TYPE'
        WHEN 'n' THEN 'SCHEMA'
        ELSE d.defaclobjtype::text
    END AS object_type,
    pg_catalog.array_to_string(d.defaclacl, E'\n') AS default_acl
FROM pg_default_acl d
ORDER BY role, schema;

-- ---------------------------------------------------------------------------
-- 8. Large Object Grants
-- ---------------------------------------------------------------------------
\echo ''
\echo '── 8. Large Object Privileges ──'

SELECT
    l.oid AS lo_oid,
    pg_catalog.pg_get_userbyid(l.lomowner) AS owner,
    CASE
        WHEN has_table_privilege('PUBLIC', 'pg_largeobject', 'SELECT') THEN 'WARN — PUBLIC read'
        ELSE 'OK'
    END AS public_access
FROM pg_largeobject_metadata l
ORDER BY l.oid
LIMIT 20;

-- ---------------------------------------------------------------------------
-- PRIVILEGE RISK SUMMARY
-- ---------------------------------------------------------------------------
\echo ''
\echo '── PRIVILEGE RISK SUMMARY ──'

SELECT 'PUBLIC CONNECT to non-template DBs' AS check_item,
    COUNT(*)::text AS count
FROM pg_database d
WHERE NOT d.datistemplate
  AND has_database_privilege(0::oid, d.oid, 'CONNECT')
UNION ALL
SELECT 'Schemas with PUBLIC CREATE',
    COUNT(*)::text
FROM pg_namespace n
WHERE n.nspname NOT LIKE 'pg_%'
  AND n.nspname != 'information_schema'
  AND has_schema_privilege('PUBLIC', n.oid, 'CREATE')
UNION ALL
SELECT 'SECURITY DEFINER functions with PUBLIC EXECUTE',
    COUNT(*)::text
FROM pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
  AND p.prosecdef = true
  AND has_function_privilege('PUBLIC', p.oid, 'EXECUTE')
UNION ALL
SELECT 'Tables/views with PUBLIC grants (non-system)',
    COUNT(*)::text
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind IN ('r','v','m')
  AND n.nspname NOT IN ('pg_catalog','information_schema','pg_toast')
  AND (
    has_table_privilege('PUBLIC', c.oid, 'SELECT')
    OR has_table_privilege('PUBLIC', c.oid, 'INSERT')
    OR has_table_privilege('PUBLIC', c.oid, 'UPDATE')
    OR has_table_privilege('PUBLIC', c.oid, 'DELETE')
  );

\echo ''
\echo '═══════════════════════════════════════════════════════════════'
\echo '  PRIVILEGE AUDIT COMPLETE'
\echo '═══════════════════════════════════════════════════════════════'

EOSQL
}

run_section "PostgreSQL Privilege Audit" run_pg_sql | tee "$REPORT_FILE"

print_summary

log_info "Report saved to: ${REPORT_FILE}"
