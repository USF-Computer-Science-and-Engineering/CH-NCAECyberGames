#!/usr/bin/env bash
# =============================================================================
# postgres/30_user_audit.sh — PostgreSQL User / Role Audit
# =============================================================================
# Lists all roles, their attributes, memberships, and flags security
# concerns such as superusers, roles without passwords, and expired passwords.
# =============================================================================
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${SCRIPT_DIR}/../common/lib.sh"
NCAE_SCRIPT_NAME="30_user_audit.sh"
REPORT_FILE="${SCRIPT_DIR}/30_user_report.txt"

ensure_pg_defaults

run_pg_sql() {
    psql -X -A --no-psqlrc --pset pager=off <<'EOSQL'

\echo '═══════════════════════════════════════════════════════════════'
\echo '  POSTGRESQL USER / ROLE AUDIT'
\echo '═══════════════════════════════════════════════════════════════'

-- ---------------------------------------------------------------------------
-- 1. All Roles with Attributes
-- ---------------------------------------------------------------------------
\echo ''
\echo '── 1. All Roles and Attributes ──'

SELECT
    r.rolname,
    r.rolsuper,
    r.rolinherit,
    r.rolcreaterole,
    r.rolcreatedb,
    r.rolcanlogin,
    r.rolreplication,
    r.rolbypassrls,
    r.rolconnlimit,
    r.rolvaliduntil,
    CASE
        WHEN r.rolsuper THEN 'CRITICAL — superuser'
        WHEN r.rolcreaterole AND r.rolcreatedb THEN 'HIGH — can create roles and databases'
        WHEN r.rolcreaterole THEN 'HIGH — can create roles'
        WHEN r.rolcreatedb THEN 'MEDIUM — can create databases'
        WHEN r.rolreplication THEN 'HIGH — replication privilege'
        WHEN r.rolbypassrls THEN 'HIGH — bypasses row-level security'
        WHEN r.rolcanlogin THEN 'INFO — login role'
        ELSE 'INFO — nologin role'
    END AS risk_level
FROM pg_roles r
ORDER BY
    r.rolsuper DESC,
    r.rolcreaterole DESC,
    r.rolreplication DESC,
    r.rolbypassrls DESC,
    r.rolname;

-- ---------------------------------------------------------------------------
-- 2. Superusers
-- ---------------------------------------------------------------------------
\echo ''
\echo '── 2. Superuser Roles ──'

SELECT rolname, rolcanlogin, rolvaliduntil
FROM pg_roles
WHERE rolsuper = true
ORDER BY rolname;

-- Count
SELECT 'Superuser count: ' || COUNT(*) AS summary
FROM pg_roles WHERE rolsuper = true;

-- ---------------------------------------------------------------------------
-- 3. Roles with Elevated Privileges
-- ---------------------------------------------------------------------------
\echo ''
\echo '── 3. Roles with CREATEROLE / CREATEDB / REPLICATION / BYPASSRLS ──'

SELECT
    rolname,
    CASE WHEN rolcreaterole THEN 'Y' ELSE 'N' END AS createrole,
    CASE WHEN rolcreatedb THEN 'Y' ELSE 'N' END AS createdb,
    CASE WHEN rolreplication THEN 'Y' ELSE 'N' END AS replication,
    CASE WHEN rolbypassrls THEN 'Y' ELSE 'N' END AS bypassrls
FROM pg_roles
WHERE rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls
ORDER BY rolname;

-- ---------------------------------------------------------------------------
-- 4. Roles Without Passwords (cannot auth with password)
-- ---------------------------------------------------------------------------
\echo ''
\echo '── 4. Login Roles Without Password Set ──'
\echo '   (rolpassword is NULL means no password auth possible)'

SELECT
    r.rolname,
    r.rolcanlogin,
    r.rolvaliduntil,
    'WARNING — no password set for login role' AS concern
FROM pg_authid r
WHERE r.rolcanlogin = true
  AND r.rolpassword IS NULL
ORDER BY r.rolname;

-- ---------------------------------------------------------------------------
-- 5. Roles with Expired Passwords
-- ---------------------------------------------------------------------------
\echo ''
\echo '── 5. Roles with Expired Passwords ──'

SELECT
    rolname,
    rolvaliduntil,
    CASE
        WHEN rolvaliduntil < NOW() THEN 'EXPIRED'
        WHEN rolvaliduntil < NOW() + INTERVAL '30 days' THEN 'EXPIRES SOON'
        ELSE 'OK'
    END AS status
FROM pg_roles
WHERE rolvaliduntil IS NOT NULL
  AND rolcanlogin = true
ORDER BY rolvaliduntil;

-- ---------------------------------------------------------------------------
-- 6. Role Memberships (who inherits from whom)
-- ---------------------------------------------------------------------------
\echo ''
\echo '── 6. Role Memberships ──'

SELECT
    r.rolname AS member_role,
    m.rolname AS member_of,
    a.admin_option,
    CASE
        WHEN a.admin_option THEN 'WARNING — can grant this role to others'
        ELSE 'INFO'
    END AS concern
FROM pg_auth_members a
JOIN pg_roles r ON r.oid = a.member
JOIN pg_roles m ON m.oid = a.roleid
ORDER BY m.rolname, r.rolname;

-- ---------------------------------------------------------------------------
-- 7. Password Encryption Methods in Use
-- ---------------------------------------------------------------------------
\echo ''
\echo '── 7. Password Encryption Methods ──'

SELECT
    rolname,
    CASE
        WHEN rolpassword LIKE 'SCRAM-SHA-256$%' THEN 'scram-sha-256'
        WHEN rolpassword LIKE 'md5%' THEN 'md5 (WEAK)'
        WHEN rolpassword IS NULL THEN 'no password'
        ELSE 'unknown format'
    END AS password_type
FROM pg_authid
WHERE rolcanlogin = true
ORDER BY
    CASE
        WHEN rolpassword LIKE 'md5%' THEN 0
        WHEN rolpassword IS NULL THEN 1
        ELSE 2
    END,
    rolname;

-- ---------------------------------------------------------------------------
-- 8. Connection Limits
-- ---------------------------------------------------------------------------
\echo ''
\echo '── 8. Connection Limits per Role ──'

SELECT rolname, rolconnlimit,
    CASE
        WHEN rolconnlimit = -1 THEN 'UNLIMITED'
        ELSE rolconnlimit::text
    END AS effective_limit
FROM pg_roles
WHERE rolcanlogin = true
ORDER BY rolconnlimit DESC, rolname;

-- ---------------------------------------------------------------------------
-- RISK SUMMARY
-- ---------------------------------------------------------------------------
\echo ''
\echo '── RISK SUMMARY ──'

SELECT
    'Total login roles' AS metric,
    COUNT(*)::text AS value
FROM pg_roles WHERE rolcanlogin = true
UNION ALL
SELECT
    'Superusers',
    COUNT(*)::text
FROM pg_roles WHERE rolsuper = true
UNION ALL
SELECT
    'Roles with CREATEROLE',
    COUNT(*)::text
FROM pg_roles WHERE rolcreaterole = true AND NOT rolsuper
UNION ALL
SELECT
    'Roles with REPLICATION',
    COUNT(*)::text
FROM pg_roles WHERE rolreplication = true AND NOT rolsuper
UNION ALL
SELECT
    'Roles with BYPASSRLS',
    COUNT(*)::text
FROM pg_roles WHERE rolbypassrls = true AND NOT rolsuper
UNION ALL
SELECT
    'Login roles without password',
    COUNT(*)::text
FROM pg_authid WHERE rolcanlogin = true AND rolpassword IS NULL
UNION ALL
SELECT
    'Roles with md5 passwords',
    COUNT(*)::text
FROM pg_authid WHERE rolcanlogin = true AND rolpassword LIKE 'md5%'
UNION ALL
SELECT
    'Expired passwords',
    COUNT(*)::text
FROM pg_roles WHERE rolcanlogin AND rolvaliduntil IS NOT NULL AND rolvaliduntil < NOW();

\echo ''
\echo '═══════════════════════════════════════════════════════════════'
\echo '  USER AUDIT COMPLETE'
\echo '═══════════════════════════════════════════════════════════════'

EOSQL
}

run_section "PostgreSQL User Audit" run_pg_sql | tee "$REPORT_FILE"

print_summary

log_info "Report saved to: ${REPORT_FILE}"
