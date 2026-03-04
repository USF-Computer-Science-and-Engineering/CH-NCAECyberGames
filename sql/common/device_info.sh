#!/usr/bin/env bash
# =============================================================================
# ncae/common/device_info.sh
# Collect Linux device info, database inventory, and DB-specific CVE checks.
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"

NCAE_SCRIPT_NAME="device_info.sh"
OUTPUT_FILE="${SCRIPT_DIR}/output-db-info.txt"

# ── Help ─────────────────────────────────────────────────────────────────────
usage() {
    show_help_header "$NCAE_SCRIPT_NAME" "Linux device info, DB inventory & CVE check"
    cat <<EOF
USAGE:
    $NCAE_SCRIPT_NAME [OPTIONS]

OPTIONS:
    -h, --help              Show this help message
    -o, --output FILE       Write output to FILE (in addition to stdout)
    --skip-cve              Skip CVE lookup

ENVIRONMENT:
    PGHOST, PGPORT, PGUSER, PGDATABASE, PGPASSWORD — Postgres connection
    MYSQL_HOST, MYSQL_PORT, MYSQL_USER, MYSQL_PWD   — MySQL connection

EXAMPLES:
    $NCAE_SCRIPT_NAME
    $NCAE_SCRIPT_NAME --output /tmp/inventory.txt
    $NCAE_SCRIPT_NAME --skip-cve
EOF
    exit 0
}

SKIP_CVE=false

while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help)      usage ;;
        -o|--output)    OUTPUT_FILE="${2:?--output requires a path}"; shift ;;
        --skip-cve)     SKIP_CVE=true ;;
        *)              log_error "Unknown option: $1"; usage ;;
    esac
    shift
done

# If output file requested, tee everything
if [ -n "$OUTPUT_FILE" ]; then
    exec > >(tee -a "$OUTPUT_FILE") 2>&1
fi

# =============================================================================
# SECTION 1: Device Information
# =============================================================================
log_section "DEVICE INFORMATION"

HOSTNAME_INFO="$(hostname -f 2>/dev/null || hostname)"
OS_INFO="$(get_os_info)"
KERNEL_INFO="$(get_kernel_version)"
UPTIME_INFO="$(uptime -p 2>/dev/null || uptime | sed 's/.*up/up/' )"
ARCH_INFO="$(uname -m 2>/dev/null || echo unknown)"

log_info "Hostname  : $HOSTNAME_INFO"
log_info "OS        : $OS_INFO"
log_info "Kernel    : $KERNEL_INFO"
log_info "Arch      : $ARCH_INFO"
log_info "Uptime    : $UPTIME_INFO"
json_line "device_info" "ok" "hostname" "$HOSTNAME_INFO" "os" "$OS_INFO" \
    "kernel" "$KERNEL_INFO" "arch" "$ARCH_INFO"

# ── CPU / RAM / Disk ────────────────────────────────────────────────────────
log_section "HARDWARE SUMMARY"

CPU_INFO="unknown"
if [ -f /proc/cpuinfo ]; then
    CPU_COUNT="$(grep -c ^processor /proc/cpuinfo 2>/dev/null || echo '?')"
    CPU_MODEL="$(grep 'model name' /proc/cpuinfo 2>/dev/null | head -1 | cut -d: -f2 | sed 's/^ //' || echo 'unknown')"
    CPU_INFO="${CPU_COUNT} x ${CPU_MODEL}"
fi
log_info "CPU       : $CPU_INFO"

RAM_INFO="unknown"
if [ -f /proc/meminfo ]; then
    TOTAL_KB="$(grep MemTotal /proc/meminfo | awk '{print $2}')"
    TOTAL_MB=$(( TOTAL_KB / 1024 ))
    FREE_KB="$(grep MemAvailable /proc/meminfo | awk '{print $2}')"
    FREE_MB=$(( ${FREE_KB:-0} / 1024 ))
    RAM_INFO="${TOTAL_MB} MB total, ${FREE_MB} MB available"
fi
log_info "RAM       : $RAM_INFO"

log_info "Disk usage:"
df -hT 2>/dev/null | head -20 || df -h 2>/dev/null | head -20 || log_warn "df not available"

log_info "Mounted filesystems:"
mount 2>/dev/null | grep -E '^/' | head -20 || log_warn "mount info unavailable"

json_line "hardware" "ok" "cpu" "$CPU_INFO" "ram_mb" "${TOTAL_MB:-0}"

# ── Network ──────────────────────────────────────────────────────────────────
log_section "NETWORK INTERFACES & DB PORTS"

log_info "Network interfaces:"
if check_cmd ip; then
    ip -br addr show 2>/dev/null || ip addr show 2>/dev/null | grep -E 'inet |^[0-9]' || true
elif check_cmd ifconfig; then
    ifconfig -a 2>/dev/null | grep -E 'inet |^[a-z]' || true
else
    log_warn "No ip or ifconfig available"
fi

log_info "Listening DB-related ports:"
find_db_ports

# ── Systemd service states ──────────────────────────────────────────────────
log_section "DATABASE SERVICE STATUS"

check_service() {
    local svc="$1"
    if check_cmd systemctl; then
        local state
        state="$(systemctl is-active "$svc" 2>/dev/null || echo 'not-found')"
        local enabled
        enabled="$(systemctl is-enabled "$svc" 2>/dev/null || echo 'not-found')"
        log_info "Service $svc: active=$state enabled=$enabled"
        json_line "service" "$state" "name" "$svc" "enabled" "$enabled"
    else
        # Fallback: check /etc/init.d or process
        if [ -x "/etc/init.d/$svc" ]; then
            log_info "Service $svc: init script exists"
        else
            log_info "Service $svc: not found (no systemctl, no init script)"
        fi
    fi
}

for svc in postgresql postgresql@* postgres mysql mysqld mariadb; do
    check_service "$svc" 2>/dev/null || true
done

# ── Running DB processes ─────────────────────────────────────────────────────
log_section "RUNNING DATABASE PROCESSES"
DB_PROCS="$(find_db_processes)"
if [ -n "$DB_PROCS" ]; then
    echo "$DB_PROCS"
else
    log_info "No database processes detected."
fi

# =============================================================================
# SECTION 2: PostgreSQL Inventory
# =============================================================================
log_section "POSTGRESQL INVENTORY"

PG_CLIENT_VER="none"
PG_SERVER_VER="none"
PG_BIN_PATH="none"

if check_cmd psql; then
    PG_CLIENT_VER="$(psql --version 2>/dev/null | head -1 || echo 'unknown')"
    PG_BIN_PATH="$(command -v psql)"
    log_info "psql client : $PG_CLIENT_VER"
    log_info "psql path   : $PG_BIN_PATH"

    # Try connecting to get server version
    if PG_SRV="$(pg_run_query "SELECT version();" 2>/dev/null)"; then
        PG_SERVER_VER="$PG_SRV"
        log_info "Server ver  : $PG_SERVER_VER"

        # Get server_version_num for CVE matching
        PG_VER_NUM="$(pg_run_query "SHOW server_version_num;" 2>/dev/null || echo '')"
        PG_VER_SHORT="$(pg_run_query "SHOW server_version;" 2>/dev/null || echo '')"
        log_info "Version num : ${PG_VER_NUM:-unknown}"

        # List databases
        log_info "Databases:"
        pg_run_query_full "SELECT datname, pg_catalog.pg_get_userbyid(datdba) AS owner, pg_encoding_to_char(encoding) AS encoding, datcollate FROM pg_database WHERE NOT datistemplate ORDER BY datname;" 2>/dev/null || log_warn "Could not list databases"
    else
        log_warn "Cannot connect to PostgreSQL server (connection env vars may be needed)"
        # Fall back to client version for CVE matching
        PG_VER_SHORT="$(echo "$PG_CLIENT_VER" | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1 || echo '')"
        if [ -n "$PG_VER_SHORT" ]; then
            # Build version_num from client version (e.g. 17.8 → 170008, 15.5 → 150005)
            IFS='.' read -r _pg_maj _pg_min _pg_patch <<< "$PG_VER_SHORT"
            _pg_patch="${_pg_patch:-0}"
            PG_VER_NUM=$(( _pg_maj * 10000 + _pg_min * 100 + _pg_patch ))
            # Normalise PG_VER_SHORT to major.minor
            PG_VER_SHORT="${_pg_maj}.${_pg_min}"
            log_info "Using client version for CVE check: ${PG_VER_SHORT} (version_num=${PG_VER_NUM})"
        fi
    fi
else
    log_info "psql client not found on this system."
fi

json_line "postgres_inventory" "ok" "client_ver" "$PG_CLIENT_VER" "server_ver" "$PG_SERVER_VER" "bin_path" "$PG_BIN_PATH"

# =============================================================================
# SECTION 3: MySQL / MariaDB Inventory
# =============================================================================
log_section "MYSQL / MARIADB INVENTORY"

MY_CLIENT_VER="none"
MY_SERVER_VER="none"
MY_BIN_PATH="none"

if check_cmd mysql; then
    MY_CLIENT_VER="$(mysql --version 2>/dev/null | head -1 || echo 'unknown')"
    MY_BIN_PATH="$(command -v mysql)"
    log_info "mysql client : $MY_CLIENT_VER"
    log_info "mysql path   : $MY_BIN_PATH"

    # Try connecting to get server version
    if MY_SRV="$(my_run_query "SELECT version();" 2>/dev/null)"; then
        MY_SERVER_VER="$MY_SRV"
        log_info "Server ver   : $MY_SERVER_VER"

        # List databases
        log_info "Databases:"
        my_run_query_full "SELECT table_schema AS 'Database', ROUND(SUM(data_length+index_length)/1024/1024,2) AS 'Size_MB' FROM information_schema.tables GROUP BY table_schema ORDER BY table_schema;" 2>/dev/null || log_warn "Could not list databases"
    else
        log_warn "Cannot connect to MySQL/MariaDB server (connection env vars may be needed)"
    fi
else
    log_info "mysql client not found on this system."
fi

json_line "mysql_inventory" "ok" "client_ver" "$MY_CLIENT_VER" "server_ver" "$MY_SERVER_VER" "bin_path" "$MY_BIN_PATH"

# =============================================================================
# SECTION 4: PostgreSQL CVE Check (Offline / Hardcoded)
# =============================================================================
log_section "POSTGRESQL CVE CHECK"

if [ "$SKIP_CVE" = true ]; then
    log_info "CVE check skipped (--skip-cve)."
    json_line "cve_check" "skipped" "reason" "user_requested_skip"
elif [ -n "${PG_VER_NUM:-}" ]; then

    # ── Hardcoded CVE database ───────────────────────────────────────────
    # Version comparison uses server_version_num (e.g. 150005 = 15.5).
    # For each CVE we list major:fix_vernum pairs.  If the running version
    # is below the fix for its major, or older than the lowest listed major,
    # it is flagged as vulnerable.
    # ─────────────────────────────────────────────────────────────────────

    PG_MAJOR=$(( PG_VER_NUM / 10000 ))
    VER_NUM="$PG_VER_NUM"

    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║  Offline CVE check against known PostgreSQL advisories.    ║"
    echo "║  Verify results against official PostgreSQL advisories at  ║"
    echo "║  https://www.postgresql.org/support/security/              ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""

    log_info "Checking PostgreSQL ${PG_VER_SHORT:-unknown} (version_num=${VER_NUM}, major=${PG_MAJOR}) ..."

    CVE_HIT_COUNT=0

    # check_cve CVE_ID SEVERITY "DESCRIPTION" major1:fix1 major2:fix2 ...
    check_cve() {
        local cve_id="$1" severity="$2" description="$3"
        shift 3
        local vulnerable=false fix_found=false
        local lowest_major=999

        for pair in "$@"; do
            local maj="${pair%%:*}"
            local fix="${pair##*:}"
            [ "$maj" -lt "$lowest_major" ] && lowest_major="$maj"
            if [ "$PG_MAJOR" -eq "$maj" ]; then
                fix_found=true
                if [ "$VER_NUM" -lt "$fix" ]; then
                    vulnerable=true
                fi
            fi
        done

        # Major older than lowest listed → EOL / never patched
        if [ "$fix_found" = false ] && [ "$PG_MAJOR" -lt "$lowest_major" ]; then
            vulnerable=true
        fi

        if [ "$vulnerable" = true ]; then
            log_warn "  VULNERABLE  ${cve_id}  [${severity}]  ${description}"
            CVE_HIT_COUNT=$(( CVE_HIT_COUNT + 1 ))
        fi
    }

    # ── 2025 ─────────────────────────────────────────────────────────────
    check_cve "CVE-2025-1094" "HIGH" \
        "SQL injection via libpq PQescapeLiteral/PQescapeIdentifier" \
        13:130019 14:140016 15:150011 16:160007 17:170003

    # ── 2024 ─────────────────────────────────────────────────────────────
    check_cve "CVE-2024-10979" "HIGH" \
        "PL/Perl environment variable manipulation" \
        12:120021 13:130017 14:140014 15:150009 16:160005 17:170001

    check_cve "CVE-2024-10976" "HIGH" \
        "Row security policies disregarded in subqueries" \
        12:120021 13:130017 14:140014 15:150009 16:160005 17:170001

    check_cve "CVE-2024-10977" "MEDIUM" \
        "libpq SSL negotiation vulnerability" \
        12:120021 13:130017 14:140014 15:150009 16:160005 17:170001

    check_cve "CVE-2024-7348" "HIGH" \
        "pg_dump executes arbitrary SQL via crafted object names" \
        12:120020 13:130016 14:140013 15:150008 16:160004

    check_cve "CVE-2024-4317" "MEDIUM" \
        "Unauthorized access to pg_stats_ext and pg_stats_ext_exprs" \
        14:140012 15:150007 16:160003

    check_cve "CVE-2024-0985" "HIGH" \
        "REFRESH MATERIALIZED VIEW CONCURRENTLY allows arbitrary SQL" \
        12:120018 13:130014 14:140011 15:150006 16:160002

    # ── 2023 ─────────────────────────────────────────────────────────────
    check_cve "CVE-2023-5869" "HIGH" \
        "Buffer overrun from integer overflow in array modification" \
        12:120017 13:130013 14:140010 15:150005 16:160001

    check_cve "CVE-2023-5868" "MEDIUM" \
        "Memory disclosure in aggregate function calls" \
        12:120017 13:130013 14:140010 15:150005 16:160001

    check_cve "CVE-2023-5870" "MEDIUM" \
        "pg_cancel_backend can signal certain superuser processes" \
        12:120017 13:130013 14:140010 15:150005 16:160001

    check_cve "CVE-2023-39417" "HIGH" \
        "SQL injection in extension script @extowner@/@extschema@ substitutions" \
        12:120016 13:130012 14:140009 15:150004

    check_cve "CVE-2023-2454" "HIGH" \
        "Schema permission bypass via CREATE/ALTER SCHEMA" \
        12:120015 13:130011 14:140008 15:150003

    check_cve "CVE-2023-2455" "MEDIUM" \
        "Row security policies ignored via security definer functions" \
        12:120015 13:130011 14:140008 15:150003

    # ── 2022 ─────────────────────────────────────────────────────────────
    check_cve "CVE-2022-2625" "HIGH" \
        "Extension scripts can replace objects not belonging to the extension" \
        12:120012 13:130008 14:140005

    check_cve "CVE-2022-1552" "HIGH" \
        "Autovacuum/REINDEX/CREATE INDEX bypass search_path changes" \
        12:120011 13:130007 14:140003

    # ── 2021 ─────────────────────────────────────────────────────────────
    check_cve "CVE-2021-23214" "HIGH" \
        "Man-in-the-middle attack during SCRAM authentication" \
        12:120009 13:130005 14:140001

    check_cve "CVE-2021-23222" "MEDIUM" \
        "libpq processes unencrypted bytes from man-in-the-middle" \
        12:120009 13:130005 14:140001

    check_cve "CVE-2021-32027" "HIGH" \
        "Buffer overrun from integer overflow in array subscripting" \
        12:120007 13:130003

    echo ""
    if [ "$CVE_HIT_COUNT" -gt 0 ]; then
        log_warn "Known CVEs affecting this version: ${CVE_HIT_COUNT}"
    else
        log_ok "No known CVEs found for PostgreSQL ${PG_VER_SHORT:-${VER_NUM}}."
    fi
    json_line "cve_postgres" "done" "version" "${PG_VER_SHORT:-unknown}" "cve_count" "$CVE_HIT_COUNT"
else
    log_info "PostgreSQL version not detected; skipping CVE check."
fi

# =============================================================================
# SUMMARY
# =============================================================================
log_section "INVENTORY COMPLETE"
log_ok "Device info collected."

if [ "$PG_CLIENT_VER" != "none" ] || [ "$PG_SERVER_VER" != "none" ]; then
    log_ok "Postgres: client=${PG_CLIENT_VER} server=${PG_SERVER_VER}"
    json_line "inventory_pg" "complete" "pg_client" "$PG_CLIENT_VER" "pg_server" "$PG_SERVER_VER"
fi

if [ "$MY_CLIENT_VER" != "none" ] || [ "$MY_SERVER_VER" != "none" ]; then
    log_ok "MySQL:    client=${MY_CLIENT_VER} server=${MY_SERVER_VER}"
    json_line "inventory_my" "complete" "my_client" "$MY_CLIENT_VER" "my_server" "$MY_SERVER_VER"
fi

log_info "Done. Timestamp: ${NCAE_TIMESTAMP}"
exit 0
