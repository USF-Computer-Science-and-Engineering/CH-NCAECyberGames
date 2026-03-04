#!/usr/bin/env bash
# =============================================================================
# ncae/common/lib.sh — Shared library for NCAE database security audit toolkit
# =============================================================================
# Sourced by other scripts; provides logging, JSON output, dependency checks,
# and common helper functions.
# =============================================================================
set -uo pipefail

# ── Colour & formatting (disabled when stdout is not a tty) ──────────────────
if [ -t 1 ]; then
    _RED='\033[0;31m'; _GREEN='\033[0;32m'; _YELLOW='\033[1;33m'
    _CYAN='\033[0;36m'; _BOLD='\033[1m'; _RESET='\033[0m'
else
    _RED=''; _GREEN=''; _YELLOW=''; _CYAN=''; _BOLD=''; _RESET=''
fi

# ── Globals ──────────────────────────────────────────────────────────────────
NCAE_VERSION="1.0.0"
NCAE_TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date +%Y-%m-%dT%H:%M:%SZ)"
NCAE_HOSTNAME="$(hostname -f 2>/dev/null || hostname)"
NCAE_SCRIPT_NAME="${NCAE_SCRIPT_NAME:-$(basename "$0")}"

# ── Logging helpers ──────────────────────────────────────────────────────────
log_info()  { printf "${_CYAN}[INFO]${_RESET}  %s\n" "$*"; }
log_ok()    { printf "${_GREEN}[OK]${_RESET}    %s\n" "$*"; }
log_warn()  { printf "${_YELLOW}[WARN]${_RESET}  %s\n" "$*" >&2; }
log_error() { printf "${_RED}[ERROR]${_RESET} %s\n" "$*" >&2; }
log_fatal() { printf "${_RED}[FATAL]${_RESET} %s\n" "$*" >&2; exit 1; }
log_section() {
    printf "\n${_BOLD}═══════════════════════════════════════════════════════════════${_RESET}\n"
    printf "${_BOLD}  %s${_RESET}\n" "$*"
    printf "${_BOLD}═══════════════════════════════════════════════════════════════${_RESET}\n"
}

# ── JSON helpers ─────────────────────────────────────────────────────────────
# Emit a single JSON line (JSONL). Arguments: section, status, key=value pairs.
# Usage: json_line "section_name" "status" "key1" "val1" "key2" "val2" ...
json_line() {
    local section="${1:?section required}" status="${2:?status required}"
    shift 2
    local pairs=""
    while [ $# -ge 2 ]; do
        # Escape double quotes in values
        local k="$1" v="$2"
        v="$(printf '%s' "$v" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\t/\\t/g')"
        [ -n "$pairs" ] && pairs="${pairs}, "
        pairs="${pairs}\"${k}\": \"${v}\""
        shift 2
    done
    printf '{"timestamp":"%s","host":"%s","script":"%s","section":"%s","status":"%s"%s}\n' \
        "$NCAE_TIMESTAMP" "$NCAE_HOSTNAME" "$NCAE_SCRIPT_NAME" "$section" "$status" \
        "$([ -n "$pairs" ] && echo ", ${pairs}" || echo "")"
}

# Emit a JSON line with an array field (for lists of items).
# Usage: json_line_array "section" "status" "items_key" item1 item2 ...
json_line_array() {
    local section="${1:?}" status="${2:?}" key="${3:?}"
    shift 3
    local items=""
    for item in "$@"; do
        item="$(printf '%s' "$item" | sed 's/\\/\\\\/g; s/"/\\"/g')"
        [ -n "$items" ] && items="${items}, "
        items="${items}\"${item}\""
    done
    printf '{"timestamp":"%s","host":"%s","script":"%s","section":"%s","status":"%s","%s":[%s]}\n' \
        "$NCAE_TIMESTAMP" "$NCAE_HOSTNAME" "$NCAE_SCRIPT_NAME" "$section" "$status" "$key" "$items"
}

# ── Dependency checking ──────────────────────────────────────────────────────
# require_cmd "cmd" — fatal if missing
require_cmd() {
    command -v "$1" >/dev/null 2>&1 || log_fatal "Required command not found: $1"
}

# check_cmd "cmd" — returns 0/1, no abort
check_cmd() {
    command -v "$1" >/dev/null 2>&1
}

# require_one_of cmd1 cmd2 cmd3 — fatal if none found; prints which was found
require_one_of() {
    for cmd in "$@"; do
        if command -v "$cmd" >/dev/null 2>&1; then
            echo "$cmd"
            return 0
        fi
    done
    log_fatal "None of these commands found: $*"
}

# ── File safety ──────────────────────────────────────────────────────────────
# safe_mkdir — create directory, fail if cannot
safe_mkdir() {
    local dir="$1"
    if [ -e "$dir" ] && [ ! -d "$dir" ]; then
        log_fatal "Path exists but is not a directory: $dir"
    fi
    mkdir -p "$dir" || log_fatal "Cannot create directory: $dir"
}

# Generate a timestamped, non-colliding backup directory name
timestamped_dir() {
    local base="${1:?base path required}" prefix="${2:-backup}"
    local ts
    ts="$(date +%Y%m%d_%H%M%S)"
    local dir="${base}/${prefix}_${ts}_$$"
    if [ -d "$dir" ]; then
        dir="${dir}_$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
    fi
    echo "$dir"
}

# ── Postgres helpers ─────────────────────────────────────────────────────────
# Run a psql command in non-interactive, tuples-only mode.
# Respects PGHOST, PGPORT, PGUSER, PGDATABASE, PGPASSWORD env vars.
pg_run_query() {
    local query="${1:?query required}"
    psql -X -A -t --no-psqlrc --pset pager=off -c "$query" 2>&1
}

# Run a psql query and return full tabular output with headers.
pg_run_query_full() {
    local query="${1:?query required}"
    psql -X -A --no-psqlrc --pset pager=off -c "$query" 2>&1
}

# Run a SQL file through psql
pg_run_file() {
    local file="${1:?SQL file required}"
    psql -X -A --no-psqlrc --pset pager=off -f "$file" 2>&1
}

# ── MySQL helpers ────────────────────────────────────────────────────────────
my_run_query() {
    local query="${1:?query required}"
    local args=(--batch --skip-pager --skip-column-names)
    [ -n "${MYSQL_HOST:-}" ] && args+=("-h" "$MYSQL_HOST")
    [ -n "${MYSQL_PORT:-}" ] && args+=("-P" "$MYSQL_PORT")
    [ -n "${MYSQL_USER:-}" ] && args+=("-u" "$MYSQL_USER")
    mysql "${args[@]}" -e "$query" 2>&1
}

my_run_query_full() {
    local query="${1:?query required}"
    local args=(--batch --skip-pager)
    [ -n "${MYSQL_HOST:-}" ] && args+=("-h" "$MYSQL_HOST")
    [ -n "${MYSQL_PORT:-}" ] && args+=("-P" "$MYSQL_PORT")
    [ -n "${MYSQL_USER:-}" ] && args+=("-u" "$MYSQL_USER")
    mysql "${args[@]}" -e "$query" 2>&1
}

my_run_file() {
    local file="${1:?SQL file required}"
    local args=(--batch --skip-pager --skip-column-names)
    [ -n "${MYSQL_HOST:-}" ] && args+=("-h" "$MYSQL_HOST")
    [ -n "${MYSQL_PORT:-}" ] && args+=("-P" "$MYSQL_PORT")
    [ -n "${MYSQL_USER:-}" ] && args+=("-u" "$MYSQL_USER")
    mysql "${args[@]}" < "$file" 2>&1
}

# ── Checksum helpers ─────────────────────────────────────────────────────────
compute_checksum() {
    local file="${1:?}"
    if check_cmd sha256sum; then
        sha256sum "$file"
    elif check_cmd shasum; then
        shasum -a 256 "$file"
    else
        log_warn "No sha256sum/shasum available; skipping checksum for $file"
    fi
}

# ── Argument parsing helpers ─────────────────────────────────────────────────
show_help_header() {
    local script_name="${1:?}" description="${2:?}"
    cat <<EOF
${_BOLD}${script_name}${_RESET} — ${description}
Part of NCAE Database Security Audit Toolkit v${NCAE_VERSION}

EOF
}

# ── OS info helpers ──────────────────────────────────────────────────────────
get_os_info() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        echo "${PRETTY_NAME:-${NAME:-Linux} ${VERSION:-unknown}}"
    elif check_cmd lsb_release; then
        lsb_release -ds 2>/dev/null
    else
        echo "Linux (unknown distro)"
    fi
}

get_kernel_version() {
    uname -r 2>/dev/null || echo "unknown"
}

# ── Network helpers ──────────────────────────────────────────────────────────
# List listening TCP sockets; prefer ss, fallback to netstat
list_listening_tcp() {
    if check_cmd ss; then
        ss -tlnp 2>/dev/null
    elif check_cmd netstat; then
        netstat -tlnp 2>/dev/null
    else
        log_warn "Neither ss nor netstat available"
        echo "(unavailable)"
    fi
}

# Find DB-related listening ports
find_db_ports() {
    list_listening_tcp | grep -iE 'postgres|mysql|mariadb|:5432|:3306' || true
}

# ── Process helpers ──────────────────────────────────────────────────────────
find_db_processes() {
    ps aux 2>/dev/null | grep -iE 'postgres|postmaster|mysql|mariadbd|mysqld' | grep -v grep || true
}

# ── Misc ─────────────────────────────────────────────────────────────────────
# Check if running as root
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log_warn "Not running as root; some checks may be limited."
        return 1
    fi
    return 0
}

# Portable temp file creation
make_temp() {
    mktemp "${TMPDIR:-/tmp}/ncae_XXXXXX"
}

# ── Resilience helpers ────────────────────────────────────────────────────────
# Track sections that pass/fail for summary reporting
NCAE_PASSED_SECTIONS=()
NCAE_FAILED_SECTIONS=()

# run_section "Label" command [args...]
# Runs a command in a subshell; logs warning on failure, appends to pass/fail lists.
run_section() {
    local label="${1:?section label required}"
    shift
    log_section "$label"
    if ( "$@" ); then
        NCAE_PASSED_SECTIONS+=("$label")
        return 0
    else
        local rc=$?
        log_warn "Section failed: ${label} (exit code ${rc})"
        NCAE_FAILED_SECTIONS+=("$label")
        return 0  # don't propagate — keep going
    fi
}

# print_summary — print pass/fail recap
print_summary() {
    local total=$(( ${#NCAE_PASSED_SECTIONS[@]} + ${#NCAE_FAILED_SECTIONS[@]} ))
    log_section "SUMMARY"
    log_info "Sections run   : ${total}"
    log_ok   "Sections passed: ${#NCAE_PASSED_SECTIONS[@]}"
    if [ "${#NCAE_FAILED_SECTIONS[@]}" -gt 0 ]; then
        log_warn "Sections failed: ${#NCAE_FAILED_SECTIONS[@]}"
        for s in "${NCAE_FAILED_SECTIONS[@]}"; do
            log_warn "  - ${s}"
        done
    else
        log_ok "All sections passed."
    fi
}

# ── Database defaults ────────────────────────────────────────────────────────
ensure_mysql_defaults() {
    export MYSQL_HOST="${MYSQL_HOST:-127.0.0.1}"
    export MYSQL_PORT="${MYSQL_PORT:-3306}"
    export MYSQL_USER="${MYSQL_USER:-root}"
    if [ -z "${MYSQL_PWD:-}" ] && [ ! -f "${HOME}/.my.cnf" ]; then
        log_warn "MYSQL_PWD not set and ~/.my.cnf not found — connection may fail or prompt for password."
    fi
    log_info "MySQL connection: ${MYSQL_USER}@${MYSQL_HOST}:${MYSQL_PORT}"
}

ensure_pg_defaults() {
    if [ -z "${PGHOST:-}" ]; then
        read -rp "PostgreSQL host [localhost]: " _pg_host
        export PGHOST="${_pg_host:-localhost}"
    fi
    if [ -z "${PGPORT:-}" ]; then
        read -rp "PostgreSQL port [5432]: " _pg_port
        export PGPORT="${_pg_port:-5432}"
    fi
    if [ -z "${PGUSER:-}" ]; then
        read -rp "PostgreSQL user [postgres]: " _pg_user
        export PGUSER="${_pg_user:-postgres}"
    fi
    if [ -z "${PGDATABASE:-}" ]; then
        read -rp "PostgreSQL database [postgres]: " _pg_db
        export PGDATABASE="${_pg_db:-postgres}"
    fi
    if [ -z "${PGPASSWORD:-}" ]; then
        read -rsp "PostgreSQL password: " _pg_pass
        echo ""
        export PGPASSWORD="${_pg_pass}"
    fi
    log_info "PostgreSQL connection: ${PGUSER}@${PGHOST}:${PGPORT}/${PGDATABASE}"
}

# ── SQL file runners (resilient — partial SQL errors don't abort) ────────────
# run_sql_file_mysql FILE — pipe a .sql through the mysql client
run_sql_file_mysql() {
    local file="${1:?SQL file required}"
    [ ! -f "$file" ] && { log_error "SQL file not found: $file"; return 1; }
    local args=(--batch --skip-pager --force)
    [ -n "${MYSQL_HOST:-}" ] && args+=("-h" "$MYSQL_HOST")
    [ -n "${MYSQL_PORT:-}" ] && args+=("-P" "$MYSQL_PORT")
    [ -n "${MYSQL_USER:-}" ] && args+=("-u" "$MYSQL_USER")
    mysql "${args[@]}" < "$file"
}

# run_sql_file_pg FILE — run a .sql through psql
run_sql_file_pg() {
    local file="${1:?SQL file required}"
    [ ! -f "$file" ] && { log_error "SQL file not found: $file"; return 1; }
    psql -X -A --no-psqlrc --pset pager=off -f "$file"
}

# ── Database detection ───────────────────────────────────────────────────────
# detect_db_type — echoes "mysql", "postgres", "both", or "none"
detect_db_type() {
    local has_mysql=false has_pg=false

    # Check for client binaries
    check_cmd mysql   && has_mysql=true
    check_cmd psql    && has_pg=true

    # Check for running processes (if client binary wasn't found, processes don't help)
    if ! $has_mysql; then
        pgrep -x mysqld   >/dev/null 2>&1 && has_mysql=true
        pgrep -x mariadbd  >/dev/null 2>&1 && has_mysql=true
    fi
    if ! $has_pg; then
        pgrep -x postgres   >/dev/null 2>&1 && has_pg=true
        pgrep -x postmaster >/dev/null 2>&1 && has_pg=true
    fi

    if $has_mysql && $has_pg; then echo "both"
    elif $has_mysql;            then echo "mysql"
    elif $has_pg;               then echo "postgres"
    else                              echo "none"
    fi
}

log_info "NCAE common library loaded (v${NCAE_VERSION})"
