#!/usr/bin/env bash
# =============================================================================
# ncae/postgres/20_backup_pg.sh
# PostgreSQL Backup Script — safe, timestamped, checksummed
# =============================================================================
# Creates a complete backup: base backup or pg_dumpall + per-db dumps,
# roles/globals, config files, with compression and manifest.
#
# NEVER overwrites existing backups (timestamped directories).
# =============================================================================
set -uo pipefail

umask 077

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${SCRIPT_DIR}/../common/lib.sh"

# Capture all output to report file
exec > >(tee "${SCRIPT_DIR}/20_backup_report.txt") 2>&1

NCAE_SCRIPT_NAME="20_backup_pg.sh"
ensure_pg_defaults

# ── Defaults ─────────────────────────────────────────────────────────────────
BACKUP_BASE="/var/backups/ncae/postgres"
USE_BASEBACKUP="auto"   # auto | yes | no
COMPRESS="gzip"         # gzip | none
PARALLEL_JOBS=2

# ── Help ─────────────────────────────────────────────────────────────────────
usage() {
    show_help_header "$NCAE_SCRIPT_NAME" "PostgreSQL backup with checksums & manifest"
    cat <<'EOF'
USAGE:
    20_backup_pg.sh [OPTIONS]

OPTIONS:
    -h, --help                Show this help
    -d, --dest DIR            Base backup directory (default: /var/backups/ncae/postgres)
    --mode basebackup|dump    Force backup mode (default: auto-detect)
    --no-compress             Disable compression
    -j, --jobs N              Parallel dump jobs (default: 2)

ENVIRONMENT:
    PGHOST, PGPORT, PGUSER, PGDATABASE, PGPASSWORD — connection parameters
    or use .pgpass file

EXAMPLES:
    sudo ./20_backup_pg.sh
    sudo ./20_backup_pg.sh --dest /mnt/backup/pg --mode dump
    PGUSER=postgres PGHOST=localhost ./20_backup_pg.sh
EOF
    exit 0
}

while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help)        usage ;;
        -d|--dest)        BACKUP_BASE="${2:?--dest requires a path}"; shift ;;
        --mode)
            case "${2:-}" in
                basebackup) USE_BASEBACKUP="yes" ;;
                dump)       USE_BASEBACKUP="no" ;;
                *)          log_fatal "--mode must be 'basebackup' or 'dump'" ;;
            esac
            shift ;;
        --no-compress)    COMPRESS="none" ;;
        -j|--jobs)        PARALLEL_JOBS="${2:?--jobs requires a number}"; shift ;;
        *)                log_error "Unknown option: $1"; usage ;;
    esac
    shift
done

if ! [[ "$PARALLEL_JOBS" =~ ^[1-9][0-9]*$ ]]; then
    log_fatal "--jobs must be a positive integer"
fi

# ── Dependency checks ────────────────────────────────────────────────────────
require_cmd psql

# Determine backup mode
if [ "$USE_BASEBACKUP" = "auto" ]; then
    if check_cmd pg_basebackup; then
        USE_BASEBACKUP="yes"
        log_info "pg_basebackup found; will use physical backup."
    else
        USE_BASEBACKUP="no"
        log_info "pg_basebackup not found; falling back to pg_dumpall + pg_dump."
    fi
fi

if [ "$USE_BASEBACKUP" = "no" ]; then
    require_cmd pg_dumpall
    require_cmd pg_dump
fi

# Compression tool
if [ "$COMPRESS" = "gzip" ]; then
    require_cmd gzip
fi

# ── Create timestamped backup directory ──────────────────────────────────────
BACKUP_DIR="$(timestamped_dir "$BACKUP_BASE" "pgbackup")"
safe_mkdir "$BACKUP_DIR"
log_section "POSTGRESQL BACKUP"
log_info "Backup directory: ${BACKUP_DIR}"
log_info "Mode: ${USE_BASEBACKUP}"
log_info "Compression: ${COMPRESS}"

MANIFEST_FILE="${BACKUP_DIR}/MANIFEST.txt"
ERRORS=0

write_manifest() {
    echo "$1" >> "$MANIFEST_FILE"
}
write_manifest "# NCAE PostgreSQL Backup Manifest"
write_manifest "# Timestamp: ${NCAE_TIMESTAMP}"
write_manifest "# Host: ${NCAE_HOSTNAME}"
write_manifest "# Mode: ${USE_BASEBACKUP}"
write_manifest "# Compression: ${COMPRESS}"
write_manifest ""

# ── Helper: compress + checksum ──────────────────────────────────────────────
compress_and_checksum() {
    local file="$1"
    if [ "$COMPRESS" = "gzip" ] && [ -f "$file" ]; then
        gzip "$file" || { log_error "gzip failed for $file"; ERRORS=$((ERRORS+1)); return 1; }
        file="${file}.gz"
    fi
    if [ -f "$file" ]; then
        local cksum
        cksum="$(compute_checksum "$file")"
        write_manifest "$cksum"
        log_ok "  Checksummed: $file"
    fi
}

# =============================================================================
# 1. Backup Roles & Globals
# =============================================================================
log_info "Backing up roles and globals..."
GLOBALS_FILE="${BACKUP_DIR}/globals.sql"
if pg_dumpall --globals-only > "$GLOBALS_FILE" 2>/dev/null || \
   pg_dumpall -g > "$GLOBALS_FILE" 2>/dev/null; then
    log_ok "Globals dumped."
    compress_and_checksum "$GLOBALS_FILE"
else
    log_error "Failed to dump globals."
    ERRORS=$((ERRORS+1))
fi

# =============================================================================
# 2. Main backup
# =============================================================================
if [ "$USE_BASEBACKUP" = "yes" ]; then
    # ── Physical backup with pg_basebackup ───────────────────────────────
    log_info "Running pg_basebackup..."
    BASEBACKUP_DIR="${BACKUP_DIR}/basebackup"
    safe_mkdir "$BASEBACKUP_DIR"

    PG_BB_EXTRA=""
    # Check if pg_basebackup supports --checkpoint=fast
    if pg_basebackup --help 2>/dev/null | grep -q '\-\-checkpoint'; then
        PG_BB_EXTRA="--checkpoint=fast"
    fi

    if pg_basebackup -D "$BASEBACKUP_DIR" -Ft -z -Xs $PG_BB_EXTRA -P 2>&1; then
        log_ok "pg_basebackup completed."
        # Checksum each tar
        for tarfile in "$BASEBACKUP_DIR"/*.tar.gz "$BASEBACKUP_DIR"/*.tar; do
            [ -f "$tarfile" ] && {
                cksum="$(compute_checksum "$tarfile")"
                write_manifest "$cksum"
            }
        done
    else
        log_error "pg_basebackup failed."
        ERRORS=$((ERRORS+1))
    fi
else
    # ── Logical backup with pg_dumpall + per-DB pg_dump ──────────────────
    log_info "Running pg_dumpall (schema-only, full cluster)..."
    DUMPALL_FILE="${BACKUP_DIR}/pg_dumpall_full.sql"
    if pg_dumpall > "$DUMPALL_FILE" 2>/dev/null; then
        log_ok "pg_dumpall completed."
        compress_and_checksum "$DUMPALL_FILE"
    else
        log_error "pg_dumpall failed."
        ERRORS=$((ERRORS+1))
    fi

    # Per-database dumps
    log_info "Dumping individual databases..."
    DB_LIST="$(pg_run_query "SELECT datname FROM pg_database WHERE NOT datistemplate AND datallowconn ORDER BY datname;" 2>/dev/null || echo '')"
    if [ -n "$DB_LIST" ]; then
        DB_DUMP_DIR="${BACKUP_DIR}/databases"
        safe_mkdir "$DB_DUMP_DIR"
        while IFS= read -r dbname; do
            [ -z "$dbname" ] && continue
            log_info "  Dumping: ${dbname}..."
            DUMP_FILE="${DB_DUMP_DIR}/${dbname}.custom"
            if pg_dump -Fc -j "$PARALLEL_JOBS" -f "$DUMP_FILE" "$dbname" 2>/dev/null || \
               pg_dump -Fc -f "$DUMP_FILE" "$dbname" 2>/dev/null; then
                log_ok "  Database ${dbname} dumped."
                if [ -f "$DUMP_FILE" ]; then
                    cksum="$(compute_checksum "$DUMP_FILE")"
                    write_manifest "$cksum"
                fi
            else
                log_error "  Failed to dump database: ${dbname}"
                ERRORS=$((ERRORS+1))
            fi
        done <<< "$DB_LIST"
    else
        log_warn "No databases found to dump individually."
    fi
fi

# =============================================================================
# 3. Capture config files
# =============================================================================
log_info "Capturing configuration files..."
CONFIG_DIR="${BACKUP_DIR}/config"
safe_mkdir "$CONFIG_DIR"

# Try to find config file paths from pg_settings
PG_CONFIG_FILE="$(pg_run_query "SHOW config_file;" 2>/dev/null || echo '')"
PG_CONF_DIR="${PG_CONFIG_FILE%/*}"
[ "$PG_CONF_DIR" = "$PG_CONFIG_FILE" ] && PG_CONF_DIR=""
PG_DATA_DIR="$(pg_run_query "SHOW data_directory;" 2>/dev/null || echo '')"

# List of config files to capture
CONFIG_FILES=(
    "${PG_CONF_DIR}/postgresql.conf"
    "${PG_CONF_DIR}/pg_hba.conf"
    "${PG_CONF_DIR}/pg_ident.conf"
    "${PG_DATA_DIR}/postgresql.conf"
    "${PG_DATA_DIR}/pg_hba.conf"
    "${PG_DATA_DIR}/pg_ident.conf"
    "/etc/postgresql/*/*/postgresql.conf"
    "/etc/postgresql/*/*/pg_hba.conf"
    "/etc/postgresql/*/*/pg_ident.conf"
)

CAPTURED_FILES=""
for conf in "${CONFIG_FILES[@]}"; do
    # Expand globs
    for f in $conf; do
        if [ -f "$f" ] && [ -r "$f" ]; then
            # Avoid duplicates
            real_f="$(readlink -f "$f" 2>/dev/null || echo "$f")"
            if echo "$CAPTURED_FILES" | grep -qF "$real_f"; then
                continue
            fi
            CAPTURED_FILES="${CAPTURED_FILES}${real_f}\n"
            dest_name="$(echo "$real_f" | tr '/' '_' | sed 's/^_//')"
            cp "$f" "${CONFIG_DIR}/${dest_name}" 2>/dev/null && {
                log_ok "  Captured: $f"
                write_manifest "CONFIG: $f -> ${dest_name}"
            } || log_warn "  Could not copy: $f"
        fi
    done
done

# Capture systemd overrides if they exist
for svc_dir in /etc/systemd/system/postgresql*.service.d /etc/systemd/system/postgres*.service.d; do
    if [ -d "$svc_dir" ]; then
        cp -r "$svc_dir" "${CONFIG_DIR}/" 2>/dev/null && \
            log_ok "  Captured systemd overrides: $svc_dir" || true
    fi
done

# =============================================================================
# 4. Finalize manifest
# =============================================================================
write_manifest ""
write_manifest "# Backup completed: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
write_manifest "# Errors: ${ERRORS}"
write_manifest "# Files:"
find "$BACKUP_DIR" -type f | sort | while read -r f; do
    write_manifest "  $f"
done

log_section "BACKUP SUMMARY"
log_info "Backup directory : ${BACKUP_DIR}"
log_info "Manifest         : ${MANIFEST_FILE}"
log_info "Errors           : ${ERRORS}"

if [ "$ERRORS" -gt 0 ]; then
    log_warn "Backup completed with ${ERRORS} error(s) — review warnings above."
    json_line "pg_backup" "warning" "dest" "$BACKUP_DIR" "errors" "$ERRORS" "mode" "$USE_BASEBACKUP"
else
    log_ok "Backup completed successfully."
    json_line "pg_backup" "ok" "dest" "$BACKUP_DIR" "errors" "0" "mode" "$USE_BASEBACKUP"
fi

log_info "Report saved to: ${SCRIPT_DIR}/20_backup_report.txt"

exit 0
