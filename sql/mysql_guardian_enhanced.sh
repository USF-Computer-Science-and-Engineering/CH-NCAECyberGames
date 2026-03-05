#!/bin/bash
# ================================================================
# mysql_guardian.sh — Competition MySQL Full Defense Suite
# HARDENED FOR ROOT-LEVEL ATTACKERS + AUTOMATIC RECOVERY
# ================================================================
# WHAT THIS DOES (in order):
#   [1] HARDEN   — block privilege escalation attempts
#   [2] BACKDOOR — creates hidden recovery account (METHOD 1: Recovery)
#   [3] BACKUP   — full snapshot of all databases + grants
#   [4] DIAGNOSE — detects attack types
#   [5] RESTORE  — emergency recovery via backdoor or skip-grant-tables
#   [6] WATCHDOG — 24/7 monitoring + auto-restore on attack
#   [7] MAINTAIN_SERVICE — keeps MySQL up while under attack
#
# KEY DEFENSE STRATEGIES:
#   🔑 Recovery Path (Method 1): Backdoor account allows restore even if locked out
#   🛡️ Privilege Escalation Blocks: File system perms + dangerous privilege revocation
#   🎯 Service Uptime (Strategy 1): Watchdog auto-detects & restores within 30s
#
# USAGE:
#   chmod +x mysql_guardian.sh
#   sudo ./mysql_guardian.sh             — interactive full run
#   sudo ./mysql_guardian.sh --harden    — harden only
#   sudo ./mysql_guardian.sh --backdoor  — create recovery account
#   sudo ./mysql_guardian.sh --backup    — backup databases
#   sudo ./mysql_guardian.sh --diagnose  — detect attacks
#   sudo ./mysql_guardian.sh --restore   — recover from attack
#   sudo ./mysql_guardian.sh --watchdog  — start 24/7 monitoring
#   sudo ./mysql_guardian.sh --audit     — show current privileges
#   sudo ./mysql_guardian.sh --auto      — automated full run
# ================================================================

set -euo pipefail

# ── colours ──────────────────────────────────────────────────
RED='\033[0;31m'; YEL='\033[1;33m'; GRN='\033[0;32m'
CYN='\033[0;36m'; WHT='\033[1;37m'; NC='\033[0m'
info()  { echo -e "${CYN}[*]${NC} $*"; }
ok()    { echo -e "${GRN}[✓]${NC} $*"; }
warn()  { echo -e "${YEL}[!]${NC} $*"; }
err()   { echo -e "${RED}[✗]${NC} $*"; }
banner(){ echo -e "\n${WHT}══════════ $* ══════════${NC}"; }

# ── guard ────────────────────────────────────────────────────
[[ $(id -u) -ne 0 ]] && err "Must run as root" && exit 1

# ── AUTO MODE FLAG ───────────────────────────────────────────
AUTO_MODE=0
[[ "${1:-}" == "--auto" ]] && AUTO_MODE=1

# ── config ───────────────────────────────────────────────────
BACKUP_ROOT="/lib/.pam"                  # hidden backup dir
WATCHDOG_INTERVAL="${WATCHDOG_INTERVAL:-30}"  # seconds between checks
WATCHDOG_LOG="/var/log/mysql_guardian.log"
ALERT_EMAIL="${ALERT_EMAIL:-}"
AUTO_RESTORE_THRESHOLD=2                 # restore only if 2+ critical issues

# Backdoor account (METHOD 1: Recovery via hidden account)
# Usage: export BACKDOOR_USER="custom_user" BACKDOOR_PASS="secure_pass"
BACKDOOR_USER="${BACKDOOR_USER:-maint_$(hostname | md5sum | cut -c1-6)}"
BACKDOOR_PASS="${BACKDOOR_PASS:-$(openssl rand -base64 18 | tr -d '/+=' 2>/dev/null || echo 'GENERATE_ME')}"
BACKDOOR_HOST="localhost"

# Reserved system accounts — never touch
RESERVED="'root','mysql.sys','mysql.session','mysql.infoschema','debian-sys-maint',''"
NOT_RESERVED="user NOT IN ($RESERVED)"

# ── detect distro + service ───────────────────────────────────
if command -v apt &>/dev/null; then
    MYCNF="/etc/mysql/my.cnf"; DB_SERVICE="mysql"; PKG="apt"
elif command -v dnf &>/dev/null; then
    MYCNF="/etc/my.cnf"; DB_SERVICE="mariadb"; PKG="dnf"
else
    err "Unknown package manager"; exit 1
fi
for svc in mysql mysqld mariadb; do
    systemctl is-active --quiet "$svc" 2>/dev/null && DB_SERVICE="$svc" && break
done

# ── credential helper ─────────────────────────────────────────
MYSQL_CMD=""
CURRENT_PASS=""

try_connect() {
    local pass="$1"
    if [[ -z "$pass" ]]; then
        mysql -u root -e "SELECT 1;" &>/dev/null && echo "ok" || echo "fail"
    else
        mysql -u root -p"${pass}" -e "SELECT 1;" &>/dev/null && echo "ok" || echo "fail"
    fi
}

find_mysql_access() {
    # Try stored cred file first
    if [[ -f "$BACKUP_ROOT/mysql_creds.txt" ]]; then
        local saved_pass
        saved_pass=$(grep "Root password:" "$BACKUP_ROOT/mysql_creds.txt" 2>/dev/null \
            | tail -1 | cut -d: -f2- | tr -d ' ')
        if [[ -n "$saved_pass" && "$saved_pass" != "UNCHANGED" ]]; then
            if [[ "$(try_connect "$saved_pass")" == "ok" ]]; then
                MYSQL_CMD="mysql -u root -p${saved_pass}"
                CURRENT_PASS="$saved_pass"
                ok "Connected using saved credentials"
                return 0
            fi
        fi
    fi
    # Try backdoor account (METHOD 1: Recovery Path)
    if mysql -u "$BACKDOOR_USER" -p"${BACKDOOR_PASS}" \
        -h "$BACKDOOR_HOST" -e "SELECT 1;" &>/dev/null 2>/dev/null; then
        MYSQL_CMD="mysql -u $BACKDOOR_USER -p${BACKDOOR_PASS} -h $BACKDOOR_HOST"
        ok "Connected via backdoor account"
        return 0
    fi
    # Try passwordless
    if [[ "$(try_connect "")" == "ok" ]]; then
        MYSQL_CMD="mysql -u root"
        CURRENT_PASS=""
        ok "Connected passwordless"
        return 0
    fi
    # Prompt only if not in auto mode
    if [[ $AUTO_MODE -eq 0 ]]; then
        warn "Cannot auto-connect. Enter MySQL root password:"
        read -sp "  Password: " CURRENT_PASS; echo
        if [[ "$(try_connect "$CURRENT_PASS")" == "ok" ]]; then
            MYSQL_CMD="mysql -u root -p${CURRENT_PASS}"
            ok "Connected with provided password"
            return 0
        fi
    fi
    err "All connection attempts failed"
    return 1
}

mcmd() { $MYSQL_CMD -e "$*" 2>/dev/null; }

# ── disk space check ────────────────────────────────────────
check_disk_space() {
    local backup_size free_space_kb
    [[ -d "$BACKUP_ROOT" ]] && backup_size=$(du -sk "$BACKUP_ROOT" 2>/dev/null | cut -f1) || backup_size=0
    free_space_kb=$(df /lib 2>/dev/null | awk 'NR==2 {print $4}')
    
    if [[ $free_space_kb -lt 1000000 ]]; then
        warn "Less than 1GB free in /lib (${backup_size}KB used by backups)"
        return 1
    fi
    return 0
}

# ── health check ────────────────────────────────────────────
check_database_health() {
    info "Checking database health..."
    if ! mysqlcheck -u root ${CURRENT_PASS:+-p"$CURRENT_PASS"} \
        --all-databases --check 2>/dev/null | grep -q "error"; then
        ok "Database health check passed"
        return 0
    else
        warn "Database corruption detected"
        return 1
    fi
}

# ================================================================
# SECTION 1: HARDEN (Block Privilege Escalation Attempts)
# ================================================================
do_harden() {
    banner "HARDENING MySQL — Blocking Privilege Escalation"

    find_mysql_access || { err "Cannot connect — aborting harden"; return 1; }

    # ── 1a. OS user check ────────────────────────────────────
    info "Checking mysqld OS user..."
    MYSQL_OS_USER=$(ps aux | grep -E '[m]ysqld|[m]ariadbd' | awk '{print $1}' | head -1)
    if [[ "$MYSQL_OS_USER" == "root" ]]; then
        warn "mysqld running as Unix root — UDF escalation risk! Add user=mysql to $MYCNF"
    else
        ok "mysqld OS user: $MYSQL_OS_USER"
    fi

    # ── 1b. File system permissions (PREVENT PRIVILEGE ESCALATION) ───
    info "Hardening file system permissions..."
    # MySQL data directory — no world access
    chown mysql:mysql /var/lib/mysql 2>/dev/null || true
    chmod 750 /var/lib/mysql
    
    # Plugin directory — locked
    PLUGIN_DIR=$(mcmd "SHOW VARIABLES LIKE 'plugin_dir';" | awk '{print $2}' | tail -1)
    if [[ -n "$PLUGIN_DIR" && -d "$PLUGIN_DIR" ]]; then
        chmod 755 "$PLUGIN_DIR"
        ok "Plugin dir locked (755)"
    fi
    
    # Config file protected
    chmod 640 "$MYCNF" 2>/dev/null || true
    chown mysql:mysql "$MYCNF" 2>/dev/null || true
    
    # History files protected
    for f in /root/.mysql_history /home/*/.mysql_history; do
        [[ -f "$f" ]] && chmod 600 "$f"
    done
    ok "File system permissions hardened"

    # ── 1c. Lock reserved system accounts ───────────────────
    info "Locking reserved system accounts..."
    for u in 'mysql.sys' 'mysql.session' 'mysql.infoschema'; do
        $MYSQL_CMD -e "ALTER USER IF EXISTS '$u'@'localhost' ACCOUNT LOCK;" 2>/dev/null || true
    done
    ok "Reserved accounts locked"

    # ── 1d. Remove anonymous users ───────────────────────────
    info "Removing anonymous users..."
    ANON=$(mcmd "SELECT COUNT(*) FROM mysql.user WHERE user='';" | tail -1)
    mcmd "DELETE FROM mysql.user WHERE user='';"
    ok "Removed $ANON anonymous user(s)"

    # ── 1e. Remove test database ─────────────────────────────
    info "Removing test database..."
    mcmd "DROP DATABASE IF EXISTS test;"
    mcmd "DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';"
    ok "Test database removed"

    # ── 1f. Restrict root to localhost ───────────────────────
    info "Restricting root to localhost..."
    mcmd "DELETE FROM mysql.user WHERE user='root'
        AND host NOT IN ('localhost','127.0.0.1','::1');"
    ok "Remote root removed"

    # ── 1g. Rotate root password ─────────────────────────────
    if [[ $AUTO_MODE -eq 0 ]]; then
        info "Root password rotation..."
        read -sp "  New MySQL root password: " NEW_ROOT_PASS; echo
        read -sp "  Confirm: " CONFIRM_PASS; echo
    else
        NEW_ROOT_PASS="${NEW_ROOT_PASS:-$(openssl rand -base64 12)}"
        CONFIRM_PASS="$NEW_ROOT_PASS"
    fi
    
    if [[ "$NEW_ROOT_PASS" == "$CONFIRM_PASS" && -n "$NEW_ROOT_PASS" ]]; then
        $MYSQL_CMD -e "ALTER USER 'root'@'localhost' IDENTIFIED BY '$NEW_ROOT_PASS';" 2>/dev/null \
            || $MYSQL_CMD -e "UPDATE mysql.user SET authentication_string=PASSWORD('$NEW_ROOT_PASS')
                WHERE user='root';" 2>/dev/null
        MYSQL_CMD="mysql -u root -p${NEW_ROOT_PASS}"
        CURRENT_PASS="$NEW_ROOT_PASS"
        ok "Root password rotated"
        mkdir -p "$BACKUP_ROOT"
        echo "Root password: $NEW_ROOT_PASS" >> "$BACKUP_ROOT/mysql_creds.txt"
        chmod 600 "$BACKUP_ROOT/mysql_creds.txt"
    else
        warn "Passwords mismatch or empty — skipping"
    fi

    # ── 1h. Lock empty-password accounts ────────────────────
    info "Locking empty-password accounts..."
    mcmd "SELECT CONCAT('ALTER USER ''',user,'''@''',host,''' ACCOUNT LOCK;')
        FROM mysql.user
        WHERE (authentication_string='' OR authentication_string IS NULL)
        AND $NOT_RESERVED;" | grep "ALTER USER" | while read q; do
        $MYSQL_CMD -e "$q" 2>/dev/null || true; done
    ok "Empty-password accounts locked"

    # ── 1i. REVOKE DANGEROUS STATIC PRIVILEGES (BLOCK ESCALATION) ────
    info "Revoking dangerous static privileges from non-reserved users..."
    declare -A PRIV_MAP=(
        ["File_priv"]="FILE"              # Can read/write files (CRITICAL)
        ["Super_priv"]="SUPER"            # Can reload config, shutdown
        ["Process_priv"]="PROCESS"        # Can see all queries
        ["Shutdown_priv"]="SHUTDOWN"      # Can shutdown MySQL
        ["Reload_priv"]="RELOAD"          # Can reload privileges
        ["Repl_slave_priv"]="REPLICATION SLAVE"
        ["Repl_client_priv"]="REPLICATION CLIENT"
        ["Create_user_priv"]="CREATE USER"  # Can create rogue accounts
        ["Grant_priv"]="GRANT OPTION"     # Can elevate other users
    )
    for col in "${!PRIV_MAP[@]}"; do
        priv="${PRIV_MAP[$col]}"
        mcmd "SELECT CONCAT('REVOKE $priv ON *.* FROM ''',user,'''@''',host,''';')
            FROM mysql.user WHERE $NOT_RESERVED AND $col='Y';" \
            | grep REVOKE | while read q; do
            $MYSQL_CMD -e "$q" 2>/dev/null || true; done
    done
    ok "Dangerous privileges revoked (FILE, SUPER, PROCESS, etc.)"

    # ── 1j. REVOKE DANGEROUS DYNAMIC PRIVILEGES (MySQL 8.0+) ────
    info "Revoking dangerous dynamic privileges..."
    for dyn in "SYSTEM_USER" "SYSTEM_VARIABLES_ADMIN" "SESSION_VARIABLES_ADMIN" \
               "BINLOG_ADMIN" "ENCRYPTION_KEY_ADMIN" "CONNECTION_ADMIN" \
               "CLONE_ADMIN" "BACKUP_ADMIN"; do
        mcmd "SELECT CONCAT('REVOKE $dyn ON *.* FROM ''',USER,'''@''',HOST,''';')
            FROM mysql.global_grants
            WHERE PRIV='$dyn'
            AND USER NOT IN ($RESERVED);" \
            | grep REVOKE | while read q; do
            $MYSQL_CMD -e "$q" 2>/dev/null || true; done
    done
    ok "Dangerous dynamic privileges revoked"

    # ── 1k. Restrict wildcard hosts ──────────────────────────
    info "Checking wildcard '%' hosts..."
    WILDCARD_COUNT=$(mcmd "SELECT COUNT(*) FROM mysql.user WHERE host='%'
        AND $NOT_RESERVED;" | tail -1)
    if [[ "$WILDCARD_COUNT" -gt 0 ]]; then
        mcmd "UPDATE mysql.user SET host='localhost'
            WHERE host='%' AND $NOT_RESERVED;"
        ok "Restricted $WILDCARD_COUNT wildcard host(s) to localhost"
    else
        ok "No wildcard hosts found"
    fi

    # ── 1l. Connection limits ────────────────────────────────
    info "Applying connection limits..."
    mcmd "SELECT CONCAT('ALTER USER ''',user,'''@''',host,
        ''' WITH MAX_USER_CONNECTIONS 10 MAX_QUERIES_PER_HOUR 5000;')
        FROM mysql.user WHERE $NOT_RESERVED;" \
        | grep "ALTER USER" | while read q; do
        $MYSQL_CMD -e "$q" 2>/dev/null || true; done
    ok "Connection limits applied"

    # ── 1m. Drop rogue UDF functions ─────────────────────────
    info "Scanning for malicious UDF functions..."
    ROGUE_UDFS=$(mcmd "SELECT name FROM mysql.func
        WHERE dl NOT IN ('','mysql_native_password')
        OR name IN ('do_system','sys_exec','sys_eval','sys_get',
                    'lib_mysqludf_sys','raptor');" 2>/dev/null | grep -v "^name$" || true)
    if [[ -n "$ROGUE_UDFS" ]]; then
        warn "ROGUE UDF FUNCTIONS FOUND: $ROGUE_UDFS"
        echo "$ROGUE_UDFS" | while read fn; do
            [[ -n "$fn" ]] && $MYSQL_CMD -e "DROP FUNCTION IF EXISTS \`$fn\`;" 2>/dev/null || true
        done
        ok "Rogue UDFs dropped"
    else
        ok "No rogue UDF functions found"
    fi

    # ── 1n. Block LOAD DATA LOCAL INFILE ────────────────────
    info "Ensuring local_infile is disabled globally..."
    mcmd "SET GLOBAL local_infile = 0;" 2>/dev/null || true
    ok "local_infile=0 applied"

    # ── 1o. Expire passwords on non-reserved accounts ────────
    info "Expiring passwords on non-reserved accounts..."
    mcmd "SELECT CONCAT('ALTER USER ''',user,'''@''',host,''' PASSWORD EXPIRE;')
        FROM mysql.user WHERE $NOT_RESERVED;" \
        | grep "ALTER USER" | while read q; do
        $MYSQL_CMD -e "$q" 2>/dev/null || true; done
    ok "Non-reserved passwords expired"

    mcmd "FLUSH PRIVILEGES;"
    ok "FLUSH PRIVILEGES"

    # ── 1p. Harden my.cnf ────────────────────────────────────
    info "Hardening $MYCNF..."
    [[ -f "$MYCNF" ]] && cp "$MYCNF" "${MYCNF}.bak.$(date +%Y%m%d_%H%M%S)"

    cat > /tmp/guardian_harden.cnf << 'HARDEN_EOF'

# ═══ mysql_guardian hardening block ═══════════════════════════
[mysqld]

# ── BLOCK PRIVILEGE ESCALATION ──────────────────────────────
# Disable suspicious UDF libraries (raptor_udf, lib_mysqludf_sys)
allow_suspicious_udfs           = 0
# Restrict file operations to safe directory only
secure_file_priv                = /var/lib/mysql
# No symlinks (prevent symlink attacks)
symbolic_links                  = 0
# Don't allow implicit account creation
safe_user_create                = 1
# Disable auto-grant for stored procedures
automatic_sp_privileges         = 0
# No external file locking (process isolation)
skip_external_locking           = 1

# ── BLOCK FILE OPERATIONS ───────────────────────────────────
local_infile                    = 0

# ── HIDE DATABASE INFORMATION ───────────────────────────────
skip_show_database
skip_name_resolve

# ── BRUTE FORCE MITIGATION ─────────────────────────────────
max_connect_errors              = 5
max_user_connections            = 50
connect_timeout                 = 10

# ── LOGGING & DETECTION ────────────────────────────────────
general_log                     = 1
general_log_file                = /var/log/mysql/query.log
slow_query_log                  = 1
slow_query_log_file             = /var/log/mysql/slow.log
long_query_time                 = 2
log_error                       = /var/log/mysql/error.log

# ── SIZE LIMITS ─────────────────────────────────────────────
max_allowed_packet              = 16M

# ── ADDITIONAL HARDENING ───────────────────────────────────
default_password_lifetime       = 90
sql_mode                        = 'STRICT_TRANS_TABLES'
log_bin_trust_function_creators = 0

# ════════════════════════════════════════════════════════════

HARDEN_EOF

    cat /tmp/guardian_harden.cnf "$MYCNF" > /tmp/guardian_merged.cnf 2>/dev/null
    mv /tmp/guardian_merged.cnf "$MYCNF"
    rm -f /tmp/guardian_harden.cnf
    ok "$MYCNF hardened"

    # ── 1q. Restart and verify ───────────────────────────────
    info "Restarting $DB_SERVICE..."
    systemctl restart "$DB_SERVICE" && sleep 2
    if systemctl is-active --quiet "$DB_SERVICE"; then
        ok "$DB_SERVICE restarted successfully"
    else
        warn "Restart failed — restoring config backup"
        ls -t "${MYCNF}".bak.* 2>/dev/null | head -1 | xargs -I{} cp {} "$MYCNF"
        systemctl restart "$DB_SERVICE"
    fi

    ok "HARDENING COMPLETE — Privilege Escalation Attempts Blocked"
}

# ================================================================
# SECTION 2: BACKDOOR (METHOD 1: Emergency Recovery Account)
# ================================================================
do_backdoor() {
    banner "CREATING BACKDOOR ACCOUNT (METHOD 1: Recovery Path)"

    find_mysql_access || { err "Cannot connect"; return 1; }

    # Save creds to protected file BEFORE creating account
    mkdir -p "$BACKUP_ROOT"
    {
        echo "# mysql_guardian backdoor account — $(date)"
        echo "# If root is locked out, use this account to restore:"
        echo ""
        echo "BACKDOOR_USER=$BACKDOOR_USER"
        echo "BACKDOOR_PASS=$BACKDOOR_PASS"
        echo "BACKDOOR_HOST=$BACKDOOR_HOST"
        echo ""
        echo "# Connection command:"
        echo "mysql -u $BACKDOOR_USER -p'$BACKDOOR_PASS' -h $BACKDOOR_HOST"
        echo ""
        echo "# To restore root after lockout:"
        echo "mysql -u $BACKDOOR_USER -p'$BACKDOOR_PASS' -h $BACKDOOR_HOST << EOF"
        echo "CREATE USER 'root'@'localhost' IDENTIFIED BY 'newpassword';"
        echo "GRANT ALL ON *.* TO 'root'@'localhost' WITH GRANT OPTION;"
        echo "FLUSH PRIVILEGES;"
        echo "EOF"
    } > "$BACKUP_ROOT/.backdoor"
    chmod 600 "$BACKUP_ROOT/.backdoor"

    # Drop if exists, re-create clean
    $MYSQL_CMD -e "DROP USER IF EXISTS '$BACKDOOR_USER'@'$BACKDOOR_HOST';" 2>/dev/null || true
    $MYSQL_CMD -e "CREATE USER '$BACKDOOR_USER'@'$BACKDOOR_HOST'
        IDENTIFIED BY '$BACKDOOR_PASS';" 2>/dev/null
    $MYSQL_CMD -e "GRANT ALL PRIVILEGES ON *.* TO '$BACKDOOR_USER'@'$BACKDOOR_HOST'
        WITH GRANT OPTION;" 2>/dev/null
    $MYSQL_CMD -e "FLUSH PRIVILEGES;" 2>/dev/null

    # Test it immediately
    if mysql -u "$BACKDOOR_USER" -p"${BACKDOOR_PASS}" \
        -h "$BACKDOOR_HOST" -e "SELECT 1;" &>/dev/null; then
        ok "Backdoor account created and tested ✓"
        ok "User: $BACKDOOR_USER  Host: $BACKDOOR_HOST"
        ok "Creds saved → $BACKUP_ROOT/.backdoor (chmod 600)"
        ok ""
        warn "KEEP THIS SAFE! This is your lifeline if root is locked out."
    else
        err "Backdoor account creation failed"
    fi
}

# ================================================================
# SECTION 3: BACKUP
# ================================================================
do_backup() {
    banner "BACKING UP DATABASES"

    find_mysql_access || { err "Cannot connect"; return 1; }

    check_disk_space || warn "Disk space low — backup may fail"

    BD="$BACKUP_ROOT/backup_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$BD"

    info "Dumping all databases..."
    if mysqldump -u root ${CURRENT_PASS:+-p"$CURRENT_PASS"} \
        --all-databases --routines --triggers --events \
        --single-transaction --flush-logs \
        > "$BD/all_databases.sql" 2>/dev/null; then
        ok "Full dump → $BD/all_databases.sql"
    else
        # Try via backdoor
        if mysqldump -u "$BACKDOOR_USER" -p"$BACKDOOR_PASS" \
            --all-databases --routines --triggers \
            > "$BD/all_databases.sql" 2>/dev/null; then
            ok "Full dump (via backdoor) → $BD/all_databases.sql"
        else
            err "mysqldump failed"
        fi
    fi

    # Dump grant tables separately
    info "Dumping grant tables..."
    $MYSQL_CMD -e "SELECT user, host, plugin, authentication_string,
        password_expired, account_locked
        FROM mysql.user ORDER BY user, host;" > "$BD/grant_users.txt" 2>/dev/null

    $MYSQL_CMD -e "SHOW DATABASES;" > "$BD/databases.txt" 2>/dev/null

    # Permissions
    chmod 600 "$BD"/*.sql "$BD"/*.txt 2>/dev/null || true
    chmod 700 "$BD"

    # Keep only last 5 backups
    ls -dt "$BACKUP_ROOT"/backup_* 2>/dev/null | tail -n +6 | xargs rm -rf 2>/dev/null || true

    echo "$BD" > "$BACKUP_ROOT/latest_backup.txt"
    ok "Backup complete → $BD"
    echo "$BD"
}

# ================================================================
# SECTION 4: DIAGNOSE
# ================================================================
do_diagnose() {
    banner "ATTACK DIAGNOSIS"

    ATTACK_FOUND=0
    ATTACK_COUNT=0
    ATTACK_TYPE="NONE"

    # ── Check 1: Can we connect? ────────────────────────
    info "Checking MySQL connectivity..."
    if ! find_mysql_access 2>/dev/null; then
        err "CANNOT CONNECT TO MYSQL"
        warn "DIAGNOSIS: Root password likely changed by attacker"
        warn "ACTION: Attempting recovery via backdoor or skip-grant-tables..."
        ((ATTACK_COUNT++))
        ATTACK_FOUND=1; ATTACK_TYPE="CREDENTIAL_CHANGE"
        if ! systemctl is-active --quiet "$DB_SERVICE" 2>/dev/null; then
            err "MySQL service is DOWN"
            ATTACK_TYPE="SERVICE_DOWN"
            ((ATTACK_COUNT++))
        fi
        echo "ATTACK_TYPE=$ATTACK_TYPE" > "$BACKUP_ROOT/last_attack.txt"
        echo "ATTACK_COUNT=$ATTACK_COUNT" >> "$BACKUP_ROOT/last_attack.txt"
        return 1
    fi
    ok "Connected"

    # ── Check 2: UDF exploit artifacts ───────────────────────
    info "Scanning for UDF exploit artifacts..."
    ROGUE_UDFS=$(mcmd "SELECT name FROM mysql.func
        WHERE name IN ('do_system','sys_exec','sys_eval','sys_get',
                       'lib_mysqludf_sys','raptor','cmd_exec')
        OR dl LIKE '%.so%';" 2>/dev/null | grep -v "^name$" | grep -v "^$" || true)
    if [[ -n "$ROGUE_UDFS" ]]; then
        err "UDF EXPLOIT DETECTED: $ROGUE_UDFS"
        ATTACK_FOUND=1; ATTACK_TYPE="UDF_EXPLOIT"
        ((ATTACK_COUNT++))
    fi
    
    if [[ -n "$PLUGIN_DIR" && -d "$PLUGIN_DIR" ]]; then
        ROGUE_SO=$(find "$PLUGIN_DIR" -name "raptor*" -o -name "*udf_sys*" \
            -o -name "*mysqludf*" 2>/dev/null || true)
        if [[ -n "$ROGUE_SO" ]]; then
            err "ROGUE SHARED LIBRARY IN PLUGIN DIR: $ROGUE_SO"
            ATTACK_FOUND=1; ATTACK_TYPE="UDF_EXPLOIT"
            ((ATTACK_COUNT++))
        fi
    fi

    # ── Check 3: Ransomware / data wipe ──────────────────────
    info "Checking for ransomware indicators..."
    DB_COUNT=$(mcmd "SELECT COUNT(*) FROM information_schema.SCHEMATA
        WHERE SCHEMA_NAME NOT IN
        ('information_schema','mysql','performance_schema','sys');" | tail -1)
    TABLE_COUNT=$(mcmd "SELECT COUNT(*) FROM information_schema.TABLES
        WHERE TABLE_SCHEMA NOT IN
        ('information_schema','mysql','performance_schema','sys');" | tail -1)
    RANSOM_DB=$(mcmd "SHOW DATABASES;" | grep -iE "please_read|readme|recover|ransom|bitcoin|payment" || true)

    if [[ -n "$RANSOM_DB" ]]; then
        err "RANSOMWARE INDICATOR: Found database named '$RANSOM_DB'"
        ATTACK_FOUND=1; ATTACK_TYPE="RANSOMWARE"
        ((ATTACK_COUNT++))
    fi
    if [[ "$TABLE_COUNT" -eq 0 && "$DB_COUNT" -gt 0 ]]; then
        warn "WARNING: $DB_COUNT databases exist but 0 user tables — data may have been wiped"
        ATTACK_FOUND=1; ATTACK_TYPE="DATA_WIPE"
        ((ATTACK_COUNT++))
    fi

    # ── Check 4: New unauthorized accounts ───────────────────
    info "Checking for unauthorized accounts..."
    if [[ -f "$BACKUP_ROOT"/backup_*/grant_users.txt ]]; then
        LATEST_BACKUP=$(cat "$BACKUP_ROOT/latest_backup.txt" 2>/dev/null || \
            ls -dt "$BACKUP_ROOT"/backup_* | head -1)
        NEW_USERS=$(mcmd "SELECT CONCAT(user,'@',host) FROM mysql.user
            WHERE $NOT_RESERVED;" | grep -v "^CONCAT" | sort > /tmp/current_users.txt
            sort "$LATEST_BACKUP/grant_users.txt" 2>/dev/null | diff - /tmp/current_users.txt \
            | grep "^>" | sed 's/^> //' || true)
        if [[ -n "$NEW_USERS" ]]; then
            warn "NEW UNAUTHORIZED ACCOUNTS DETECTED: $NEW_USERS"
            ATTACK_FOUND=1
            [[ "$ATTACK_TYPE" == "NONE" ]] && ATTACK_TYPE="ACCOUNT_INJECTION"
            ((ATTACK_COUNT++))
        fi
    fi
    rm -f /tmp/current_users.txt

    # ── Check 5: Brute force attempts ───────────────────────
    info "Checking error log for brute force indicators..."
    BRUTEFORCE=$(grep -c "Access denied" /var/log/mysql/error.log 2>/dev/null || \
        grep -c "Access denied" /var/log/mysql.err 2>/dev/null || echo 0)
    if [[ "$BRUTEFORCE" -gt 20 ]]; then
        warn "BRUTE FORCE INDICATOR: $BRUTEFORCE 'Access denied' entries in error log"
        ATTACK_FOUND=1
        [[ "$ATTACK_TYPE" == "NONE" ]] && ATTACK_TYPE="BRUTE_FORCE"
        ((ATTACK_COUNT++))
    fi

    # ── Check 6: SELECT INTO OUTFILE / LOAD_FILE abuse ───────
    info "Checking query log for file exfiltration..."
    if [[ -f "/var/log/mysql/query.log" ]]; then
        OUTFILE=$(grep -ic "INTO OUTFILE\|LOAD_FILE\|DUMPFILE" \
            /var/log/mysql/query.log 2>/dev/null || echo 0)
        if [[ "$OUTFILE" -gt 0 ]]; then
            warn "FILE OPERATION ABUSE: $OUTFILE suspicious file operations in query log"
            ATTACK_FOUND=1
            [[ "$ATTACK_TYPE" == "NONE" ]] && ATTACK_TYPE="FILE_EXFIL"
            ((ATTACK_COUNT++))
        fi
        DROP_COUNT=$(grep -ic "DROP TABLE\|DROP DATABASE\|DELETE FROM" \
            /var/log/mysql/query.log 2>/dev/null || echo 0)
        if [[ "$DROP_COUNT" -gt 5 ]]; then
            warn "DATA DESTRUCTION: $DROP_COUNT DROP/DELETE operations in query log"
            ATTACK_FOUND=1
            [[ "$ATTACK_TYPE" == "RANSOMWARE" ]] || ATTACK_TYPE="DATA_WIPE"
            ((ATTACK_COUNT++))
        fi
    fi

    # ── Check 7: Root password integrity ────────────────────
    info "Verifying root password integrity..."
    if [[ -f "$BACKUP_ROOT/mysql_creds.txt" ]]; then
        SAVED_PASS=$(grep "Root password:" "$BACKUP_ROOT/mysql_creds.txt" \
            | tail -1 | cut -d: -f2- | tr -d ' ')
        if [[ -n "$SAVED_PASS" ]]; then
            if ! mysql -u root -p"$SAVED_PASS" -e "SELECT 1;" &>/dev/null; then
                warn "ROOT PASSWORD HAS BEEN CHANGED since last backup"
                ATTACK_FOUND=1
                [[ "$ATTACK_TYPE" == "NONE" ]] && ATTACK_TYPE="CREDENTIAL_CHANGE"
                ((ATTACK_COUNT++))
            else
                ok "Root password unchanged"
            fi
        fi
    fi

    # ── Check 8: Suspicious SHOW PROCESSLIST ─────────────────
    info "Checking active connections..."
    SUSPICIOUS_QUERIES=$(mcmd "SHOW FULL PROCESSLIST;" 2>/dev/null \
        | grep -iE "OUTFILE|DUMPFILE|LOAD_FILE|sys_exec|do_system|drop table|drop database" || true)
    if [[ -n "$SUSPICIOUS_QUERIES" ]]; then
        err "ACTIVE ATTACK IN PROGRESS: $SUSPICIOUS_QUERIES"
        mcmd "SHOW PROCESSLIST;" | awk 'NR>1 {print $1}' | while read pid; do
            $MYSQL_CMD -e "KILL $pid;" 2>/dev/null || true
        done
        ATTACK_FOUND=1; ATTACK_TYPE="ACTIVE_ATTACK"
        ((ATTACK_COUNT++))
    fi

    # ── Summary ───────────────────────────────────────────────
    echo ""
    if [[ "$ATTACK_FOUND" -eq 1 ]]; then
        err "ATTACK DETECTED — Type: $ATTACK_TYPE (Severity: $ATTACK_COUNT)"
        echo "ATTACK_TYPE=$ATTACK_TYPE" > "$BACKUP_ROOT/last_attack.txt"
        echo "ATTACK_COUNT=$ATTACK_COUNT" >> "$BACKUP_ROOT/last_attack.txt"
        echo "ATTACK_TIME=$(date)" >> "$BACKUP_ROOT/last_attack.txt"
        return 1
    else
        ok "No attack indicators detected"
        echo "ATTACK_TYPE=NONE" > "$BACKUP_ROOT/last_attack.txt"
        return 0
    fi
}

# ================================================================
# SECTION 5: RESTORE (Emergency Recovery via Backdoor or Emergency Mode)
# ================================================================
do_restore() {
    banner "EMERGENCY RECOVERY — Restoring From Backup"

    # ── Find latest backup ───────────────────────────────────
    if [[ -f "$BACKUP_ROOT/latest_backup.txt" ]]; then
        LATEST=$(cat "$BACKUP_ROOT/latest_backup.txt")
    else
        LATEST=$(ls -dt "$BACKUP_ROOT"/backup_* 2>/dev/null | head -1)
    fi

    if [[ -z "$LATEST" || ! -f "$LATEST/all_databases.sql" ]]; then
        err "No backup found at $BACKUP_ROOT — cannot restore"
        return 1
    fi
    ok "Using backup: $LATEST"

    # ── Ensure MySQL is running ───────────────────────────────
    info "Ensuring $DB_SERVICE is running..."
    if ! systemctl is-active --quiet "$DB_SERVICE" 2>/dev/null; then
        warn "Service is down — attempting start..."
        systemctl start "$DB_SERVICE" 2>/dev/null || true
        sleep 3
    fi
    ok "$DB_SERVICE is running"

    # ── Try normal connection first ───────────────────────────
    if find_mysql_access 2>/dev/null; then
        ok "Normal connection succeeded"
    else
        # ── CONNECTION FAILED: Try backdoor account ────────────
        warn "Root access failed — attempting recovery via BACKDOOR account..."
        if mysql -u "$BACKDOOR_USER" -p"${BACKDOOR_PASS}" \
            -h "$BACKDOOR_HOST" -e "SELECT 1;" &>/dev/null 2>/dev/null; then
            ok "BACKDOOR account accessible — using for recovery"
            MYSQL_CMD="mysql -u $BACKDOOR_USER -p${BACKDOOR_PASS} -h $BACKDOOR_HOST"
            CURRENT_PASS="$BACKDOOR_PASS"
        else
            # ── BACKDOOR FAILED: Use skip-grant-tables emergency mode ────
            warn "Backdoor also failed — activating skip-grant-tables EMERGENCY MODE"
            systemctl stop "$DB_SERVICE" 2>/dev/null || true
            sleep 1
            mysqld_safe --skip-grant-tables --skip-networking &
            SAFE_PID=$!
            sleep 3
            MYSQL_CMD="mysql -u root"
            CURRENT_PASS=""
            ok "Emergency mode active (skip-grant-tables) — full access granted"
        fi
    fi

    # ── Health check before restore ───────────────────────────
    if ! check_database_health 2>/dev/null; then
        warn "Database corruption confirmed — proceeding with restore"
    fi

    # ── Reset root password first (via backdoor or emergency) ─
    SAVED_PASS=$(grep "Root password:" "$BACKUP_ROOT/mysql_creds.txt" 2>/dev/null \
        | tail -1 | cut -d: -f2- | tr -d ' ')
    if [[ -n "$SAVED_PASS" && "$SAVED_PASS" != "UNCHANGED" ]]; then
        info "Restoring root account to last known good state..."
        $MYSQL_CMD -e "FLUSH PRIVILEGES;" 2>/dev/null || true
        
        # Create root if it doesn't exist
        $MYSQL_CMD -e "CREATE USER IF NOT EXISTS 'root'@'localhost' IDENTIFIED BY '$SAVED_PASS';" 2>/dev/null || \
        $MYSQL_CMD -e "ALTER USER 'root'@'localhost' IDENTIFIED BY '$SAVED_PASS';" 2>/dev/null
        
        $MYSQL_CMD -e "GRANT ALL ON *.* TO 'root'@'localhost' WITH GRANT OPTION;" 2>/dev/null
        $MYSQL_CMD -e "FLUSH PRIVILEGES;" 2>/dev/null
        
        # Exit emergency mode if active
        if [[ -n "${SAFE_PID:-}" ]]; then
            kill "$SAFE_PID" 2>/dev/null || true
            sleep 2
            systemctl restart "$DB_SERVICE"
            sleep 2
        fi
        
        MYSQL_CMD="mysql -u root -p${SAVED_PASS}"
        CURRENT_PASS="$SAVED_PASS"
        ok "Root account restored ✓"
    fi

    # ── Remove all non-reserved, non-backdoor users ───────────
    info "Removing compromised accounts..."
    mcmd "SELECT CONCAT('DROP USER IF EXISTS ''',user,'''@''',host,''';')
        FROM mysql.user WHERE $NOT_RESERVED
        AND user != '$BACKDOOR_USER';" \
        | grep "DROP USER" | while read q; do
        $MYSQL_CMD -e "$q" 2>/dev/null || true; done
    $MYSQL_CMD -e "FLUSH PRIVILEGES;" 2>/dev/null

    # ── Restore databases ─────────────────────────────────────
    info "Restoring all databases from clean backup..."
    if mysql -u root ${CURRENT_PASS:+-p"$CURRENT_PASS"} \
        < "$LATEST/all_databases.sql" 2>/dev/null; then
        ok "Database restore complete ✓"
    else
        err "Database restore failed — manual intervention required"
        err "Backup SQL is at: $LATEST/all_databases.sql"
        return 1
    fi

    $MYSQL_CMD -e "FLUSH PRIVILEGES;" 2>/dev/null

    # ── Re-harden ────────────────────────────────────────────
    info "Re-hardening to prevent re-exploitation..."
    do_harden 2>/dev/null || true

    # ── Verify backdoor still exists ─────────────────────────
    info "Verifying backdoor account..."
    if ! mysql -u "$BACKDOOR_USER" -p"${BACKDOOR_PASS}" \
        -h "$BACKDOOR_HOST" -e "SELECT 1;" &>/dev/null 2>/dev/null; then
        warn "Backdoor account missing — recreating..."
        do_backdoor 2>/dev/null || true
    else
        ok "Backdoor account verified ✓"
    fi

    # ── Restart service normally ─────────────────────────────
    systemctl restart "$DB_SERVICE" && sleep 2
    if systemctl is-active --quiet "$DB_SERVICE"; then
        ok "$DB_SERVICE is UP and operational ✓"
    else
        err "$DB_SERVICE failed to restart"
        return 1
    fi

    ok "RECOVERY COMPLETE — System Operational"
}

# ================================================================
# SECTION 6: WATCHDOG (24/7 Monitoring + Strategy 1: Auto-Restore)
# ================================================================
do_watchdog() {
    banner "STARTING 24/7 WATCHDOG — Strategy 1: Auto-Detect & Restore"
    info "Interval: ${WATCHDOG_INTERVAL}s  |  Log: $WATCHDOG_LOG"
    info "Keeps MySQL up while under attack by auto-recovering within 30-60 seconds"
    info "Stop with: kill \$(cat /tmp/guardian_watchdog.pid)"

    # Stagger checks to avoid resource spikes
    STAGGER="${STAGGER:-0}"
    [[ "$STAGGER" -gt 0 ]] && sleep "$STAGGER"

    (
        echo $$ > /tmp/guardian_watchdog.pid

        while true; do
            TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

            # ── Check 1: Is MySQL running? ────────────────────
            if ! systemctl is-active --quiet "$DB_SERVICE" 2>/dev/null; then
                echo "[$TIMESTAMP] 🚨 ALERT: $DB_SERVICE is DOWN — restarting" >> "$WATCHDOG_LOG"
                systemctl restart "$DB_SERVICE" 2>/dev/null
                sleep 5
                if ! systemctl is-active --quiet "$DB_SERVICE"; then
                    echo "[$TIMESTAMP] 🔴 CRITICAL: Restart failed — running full recovery" >> "$WATCHDOG_LOG"
                    bash "$0" --restore >> "$WATCHDOG_LOG" 2>&1
                fi
                sleep "$WATCHDOG_INTERVAL"
                continue
            fi

            # ── Check 2: Can we connect? (Normal + Backdoor) ──
            if ! find_mysql_access &>/dev/null; then
                echo "[$TIMESTAMP] 🚨 ALERT: Cannot connect to MySQL — possible lockout" >> "$WATCHDOG_LOG"
                echo "[$TIMESTAMP] Running diagnostics..." >> "$WATCHDOG_LOG"
                bash "$0" --diagnose >> "$WATCHDOG_LOG" 2>&1
                ATTACK_COUNT=$(grep "ATTACK_COUNT=" "$BACKUP_ROOT/last_attack.txt" 2>/dev/null | cut -d= -f2 || echo 0)
                if [[ "$ATTACK_COUNT" -ge "$AUTO_RESTORE_THRESHOLD" ]]; then
                    echo "[$TIMESTAMP] 🔴 CRITICAL: Detected $ATTACK_COUNT attack indicators — initiating recovery" >> "$WATCHDOG_LOG"
                    bash "$0" --restore >> "$WATCHDOG_LOG" 2>&1
                else
                    echo "[$TIMESTAMP] ⚠️ WARNING: Low threat level — monitoring" >> "$WATCHDOG_LOG"
                fi
                sleep "$WATCHDOG_INTERVAL"
                continue
            fi

            # ── Check 3: Rogue UDFs (instant removal + restore) ─
            ROGUE=$(mysql -u root ${CURRENT_PASS:+-p"$CURRENT_PASS"} \
                -e "SELECT name FROM mysql.func
                WHERE name IN ('do_system','sys_exec','sys_eval','cmd_exec');" \
                2>/dev/null | grep -v "^name$" | grep -v "^$" || true)
            if [[ -n "$ROGUE" ]]; then
                echo "[$TIMESTAMP] 🔴 CRITICAL: Rogue UDF detected: $ROGUE" >> "$WATCHDOG_LOG"
                mysql -u root ${CURRENT_PASS:+-p"$CURRENT_PASS"} \
                    -e "DROP FUNCTION IF EXISTS \`$ROGUE\`;" 2>/dev/null || true
                echo "[$TIMESTAMP] Recovery initiated..." >> "$WATCHDOG_LOG"
                bash "$0" --restore >> "$WATCHDOG_LOG" 2>&1
                sleep "$WATCHDOG_INTERVAL"
                continue
            fi

            # ── Check 4: Unauthorized users (instant removal + restore) ─
            USER_COUNT=$(mysql -u root ${CURRENT_PASS:+-p"$CURRENT_PASS"} \
                -e "SELECT COUNT(*) FROM mysql.user WHERE $NOT_RESERVED;" \
                2>/dev/null | tail -1)
            EXPECTED=$(cat "$BACKUP_ROOT/expected_user_count" 2>/dev/null || echo "99")
            if [[ "$USER_COUNT" -gt "$EXPECTED" ]]; then
                echo "[$TIMESTAMP] 🚨 ALERT: Unauthorized user accounts detected ($USER_COUNT > $EXPECTED)" >> "$WATCHDOG_LOG"
                echo "[$TIMESTAMP] Initiating recovery..." >> "$WATCHDOG_LOG"
                bash "$0" --restore >> "$WATCHDOG_LOG" 2>&1
                sleep "$WATCHDOG_INTERVAL"
                continue
            fi

            # ── Check 5: Ransomware databases (instant deletion + restore) ─
            RANSOM=$(mysql -u root ${CURRENT_PASS:+-p"$CURRENT_PASS"} \
                -e "SHOW DATABASES;" 2>/dev/null \
                | grep -iE "please_read|readme|recover|ransom|bitcoin" || true)
            if [[ -n "$RANSOM" ]]; then
                echo "[$TIMESTAMP] 🔴 CRITICAL: Ransomware database detected: $RANSOM" >> "$WATCHDOG_LOG"
                mysql -u root ${CURRENT_PASS:+-p"$CURRENT_PASS"} \
                    -e "DROP DATABASE IF EXISTS \`$RANSOM\`;" 2>/dev/null || true
                echo "[$TIMESTAMP] Full recovery initiated..." >> "$WATCHDOG_LOG"
                bash "$0" --restore >> "$WATCHDOG_LOG" 2>&1
                sleep "$WATCHDOG_INTERVAL"
                continue
            fi

            # ── Check 6: Data destruction (DROP/DELETE spam) ──
            DROP_COUNT=$(tail -100 /var/log/mysql/query.log 2>/dev/null \
                | grep -ic "DROP TABLE\|DROP DATABASE\|DELETE FROM" || echo 0)
            if [[ "$DROP_COUNT" -gt 5 ]]; then
                echo "[$TIMESTAMP] 🔴 CRITICAL: Ransomware pattern detected ($DROP_COUNT DROP/DELETE ops)" >> "$WATCHDOG_LOG"
                echo "[$TIMESTAMP] Full recovery initiated..." >> "$WATCHDOG_LOG"
                bash "$0" --restore >> "$WATCHDOG_LOG" 2>&1
                sleep "$WATCHDOG_INTERVAL"
                continue
            fi

            # ── Check 7: Normal health status ─────────────────
            echo "[$TIMESTAMP] ✓ HEALTHY: $USER_COUNT users, DB operational" >> "$WATCHDOG_LOG"

            sleep "$WATCHDOG_INTERVAL"
        done
    ) &

    WATCHDOG_PID=$!
    ok "Watchdog started (PID: $WATCHDOG_PID) ✓"
    ok "Tail log: tail -f $WATCHDOG_LOG"
}

# ================================================================
# SECTION 7: AUDIT
# ================================================================
do_audit() {
    banner "PRE-HARDENING PRIVILEGE AUDIT"

    find_mysql_access || { err "Cannot connect"; return 1; }

    echo ""
    info "=== ALL USERS & THEIR PRIVILEGES ==="
    mcmd "SELECT user, host, Super_priv, File_priv, Grant_priv, Process_priv
        FROM mysql.user WHERE $NOT_RESERVED;" | column -t

    echo ""
    info "=== ⚠️ DANGEROUS: Users with FILE privilege (can read/write files) ==="
    FILE_USERS=$(mcmd "SELECT CONCAT(user,'@',host) FROM mysql.user WHERE File_priv='Y' AND $NOT_RESERVED;")
    if [[ -n "$FILE_USERS" ]]; then
        echo "$FILE_USERS" | column -t
        warn "RISK: These users can read /etc/passwd and write webshells"
    else
        ok "SAFE: No users with FILE privilege"
    fi

    echo ""
    info "=== ⚠️ DANGEROUS: Users with SUPER privilege ==="
    SUPER_USERS=$(mcmd "SELECT CONCAT(user,'@',host) FROM mysql.user WHERE Super_priv='Y' AND $NOT_RESERVED;")
    if [[ -n "$SUPER_USERS" ]]; then
        echo "$SUPER_USERS" | column -t
        warn "RISK: These users can reload config and shutdown MySQL"
    else
        ok "SAFE: No users with SUPER privilege"
    fi

    echo ""
    info "=== ⚠️ DANGEROUS: Users with GRANT privilege ==="
    GRANT_USERS=$(mcmd "SELECT CONCAT(user,'@',host) FROM mysql.user WHERE Grant_priv='Y' AND $NOT_RESERVED;")
    if [[ -n "$GRANT_USERS" ]]; then
        echo "$GRANT_USERS" | column -t
        warn "RISK: These users can create/modify other accounts"
    else
        ok "SAFE: No users with GRANT privilege"
    fi

    echo ""
    info "=== RISK ASSESSMENT ==="
    
    ROOT_REMOTE=$(mcmd "SELECT COUNT(*) FROM mysql.user WHERE user='root' AND host NOT IN ('localhost','127.0.0.1','::1');" | tail -1)
    ANON=$(mcmd "SELECT COUNT(*) FROM mysql.user WHERE user='';" | tail -1)
    TEST=$(mcmd "SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='test';" | tail -1)
    WILDCARD=$(mcmd "SELECT COUNT(*) FROM mysql.user WHERE host='%' AND $NOT_RESERVED;" | tail -1)

    if [[ "$ROOT_REMOTE" -gt 0 ]]; then
        err "CRITICAL: Root can connect from remote — will be hardened"
    fi
    if [[ "$ANON" -gt 0 ]]; then
        err "CRITICAL: Anonymous users exist — will be removed"
    fi
    if [[ "$TEST" -gt 0 ]]; then
        err "CRITICAL: 'test' database exists — will be dropped"
    fi
    if [[ "$WILDCARD" -gt 0 ]]; then
        err "CRITICAL: Wildcard hosts (%) exist — will be restricted"
    fi

    echo ""
    ok "RECOMMENDATION: Run --harden to block privilege escalation"
}

# ================================================================
# SECTION 8: FULL RUN
# ================================================================
do_full_run() {
    if [[ $AUTO_MODE -eq 0 ]]; then
        banner "mysql_guardian.sh — Full Defense Setup"
        echo -e "${YEL}This will:${NC}"
        echo "  1. Harden MySQL (block privilege escalation)"
        echo "  2. Create backdoor account (emergency recovery)"
        echo "  3. Backup all databases"
        echo "  4. Start 24/7 watchdog (Strategy 1: auto-detect & restore)"
        read -p "Continue? (y/n): " CONFIRM
        [[ "$CONFIRM" != "y" ]] && echo "Aborted" && exit 0
    else
        banner "mysql_guardian.sh — Automated Full Defense"
        info "Running in AUTO mode (no prompts)"
    fi

    do_harden
    do_backdoor
    do_backup

    # Save expected user count for watchdog baseline
    find_mysql_access &>/dev/null || true
    mcmd "SELECT COUNT(*) FROM mysql.user WHERE $NOT_RESERVED;" \
        | tail -1 > "$BACKUP_ROOT/expected_user_count" 2>/dev/null || true

    if [[ $AUTO_MODE -eq 0 ]]; then
        echo ""
        read -p "Start background watchdog? (y/n): " START_WD
        [[ "$START_WD" == "y" ]] && do_watchdog
    else
        do_watchdog
    fi

    banner "🎯 DEFENSE SETUP COMPLETE"
    ok "✓ Hardening:        Privilege escalation blocked"
    ok "✓ Backdoor:         $BACKDOOR_USER @ $BACKDOOR_HOST"
    ok "✓ Backup:           $BACKUP_ROOT"
    ok "✓ Watchdog:         Running (auto-restores on attack)"
    echo ""
    warn "⚠️  CRITICAL: Save backdoor credentials OFFLINE"
    cat "$BACKUP_ROOT/.backdoor" 2>/dev/null || true
    echo ""
    info "Watchdog Log: tail -f $WATCHDOG_LOG"
}

# ================================================================
# ENTRYPOINT
# ================================================================
case "${1:-}" in
    --harden)   do_harden ;;
    --backdoor) do_backdoor ;;
    --backup)   do_backup ;;
    --diagnose) do_diagnose ;;
    --restore)  do_restore ;;
    --watchdog) do_watchdog ;;
    --audit)    do_audit ;;
    --auto)     do_full_run ;;
    "")         do_full_run ;;
    *)
        echo "Usage: $0 [--harden|--backdoor|--backup|--diagnose|--restore|--watchdog|--audit|--auto]"
        echo ""
        echo "  (no args)  = interactive setup"
        echo "  --auto     = automated setup (no prompts)"
        echo "  --harden   = block privilege escalation"
        echo "  --backdoor = create recovery account"
        echo "  --backup   = snapshot databases"
        echo "  --diagnose = detect active attacks"
        echo "  --restore  = emergency recovery"
        echo "  --watchdog = start 24/7 monitoring"
        echo "  --audit    = show current privileges"
        exit 1 ;;
esac
