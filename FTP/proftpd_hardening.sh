#!/bin/bash
# ======================================================================
# PROFTPD HARDENING SCRIPT — Distro-Agnostic (CCDC)
# ======================================================================
# Description:
#   Hardens a ProFTPD installation for competition use:
#     - Disables anonymous access
#     - Creates an allowed-user whitelist (only listed users may log in)
#     - Auto-detects chroot mode:
#         • Shared root: if existing config has DefaultRoot pointing to a
#           specific path, or you pass one on the command line
#         • Per-user: each user chrooted into their own home directory (~)
#     - Sets secure file/directory permissions
#     - Configures passive port range (with firewall warning)
#     - Enables TLS if a certificate is available
#     - Strips version info from the banner
#     - Applies additional hardening (connection limits, timeouts, etc.)
#     - Idempotent: safe to re-run
#
# Usage:
#   sudo ./proftpd_hardening.sh <userlist.txt> [ftp_root]
#
#   userlist.txt  — one username per line (must be existing local users)
#   ftp_root      — optional shared FTP root directory
#                   If omitted, the script auto-detects:
#                     1. Reads DefaultRoot from existing proftpd.conf → shared mode
#                     2. If DefaultRoot is ~ or not found → per-user home dir mode
#
# Notes:
#   - Must be run as root.
#   - Backs up proftpd.conf before making changes.
#   - Works on Debian/Ubuntu, RHEL/CentOS/Fedora, Arch, Alpine, SUSE.
# ======================================================================

set -euo pipefail

# ---------------------------
# Color helpers
# ---------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

# ---------------------------
# Pre-flight checks
# ---------------------------
if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root (use sudo)."
fi

if [[ -z "${1:-}" ]]; then
    echo "Usage: sudo $0 <userlist.txt> [ftp_root]"
    echo "  userlist.txt — file with one allowed FTP username per line"
    echo "  ftp_root     — shared FTP root (optional; auto-detects if omitted)"
    exit 1
fi

#apply fix to proftpd conf. It won't start without this
set +euo pipefail
echo 'LoadModule mod_delay.c' | tee -a /etc/proftpd/modules.conf > /dev/null
echo 'LoadModule mod_ls.c' | tee -a /etc/proftpd/modules.conf > /dev/null
echo 'LoadModule mod_xfer.c' | tee -a /etc/proftpd/modules.conf > /dev/null
set -euo pipefail

USERLIST_INPUT="$1"
FTP_ROOT_ARG="${2:-}"    # empty if not provided — triggers auto-detection later

if [[ ! -f "$USERLIST_INPUT" ]]; then
    error "Userlist file not found: $USERLIST_INPUT"
fi

# ---------------------------
# Detect distro & package mgr
# ---------------------------
detect_pkg_manager() {
    if command -v apt-get &>/dev/null; then
        PKG_MGR="apt"
    elif command -v dnf &>/dev/null; then
        PKG_MGR="dnf"
    elif command -v yum &>/dev/null; then
        PKG_MGR="yum"
    elif command -v pacman &>/dev/null; then
        PKG_MGR="pacman"
    elif command -v apk &>/dev/null; then
        PKG_MGR="apk"
    elif command -v zypper &>/dev/null; then
        PKG_MGR="zypper"
    else
        error "Unsupported package manager. Install proftpd manually and re-run."
    fi
    info "Detected package manager: $PKG_MGR"
}

install_proftpd() {
    if command -v proftpd &>/dev/null; then
        info "proftpd is already installed."
        return
    fi
    detect_pkg_manager
    warn "proftpd not found — installing..."
    case "$PKG_MGR" in
        apt)    apt-get update -qq && apt-get install -y -qq proftpd-basic ;;
        dnf)    dnf install -y -q proftpd ;;
        yum)    yum install -y -q proftpd ;;
        pacman) pacman -S --noconfirm proftpd ;;
        apk)    apk add --quiet proftpd ;;
        zypper) zypper install -y proftpd ;;
    esac
    info "proftpd installed."
}

# ---------------------------
# Detect init system
# ---------------------------
restart_proftpd() {
    if command -v systemctl &>/dev/null && systemctl list-units --type=service &>/dev/null 2>&1; then
        systemctl restart proftpd.service
        systemctl enable proftpd.service 2>/dev/null || true
        info "proftpd restarted & enabled (systemd)."
    elif command -v rc-service &>/dev/null; then
        rc-service proftpd restart
        rc-update add proftpd default 2>/dev/null || true
        info "proftpd restarted & enabled (OpenRC)."
    elif command -v service &>/dev/null; then
        service proftpd restart
        info "proftpd restarted (SysVinit)."
    else
        warn "Could not detect init system — restart proftpd manually."
    fi
}

# ---------------------------
# Locate proftpd.conf
# ---------------------------
find_proftpd_conf() {
    for path in /etc/proftpd/proftpd.conf /etc/proftpd.conf; do
        if [[ -f "$path" ]]; then
            PROFTPD_CONF="$path"
            info "Found config: $PROFTPD_CONF"
            return
        fi
    done
    error "Cannot find proftpd.conf. Is proftpd installed?"
}

# Detect the config directory (for Include-able drop-ins)
get_conf_dir() {
    CONF_DIR="$(dirname "$PROFTPD_CONF")"
    # On Debian, the conf.d dir is usually /etc/proftpd/conf.d
    if [[ -d "${CONF_DIR}/conf.d" ]]; then
        CONF_D="${CONF_DIR}/conf.d"
    else
        mkdir -p "${CONF_DIR}/conf.d"
        CONF_D="${CONF_DIR}/conf.d"
    fi
    info "Drop-in config directory: $CONF_D"
}

# ======================================================================
# MAIN
# ======================================================================
install_proftpd
find_proftpd_conf
get_conf_dir

# --- Backup original config ---
BACKUP="${PROFTPD_CONF}.bak.$(date +%Y%m%d%H%M%S)"
cp "$PROFTPD_CONF" "$BACKUP"
info "Config backed up to: $BACKUP"

# ---------------------------
# Detect chroot mode from existing config
# ---------------------------
CHROOT_MODE=""
FTP_ROOT=""

if [[ -n "$FTP_ROOT_ARG" ]]; then
    CHROOT_MODE="shared"
    FTP_ROOT="$FTP_ROOT_ARG"
    info "Chroot mode: SHARED (from argument: $FTP_ROOT)"
else
    # Check the backup for an existing DefaultRoot that isn't ~
    EXISTING_ROOT="$(grep -E "^[[:space:]]*DefaultRoot[[:space:]]+" "$BACKUP" 2>/dev/null \
        | tail -1 | awk '{print $2}' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')" || true
    if [[ -n "$EXISTING_ROOT" && "$EXISTING_ROOT" != "~" ]]; then
        CHROOT_MODE="shared"
        FTP_ROOT="$EXISTING_ROOT"
        info "Chroot mode: SHARED (detected from existing config: $FTP_ROOT)"
    else
        CHROOT_MODE="per-user"
        info "Chroot mode: PER-USER (each user gets chrooted to their home dir)"
    fi
fi

# ---------------------------
# Build allowed user list
# ---------------------------
FTPD_ALLOWED="/etc/proftpd/ftpd.allowed_users"
info "Building allowed userlist: $FTPD_ALLOWED"

# Ensure parent dir exists
mkdir -p "$(dirname "$FTPD_ALLOWED")"

: > "$FTPD_ALLOWED"
chmod 600 "$FTPD_ALLOWED"

ADDED=0
SKIPPED=0
ALLOWED_USERS=()

while read -r user || [[ -n "$user" ]]; do
    [[ -z "$user" || "$user" == \#* ]] && continue
    if id "$user" &>/dev/null; then
        echo "$user" >> "$FTPD_ALLOWED"
        ALLOWED_USERS+=("$user")
        ADDED=$((ADDED + 1))
    else
        warn "User '$user' does not exist on this system — skipped."
        SKIPPED=$((SKIPPED + 1))
    fi
done < "$USERLIST_INPUT"

info "Added $ADDED user(s) to whitelist ($SKIPPED skipped)."

if [[ "$ADDED" -eq 0 ]]; then
    warn "WARNING: No valid users in whitelist — ALL FTP logins will be denied!"
    warn "Verify your userlist.txt contains valid local usernames."
fi

# ---------------------------
# Create ftp_users group
# ---------------------------
if ! getent group ftp_users &>/dev/null; then
    groupadd ftp_users
    info "Created group: ftp_users"
fi

# Add whitelisted users to ftp_users group
while read -r user || [[ -n "$user" ]]; do
    [[ -z "$user" ]] && continue
    usermod -aG ftp_users "$user" 2>/dev/null || true
done < "$FTPD_ALLOWED"

# ---------------------------
# FTP root permissions
# ---------------------------
# Helper: lock down a single chroot directory
harden_chroot_dir() {
    local dir="$1"
    if [[ ! -d "$dir" ]]; then
        mkdir -p "$dir"
        info "  Created: $dir"
    fi

    # Chroot root must be owned by root and writable by the FTP user
    chown root:ftp_users "$dir"
    chmod 2775 "$dir"

    # Writable subdirectory for uploads
    local upload_dir="$dir/uploads"
    if [[ ! -d "$upload_dir" ]]; then
        mkdir -p "$upload_dir"
        info "  Created writable subdirectory: $upload_dir"
    fi
    chown root:ftp_users "$upload_dir"
    chmod 2775 "$upload_dir"

    # Fix ownership/permissions on all contents
    find "$dir" -mindepth 1 -type d -exec chown root:ftp_users {} + -exec chmod 2775 {} +
    find "$dir" -mindepth 1 -type f -exec chown root:ftp_users {} + -exec chmod 0664 {} +

    # Re-enforce chroot root
    chmod 2775 "$dir"
}

if [[ "$CHROOT_MODE" == "shared" ]]; then
    info "Setting shared FTP root permissions on: $FTP_ROOT"
    harden_chroot_dir "$FTP_ROOT"
    info "Permissions applied (chroot root=755, uploads=2775, group=ftp_users)."
else
    info "Setting per-user home directory permissions..."
    while read -r user || [[ -n "$user" ]]; do
        [[ -z "$user" ]] && continue
        home_dir="$(getent passwd "$user" 2>/dev/null | cut -d: -f6)" || true
        if [[ -z "$home_dir" || ! -d "$home_dir" ]]; then
            warn "  $user: home directory not found — skipping permissions"
            continue
        fi
        info "  Hardening: $user → $home_dir"
        harden_chroot_dir "$home_dir"
    done < "$FTPD_ALLOWED"
    info "Per-user permissions applied (each home=755, uploads/=2775, group=ftp_users)."
    warn "NOTE: Home directories are now root-owned and read-only at the top level."
    warn "Users who also SSH in cannot write to ~ (only to ~/uploads/)."
    warn "If this is a problem, consider using a separate FTP-only directory structure."
fi

# ---------------------------
# TLS detection
# ---------------------------
TLS_CERT="/etc/ssl/certs/proftpd.pem"
TLS_KEY="/etc/ssl/private/proftpd.key"
TLS_ENABLED="NO"

if [[ -f "$TLS_CERT" && -f "$TLS_KEY" ]]; then
    TLS_ENABLED="YES"
    info "TLS certificate found — will enable FTPS."
else
    warn "No TLS cert found at $TLS_CERT — TLS will be disabled."
    warn "To enable TLS, generate a cert and re-run:"
    warn "  openssl req -x509 -nodes -days 365 -newkey rsa:2048 \\"
    warn "    -keyout $TLS_KEY -out $TLS_CERT"
fi

# ---------------------------
# Build the AllowUser directive list
# ---------------------------
# ProFTPD <Limit LOGIN> uses AllowUser per user
build_allow_user_lines() {
    local indent="$1"
    while read -r user || [[ -n "$user" ]]; do
        [[ -z "$user" ]] && continue
        echo "${indent}AllowUser ${user}"
    done < "$FTPD_ALLOWED"
}

ALLOW_USER_BLOCK="$(build_allow_user_lines "    ")"

# ---------------------------
# Determine DefaultRoot directive
# ---------------------------
if [[ "$CHROOT_MODE" == "shared" ]]; then
    DEFAULT_ROOT_LINE="DefaultRoot                  ${FTP_ROOT}"
else
    DEFAULT_ROOT_LINE="DefaultRoot                  ~"
fi

# ---------------------------
# Write the hardened proftpd.conf
# ---------------------------
info "Writing hardened configuration to $PROFTPD_CONF ..."

cat > "$PROFTPD_CONF" << 'PROFTPD_CONF_HEADER'
# ======================================================================
# PROFTPD HARDENED CONFIGURATION — Auto-generated by hardening script
# ======================================================================
# WARNING: This file is overwritten each time the hardening script runs.
#          The original config was backed up before modification.
# ======================================================================

PROFTPD_CONF_HEADER

cat >> "$PROFTPD_CONF" << PROFTPD_CONF_BODY
# ---------------------------
# Load modules (Debian/Ubuntu ship a separate modules.conf)
# ---------------------------
PROFTPD_CONF_BODY

# Dynamically include modules.conf if it exists
MODULES_FILE=""
for mpath in /etc/proftpd/modules.conf /etc/proftpd/conf.d/modules.conf; do
    if [[ -f "$mpath" ]]; then
        MODULES_FILE="$mpath"
        break
    fi
done

if [[ -n "$MODULES_FILE" ]]; then
    echo "Include ${MODULES_FILE}" >> "$PROFTPD_CONF"
    info "Including modules file: $MODULES_FILE"
else
    warn "No modules.conf found — some directives may not work."
fi

echo "" >> "$PROFTPD_CONF"

cat >> "$PROFTPD_CONF" << PROFTPD_CONF_BODY
# ---------------------------
# Server identity & basics
# ---------------------------
ServerName                   "FTP Service"
ServerIdent                  on "FTP Service Ready"
DeferWelcome                 on
DefaultServer                on

# ---------------------------
# Network & listener
# ---------------------------
Port                         21
UseIPv6                      off
# Bind to all interfaces; change if you need a specific IP
# DefaultAddress             0.0.0.0

# ---------------------------
# Chroot configuration
# ---------------------------
${DEFAULT_ROOT_LINE}

# ---------------------------
# Disable anonymous access
# ---------------------------
# No <Anonymous> blocks — anonymous FTP is completely disabled.
# If a previous config had <Anonymous> sections, they have been removed.

# ---------------------------
# User authentication & whitelist
# ---------------------------
# Only users listed in the <Limit LOGIN> block may authenticate.
# Root login is always denied.
RootLogin                    off
RequireValidShell            off
AuthOrder                    mod_auth_pam.c* mod_auth_unix.c
<IfModule mod_auth_pam.c>
    AuthPAM                  on
</IfModule>

<Limit LOGIN>
${ALLOW_USER_BLOCK}
    DenyAll
</Limit>

# ---------------------------
# Connection limits & timeouts
# ---------------------------
MaxInstances                 50
MaxClientsPerHost            3
MaxLoginAttempts             3
TimeoutIdle                  300
TimeoutLogin                 60

# ---------------------------
# File & directory permissions
# ---------------------------
Umask                        007 007
# Hide real UIDs/GIDs from directory listings
DirFakeUser                  on ftp
DirFakeGroup                 on ftp

# allow writing to the chroot root
<Directory />
    <Limit WRITE STOR MKD RMD DELE RNFR RNTO>
        AllowAll
    </Limit>
</Directory>

# Allow writes in the uploads/ subdirectory
<Directory ~/uploads>
    <Limit WRITE STOR MKD RMD DELE RNFR RNTO>
        AllowAll
    </Limit>
</Directory>

PROFTPD_CONF_BODY

# Add shared-root uploads directory if in shared mode
if [[ "$CHROOT_MODE" == "shared" ]]; then
    cat >> "$PROFTPD_CONF" << SHARED_UPLOADS
<Directory ${FTP_ROOT}/uploads>
    <Limit WRITE STOR MKD RMD DELE RNFR RNTO>
        AllowAll
    </Limit>
</Directory>

SHARED_UPLOADS
fi

cat >> "$PROFTPD_CONF" << 'PROFTPD_CONF_PASSIVE'
# ---------------------------
# Passive mode (firewall-friendly)
# ---------------------------
PassivePorts                 40000 40100

# ---------------------------
# Disable dangerous commands
# ---------------------------
# Disable SITE EXEC and recursive listing abuse
<Limit SITE_EXEC>
    DenyAll
</Limit>

# Prevent CHMOD abuse (users shouldn't change permissions)
<Limit SITE_CHMOD>
    DenyAll
</Limit>

# ---------------------------
# Logging
# ---------------------------
TransferLog                  /var/log/proftpd/xferlog
SystemLog                    /var/log/proftpd/proftpd.log
ExtendedLog                  /var/log/proftpd/access.log WRITE,READ default
ExtendedLog                  /var/log/proftpd/auth.log AUTH auth

LogFormat                    default "%h %l %u %t \"%r\" %s %b"
LogFormat                    auth    "%v [%P] %h %t \"%r\" %s"

PROFTPD_CONF_PASSIVE

# ---------------------------
# TLS block (conditional)
# ---------------------------
if [[ "$TLS_ENABLED" == "YES" ]]; then
    info "Writing TLS configuration..."
    cat >> "$PROFTPD_CONF" << PROFTPD_TLS
# ---------------------------
# TLS / FTPS configuration
# ---------------------------
<IfModule mod_tls.c>
    TLSEngine                on
    TLSLog                   /var/log/proftpd/tls.log
    TLSProtocol              TLSv1.2 TLSv1.3
    TLSCipherSuite           HIGH:!aNULL:!MD5:!RC4:!eNULL:!EXPORT
    TLSCertificateFile       ${TLS_CERT}
    TLSCertificateKeyFile    ${TLS_KEY}
    TLSRequired              on
    TLSVerifyClient          off
    TLSRenegotiate           required off
    TLSOptions               NoSessionReuseRequired
</IfModule>

PROFTPD_TLS
else
    cat >> "$PROFTPD_CONF" << 'PROFTPD_NOTLS'
# ---------------------------
# TLS / FTPS (disabled — no certificate found)
# ---------------------------
# To enable TLS, generate a certificate and re-run this script:
#   openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
#     -keyout /etc/ssl/private/proftpd.key -out /etc/ssl/certs/proftpd.pem
# <IfModule mod_tls.c>
#     TLSEngine              on
# </IfModule>

PROFTPD_NOTLS
fi

# ---------------------------
# Additional hardening directives
# ---------------------------
cat >> "$PROFTPD_CONF" << 'PROFTPD_CONF_EXTRA'
# ---------------------------
# Additional hardening
# ---------------------------
# Prevent symlink attacks
AllowStoreRestart            off
AllowRetrieveRestart         on
DeleteAbortedStores          on

# Disable ident lookups (requires mod_ident — skip if not loaded)
<IfModule mod_ident.c>
    IdentLookups             off
</IfModule>

UseReverseDNS                off

# Include any additional drop-in configs
Include /etc/proftpd/conf.d/*.conf
PROFTPD_CONF_EXTRA

# ---------------------------
# Ensure log directory exists
# ---------------------------
LOG_DIR="/var/log/proftpd"
if [[ ! -d "$LOG_DIR" ]]; then
    mkdir -p "$LOG_DIR"
    info "Created log directory: $LOG_DIR"
fi
chmod 750 "$LOG_DIR"

# ---------------------------
# Remove any existing anonymous config files
# ---------------------------
# Debian ships a separate anonymous config in conf.d
for anon_file in "${CONF_D}/anonymous.conf" "${CONF_D}/anon.conf"; do
    if [[ -f "$anon_file" ]]; then
        mv "$anon_file" "${anon_file}.disabled.$(date +%Y%m%d%H%M%S)"
        warn "Disabled anonymous config: $anon_file"
    fi
done

# Ensure modules.conf loads mod_tls if TLS is enabled
if [[ -n "${MODULES_FILE:-}" && "$TLS_ENABLED" == "YES" ]]; then
    # Uncomment mod_tls if it's commented out
    if grep -qE "^#.*LoadModule[[:space:]]+mod_tls\.c" "$MODULES_FILE" 2>/dev/null; then
        sed -i 's/^#\(.*LoadModule[[:space:]]*mod_tls\.c\)/\1/' "$MODULES_FILE"
        info "Enabled mod_tls in $MODULES_FILE"
    fi
fi

# ---------------------------
# Validate configuration
# ---------------------------
info "Validating configuration syntax..."
VALIDATION_OUTPUT="$(proftpd -t -c "$PROFTPD_CONF" 2>&1)" || true
if echo "$VALIDATION_OUTPUT" | grep -qi "fatal\|error"; then
    warn "Configuration syntax check failed:"
    echo "$VALIDATION_OUTPUT" | grep -i "fatal\|error" | while read -r line; do
        warn "  $line"
    done
    warn "The backup is at: $BACKUP"
else
    info "Configuration syntax OK."
fi

# ---------------------------
# Firewall reminder
# ---------------------------
echo
warn "REMINDER: Open FTP ports in your firewall."
warn "  Port 21 (control) and passive range 40000-40100 (data)."
warn "  iptables:  iptables -A INPUT -p tcp --dport 21 -j ACCEPT"
warn "            iptables -A INPUT -p tcp --dport 40000:40100 -j ACCEPT"
warn "  firewalld: firewall-cmd --add-service=ftp --permanent"
warn "            firewall-cmd --add-port=40000-40100/tcp --permanent && firewall-cmd --reload"
warn "  ufw:       ufw allow 21/tcp && ufw allow 40000:40100/tcp"
echo

# ---------------------------
# Done — restart service
# ---------------------------
info "Configuration complete. Restarting proftpd..."
restart_proftpd

echo
info "========================================="
info " ProFTPD hardening applied successfully."
info " Config  : $PROFTPD_CONF"
info " Backup  : $BACKUP"
info " Users   : $FTPD_ALLOWED ($ADDED users)"
if [[ "$CHROOT_MODE" == "shared" ]]; then
    info " Mode    : Shared root → $FTP_ROOT"
    info " Uploads : $FTP_ROOT/uploads (writable)"
else
    info " Mode    : Per-user home directories"
    info " Uploads : ~<user>/uploads (writable)"
fi
if [[ "$TLS_ENABLED" == "YES" ]]; then
    info " TLS     : ENABLED (TLSv1.2+)"
else
    info " TLS     : DISABLED (no certificate found)"
fi
info "========================================="
