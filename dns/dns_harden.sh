#!/usr/bin/env bash
# =============================================================================
# DNS Hardening Script — NCAE CyberGames
# Auto-detects Linux distro and DNS daemon, then interactively hardens it.
# Usage: sudo bash dns_harden.sh [--monitor]
# =============================================================================
set -euo pipefail

# ── Colors & Output Helpers ──────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()    { echo -e "${CYAN}[INFO]${NC} $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
success() { echo -e "${GREEN}[ OK ]${NC} $*"; }
error()   { echo -e "${RED}[FAIL]${NC} $*"; }
header()  { echo -e "\n${BOLD}═══ $* ═══${NC}\n"; }

confirm() {
    local msg="$1"
    local response
    echo -en "${YELLOW}[PROMPT]${NC} ${msg} [y/N]: "
    read -r response
    [[ "$response" =~ ^[Yy]([Ee][Ss])?$ ]]
}

# ── Globals ──────────────────────────────────────────────────────────────────

MODE="harden"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/root/dns_backup_${TIMESTAMP}"
CHANGES_LOG=()

DISTRO_ID=""
DISTRO_VERSION=""
DISTRO_NAME=""
PKG_MANAGER=""

DNS_DAEMON=""
DNS_SERVICE=""
DNS_CONFIG=""
DNS_CONFIG_DIR=""
DNS_USER=""
DNS_GROUP=""
DNS_LOG_FILE=""

# ── Argument Parsing ────────────────────────────────────────────────────────

for arg in "$@"; do
    case "$arg" in
        --monitor|-m) MODE="monitor" ;;
        --help|-h)
            echo "Usage: sudo bash $0 [--monitor]"
            echo "  --monitor, -m   Enter log monitoring mode"
            echo "  --help, -h      Show this help"
            exit 0
            ;;
        *) error "Unknown argument: $arg"; exit 1 ;;
    esac
done

# ── Root Check ───────────────────────────────────────────────────────────────

if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root (sudo)."
    exit 1
fi

# ── Utility: safe config editing ─────────────────────────────────────────────

# Append a line to a config file if it doesn't already exist
config_ensure_line() {
    local file="$1"
    local line="$2"
    if ! grep -qF "$line" "$file" 2>/dev/null; then
        echo "$line" >> "$file"
        return 0
    fi
    return 1
}

# Remove chattr immutable if set, return 0 if it was set
unlock_file() {
    local file="$1"
    if lsattr "$file" 2>/dev/null | grep -q '^\S*i'; then
        chattr -i "$file"
        return 0
    fi
    return 1
}

log_change() {
    CHANGES_LOG+=("$1")
}

# ── Distro Detection ────────────────────────────────────────────────────────

detect_distro() {
    header "Detecting Linux Distribution"

    if [[ -f /etc/os-release ]]; then
        # shellcheck source=/dev/null
        source /etc/os-release
        DISTRO_ID="${ID:-unknown}"
        DISTRO_VERSION="${VERSION_ID:-unknown}"
        DISTRO_NAME="${PRETTY_NAME:-${NAME:-unknown}}"
    elif [[ -f /etc/redhat-release ]]; then
        DISTRO_NAME=$(cat /etc/redhat-release)
        if echo "$DISTRO_NAME" | grep -qi centos; then
            DISTRO_ID="centos"
        elif echo "$DISTRO_NAME" | grep -qi "red hat"; then
            DISTRO_ID="rhel"
        elif echo "$DISTRO_NAME" | grep -qi fedora; then
            DISTRO_ID="fedora"
        else
            DISTRO_ID="rhel-family"
        fi
        DISTRO_VERSION=$(echo "$DISTRO_NAME" | grep -oP '\d+(\.\d+)?' | head -1)
    elif command -v lsb_release &>/dev/null; then
        DISTRO_ID=$(lsb_release -si | tr '[:upper:]' '[:lower:]')
        DISTRO_VERSION=$(lsb_release -sr)
        DISTRO_NAME=$(lsb_release -sd)
    else
        DISTRO_ID="unknown"
        DISTRO_VERSION="unknown"
        DISTRO_NAME="Unknown Linux"
    fi

    # Detect package manager
    if command -v apt-get &>/dev/null; then
        PKG_MANAGER="apt"
    elif command -v dnf &>/dev/null; then
        PKG_MANAGER="dnf"
    elif command -v yum &>/dev/null; then
        PKG_MANAGER="yum"
    elif command -v zypper &>/dev/null; then
        PKG_MANAGER="zypper"
    elif command -v pacman &>/dev/null; then
        PKG_MANAGER="pacman"
    elif command -v apk &>/dev/null; then
        PKG_MANAGER="apk"
    else
        PKG_MANAGER="unknown"
    fi

    info "Distribution : ${BOLD}${DISTRO_NAME}${NC}"
    info "Distro ID    : ${DISTRO_ID}"
    info "Version      : ${DISTRO_VERSION}"
    info "Pkg Manager  : ${PKG_MANAGER}"
}

# ── DNS Daemon Detection ────────────────────────────────────────────────────

detect_dns_daemon() {
    header "Detecting DNS Service"

    local -A daemons_found=()

    # Check for each known daemon via process, systemd unit, and binary
    # BIND9 / named
    if pgrep -x named &>/dev/null || systemctl is-active named &>/dev/null 2>&1 || \
       systemctl is-active bind9 &>/dev/null 2>&1 || command -v named &>/dev/null; then
        daemons_found[bind9]=1
    fi

    # Unbound
    if pgrep -x unbound &>/dev/null || systemctl is-active unbound &>/dev/null 2>&1 || \
       command -v unbound &>/dev/null; then
        daemons_found[unbound]=1
    fi

    # Dnsmasq
    if pgrep -x dnsmasq &>/dev/null || systemctl is-active dnsmasq &>/dev/null 2>&1 || \
       command -v dnsmasq &>/dev/null; then
        daemons_found[dnsmasq]=1
    fi

    # PowerDNS Authoritative
    if pgrep -x pdns_server &>/dev/null || systemctl is-active pdns &>/dev/null 2>&1 || \
       command -v pdns_server &>/dev/null; then
        daemons_found[pdns_auth]=1
    fi

    # PowerDNS Recursor
    if pgrep -x pdns_recursor &>/dev/null || systemctl is-active pdns-recursor &>/dev/null 2>&1 || \
       command -v pdns_recursor &>/dev/null; then
        daemons_found[pdns_recursor]=1
    fi

    # Knot DNS
    if pgrep -x knotd &>/dev/null || systemctl is-active knot &>/dev/null 2>&1 || \
       command -v knotd &>/dev/null; then
        daemons_found[knot]=1
    fi

    # NSD
    if pgrep -x nsd &>/dev/null || systemctl is-active nsd &>/dev/null 2>&1 || \
       command -v nsd &>/dev/null; then
        daemons_found[nsd]=1
    fi

    # CoreDNS
    if pgrep -x coredns &>/dev/null || systemctl is-active coredns &>/dev/null 2>&1 || \
       command -v coredns &>/dev/null; then
        daemons_found[coredns]=1
    fi

    # MaraDNS
    if pgrep -x maradns &>/dev/null || pgrep -x deadwood &>/dev/null || \
       systemctl is-active maradns &>/dev/null 2>&1 || command -v maradns &>/dev/null; then
        daemons_found[maradns]=1
    fi

    local count=${#daemons_found[@]}

    if [[ $count -eq 0 ]]; then
        error "No DNS daemon detected on this system."
        echo "Checked for: BIND9, Unbound, Dnsmasq, PowerDNS, Knot, NSD, CoreDNS, MaraDNS"
        exit 1
    fi

    if [[ $count -eq 1 ]]; then
        DNS_DAEMON="${!daemons_found[@]}"
    else
        info "Multiple DNS daemons detected:"
        local options=()
        local i=1
        for d in "${!daemons_found[@]}"; do
            echo "  ${i}) ${d}"
            options+=("$d")
            ((i++))
        done
        echo -en "${YELLOW}[PROMPT]${NC} Select daemon to harden [1-${#options[@]}]: "
        local choice
        read -r choice
        if [[ "$choice" -ge 1 && "$choice" -le ${#options[@]} ]] 2>/dev/null; then
            DNS_DAEMON="${options[$((choice-1))]}"
        else
            error "Invalid selection."
            exit 1
        fi
    fi

    # Set daemon-specific paths and metadata
    case "$DNS_DAEMON" in
        bind9)
            DNS_SERVICE=$(systemctl list-units --type=service --all 2>/dev/null | grep -oP '(named|bind9)\.service' | head -1)
            [[ -z "$DNS_SERVICE" ]] && DNS_SERVICE="named"
            DNS_SERVICE="${DNS_SERVICE%.service}"
            # Find config file
            if [[ -f /etc/bind/named.conf ]]; then
                DNS_CONFIG="/etc/bind/named.conf"
                DNS_CONFIG_DIR="/etc/bind"
            elif [[ -f /etc/named.conf ]]; then
                DNS_CONFIG="/etc/named.conf"
                DNS_CONFIG_DIR="/etc/named"
                [[ -d /etc/named ]] || DNS_CONFIG_DIR="/etc"
            elif [[ -f /etc/named/named.conf ]]; then
                DNS_CONFIG="/etc/named/named.conf"
                DNS_CONFIG_DIR="/etc/named"
            fi
            DNS_USER=$(ps -eo user,comm 2>/dev/null | awk '/named/{print $1; exit}')
            [[ -z "$DNS_USER" ]] && DNS_USER="bind"
            DNS_GROUP="$DNS_USER"
            DNS_LOG_FILE="/var/log/named/queries.log"
            ;;
        unbound)
            DNS_SERVICE="unbound"
            if [[ -f /etc/unbound/unbound.conf ]]; then
                DNS_CONFIG="/etc/unbound/unbound.conf"
                DNS_CONFIG_DIR="/etc/unbound"
            fi
            DNS_USER="unbound"
            DNS_GROUP="unbound"
            DNS_LOG_FILE="/var/log/unbound/unbound.log"
            ;;
        dnsmasq)
            DNS_SERVICE="dnsmasq"
            if [[ -f /etc/dnsmasq.conf ]]; then
                DNS_CONFIG="/etc/dnsmasq.conf"
                DNS_CONFIG_DIR="/etc/dnsmasq.d"
            fi
            DNS_USER="dnsmasq"
            DNS_GROUP="dnsmasq"
            DNS_LOG_FILE="/var/log/syslog"
            [[ -f /var/log/messages ]] && DNS_LOG_FILE="/var/log/messages"
            ;;
        pdns_auth)
            DNS_SERVICE="pdns"
            if [[ -f /etc/powerdns/pdns.conf ]]; then
                DNS_CONFIG="/etc/powerdns/pdns.conf"
                DNS_CONFIG_DIR="/etc/powerdns"
            elif [[ -f /etc/pdns/pdns.conf ]]; then
                DNS_CONFIG="/etc/pdns/pdns.conf"
                DNS_CONFIG_DIR="/etc/pdns"
            fi
            DNS_USER="pdns"
            DNS_GROUP="pdns"
            DNS_LOG_FILE="/var/log/syslog"
            [[ -f /var/log/messages ]] && DNS_LOG_FILE="/var/log/messages"
            ;;
        pdns_recursor)
            DNS_SERVICE="pdns-recursor"
            if [[ -f /etc/powerdns/recursor.conf ]]; then
                DNS_CONFIG="/etc/powerdns/recursor.conf"
                DNS_CONFIG_DIR="/etc/powerdns"
            elif [[ -f /etc/pdns-recursor/recursor.conf ]]; then
                DNS_CONFIG="/etc/pdns-recursor/recursor.conf"
                DNS_CONFIG_DIR="/etc/pdns-recursor"
            fi
            DNS_USER="pdns"
            DNS_GROUP="pdns"
            DNS_LOG_FILE="/var/log/syslog"
            [[ -f /var/log/messages ]] && DNS_LOG_FILE="/var/log/messages"
            ;;
        knot)
            DNS_SERVICE="knot"
            if [[ -f /etc/knot/knot.conf ]]; then
                DNS_CONFIG="/etc/knot/knot.conf"
                DNS_CONFIG_DIR="/etc/knot"
            elif [[ -f /etc/knot-dns/knot.conf ]]; then
                DNS_CONFIG="/etc/knot-dns/knot.conf"
                DNS_CONFIG_DIR="/etc/knot-dns"
            fi
            DNS_USER="knot"
            DNS_GROUP="knot"
            DNS_LOG_FILE="/var/log/knot/knot.log"
            ;;
        nsd)
            DNS_SERVICE="nsd"
            if [[ -f /etc/nsd/nsd.conf ]]; then
                DNS_CONFIG="/etc/nsd/nsd.conf"
                DNS_CONFIG_DIR="/etc/nsd"
            fi
            DNS_USER="nsd"
            DNS_GROUP="nsd"
            DNS_LOG_FILE="/var/log/syslog"
            [[ -f /var/log/messages ]] && DNS_LOG_FILE="/var/log/messages"
            ;;
        coredns)
            DNS_SERVICE="coredns"
            # CoreDNS config is usually a Corefile
            if [[ -f /etc/coredns/Corefile ]]; then
                DNS_CONFIG="/etc/coredns/Corefile"
                DNS_CONFIG_DIR="/etc/coredns"
            elif [[ -f /etc/Corefile ]]; then
                DNS_CONFIG="/etc/Corefile"
                DNS_CONFIG_DIR="/etc"
            fi
            DNS_USER="coredns"
            DNS_GROUP="coredns"
            DNS_LOG_FILE="/var/log/coredns/coredns.log"
            ;;
        maradns)
            DNS_SERVICE="maradns"
            if [[ -f /etc/mararc ]]; then
                DNS_CONFIG="/etc/mararc"
                DNS_CONFIG_DIR="/etc/maradns"
            fi
            DNS_USER="maradns"
            DNS_GROUP="maradns"
            DNS_LOG_FILE="/var/log/syslog"
            [[ -f /var/log/messages ]] && DNS_LOG_FILE="/var/log/messages"
            ;;
    esac

    # Validate we found the config
    if [[ -z "$DNS_CONFIG" || ! -f "$DNS_CONFIG" ]]; then
        warn "Could not auto-detect config file for ${DNS_DAEMON}."
        echo -en "${YELLOW}[PROMPT]${NC} Enter the path to the main config file: "
        read -r DNS_CONFIG
        if [[ ! -f "$DNS_CONFIG" ]]; then
            error "File not found: ${DNS_CONFIG}"
            exit 1
        fi
        DNS_CONFIG_DIR=$(dirname "$DNS_CONFIG")
    fi

    # Print summary
    echo ""
    info "DNS Daemon   : ${BOLD}${DNS_DAEMON}${NC}"
    info "Service Name : ${DNS_SERVICE}"
    info "Config File  : ${DNS_CONFIG}"
    info "Config Dir   : ${DNS_CONFIG_DIR}"
    info "Run User     : ${DNS_USER}"
    info "Log File     : ${DNS_LOG_FILE}"
    echo ""

    # Show current status
    info "Service status:"
    systemctl status "${DNS_SERVICE}" --no-pager -l 2>/dev/null || true
    echo ""

    # Show listening ports
    info "Listening on port 53:"
    ss -ulnp | grep ':53 ' 2>/dev/null || true
    ss -tlnp | grep ':53 ' 2>/dev/null || true
    echo ""
}

# ── Backup ───────────────────────────────────────────────────────────────────

backup_config() {
    header "Backup"

    if ! confirm "Back up current DNS configuration to ${BACKUP_DIR}?"; then
        warn "Skipping backup — proceeding at your own risk."
        return
    fi

    mkdir -p "$BACKUP_DIR"
    cp -a "$DNS_CONFIG_DIR" "${BACKUP_DIR}/config_dir/"
    # Also copy the main config if it's outside the config dir
    if [[ "$(dirname "$DNS_CONFIG")" != "$DNS_CONFIG_DIR" ]]; then
        cp -a "$DNS_CONFIG" "${BACKUP_DIR}/"
    fi

    # Daemon-specific config dump
    case "$DNS_DAEMON" in
        bind9)
            named-checkconf -p > "${BACKUP_DIR}/named_parsed.conf" 2>/dev/null || true
            ;;
        unbound)
            cp /etc/unbound/unbound.conf "${BACKUP_DIR}/unbound.conf.bak" 2>/dev/null || true
            ;;
        knot)
            knotc conf-export "${BACKUP_DIR}/knot_export.conf" 2>/dev/null || true
            ;;
    esac

    # Save zone files if accessible
    for zdir in /var/cache/bind /var/lib/named /var/lib/knot /var/db/nsd; do
        if [[ -d "$zdir" ]]; then
            cp -a "$zdir" "${BACKUP_DIR}/zones_$(basename "$zdir")/" 2>/dev/null || true
        fi
    done

    success "Backup saved to ${BACKUP_DIR}"
    log_change "Backed up configuration to ${BACKUP_DIR}"
}

# ═════════════════════════════════════════════════════════════════════════════
# Per-Daemon Hardening Functions
# ═════════════════════════════════════════════════════════════════════════════

# ── BIND9 ────────────────────────────────────────────────────────────────────

harden_bind9() {
    header "Hardening BIND9"

    local options_file="$DNS_CONFIG"
    # BIND may split config across files; find the options block
    # Check for named.conf.options (Debian/Ubuntu style)
    if [[ -f "${DNS_CONFIG_DIR}/named.conf.options" ]]; then
        options_file="${DNS_CONFIG_DIR}/named.conf.options"
        info "Using options file: ${options_file}"
    fi

    # 1. Disable version disclosure
    if confirm "Disable version disclosure? (version/hostname/server-id → none)"; then
        # Remove existing version/hostname/server-id lines, then add
        sed -i '/^\s*version\s/d; /^\s*hostname\s/d; /^\s*server-id\s/d' "$options_file"
        # Insert into options block
        if grep -q 'options\s*{' "$options_file"; then
            sed -i '/options\s*{/a\\tversion "none";\n\thostname "none";\n\tserver-id none;' "$options_file"
            success "Version disclosure disabled."
            log_change "BIND9: Disabled version/hostname/server-id disclosure"
        else
            warn "Could not find options block in ${options_file}. Add manually:"
            echo '  options { version "none"; hostname "none"; server-id none; };'
        fi
    fi

    # 2. Restrict zone transfers
    if confirm "Restrict zone transfers globally? (allow-transfer { none; })"; then
        sed -i '/^\s*allow-transfer\s/d' "$options_file"
        if grep -q 'options\s*{' "$options_file"; then
            sed -i '/options\s*{/a\\tallow-transfer { none; };' "$options_file"
            success "Zone transfers restricted globally."
            log_change "BIND9: Set allow-transfer { none; } globally"
        fi
    fi

    # 3. Restrict recursion
    if confirm "Restrict recursion to localhost and RFC1918 networks?"; then
        sed -i '/^\s*allow-recursion\s/d; /^\s*allow-query-cache\s/d' "$options_file"
        if grep -q 'options\s*{' "$options_file"; then
            sed -i '/options\s*{/a\\tallow-recursion { localhost; 10.0.0.0/8; 172.16.0.0/12; 192.168.0.0/16; };\n\tallow-query-cache { localhost; 10.0.0.0/8; 172.16.0.0/12; 192.168.0.0/16; };' "$options_file"
            success "Recursion restricted to internal networks."
            log_change "BIND9: Restricted recursion to localhost + RFC1918"
        fi
    fi

    # 4. Disable dynamic updates
    if confirm "Disable dynamic updates globally? (allow-update { none; })"; then
        # Add to options block as a global default
        sed -i '/^\s*allow-update\s.*{.*none.*}/d' "$options_file"
        if grep -q 'options\s*{' "$options_file"; then
            sed -i '/options\s*{/a\\tallow-update { none; };' "$options_file"
            success "Dynamic updates disabled globally."
            log_change "BIND9: Disabled dynamic updates"
        fi
    fi

    # 5. Enable response rate limiting
    if confirm "Enable Response Rate Limiting (RRL)? (mitigates DNS amplification)"; then
        if ! grep -q 'rate-limit' "$options_file" 2>/dev/null; then
            if grep -q 'options\s*{' "$options_file"; then
                sed -i '/options\s*{/a\\trate-limit {\n\t\tresponses-per-second 10;\n\t\twindow 5;\n\t};' "$options_file"
                success "RRL enabled (10 responses/sec, 5 sec window)."
                log_change "BIND9: Enabled RRL (10 rps, 5s window)"
            fi
        else
            info "RRL already configured."
        fi
    fi

    # 6. Minimize responses
    if confirm "Enable minimal responses? (reduces information leakage)"; then
        sed -i '/^\s*minimal-responses\s/d' "$options_file"
        if grep -q 'options\s*{' "$options_file"; then
            sed -i '/options\s*{/a\\tminimal-responses yes;' "$options_file"
            success "Minimal responses enabled."
            log_change "BIND9: Enabled minimal-responses"
        fi
    fi

    # 7. Validate configuration
    info "Validating BIND9 configuration..."
    if named-checkconf "$DNS_CONFIG" 2>&1; then
        success "Configuration is valid."
    else
        error "Configuration validation failed! Review the errors above."
        if confirm "Restore from backup?"; then
            cp -a "${BACKUP_DIR}/config_dir/"* "$DNS_CONFIG_DIR/" 2>/dev/null || true
            success "Restored from backup."
        fi
    fi
}

# ── Unbound ──────────────────────────────────────────────────────────────────

harden_unbound() {
    header "Hardening Unbound"

    local conf="$DNS_CONFIG"
    local conf_dir="${DNS_CONFIG_DIR}/unbound.conf.d"
    local hardening_conf="${conf_dir}/hardening.conf"

    # Create drop-in directory if it doesn't exist
    mkdir -p "$conf_dir" 2>/dev/null || true

    # Ensure include directive exists
    if ! grep -q "include.*unbound.conf.d" "$conf" 2>/dev/null; then
        echo 'include: "/etc/unbound/unbound.conf.d/*.conf"' >> "$conf"
    fi

    # We'll write hardening to a drop-in file to avoid mangling the main config
    echo "server:" > "$hardening_conf"

    # 1. Hide identity and version
    if confirm "Hide server identity and version?"; then
        {
            echo "    hide-identity: yes"
            echo "    hide-version: yes"
        } >> "$hardening_conf"
        success "Identity and version hidden."
        log_change "Unbound: hide-identity/hide-version enabled"
    fi

    # 2. Restrict access control
    if confirm "Restrict access to localhost and RFC1918 networks only?"; then
        {
            echo "    access-control: 0.0.0.0/0 refuse"
            echo "    access-control: 127.0.0.0/8 allow"
            echo "    access-control: 10.0.0.0/8 allow"
            echo "    access-control: 172.16.0.0/12 allow"
            echo "    access-control: 192.168.0.0/16 allow"
            echo "    access-control: ::1/128 allow"
        } >> "$hardening_conf"
        success "Access control restricted to internal networks."
        log_change "Unbound: Restricted access-control to localhost + RFC1918"
    fi

    # 3. Harden glue and additional data
    if confirm "Enable hardening options? (harden-glue, harden-dnssec-stripped, etc.)"; then
        {
            echo "    harden-glue: yes"
            echo "    harden-dnssec-stripped: yes"
            echo "    harden-referral-path: yes"
            echo "    harden-algo-downgrade: yes"
            echo "    use-caps-for-id: yes"
            echo "    val-clean-additional: yes"
        } >> "$hardening_conf"
        success "Hardening options enabled."
        log_change "Unbound: Enabled harden-glue, harden-dnssec-stripped, harden-referral-path, use-caps-for-id"
    fi

    # 4. Private address protection (prevent DNS rebinding)
    if confirm "Enable private address protection? (blocks rebinding attacks)"; then
        {
            echo "    private-address: 10.0.0.0/8"
            echo "    private-address: 172.16.0.0/12"
            echo "    private-address: 192.168.0.0/16"
            echo "    private-address: 169.254.0.0/16"
            echo "    private-address: fd00::/8"
            echo "    private-address: fe80::/10"
        } >> "$hardening_conf"
        success "Private address protection enabled."
        log_change "Unbound: Enabled private-address protection"
    fi

    # 5. Limit outstanding queries and cache
    if confirm "Set query and cache limits? (mitigates resource exhaustion)"; then
        {
            echo "    unwanted-reply-threshold: 10000"
            echo "    num-queries-per-thread: 1024"
            echo "    jostle-timeout: 200"
        } >> "$hardening_conf"
        success "Query limits set."
        log_change "Unbound: Set unwanted-reply-threshold=10000, num-queries-per-thread=1024"
    fi

    # 6. Enable logging
    if confirm "Enable query logging?"; then
        mkdir -p /var/log/unbound 2>/dev/null || true
        chown "${DNS_USER}:${DNS_GROUP}" /var/log/unbound 2>/dev/null || true
        {
            echo "    logfile: \"/var/log/unbound/unbound.log\""
            echo "    log-queries: yes"
            echo "    log-replies: yes"
            echo "    log-servfail: yes"
            echo "    verbosity: 1"
        } >> "$hardening_conf"
        success "Query logging enabled."
        log_change "Unbound: Enabled query/reply logging to /var/log/unbound/unbound.log"
    fi

    # Validate
    info "Validating Unbound configuration..."
    if unbound-checkconf "$conf" 2>&1; then
        success "Configuration is valid."
    else
        error "Configuration validation failed!"
        if confirm "Remove hardening drop-in and retry?"; then
            rm -f "$hardening_conf"
            warn "Removed ${hardening_conf}. Please review manually."
        fi
    fi
}

# ── Dnsmasq ──────────────────────────────────────────────────────────────────

harden_dnsmasq() {
    header "Hardening Dnsmasq"

    local conf="$DNS_CONFIG"

    # 1. Bind to specific interfaces
    if confirm "Restrict Dnsmasq to listen only on localhost? (bind-interfaces + listen-address)"; then
        sed -i '/^\s*listen-address\s*=/d; /^\s*bind-interfaces/d' "$conf"
        config_ensure_line "$conf" "bind-interfaces"
        config_ensure_line "$conf" "listen-address=127.0.0.1"
        info "NOTE: Add additional listen-address= lines for other interfaces as needed."
        success "Dnsmasq bound to localhost."
        log_change "Dnsmasq: Set bind-interfaces + listen-address=127.0.0.1"
    fi

    # 2. Disable open resolver
    if confirm "Enable local-service? (only responds to queries from directly connected networks)"; then
        config_ensure_line "$conf" "local-service"
        success "local-service enabled."
        log_change "Dnsmasq: Enabled local-service"
    fi

    # 3. Filter Windows DNS noise
    if confirm "Enable filterwin2k? (blocks SOA/SRV/A queries for Windows-only names)"; then
        config_ensure_line "$conf" "filterwin2k"
        success "filterwin2k enabled."
        log_change "Dnsmasq: Enabled filterwin2k"
    fi

    # 4. Disable TFTP
    if grep -q '^\s*enable-tftp' "$conf" 2>/dev/null; then
        if confirm "TFTP is enabled. Disable it?"; then
            sed -i 's/^\s*enable-tftp/#enable-tftp/' "$conf"
            success "TFTP disabled."
            log_change "Dnsmasq: Disabled TFTP"
        fi
    fi

    # 5. Set DNS cache size
    if confirm "Set DNS cache size to 1000 entries?"; then
        sed -i '/^\s*cache-size\s*=/d' "$conf"
        config_ensure_line "$conf" "cache-size=1000"
        success "Cache size set to 1000."
        log_change "Dnsmasq: Set cache-size=1000"
    fi

    # 6. Prevent DNS rebinding
    if confirm "Enable stop-dns-rebind? (blocks private IP responses from upstream)"; then
        config_ensure_line "$conf" "stop-dns-rebind"
        config_ensure_line "$conf" "rebind-localhost-ok"
        success "DNS rebinding protection enabled."
        log_change "Dnsmasq: Enabled stop-dns-rebind"
    fi

    # 7. Enable logging
    if confirm "Enable DNS query logging?"; then
        config_ensure_line "$conf" "log-queries"
        config_ensure_line "$conf" "log-facility=/var/log/dnsmasq.log"
        DNS_LOG_FILE="/var/log/dnsmasq.log"
        touch "$DNS_LOG_FILE" 2>/dev/null
        success "Query logging enabled to ${DNS_LOG_FILE}"
        log_change "Dnsmasq: Enabled log-queries to /var/log/dnsmasq.log"
    fi

    # Validate
    info "Validating Dnsmasq configuration..."
    if dnsmasq --test 2>&1; then
        success "Configuration is valid."
    else
        error "Configuration validation failed!"
    fi
}

# ── PowerDNS Authoritative ───────────────────────────────────────────────────

harden_pdns_auth() {
    header "Hardening PowerDNS Authoritative"

    local conf="$DNS_CONFIG"

    # 1. Disable zone transfers
    if confirm "Disable AXFR zone transfers? (disable-axfr=yes)"; then
        sed -i '/^\s*disable-axfr\s*=/d' "$conf"
        config_ensure_line "$conf" "disable-axfr=yes"
        success "AXFR disabled."
        log_change "PowerDNS Auth: Disabled AXFR"
    fi

    # 2. Hide version
    if confirm "Hide version string?"; then
        sed -i '/^\s*version-string\s*=/d' "$conf"
        config_ensure_line "$conf" "version-string=anonymous"
        success "Version string hidden."
        log_change "PowerDNS Auth: Set version-string=anonymous"
    fi

    # 3. Disable API
    if confirm "Disable the HTTP API? (api=no)"; then
        sed -i '/^\s*api\s*=/d; /^\s*api-key\s*=/d' "$conf"
        config_ensure_line "$conf" "api=no"
        success "API disabled."
        log_change "PowerDNS Auth: Disabled API"
    fi

    # 4. Disable webserver
    if confirm "Disable the built-in webserver?"; then
        sed -i '/^\s*webserver\s*=/d' "$conf"
        config_ensure_line "$conf" "webserver=no"
        success "Webserver disabled."
        log_change "PowerDNS Auth: Disabled webserver"
    fi

    # 5. Restrict local address
    if confirm "Bind to specific address only? (default: 0.0.0.0 → 127.0.0.1)"; then
        echo -en "${YELLOW}[PROMPT]${NC} Enter listen address (e.g., 0.0.0.0 or specific IP) [127.0.0.1]: "
        local addr
        read -r addr
        addr="${addr:-127.0.0.1}"
        sed -i '/^\s*local-address\s*=/d' "$conf"
        config_ensure_line "$conf" "local-address=${addr}"
        success "Listening on ${addr}."
        log_change "PowerDNS Auth: Set local-address=${addr}"
    fi

    # 6. Enable logging
    if confirm "Enable query logging? (loglevel=5)"; then
        sed -i '/^\s*loglevel\s*=/d; /^\s*log-dns-queries\s*=/d' "$conf"
        config_ensure_line "$conf" "loglevel=5"
        config_ensure_line "$conf" "log-dns-queries=yes"
        success "Query logging enabled."
        log_change "PowerDNS Auth: Enabled query logging (loglevel=5)"
    fi

    # 7. Disable recursive queries
    if confirm "Disable recursion? (allow-recursion=no)"; then
        sed -i '/^\s*allow-recursion\s*=/d' "$conf"
        config_ensure_line "$conf" "allow-recursion=no"
        success "Recursion disabled."
        log_change "PowerDNS Auth: Disabled recursion"
    fi
}

# ── PowerDNS Recursor ───────────────────────────────────────────────────────

harden_pdns_recursor() {
    header "Hardening PowerDNS Recursor"

    local conf="$DNS_CONFIG"

    # 1. Restrict allow-from
    if confirm "Restrict recursion to localhost and RFC1918 networks?"; then
        sed -i '/^\s*allow-from\s*=/d' "$conf"
        config_ensure_line "$conf" "allow-from=127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16"
        success "Recursion restricted to internal networks."
        log_change "PowerDNS Recursor: Restricted allow-from to RFC1918"
    fi

    # 2. Hide version
    if confirm "Hide version string?"; then
        sed -i '/^\s*version-string\s*=/d' "$conf"
        config_ensure_line "$conf" "version-string=anonymous"
        success "Version string hidden."
        log_change "PowerDNS Recursor: Set version-string=anonymous"
    fi

    # 3. Disable API
    if confirm "Disable HTTP API?"; then
        sed -i '/^\s*api-config-dir\s*=/d; /^\s*webserver\s*=/d' "$conf"
        config_ensure_line "$conf" "webserver=no"
        success "API/webserver disabled."
        log_change "PowerDNS Recursor: Disabled webserver/API"
    fi

    # 4. Quiet mode
    if confirm "Enable quiet mode? (reduces information in responses)"; then
        sed -i '/^\s*quiet\s*=/d' "$conf"
        config_ensure_line "$conf" "quiet=yes"
        success "Quiet mode enabled."
        log_change "PowerDNS Recursor: Enabled quiet mode"
    fi

    # 5. Restrict local address
    if confirm "Restrict listening address?"; then
        echo -en "${YELLOW}[PROMPT]${NC} Enter listen address [127.0.0.1]: "
        local addr
        read -r addr
        addr="${addr:-127.0.0.1}"
        sed -i '/^\s*local-address\s*=/d' "$conf"
        config_ensure_line "$conf" "local-address=${addr}"
        success "Listening on ${addr}."
        log_change "PowerDNS Recursor: Set local-address=${addr}"
    fi

    # 6. Enable logging
    if confirm "Enable trace logging?"; then
        sed -i '/^\s*trace\s*=/d; /^\s*quiet\s*=/d' "$conf"
        config_ensure_line "$conf" "trace=yes"
        success "Trace logging enabled."
        log_change "PowerDNS Recursor: Enabled trace logging"
    fi
}

# ── Knot DNS ─────────────────────────────────────────────────────────────────

harden_knot() {
    header "Hardening Knot DNS"

    local conf="$DNS_CONFIG"

    # 1. Hide version
    if confirm "Hide server version?"; then
        if grep -q 'version:' "$conf" 2>/dev/null; then
            sed -i 's/^\(\s*\)version:.*/\1version: ""/' "$conf"
        else
            # Insert under server: block
            sed -i '/^server:/a\    version: ""' "$conf"
        fi
        success "Version hidden."
        log_change "Knot DNS: Hidden version string"
    fi

    # 2. Restrict zone transfers via ACL
    if confirm "Create a deny-all ACL for zone transfers?"; then
        if ! grep -q 'acl:' "$conf" 2>/dev/null; then
            cat >> "$conf" << 'KNOT_ACL'

acl:
  - id: deny-all-xfr
    address: 0.0.0.0/0
    action: transfer
    deny: on
KNOT_ACL
        else
            info "ACL section exists — please review and restrict transfer ACLs manually."
        fi
        success "Zone transfer ACL added."
        log_change "Knot DNS: Added deny-all zone transfer ACL"
    fi

    # 3. Enable rate limiting module
    if confirm "Enable rate limiting (mod-rrl)?"; then
        if ! grep -q 'mod-rrl' "$conf" 2>/dev/null; then
            cat >> "$conf" << 'KNOT_RRL'

mod-rrl:
  - id: default
    rate-limit: 200
    slip: 2
KNOT_RRL
            # Note: user must also add "module: mod-rrl/default" to their template/zone
            info "NOTE: You must also add 'module: mod-rrl/default' to your zone template."
        fi
        success "RRL module configured."
        log_change "Knot DNS: Added mod-rrl configuration"
    fi

    # 4. Enable logging
    if confirm "Enable query logging?"; then
        if ! grep -q 'log:' "$conf" 2>/dev/null; then
            cat >> "$conf" << 'KNOT_LOG'

log:
  - target: syslog
    any: info
  - target: /var/log/knot/knot.log
    any: info
    zone: debug
KNOT_LOG
            mkdir -p /var/log/knot 2>/dev/null || true
            chown "${DNS_USER}:${DNS_GROUP}" /var/log/knot 2>/dev/null || true
        fi
        success "Logging configured."
        log_change "Knot DNS: Enabled logging to /var/log/knot/knot.log"
    fi

    # Validate
    info "Validating Knot DNS configuration..."
    if knotc conf-check 2>&1; then
        success "Configuration is valid."
    else
        error "Configuration validation failed!"
    fi
}

# ── NSD ──────────────────────────────────────────────────────────────────────

harden_nsd() {
    header "Hardening NSD"

    local conf="$DNS_CONFIG"

    # 1. Hide version
    if confirm "Hide server version? (hide-version: yes)"; then
        if grep -q 'hide-version:' "$conf" 2>/dev/null; then
            sed -i 's/^\(\s*\)hide-version:.*/\1hide-version: yes/' "$conf"
        else
            # Add under server: block
            if grep -q 'server:' "$conf"; then
                sed -i '/^server:/a\    hide-version: yes' "$conf"
            else
                echo -e "server:\n    hide-version: yes" >> "$conf"
            fi
        fi
        success "Version hidden."
        log_change "NSD: Hidden version"
    fi

    # 2. Restrict zone transfers
    if confirm "Review and restrict zone transfers? (remove provide-xfr lines)"; then
        local xfr_count
        xfr_count=$(grep -c 'provide-xfr:' "$conf" 2>/dev/null || echo "0")
        if [[ "$xfr_count" -gt 0 ]]; then
            info "Found ${xfr_count} provide-xfr entries:"
            grep 'provide-xfr:' "$conf" 2>/dev/null || true
            if confirm "Comment out all provide-xfr lines?"; then
                sed -i 's/^\(\s*provide-xfr:\)/# \1/' "$conf"
                success "Zone transfer entries commented out."
                log_change "NSD: Commented out all provide-xfr entries"
            fi
        else
            info "No provide-xfr entries found."
        fi
    fi

    # 3. Restrict notify
    if confirm "Review allow-notify entries?"; then
        local notify_count
        notify_count=$(grep -c 'allow-notify:' "$conf" 2>/dev/null || echo "0")
        if [[ "$notify_count" -gt 0 ]]; then
            info "Found ${notify_count} allow-notify entries:"
            grep 'allow-notify:' "$conf" 2>/dev/null || true
        else
            info "No allow-notify entries found."
        fi
    fi

    # 4. Enable logging verbosity
    if confirm "Increase logging verbosity? (verbosity: 2)"; then
        if grep -q 'verbosity:' "$conf" 2>/dev/null; then
            sed -i 's/^\(\s*\)verbosity:.*/\1verbosity: 2/' "$conf"
        else
            sed -i '/^server:/a\    verbosity: 2' "$conf"
        fi
        success "Logging verbosity increased."
        log_change "NSD: Set verbosity to 2"
    fi

    # Validate
    info "Validating NSD configuration..."
    if nsd-checkconf "$conf" 2>&1; then
        success "Configuration is valid."
    else
        error "Configuration validation failed!"
    fi
}

# ── CoreDNS ──────────────────────────────────────────────────────────────────

harden_coredns() {
    header "Hardening CoreDNS"

    local conf="$DNS_CONFIG"

    info "Current Corefile:"
    echo "---"
    cat "$conf"
    echo "---"

    # 1. Restrict listening
    if confirm "Review listening address in Corefile?"; then
        info "CoreDNS listens on addresses defined in the Corefile server blocks."
        info "Example: Change ':53' to '127.0.0.1:53' or a specific IP."
        info "Please edit the Corefile manually if needed."
    fi

    # 2. Add logging plugin
    if confirm "Add the 'log' plugin for query logging?"; then
        if ! grep -q '^\s*log' "$conf" 2>/dev/null; then
            # Add log directive inside the first server block
            sed -i '/{/a\    log' "$conf"
            success "Log plugin added."
            log_change "CoreDNS: Added log plugin"
        else
            info "Log plugin already present."
        fi
    fi

    # 3. Add errors plugin
    if confirm "Add the 'errors' plugin for error logging?"; then
        if ! grep -q '^\s*errors' "$conf" 2>/dev/null; then
            sed -i '/{/a\    errors' "$conf"
            success "Errors plugin added."
            log_change "CoreDNS: Added errors plugin"
        else
            info "Errors plugin already present."
        fi
    fi

    # 4. Remove unnecessary plugins
    if confirm "Review Corefile for potentially dangerous plugins? (chaos, pprof, etc.)"; then
        for plugin in chaos pprof debug; do
            if grep -q "^\s*${plugin}" "$conf" 2>/dev/null; then
                warn "Found '${plugin}' plugin — consider removing it."
                if confirm "Remove '${plugin}' plugin?"; then
                    sed -i "/^\s*${plugin}/d" "$conf"
                    success "Removed ${plugin}."
                    log_change "CoreDNS: Removed ${plugin} plugin"
                fi
            fi
        done
    fi

    # 5. Validate
    info "CoreDNS config validation requires running 'coredns -conf ${conf} -plugins'."
    info "Manual review recommended."
}

# ── MaraDNS ──────────────────────────────────────────────────────────────────

harden_maradns() {
    header "Hardening MaraDNS"

    local conf="$DNS_CONFIG"

    # 1. Restrict recursive access
    if confirm "Restrict recursive access to localhost?"; then
        if ! grep -q 'recursive_acl' "$conf" 2>/dev/null; then
            config_ensure_line "$conf" 'recursive_acl = "127.0.0.1/8"'
        else
            sed -i 's/^\s*recursive_acl\s*=.*/recursive_acl = "127.0.0.1\/8"/' "$conf"
        fi
        success "Recursive ACL restricted."
        log_change "MaraDNS: Restricted recursive_acl to 127.0.0.1/8"
    fi

    # 2. Bind to specific interface
    if confirm "Restrict MaraDNS to bind to a specific IP?"; then
        echo -en "${YELLOW}[PROMPT]${NC} Enter bind address [127.0.0.1]: "
        local addr
        read -r addr
        addr="${addr:-127.0.0.1}"
        sed -i "s/^\s*bind_address\s*=.*/bind_address = \"${addr}\"/" "$conf"
        success "Bound to ${addr}."
        log_change "MaraDNS: Set bind_address=${addr}"
    fi

    # 3. Hide version
    if confirm "Hide version string?"; then
        if ! grep -q 'hide_disclaimer' "$conf" 2>/dev/null; then
            config_ensure_line "$conf" 'hide_disclaimer = "YES"'
        else
            sed -i 's/^\s*hide_disclaimer\s*=.*/hide_disclaimer = "YES"/' "$conf"
        fi
        success "Version hidden."
        log_change "MaraDNS: Set hide_disclaimer=YES"
    fi

    # 4. Disable TCP (if not needed)
    if confirm "Disable TCP queries? (reduces attack surface if TCP not needed)"; then
        if ! grep -q 'tcp_convert' "$conf" 2>/dev/null; then
            config_ensure_line "$conf" 'tcp_convert = 0'
        else
            sed -i 's/^\s*tcp_convert\s*=.*/tcp_convert = 0/' "$conf"
        fi
        success "TCP disabled."
        log_change "MaraDNS: Disabled TCP"
    fi
}

# ═════════════════════════════════════════════════════════════════════════════
# General Hardening (applies to all daemons)
# ═════════════════════════════════════════════════════════════════════════════

general_harden() {
    header "General Hardening"

    # 1. File permissions
    if confirm "Restrict config file permissions? (root:${DNS_GROUP}, 640)"; then
        if id "$DNS_USER" &>/dev/null; then
            chown "root:${DNS_GROUP}" "$DNS_CONFIG" 2>/dev/null || chown root "$DNS_CONFIG"
            chmod 640 "$DNS_CONFIG"
            # Also fix config directory
            find "$DNS_CONFIG_DIR" -type f -name "*.conf" -exec chown "root:${DNS_GROUP}" {} \; 2>/dev/null || true
            find "$DNS_CONFIG_DIR" -type f -name "*.conf" -exec chmod 640 {} \; 2>/dev/null || true
            success "Permissions set: root:${DNS_GROUP} 640"
            log_change "General: Set config permissions to root:${DNS_GROUP} 640"
        else
            warn "User ${DNS_USER} not found — setting owner to root only."
            chown root "$DNS_CONFIG"
            chmod 600 "$DNS_CONFIG"
            log_change "General: Set config permissions to root 600 (DNS user not found)"
        fi
    fi

    # 2. Immutable configs
    if confirm "Set immutable flag on main config? (chattr +i — prevents modification)"; then
        chattr +i "$DNS_CONFIG" 2>/dev/null || warn "chattr not available or not supported on this filesystem."
        success "Immutable flag set on ${DNS_CONFIG}"
        warn "Remember: use 'chattr -i ${DNS_CONFIG}' before making future changes."
        log_change "General: Set chattr +i on ${DNS_CONFIG}"
    fi

    # 3. Process user check
    if confirm "Verify DNS daemon runs as non-root user?"; then
        local run_user
        run_user=$(ps -eo user,comm 2>/dev/null | grep -E "(named|unbound|dnsmasq|pdns|knotd|nsd|coredns|maradns|deadwood)" | awk '{print $1}' | head -1)
        if [[ -n "$run_user" && "$run_user" != "root" ]]; then
            success "DNS daemon running as user: ${run_user}"
        elif [[ "$run_user" == "root" ]]; then
            warn "DNS daemon is running as root! This is a security risk."
            info "Consider configuring the daemon to drop privileges."
        else
            info "Could not determine running user (daemon may not be running)."
        fi

        # Check nologin shell
        if id "$DNS_USER" &>/dev/null; then
            local user_shell
            user_shell=$(getent passwd "$DNS_USER" 2>/dev/null | cut -d: -f7)
            if [[ "$user_shell" == *"nologin"* || "$user_shell" == *"false"* ]]; then
                success "User ${DNS_USER} has nologin shell: ${user_shell}"
            else
                warn "User ${DNS_USER} has shell: ${user_shell}"
                if confirm "Change ${DNS_USER} shell to /usr/sbin/nologin?"; then
                    usermod -s /usr/sbin/nologin "$DNS_USER" 2>/dev/null || \
                    usermod -s /sbin/nologin "$DNS_USER" 2>/dev/null || \
                    warn "Could not change shell."
                    # Lock the password
                    passwd -l "$DNS_USER" 2>/dev/null || true
                    success "Shell changed and password locked."
                    log_change "General: Set ${DNS_USER} shell to nologin, locked password"
                fi
            fi
        fi
    fi

    # 4. Systemd hardening
    if confirm "Apply systemd service hardening? (NoNewPrivileges, PrivateTmp, etc.)"; then
        local override_dir="/etc/systemd/system/${DNS_SERVICE}.service.d"
        mkdir -p "$override_dir"
        cat > "${override_dir}/hardening.conf" << 'SYSTEMD_HARDENING'
[Service]
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
MemoryDenyWriteExecute=yes
LockPersonality=yes
SYSTEMD_HARDENING

        # Add ReadWritePaths based on daemon
        case "$DNS_DAEMON" in
            bind9)
                echo "ReadWritePaths=/var/cache/bind /var/run/named /run/named ${DNS_CONFIG_DIR} /var/log/named" \
                    >> "${override_dir}/hardening.conf"
                ;;
            unbound)
                echo "ReadWritePaths=/var/lib/unbound /run/unbound /var/log/unbound ${DNS_CONFIG_DIR}" \
                    >> "${override_dir}/hardening.conf"
                ;;
            dnsmasq)
                echo "ReadWritePaths=/var/run/dnsmasq /var/lib/misc /var/log" \
                    >> "${override_dir}/hardening.conf"
                ;;
            knot)
                echo "ReadWritePaths=/var/lib/knot /run/knot /var/log/knot ${DNS_CONFIG_DIR}" \
                    >> "${override_dir}/hardening.conf"
                ;;
            nsd)
                echo "ReadWritePaths=/var/lib/nsd /var/db/nsd /run/nsd /var/log ${DNS_CONFIG_DIR}" \
                    >> "${override_dir}/hardening.conf"
                ;;
            *)
                echo "ReadWritePaths=/var/log /run ${DNS_CONFIG_DIR}" \
                    >> "${override_dir}/hardening.conf"
                ;;
        esac

        systemctl daemon-reload
        success "Systemd hardening applied to ${DNS_SERVICE}."
        log_change "General: Applied systemd hardening drop-in for ${DNS_SERVICE}"
    fi
}

# ═════════════════════════════════════════════════════════════════════════════
# Verification
# ═════════════════════════════════════════════════════════════════════════════

verify_dns() {
    header "Verification"

    # 1. Config validation (daemon-specific)
    info "Running config validation..."
    case "$DNS_DAEMON" in
        bind9)    named-checkconf "$DNS_CONFIG" 2>&1 && success "Config valid." || error "Config invalid!" ;;
        unbound)  unbound-checkconf "$DNS_CONFIG" 2>&1 && success "Config valid." || error "Config invalid!" ;;
        dnsmasq)  dnsmasq --test 2>&1 && success "Config valid." || error "Config invalid!" ;;
        knot)     knotc conf-check 2>&1 && success "Config valid." || error "Config invalid!" ;;
        nsd)      nsd-checkconf "$DNS_CONFIG" 2>&1 && success "Config valid." || error "Config invalid!" ;;
        *)        info "No built-in validator for ${DNS_DAEMON} — skipping." ;;
    esac

    # 2. Restart service
    if confirm "Restart ${DNS_SERVICE} service to apply changes?"; then
        # Need to remove immutable flag if set
        chattr -i "$DNS_CONFIG" 2>/dev/null || true
        if systemctl restart "$DNS_SERVICE" 2>&1; then
            success "Service restarted successfully."
            log_change "Restarted ${DNS_SERVICE}"
        else
            error "Service restart failed!"
            systemctl status "$DNS_SERVICE" --no-pager -l 2>/dev/null || true
            warn "Check logs with: journalctl -xeu ${DNS_SERVICE}"
        fi
        # Re-set immutable if it was set
        if echo "${CHANGES_LOG[@]}" | grep -q "chattr +i"; then
            if confirm "Re-apply immutable flag on config?"; then
                chattr +i "$DNS_CONFIG" 2>/dev/null || true
            fi
        fi
    fi

    # 3. Test DNS resolution
    info "Testing DNS resolution..."
    if command -v dig &>/dev/null; then
        local test_result
        test_result=$(dig @127.0.0.1 localhost A +short +time=3 +tries=1 2>&1)
        if [[ $? -eq 0 ]]; then
            success "DNS resolution working (dig @127.0.0.1 localhost → ${test_result:-empty})"
        else
            warn "DNS resolution test returned non-zero (may be expected for authoritative-only servers)"
        fi
    elif command -v host &>/dev/null; then
        if host localhost 127.0.0.1 &>/dev/null; then
            success "DNS resolution working."
        else
            warn "DNS resolution test failed."
        fi
    else
        info "Neither dig nor host available — install dnsutils/bind-utils to test."
    fi

    # 4. Test zone transfer is refused
    if command -v dig &>/dev/null; then
        info "Testing zone transfer protection..."
        local axfr_result
        axfr_result=$(dig @127.0.0.1 AXFR . +time=3 +tries=1 2>&1 | tail -3)
        if echo "$axfr_result" | grep -qi "refused\|failed\|Transfer failed\|SERVFAIL"; then
            success "Zone transfers properly refused."
        else
            info "AXFR test result (review manually): ${axfr_result}"
        fi
    fi
}

# ═════════════════════════════════════════════════════════════════════════════
# Monitor Mode
# ═════════════════════════════════════════════════════════════════════════════

monitor_dns() {
    header "DNS Log Monitor"

    # Detect daemon if not already done
    if [[ -z "$DNS_DAEMON" ]]; then
        detect_distro
        detect_dns_daemon
    fi

    local logfile="$DNS_LOG_FILE"

    # Try journalctl if log file doesn't exist
    if [[ ! -f "$logfile" ]]; then
        info "Log file ${logfile} not found. Trying journalctl for ${DNS_SERVICE}..."
        if systemctl is-active "$DNS_SERVICE" &>/dev/null; then
            info "Monitoring via journalctl -fu ${DNS_SERVICE}"
            info "Highlighting: ${RED}AXFR/IXFR${NC} | ${YELLOW}denied/refused/ANY${NC} | ${CYAN}reload/restart${NC}"
            echo "Press Ctrl+C to exit."
            echo ""
            journalctl -fu "$DNS_SERVICE" 2>/dev/null | while IFS= read -r line; do
                if echo "$line" | grep -qiE 'axfr|ixfr|zone.transfer'; then
                    echo -e "${RED}${line}${NC}"
                elif echo "$line" | grep -qiE 'denied|refused|reject|error|fail'; then
                    echo -e "${YELLOW}${line}${NC}"
                elif echo "$line" | grep -qiE 'ANY|HINFO|RRSIG|TXT.*\.\s'; then
                    echo -e "${YELLOW}${line}${NC}"
                elif echo "$line" | grep -qiE 'reload|restart|reconfigure|starting|stopping'; then
                    echo -e "${CYAN}${line}${NC}"
                else
                    echo "$line"
                fi
            done
            return
        else
            error "Cannot find log source. Check DNS logging configuration."
            exit 1
        fi
    fi

    info "Monitoring: ${logfile}"
    info "Highlighting: ${RED}AXFR/IXFR${NC} | ${YELLOW}denied/refused/ANY${NC} | ${CYAN}reload/restart${NC}"
    echo "Press Ctrl+C to exit."
    echo ""

    tail -f "$logfile" 2>/dev/null | while IFS= read -r line; do
        if echo "$line" | grep -qiE 'axfr|ixfr|zone.transfer'; then
            echo -e "${RED}${line}${NC}"
        elif echo "$line" | grep -qiE 'denied|refused|reject|error|fail'; then
            echo -e "${YELLOW}${line}${NC}"
        elif echo "$line" | grep -qiE 'ANY|HINFO|RRSIG'; then
            echo -e "${YELLOW}${line}${NC}"
        elif echo "$line" | grep -qiE 'reload|restart|reconfigure|starting|stopping'; then
            echo -e "${CYAN}${line}${NC}"
        else
            echo "$line"
        fi
    done
}

# ═════════════════════════════════════════════════════════════════════════════
# Summary
# ═════════════════════════════════════════════════════════════════════════════

print_summary() {
    header "Hardening Summary"

    if [[ ${#CHANGES_LOG[@]} -eq 0 ]]; then
        info "No changes were made."
        return
    fi

    info "Changes applied (${#CHANGES_LOG[@]} total):"
    echo ""
    local i=1
    for change in "${CHANGES_LOG[@]}"; do
        echo -e "  ${GREEN}${i}.${NC} ${change}"
        ((i++))
    done
    echo ""

    if [[ -d "$BACKUP_DIR" ]]; then
        info "Backup location: ${BACKUP_DIR}"
        info "To restore: cp -a ${BACKUP_DIR}/config_dir/* ${DNS_CONFIG_DIR}/ && systemctl restart ${DNS_SERVICE}"
    fi
    echo ""
    success "Hardening complete."
}

# ═════════════════════════════════════════════════════════════════════════════
# Main
# ═════════════════════════════════════════════════════════════════════════════

main() {
    echo ""
    echo -e "${BOLD}╔═══════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}║       DNS Hardening Script — NCAE CyberGames         ║${NC}"
    echo -e "${BOLD}╚═══════════════════════════════════════════════════════╝${NC}"
    echo ""

    # Phase 1: Detection
    detect_distro
    detect_dns_daemon

    if [[ "$MODE" == "monitor" ]]; then
        monitor_dns
        exit 0
    fi

    # Phase 2: Backup
    backup_config

    # Phase 3: Daemon-specific hardening
    case "$DNS_DAEMON" in
        bind9)          harden_bind9 ;;
        unbound)        harden_unbound ;;
        dnsmasq)        harden_dnsmasq ;;
        pdns_auth)      harden_pdns_auth ;;
        pdns_recursor)  harden_pdns_recursor ;;
        knot)           harden_knot ;;
        nsd)            harden_nsd ;;
        coredns)        harden_coredns ;;
        maradns)        harden_maradns ;;
        *)
            error "Unknown daemon: ${DNS_DAEMON}"
            exit 1
            ;;
    esac

    # Phase 4: General hardening
    general_harden

    # Phase 5: Verification
    verify_dns

    # Phase 6: Summary
    print_summary
}

main "$@"
