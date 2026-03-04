#!/usr/bin/env bash

set -euo pipefail


TEAM_NUM=8
DOMAIN="www.team${TEAM_NUM}.ncaecybergames.org"
INTERNAL_IP="192.168.${TEAM_NUM}.5"
EXTERNAL_IP="172.18.13.${TEAM_NUM}"
CA_SERVER="https://ca.ncaecybergames.org/"
WEB_APP_SERVICE="web_app"  # Replace with name of web app
WEB_APP_CONFIG_DIR="/var/lib/web_app"  # Replace with dir location of web app's config

HTTP_PORT=80
HTTPS_PORT=443


# ---------------------------------------------------------------------------
# HELPER FUNCTIONS
# ---------------------------------------------------------------------------

info()    { echo -e "\e[36m[INFO]\e[0m  $*"; }
success() { echo -e "\e[32m[OK]\e[0m    $*"; }
warn()    { echo -e "\e[33m[WARN]\e[0m  $*"; }
error()   { echo -e "\e[31m[ERROR]\e[0m $*"; exit 1; }

require_root() {
    [[ "$EUID" -eq 0 ]] || error "Please run as root: sudo bash $0"
}


# ---------------------------------------------------------------------------
# STEP 1: DETECT FLASK PORT
# ---------------------------------------------------------------------------

detect_flask_port() {
    info "Detecting Flask port..."

    # First, try to find it from a running process
    local port
    port=$(ss -tlnp 2>/dev/null \
        | grep -E '(python|flask|gunicorn|uwsgi)' \
        | grep -oP '(?<=:)\d+(?=\s)' \
        | head -1 || true)

    if [[ -n "$port" ]]; then
        success "Detected Flask running on port $port"
        FLASK_PORT="$port"
        return
    fi

    warn "Could not detect Flask port. Defaulting to 5000."
    warn "If that's wrong, edit FLASK_PORT in /etc/nginx/sites-available/${DOMAIN}.conf"
    warn "and run: sudo nginx -t && sudo systemctl reload nginx"
    FLASK_PORT=5000
}


# ---------------------------------------------------------------------------
# STEP 2: ENSURE web_app IS RUNNING
# ---------------------------------------------------------------------------

ensure_web_app() {
    info "Checking web_app service..."

    if ! systemctl list-unit-files | grep -q "${WEB_APP_SERVICE}.service"; then
        warn "<web_app>.service not found in systemd. Skipping auto-start."
        warn "Make sure the app is running before scoring begins!"
        return
    fi

    # Enable so it starts on reboot
    systemctl enable "${WEB_APP_SERVICE}" 2>/dev/null || true

    if ! systemctl is-active --quiet "${WEB_APP_SERVICE}"; then
        info "Starting web_app..."
        systemctl start "${WEB_APP_SERVICE}" || warn "Could not start web_app - check the service manually."
    else
        success "web_app is already running."
    fi

}

# ---------------------------------------------------------------------------
# STEP 3: INSTALL NGINX AND CERTBOT
# ---------------------------------------------------------------------------

install_dependencies() {
    info "Updating package list and installing nginx + certbot..."
    apt-get update -qq
    apt-get install -y -qq nginx certbot python3-certbot-nginx curl ufw

    # Make sure nginx is enabled and running
    systemctl enable nginx
    systemctl start nginx || true
    success "Nginx installed and started."
}


# ---------------------------------------------------------------------------
# STEP 4: WRITE NGINX CONFIGURATION
# ---------------------------------------------------------------------------
# This creates two server blocks:
#   - Port 80:  serves HTTP (required for WWW Port 80 scoring check)
#               and redirects to HTTPS once SSL is set up
#   - Port 443: reverse proxy to Flask, with SSL and hardening headers
#
# NOTE: We keep port 80 alive and proxying even after SSL is set up,
#       because the scoring check for "WWW Port 80" just needs a 200.
#       We do NOT do a hard redirect 80→443, since that would break the
#       port-80 scoring check.


write_nginx_config() {
    info "Writing Nginx configuration for ${DOMAIN}..."

    local CONF_PATH="/etc/nginx/sites-available/${DOMAIN}.conf"
    local ENABLED_PATH="/etc/nginx/sites-enabled/${DOMAIN}.conf"

    # Back up any existing default site so we don't conflict
    if [[ -f /etc/nginx/sites-enabled/default ]]; then
        rm -f /etc/nginx/sites-enabled/default
        info "Removed default nginx site to avoid port conflicts."
    fi

    cat > "$CONF_PATH" <<NGINXCONF
# -----------------------------------------------------------------------
# HTTP Server (Port 80)
# Scoring check "WWW Port 80" hits this. It MUST return 200.
# We proxy to Flask here too so content scoring also passes on port 80.
# -----------------------------------------------------------------------
server {
    listen ${HTTP_PORT};
    server_name ${DOMAIN} ${EXTERNAL_IP} ${INTERNAL_IP};

    # Log to a dedicated file so you can monitor scoring hits
    access_log /var/log/nginx/${DOMAIN}_http_access.log;
    error_log  /var/log/nginx/${DOMAIN}_http_error.log warn;

    # Fast path for simple checks (keeps a cheap 200 even if app is slow)
    location = /robots.txt {
        add_header Content-Type text/plain;
        return 200 "User-agent: *\nDisallow:\n";
    }

    # --- Pass all traffic to the Flask app ---
    location / {
        proxy_pass         http://127.0.0.1:${FLASK_PORT};
        proxy_http_version 1.1;

        # Forward the real client IP to Flask
        proxy_set_header   Host              \$host;
        proxy_set_header   X-Real-IP         \$remote_addr;
        proxy_set_header   X-Forwarded-For   \$proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto \$scheme;

        # Timeouts — generous enough for slow scoring checks
        proxy_connect_timeout 10s;
        proxy_send_timeout    30s;
        proxy_read_timeout    30s;

        # Apply general rate limit
        limit_req zone=general_zone burst=50 nodelay;
    }

    # --- Tighter rate limit on login endpoint ---
    location ~* ^/(login|admin|signin) {
        proxy_pass         http://127.0.0.1:${FLASK_PORT};
        proxy_http_version 1.1;
        proxy_set_header   Host              \$host;
        proxy_set_header   X-Real-IP         \$remote_addr;
        proxy_set_header   X-Forwarded-For   \$proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto \$scheme;

        limit_req zone=login_zone burst=10 nodelay;
    }

    # --- Block common red team recon paths ---
    location ~* \.(git|env|sh|py|bak|sql|conf|cfg|ini|log)\$ {
        deny all;
        return 404;
    }
    location ~* ^/(\.git|\.env|admin/sys_mon|debug|endpoint) {
        deny all;
        return 404;
    }
}

# -----------------------------------------------------------------------
# HTTPS Server (Port 443) — certbot will fill in ssl_certificate paths
# -----------------------------------------------------------------------
server {
    listen ${HTTPS_PORT} ssl;
    server_name ${DOMAIN};

    access_log /var/log/nginx/${DOMAIN}_https_access.log;
    error_log  /var/log/nginx/${DOMAIN}_https_error.log warn;

    # --- SSL certificate paths ---
    # certbot will update these automatically. If certbot hasn't run yet,
    # this block is commented out until you run Step 5 (get_ssl_cert).
    ssl_certificate     /etc/letsencrypt/live/${DOMAIN}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${DOMAIN}/privkey.pem;

    # Only allow modern TLS versions (blocks old, vulnerable versions)
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    # Cache SSL sessions for performance
    ssl_session_cache   shared:SSL:10m;
    ssl_session_timeout 10m;

    # --- Security headers ---
    # These make it harder for red team to exploit the browser/app
    add_header X-Frame-Options           "SAMEORIGIN"            always;
    add_header X-Content-Type-Options    "nosniff"               always;
    add_header X-XSS-Protection          "1; mode=block"         always;
    add_header Referrer-Policy           "strict-origin"         always;
    add_header Strict-Transport-Security "max-age=31536000"      always;

    location = /robots.txt {
        add_header Content-Type text/plain;
        return 200 "User-agent: *\nDisallow:\n";
    }

    # --- Proxy to Flask (same as port 80) ---
    location / {
        proxy_pass         http://127.0.0.1:${FLASK_PORT};
        proxy_http_version 1.1;
        proxy_set_header   Host              \$host;
        proxy_set_header   X-Real-IP         \$remote_addr;
        proxy_set_header   X-Forwarded-For   \$proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto https;
        proxy_connect_timeout 10s;
        proxy_send_timeout    30s;
        proxy_read_timeout    30s;
        limit_req zone=general_zone burst=50 nodelay;
    }

    location ~* ^/(login|admin|signin) {
        proxy_pass         http://127.0.0.1:${FLASK_PORT};
        proxy_http_version 1.1;
        proxy_set_header   Host              \$host;
        proxy_set_header   X-Real-IP         \$remote_addr;
        proxy_set_header   X-Forwarded-For   \$proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto https;
        limit_req zone=login_zone burst=10 nodelay;
    }

    location ~* \.(git|env|sh|py|bak|sql|conf|cfg|ini|log)\$ {
        deny all;
        return 404;
    }
    location ~* ^/(\.git|\.env|admin/sys_mon|debug|endpoint) {
        deny all;
        return 404;
    }
}
NGINXCONF

    # Enable the site
    ln -sf "$CONF_PATH" "$ENABLED_PATH"
    success "Nginx config written to $CONF_PATH"
}


# ---------------------------------------------------------------------------
# STEP 5: HARDEN GLOBAL NGINX SETTINGS
# ---------------------------------------------------------------------------
# These go in nginx.conf and apply to all sites.

harden_nginx_globals() {
    info "Hardening global Nginx settings..."

    # Back up original
    cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak 2>/dev/null || true

    # Patch the http block — only if not already patched
    local SNIPPET="/etc/nginx/conf.d/hardening.conf"
    cat > "$SNIPPET" <<'EOF'
# --- Nginx global hardening ---

# Hide Nginx version from response headers (red team recon)
server_tokens off;

# Limit request body size (prevent large upload attacks)
client_max_body_size 10M;

# Prevent clickjacking at the global level
add_header X-Frame-Options "SAMEORIGIN" always;

# Timeout settings (drop slow/idle connections from red team)
client_body_timeout   12s;
client_header_timeout 12s;
keepalive_timeout     15s;
send_timeout          10s;

# Rate limit zones referenced by the site config
limit_req_zone $binary_remote_addr zone=general_zone:10m rate=10r/s;
limit_req_zone $binary_remote_addr zone=login_zone:10m rate=3r/s;
EOF

    success "Global hardening config written to $SNIPPET"
}

# ---------------------------------------------------------------------------
# STEP 6: OBTAIN SSL CERTIFICATE
# ---------------------------------------------------------------------------
get_ssl_cert() {
    info "Requesting SSL Certificate from internal CA..."
    # We use --register-unsafely-without-email to bypass email prompts,
    # or you can provide -m admin@team8.ncaecybergames.org
    certbot --nginx --server "${CA_SERVER}" -d "${DOMAIN}" --non-interactive --agree-tos --register-unsafely-without-email --no-random-sleep-on-renew

    if [[ $? -eq 0 ]]; then
        success "SSL Certificate installed successfully."
    else
        warn "Certbot failed. You may need to run it manually."
        warn "Manual command: certbot --nginx --server ${CA_SERVER} -d ${DOMAIN} --no-random-sleep-on-renew"
    fi
}



# ---------------------------------------------------------------------------
# STEP 9: FIREWALL (UFW)
# ---------------------------------------------------------------------------
# Only allow what's needed for scoring. Block everything else.

setup_firewall() {
    info "Configuring UFW firewall..."

    ufw --force reset       # Start fresh
    ufw default deny incoming
    ufw default allow outgoing

    ufw allow 80/tcp   comment "HTTP (WWW Port 80 scoring)"
    ufw allow 443/tcp  comment "HTTPS (WWW SSL scoring)"
    ufw allow 22/tcp   comment "SSH (keep access to your own machine)"

    # Allow scoring system to reach from the external LAN
    ufw allow from 172.18.0.0/16 to any port 80
    ufw allow from 172.18.0.0/16 to any port 443

    # Allow internal LAN
    ufw allow from 192.168.${TEAM_NUM}.0/24

    ufw --force enable
    success "UFW firewall active. Run 'ufw status verbose' to verify."
}


# ---------------------------------------------------------------------------
# STEP 10: FINAL VALIDATION
# ---------------------------------------------------------------------------

validate() {
    info "Running final validation checks..."
    echo ""

    # Test nginx config
    if nginx -t 2>/dev/null; then
        success "Nginx config syntax: OK"
    else
        warn "Nginx config has errors — run 'nginx -t' to debug"
    fi

    # Check nginx is running
    if systemctl is-active --quiet nginx; then
        success "Nginx service: RUNNING"
    else
        warn "Nginx service: NOT RUNNING — try: sudo systemctl start nginx"
    fi

    # Check web_app is running
    if systemctl list-unit-files | grep -q "${WEB_APP_SERVICE}.service"; then
        if systemctl is-active --quiet "${WEB_APP_SERVICE}"; then
            success "web_app service: RUNNING"
        else
            warn "web_app service: NOT RUNNING — try: sudo systemctl start ${WEB_APP_SERVICE}"
        fi
    fi

    # Check port 80 responds
    local HTTP_CODE
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "http://127.0.0.1/" 2>/dev/null || echo "000")
    if [[ "$HTTP_CODE" == "200" ]]; then
        success "Port 80 response: $HTTP_CODE OK"
    else
        warn "Port 80 response: $HTTP_CODE (expected 200) — is Flask running on port $FLASK_PORT?"
    fi

    # Check port 443 responds
    local HTTPS_CODE
    HTTPS_CODE="$(curl -k -s -o /dev/null -w "%{http_code}" --max-time 5 "https://127.0.0.1/" 2>/dev/null || echo "000")"
    if [[ "${HTTPS_CODE}" == "200" || "${HTTPS_CODE}" == "301" || "${HTTPS_CODE}" == "302" ]]; then
    success "Port 443 response: ${HTTPS_CODE} OK"
    else
    warn "Port 443 response: ${HTTPS_CODE}. Check nginx logs and cert status."
    fi

    # Check SSL cert
    if [[ -f "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" ]]; then
        success "SSL certificate: EXISTS"
    else
        warn "SSL certificate: NOT FOUND — run Step 6 manually:"
        warn "  certbot --nginx --server ${CA_SERVER} -d ${DOMAIN} --no-random-sleep-on-renew"
    fi

    echo ""
    info "Flask backend port used: ${FLASK_PORT}"
    info "Nginx config: /etc/nginx/sites-available/${DOMAIN}.conf"
    echo ""
}



# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------

require_root

echo ""
echo "============================================================"
echo "  NCAE CyberGames 2026 - Team ${TEAM_NUM} - Web Hardening"
echo "============================================================"
echo ""

detect_flask_port        # Step 1 - must run first, sets $FLASK_PORT
ensure_web_app           # Step 2
install_dependencies     # Step 3
write_nginx_config       # Step 4 - uses $FLASK_PORT
harden_nginx_globals     # Step 5

get_ssl_cert             # Step 6
setup_firewall           # Step 9

# Reload nginx with the final config
systemctl reload nginx 2>/dev/null || systemctl restart nginx

validate                 # Step 10

echo "============================================================"
echo "  Done! Good luck, Team ${TEAM_NUM}!"
echo "============================================================"
echo ""
