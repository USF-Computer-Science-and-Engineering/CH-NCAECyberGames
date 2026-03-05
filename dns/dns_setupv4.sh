#!/bin/bash
set -e

################################
# ROOT CHECK
################################

if [[ $EUID -ne 0 ]]; then
    echo "Run as root"
    exit 1
fi

################################
# INPUT BASIC INFO
################################

read -p "Team number: " TEAM
read -p "Internal domain (example team${TEAM}.net): " INT_DOMAIN
read -p "External domain (example team${TEAM}.ncaecybergames.org): " EXT_DOMAIN

################################
# INSTALL BIND
################################

echo "[+] Installing BIND if missing"

if ! rpm -q bind &>/dev/null; then
    dnf install -y bind bind-utils
fi

################################
# STOP NAMED IF RUNNING
################################

systemctl stop named 2>/dev/null || true

################################
# DIRECTORIES
################################

ZONE_DIR="/var/named/zones"
LOG_DIR="/var/log/named"

mkdir -p "$ZONE_DIR"
mkdir -p "$LOG_DIR"

################################
# LOGGING FIX
################################

touch "$LOG_DIR/queries.log"
chown -R named:named "$LOG_DIR"
chmod 750 "$LOG_DIR"
chmod 640 "$LOG_DIR/queries.log"

restorecon -Rv "$LOG_DIR"

################################
# SERIAL
################################

SERIAL=$(date +%Y%m%d%H)

################################
# HOST COLLECTION
################################

declare -a INT_HOSTS
declare -a EXT_HOSTS

echo ""
echo "=== ADD INTERNAL HOSTS ==="
echo "Example: www 192.168.${TEAM}.5"
echo ""

while true; do
    read -p "Hostname (or 'done'): " HOST
    [[ "$HOST" == "done" ]] && break
    [[ -z "$HOST" ]] && continue

    read -p "IP Address: " IP

    INT_HOSTS+=("$HOST $IP")
done

echo ""
echo "=== ADD EXTERNAL HOSTS ==="
echo "Example: www 172.18.13.${TEAM}"
echo ""

while true; do
    read -p "Hostname (or 'done'): " HOST
    [[ "$HOST" == "done" ]] && break
    [[ -z "$HOST" ]] && continue

    read -p "IP Address: " IP

    EXT_HOSTS+=("$HOST $IP")
done

################################
# NAMESERVER
################################

read -p "Which hostname is the DNS server? (example ns1): " NS_HOST

################################
# INTERNAL FORWARD ZONE
################################

INT_ZONE="$ZONE_DIR/internal.${INT_DOMAIN}.zone"

cat > "$INT_ZONE" <<EOF
\$TTL 10800
@ IN SOA ${NS_HOST}.${INT_DOMAIN}. hostmaster.${INT_DOMAIN}. (
    ${SERIAL}
    3600
    1800
    604800
    86400 )

    IN NS ${NS_HOST}.${INT_DOMAIN}.

EOF

for entry in "${INT_HOSTS[@]}"; do

    HOST=$(echo "$entry" | awk '{print $1}')
    IP=$(echo "$entry" | awk '{print $2}')

    echo "$HOST IN A $IP" >> "$INT_ZONE"

done

################################
# EXTERNAL FORWARD ZONE
################################

EXT_ZONE="$ZONE_DIR/external.${EXT_DOMAIN}.zone"

cat > "$EXT_ZONE" <<EOF
\$TTL 10800
@ IN SOA ${NS_HOST}.${EXT_DOMAIN}. hostmaster.${EXT_DOMAIN}. (
    ${SERIAL}
    3600
    1800
    604800
    86400 )

    IN NS ${NS_HOST}.${EXT_DOMAIN}.

EOF

for entry in "${EXT_HOSTS[@]}"; do

    HOST=$(echo "$entry" | awk '{print $1}')
    IP=$(echo "$entry" | awk '{print $2}')

    echo "$HOST IN A $IP" >> "$EXT_ZONE"

done

################################
# INTERNAL REVERSE ZONE
################################

REV_INT="${TEAM}.168.192"
REV_INT_FILE="$ZONE_DIR/rev.internal.${INT_DOMAIN}.zone"

cat > "$REV_INT_FILE" <<EOF
\$TTL 10800
@ IN SOA ${NS_HOST}.${INT_DOMAIN}. hostmaster.${INT_DOMAIN}. (
    ${SERIAL}
    3600
    1800
    604800
    86400 )

    IN NS ${NS_HOST}.${INT_DOMAIN}.

EOF

for entry in "${INT_HOSTS[@]}"; do

    HOST=$(echo "$entry" | awk '{print $1}')
    IP=$(echo "$entry" | awk '{print $2}')

    LAST=$(echo "$IP" | awk -F. '{print $4}')

    echo "$LAST IN PTR $HOST.${INT_DOMAIN}." >> "$REV_INT_FILE"

done

################################
# EXTERNAL REVERSE ZONE
################################

REV_EXT="18.172"
REV_EXT_FILE="$ZONE_DIR/rev.external.${EXT_DOMAIN}.zone"

cat > "$REV_EXT_FILE" <<EOF
\$TTL 10800
@ IN SOA ${NS_HOST}.${EXT_DOMAIN}. hostmaster.${EXT_DOMAIN}. (
    ${SERIAL}
    3600
    1800
    604800
    86400 )

    IN NS ${NS_HOST}.${EXT_DOMAIN}.

EOF

for entry in "${EXT_HOSTS[@]}"; do

    HOST=$(echo "$entry" | awk '{print $1}')
    IP=$(echo "$entry" | awk '{print $2}')

    OCT3=$(echo "$IP" | awk -F. '{print $3}')
    OCT4=$(echo "$IP" | awk -F. '{print $4}')

    echo "$OCT4.$OCT3 IN PTR $HOST.${EXT_DOMAIN}." >> "$REV_EXT_FILE"

done

################################
# NAMED CONFIG
################################

cat > /etc/named.conf <<EOF

options {
    listen-on port 53 { any; };
    listen-on-v6 { none; };

    directory "/var/named";

    allow-query { any; };
    recursion no;
    allow-transfer { none; };

    dnssec-validation no;

    pid-file "/run/named/named.pid";
};

logging {
    channel query_log {
        file "${LOG_DIR}/queries.log" versions 3 size 5m;
        severity info;
        print-time yes;
    };

    category queries { query_log; };
};

zone "${INT_DOMAIN}" IN {
    type master;
    file "zones/internal.${INT_DOMAIN}.zone";
};

zone "${EXT_DOMAIN}" IN {
    type master;
    file "zones/external.${EXT_DOMAIN}.zone";
};

zone "${REV_INT}.in-addr.arpa" IN {
    type master;
    file "zones/rev.internal.${INT_DOMAIN}.zone";
};

zone "${REV_EXT}.in-addr.arpa" IN {
    type master;
    file "zones/rev.external.${EXT_DOMAIN}.zone";
};

EOF

################################
# PERMISSIONS
################################

chown -R named:named "$ZONE_DIR"
chmod -R 640 "$ZONE_DIR"/*
restorecon -Rv "$ZONE_DIR"

################################
# FIREWALL
################################

firewall-cmd --add-service=dns --permanent
firewall-cmd --reload

################################
# VALIDATION
################################

echo "[+] Validating configuration"

named-checkconf -z
named-checkzone "${INT_DOMAIN}" "$INT_ZONE"
named-checkzone "${EXT_DOMAIN}" "$EXT_ZONE"
named-checkzone "${REV_INT}.in-addr.arpa" "$REV_INT_FILE"
named-checkzone "${REV_EXT}.in-addr.arpa" "$REV_EXT_FILE"

################################
# START SERVICE
################################

systemctl enable named
systemctl restart named

echo ""
echo "DNS deployment complete"
echo ""
echo "Run tests:"
echo "dig @localhost www.${INT_DOMAIN}"
echo "dig @localhost -x 192.168.${TEAM}.5"
echo "dig @localhost www.${EXT_DOMAIN}"
echo "dig @localhost -x 172.18.13.${TEAM}"
echo ""