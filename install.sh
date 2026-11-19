#!/usr/bin/env bash
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Please run as root or with sudo: sudo bash install.sh" >&2
  exit 1
fi

SOURCE_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
INSTALL_DIR="/opt/shree-gatepass"

if [[ -f "$INSTALL_DIR/.env" ]]; then
  echo "Existing Shree GatePass installation found at $INSTALL_DIR."
  echo "Running update.sh to preserve your existing database, .env, uploads, and backups..."
  exec bash "$SOURCE_DIR/update.sh"
fi

echo "==> [1/6] Updating system packages & installing prerequisites..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y ca-certificates curl openssl python3 tar

echo "==> [2/6] Installing Docker Engine & Docker Compose..."
if ! command -v docker >/dev/null 2>&1 || ! docker compose version >/dev/null 2>&1; then
  if ! apt-get install -y docker.io docker-compose-v2; then
    curl -fsSL https://get.docker.com | sh
  fi
fi
systemctl enable --now docker

echo "==> [3/6] Copying Shree GatePass files to $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR" "$INSTALL_DIR/uploads" "$INSTALL_DIR/backups" "$INSTALL_DIR/secrets"
if [[ "$SOURCE_DIR" != "$INSTALL_DIR" ]]; then
  tar -C "$SOURCE_DIR" \
    --exclude='./.git' \
    --exclude='./.env' \
    --exclude='./secrets' \
    --exclude='./uploads' \
    --exclude='./backups' \
    --exclude='./__pycache__' \
    --exclude='./*.zip' \
    --exclude='./android-app/.gradle' \
    --exclude='./android-app/app/build' \
    -cf - . | tar -C "$INSTALL_DIR" -xf -
fi

SERVER_IP="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
SERVER_IP="${SERVER_IP:-127.0.0.1}"
APP_FQDN="${APP_FQDN:-$SERVER_IP}"
SITE_NAME="${SITE_NAME:-gatepass.local}"
HTTP_PORT="${HTTP_PORT:-8858}"
HTTPS_PORT="${HTTPS_PORT:-8859}"
APP_PORT="${APP_PORT:-18050}"
DB_PASSWORD="$(openssl rand -hex 32)"
APP_SECRET="$(openssl rand -hex 48)"
export APP_FQDN SITE_NAME HTTP_PORT HTTPS_PORT APP_PORT DB_PASSWORD APP_SECRET

echo "==> [4/6] Generating secure configuration (.env) & SSL certificates..."
python3 - "$INSTALL_DIR/.env" <<'PYENV'
import os, sys
keys = ("APP_FQDN", "SITE_NAME", "HTTP_PORT", "HTTPS_PORT", "APP_PORT", "DB_PASSWORD", "APP_SECRET")
def q(v):
    return "'" + v.replace("\\", "\\\\").replace("'", "\\'") + "'"
with open(sys.argv[1], "w", encoding="utf-8") as f:
    for k in keys:
        f.write(f"{k}={q(os.environ[k])}\n")
    f.write("COOKIE_SECURE='false'\n")
    f.write("BACKUP_DIR='/backups'\n")
    f.write("UPLOAD_DIR='/app/uploads'\n")
    f.write("TZ='Asia/Kolkata'\n")
PYENV

chmod 600 "$INSTALL_DIR/.env"
chown -R 10001:10001 "$INSTALL_DIR/uploads" "$INSTALL_DIR/backups"
chmod 700 "$INSTALL_DIR/uploads" "$INSTALL_DIR/backups" "$INSTALL_DIR/secrets"

ALL_IPS="$(hostname -I 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | grep -v '^127\.' | sort -u || true)"
SAN_LIST="DNS:$APP_FQDN,DNS:localhost,IP:$SERVER_IP,IP:127.0.0.1"
if [[ -n "$SITE_NAME" ]]; then
  case ",$SAN_LIST," in *,"DNS:${SITE_NAME}",*) ;; *) SAN_LIST="${SAN_LIST},DNS:$SITE_NAME,DNS:${SITE_NAME%.local}.local,DNS:${SITE_NAME%.local}" ;; esac
fi
for _ip in $ALL_IPS; do
  case ",$SAN_LIST," in *,"IP:${_ip}",*) ;; *) SAN_LIST="${SAN_LIST},IP:${_ip}" ;; esac
done

if command -v apt-get >/dev/null 2>&1; then
  if ! command -v avahi-daemon >/dev/null 2>&1; then
    apt-get update -y && apt-get install -y avahi-daemon avahi-utils >/dev/null 2>&1 || true
  fi
  systemctl enable --now avahi-daemon >/dev/null 2>&1 || true
fi
if [[ -n "$SITE_NAME" ]] && ! grep -q "$SITE_NAME" /etc/hosts 2>/dev/null; then
  echo "$SERVER_IP $SITE_NAME ${SITE_NAME%.local}" >> /etc/hosts 2>/dev/null || true
fi

if [[ ! -s "$INSTALL_DIR/secrets/ca.crt" || ! -s "$INSTALL_DIR/secrets/ca.key" ]]; then
  openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
    -keyout "$INSTALL_DIR/secrets/ca.key" \
    -out "$INSTALL_DIR/secrets/ca.crt" \
    -subj "/CN=Shree GatePass Root CA/O=Shree GatePass Security" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash"
fi
chmod 600 "$INSTALL_DIR/secrets/ca.key"
chmod 644 "$INSTALL_DIR/secrets/ca.crt"

if [[ ! -s "$INSTALL_DIR/secrets/nginx.crt" || ! -s "$INSTALL_DIR/secrets/nginx.key" ]] || ! openssl verify -CAfile "$INSTALL_DIR/secrets/ca.crt" "$INSTALL_DIR/secrets/nginx.crt" >/dev/null 2>&1; then
  TMP_CERT_DIR="$(mktemp -d)"
  openssl genrsa -out "$INSTALL_DIR/secrets/nginx.key" 2048
  openssl req -new -key "$INSTALL_DIR/secrets/nginx.key" -out "$TMP_CERT_DIR/server.csr" -subj "/CN=$APP_FQDN/O=Shree GatePass"
  cat > "$TMP_CERT_DIR/leaf.ext" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
subjectAltName=$SAN_LIST
EOF
  openssl x509 -req -in "$TMP_CERT_DIR/server.csr" \
    -CA "$INSTALL_DIR/secrets/ca.crt" -CAkey "$INSTALL_DIR/secrets/ca.key" -CAcreateserial \
    -out "$TMP_CERT_DIR/leaf.crt" -days 365 -sha256 -extfile "$TMP_CERT_DIR/leaf.ext"
  cat "$TMP_CERT_DIR/leaf.crt" "$INSTALL_DIR/secrets/ca.crt" > "$INSTALL_DIR/secrets/nginx.crt"
  rm -rf "$TMP_CERT_DIR" "$INSTALL_DIR/secrets/ca.srl"
fi
chmod 600 "$INSTALL_DIR/secrets/nginx.key"
chmod 644 "$INSTALL_DIR/secrets/nginx.crt"
chmod +x "$INSTALL_DIR/backup.sh" "$INSTALL_DIR/restore.sh" "$INSTALL_DIR/update.sh" "$INSTALL_DIR/install.sh" || true

echo "==> [5/6] Configuring firewall ports & building Docker containers..."
if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
  ufw allow 5353/udp >/dev/null 2>&1 || true
  ufw allow "${HTTP_PORT}/tcp" >/dev/null 2>&1 || true
  ufw allow "${HTTPS_PORT}/tcp" >/dev/null 2>&1 || true
  echo "Opened UFW ports: ${HTTP_PORT}/tcp, ${HTTPS_PORT}/tcp, 5353/udp"
fi

cd "$INSTALL_DIR"
docker compose build app
docker compose up -d

echo "==> [6/6] Installing automatic daily/weekly/monthly backup timers..."
if [[ -d "$INSTALL_DIR/systemd" ]]; then
  install -m 0644 "$INSTALL_DIR/systemd/gatepass-backup@.service" /etc/systemd/system/gatepass-backup@.service
  for kind in daily weekly monthly; do
    install -m 0644 "$INSTALL_DIR/systemd/gatepass-backup-$kind.timer" "/etc/systemd/system/gatepass-backup-$kind.timer"
  done
  systemctl daemon-reload
  systemctl enable --now gatepass-backup-daily.timer gatepass-backup-weekly.timer gatepass-backup-monthly.timer
fi

echo
echo "======================================================================"
echo "  Shree GatePass (Standalone Visitor & Material System) is running!"
echo "======================================================================"
echo "  Admin & Staff Portal  : https://$APP_FQDN:$HTTPS_PORT"
echo "  Security Gate Kiosk   : https://$APP_FQDN:$HTTPS_PORT/portal"
echo "  Install Directory     : $INSTALL_DIR"
echo "======================================================================"
docker compose ps
