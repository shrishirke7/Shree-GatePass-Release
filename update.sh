#!/usr/bin/env bash
set -euo pipefail
if [[ "$(id -u)" -ne 0 ]]; then echo "Run with: sudo bash update.sh" >&2; exit 1; fi
SOURCE_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
INSTALL_DIR="/opt/shree-gatepass"
[[ -f "$INSTALL_DIR/.env" ]] || { echo "No installed Shree GatePass configuration found at $INSTALL_DIR." >&2; exit 1; }
if [[ "$SOURCE_DIR" != "$INSTALL_DIR" ]]; then
  tar -C "$SOURCE_DIR" --exclude='./.git' --exclude='./.env' --exclude='./secrets' --exclude='./uploads' --exclude='./backups' --exclude='./__pycache__' --exclude='./*.zip' -cf - . | tar -C "$INSTALL_DIR" -xf -
fi
chmod +x "$INSTALL_DIR"/*.sh 2>/dev/null || true
cd "$INSTALL_DIR"
set -a
. "$INSTALL_DIR/.env"
set +a
SERVER_IP="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
SERVER_IP="${SERVER_IP:-127.0.0.1}"
ALL_IPS="$(hostname -I 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | grep -v '^127\.' | sort -u || true)"
SITE_NAME="${SITE_NAME:-gatepass.local}"
SAN_LIST="DNS:${APP_FQDN:-localhost},DNS:localhost,IP:127.0.0.1"
if [[ -n "$SITE_NAME" ]]; then
  case ",$SAN_LIST," in *,"DNS:${SITE_NAME}",*) ;; *) SAN_LIST="${SAN_LIST},DNS:$SITE_NAME,DNS:${SITE_NAME%.local}.local,DNS:${SITE_NAME%.local}" ;; esac
fi
for _ip in $ALL_IPS; do
  case ",$SAN_LIST," in *,"IP:${_ip}",*) ;; *) SAN_LIST="${SAN_LIST},IP:${_ip}" ;; esac
done

if [[ ! -s "$INSTALL_DIR/secrets/ca.crt" || ! -s "$INSTALL_DIR/secrets/ca.key" ]]; then
  openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
    -keyout "$INSTALL_DIR/secrets/ca.key" -out "$INSTALL_DIR/secrets/ca.crt" \
    -subj "/CN=Shree GatePass Root CA/O=Shree GatePass Security" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash"
  chmod 600 "$INSTALL_DIR/secrets/ca.key"
  chmod 644 "$INSTALL_DIR/secrets/ca.crt"
fi

NEEDS_LEAF=0
if [[ ! -s "$INSTALL_DIR/secrets/nginx.crt" || ! -s "$INSTALL_DIR/secrets/nginx.key" ]]; then
  NEEDS_LEAF=1
elif ! openssl verify -CAfile "$INSTALL_DIR/secrets/ca.crt" "$INSTALL_DIR/secrets/nginx.crt" >/dev/null 2>&1; then
  NEEDS_LEAF=1
elif ! openssl x509 -in "$INSTALL_DIR/secrets/nginx.crt" -noout -ext subjectAltName 2>/dev/null | grep -q "$SERVER_IP"; then
  NEEDS_LEAF=1
fi
if [[ "$NEEDS_LEAF" -eq 1 ]]; then
  TMP_CERT_DIR="$(mktemp -d)"
  openssl genrsa -out "$INSTALL_DIR/secrets/nginx.key" 2048
  openssl req -new -key "$INSTALL_DIR/secrets/nginx.key" -out "$TMP_CERT_DIR/server.csr" -subj "/CN=${APP_FQDN:-$SERVER_IP}/O=Shree GatePass"
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
  chmod 600 "$INSTALL_DIR/secrets/nginx.key"
  chmod 644 "$INSTALL_DIR/secrets/nginx.crt"
fi

if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
  ufw allow "${HTTP_PORT:-8858}/tcp" >/dev/null 2>&1 || true
  ufw allow "${HTTPS_PORT:-8859}/tcp" >/dev/null 2>&1 || true
fi

docker compose build app
bash ./backup.sh manual
docker compose pull web
docker compose up -d
echo "Shree GatePass update complete."
docker compose ps
