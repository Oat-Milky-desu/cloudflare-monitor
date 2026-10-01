#!/usr/bin/env bash
set -euo pipefail
umask 077

# The dashboard replaces these three markers with base64-encoded UTF-8 files.
CONFIG_B64='__CONFIG_BASE64__'
AGENT_B64='__AGENT_BASE64__'
SERVICE_B64='__SERVICE_BASE64__'

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

decode_embedded_files() {
  local target_dir="$1"
  printf '%s' "$CONFIG_B64" | base64 -d > "$target_dir/config.json" || return 1
  printf '%s' "$AGENT_B64" | base64 -d > "$target_dir/agent.py" || return 1
  printf '%s' "$SERVICE_B64" | base64 -d > "$target_dir/service.template" || return 1
}

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  fail "Run this installer as root, for example: curl ... | sudo bash"
fi

case "${CONFIG_B64}${AGENT_B64}${SERVICE_B64}" in
  *__CONFIG_BASE64__*|*__AGENT_BASE64__*|*__SERVICE_BASE64__*)
    fail "This installer is missing its embedded client files. Generate a fresh install command from the dashboard."
    ;;
esac

command -v base64 >/dev/null 2>&1 || fail "The base64 utility is required to install this client."
command -v mktemp >/dev/null 2>&1 || fail "The mktemp utility is required to install this client."
command -v systemctl >/dev/null 2>&1 || fail "This installer requires a systemd Linux server."
systemctl --version >/dev/null 2>&1 || fail "This installer requires a systemd Linux server."
system_state="$(systemctl is-system-running 2>/dev/null || true)"
case "$system_state" in
  running|degraded) ;;
  *) fail "systemd is installed but its system service manager is not running." ;;
esac

WORK_DIR="$(mktemp -d)"
cleanup() {
  rm -f "$WORK_DIR/config.json" "$WORK_DIR/agent.py" "$WORK_DIR/service.template" "$WORK_DIR/service"
  rmdir "$WORK_DIR" 2>/dev/null || true
}
trap cleanup EXIT

decode_embedded_files "$WORK_DIR" || fail "Could not decode the embedded installer files."

if ! command -v python3 >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y python3
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y python3
  elif command -v yum >/dev/null 2>&1; then
    yum install -y python3
  elif command -v zypper >/dev/null 2>&1; then
    zypper --non-interactive install python3
  else
    fail "Python 3 is missing and no supported package manager was found (apt, dnf, yum, or zypper)."
  fi
fi
command -v python3 >/dev/null 2>&1 || fail "Python 3 could not be installed."
if ! python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 7) else 1)' >/dev/null 2>&1; then
  fail "Python 3.7 or newer is required to run the server probe client."
fi

if ! SERVER_ID="$(python3 - "$WORK_DIR/config.json" 2>/dev/null <<'PY'
import json
import re
import sys

try:
    with open(sys.argv[1], "r", encoding="utf-8") as config_file:
        config = json.load(config_file)
    server_id = config.get("serverId") if isinstance(config, dict) else None
    if not isinstance(server_id, str) or not re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", server_id):
        raise ValueError()
except Exception:
    sys.exit(1)
sys.stdout.write(server_id)
PY
)"; then
  fail "The embedded configuration has an invalid server ID. Generate a fresh install command from the dashboard."
fi

if [[ ! -s "$WORK_DIR/agent.py" || ! -s "$WORK_DIR/service.template" ]]; then
  fail "The embedded client files are empty. Generate a fresh install command from the dashboard."
fi

PYTHON_PATH="$(python3 -c 'import sys; print(sys.executable)')"
case "$PYTHON_PATH" in
  /*) ;;
  *) fail "Python 3 did not report an absolute executable path." ;;
esac
case "$PYTHON_PATH" in
  *[!A-Za-z0-9_./+-]*) fail "Python 3 is installed at a path systemd cannot use safely." ;;
esac

python3 - "$WORK_DIR/service.template" "$WORK_DIR/service" "$PYTHON_PATH" "$SERVER_ID" <<'PY'
import re
import sys

source_path, output_path, python_path, server_id = sys.argv[1:]
with open(source_path, "r", encoding="utf-8") as source:
    template = source.read()
if not re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", server_id):
    sys.exit(1)
if "__PYTHON_PATH__" not in template or "__SERVER_ID__" not in template:
    sys.exit(1)
service = template.replace("__PYTHON_PATH__", python_path).replace("__SERVER_ID__", server_id)
if "__PYTHON_PATH__" in service or "__SERVER_ID__" in service:
    sys.exit(1)
with open(output_path, "w", encoding="utf-8") as output:
    output.write(service)
PY
[[ -s "$WORK_DIR/service" ]] || fail "The embedded systemd service template is invalid."

command -v getent >/dev/null 2>&1 || fail "The getent utility is required to create the service account."
command -v groupadd >/dev/null 2>&1 || fail "The groupadd utility is required to create the service account."
command -v useradd >/dev/null 2>&1 || fail "The useradd utility is required to create the service account."
if ! command -v nologin >/dev/null 2>&1; then
  if [[ -x /usr/sbin/nologin ]]; then
    NOLOGIN=/usr/sbin/nologin
  elif [[ -x /sbin/nologin ]]; then
    NOLOGIN=/sbin/nologin
  else
    fail "Could not find a no-login shell for the service account."
  fi
else
  NOLOGIN="$(command -v nologin)"
fi

if ! getent group server-probe >/dev/null 2>&1; then
  groupadd --system server-probe
fi
if getent passwd server-probe >/dev/null 2>&1; then
  command -v usermod >/dev/null 2>&1 || fail "The usermod utility is required to secure the service account."
  usermod --gid server-probe --home /nonexistent --shell "$NOLOGIN" server-probe
else
  useradd --system --gid server-probe --home-dir /nonexistent --shell "$NOLOGIN" server-probe
fi

APP_DIR="/opt/server-probe/$SERVER_ID"
CONFIG_DIR=/etc/server-probe
CONFIG_PATH="$CONFIG_DIR/$SERVER_ID.json"
UNIT_NAME="server-probe-$SERVER_ID.service"
UNIT_PATH="/etc/systemd/system/$UNIT_NAME"
WAS_ACTIVE=0
if systemctl is-active --quiet "$UNIT_NAME"; then
  WAS_ACTIVE=1
fi
for target in "$APP_DIR" "$APP_DIR/agent.py" "$CONFIG_PATH" "$UNIT_PATH"; do
  [[ ! -L "$target" ]] || fail "A symbolic link already occupies an installation path. Remove that link and retry."
done

install -d -o root -g root -m 0755 /opt/server-probe
install -d -o root -g server-probe -m 0750 "$APP_DIR"
install -d -o root -g root -m 0755 "$CONFIG_DIR"
install -o root -g server-probe -m 0640 "$WORK_DIR/agent.py" "$APP_DIR/agent.py"
install -o root -g server-probe -m 0640 "$WORK_DIR/config.json" "$CONFIG_PATH"
install -o root -g root -m 0644 "$WORK_DIR/service" "$UNIT_PATH"

systemctl daemon-reload
systemctl enable --now "$UNIT_NAME" >/dev/null
if [[ "$WAS_ACTIVE" -eq 1 ]]; then
  systemctl restart "$UNIT_NAME" >/dev/null
fi
if ! systemctl is-active --quiet "$UNIT_NAME"; then
  fail "The server probe service did not become active. Check its systemd journal for details."
fi
printf 'Installed and started server probe service %s.\n' "$UNIT_NAME"
