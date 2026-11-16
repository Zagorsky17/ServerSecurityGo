#!/usr/bin/env bash
# Только одноразовый GitHub runner: проверка настоящего юнита и watchdog.
set -euo pipefail
[ "${GITHUB_ACTIONS:-}" = true ] && [ "$(id -u)" = 0 ] || exit 2
repo="$(cd "$(dirname "$0")/../.." && pwd)"
# shellcheck source=../../scripts/lib.sh
. "$repo/scripts/lib.sh"
for path in "$APP_DIR" "$DATA_DIR" "$UNIT_PATH" "$UNIT_PATH.d"; do
  if [ -e "$path" ] || [ -L "$path" ]; then die "путь уже существует: $path"; fi
done
cleanup() {
  systemctl stop "$APP_NAME" || true
  journalctl -u "$APP_NAME" -n 200 --no-pager || true
  rm -f -- "$UNIT_PATH" "$UNIT_PATH.d/test.conf"
  rmdir "$UNIT_PATH.d"
  rm -rf -- "$APP_DIR" "$DATA_DIR"
  systemctl daemon-reload
  systemctl reset-failed "$APP_NAME" || true
}
trap cleanup EXIT
install -d "$APP_DIR/bin" "$UNIT_PATH.d"
install -m 0755 "$1" "$APP_DIR/bin/$APP_NAME"
install -m 0644 "$repo/deploy/$APP_NAME.service" "$UNIT_PATH"
grep -qx "WatchdogSec=30s" "$UNIT_PATH"
grep -qx "NotifyAccess=main" "$UNIT_PATH"
install -m 0600 "$repo/.env.example" "$APP_DIR/.env"
cat >> "$APP_DIR/.env" <<'ENV'
SSG_LISTEN_ADDR=off
SSG_SCAN_INTERVAL=2s
ENV
cat > "$UNIT_PATH.d/test.conf" <<'UNIT'
[Service]
WatchdogSec=5s
TimeoutAbortSec=2s
RestartSec=1s
UNIT
write_self_baseline
systemctl daemon-reload
systemctl start "$APP_NAME"
ready() { curl -fsS --max-time 2 --unix-socket /run/serversecuritygo/api.sock http://localhost/healthz >/dev/null; }
for _ in $(seq 1 30); do if ready 2>/dev/null; then break; fi; sleep 1; done
ready
curl -fsS --unix-socket /run/serversecuritygo/api.sock http://localhost/api/status > /tmp/ssg-status.json
curl -fsS --unix-socket /run/serversecuritygo/api.sock http://localhost/api/system > /tmp/ssg-system.json
python3 - <<'PY'
import json
s=json.load(open('/tmp/ssg-status.json'))
assert s['ready'] and not s['stale'] and s['stats']['restricted']==0, s
f=json.load(open('/tmp/ssg-system.json'))['findings']
assert not [x for x in f if x['id'].startswith('self_')], f
PY
before="$(systemctl show "$APP_NAME" -p WatchdogTimestampMonotonic --value)"
sleep 3
after="$(systemctl show "$APP_NAME" -p WatchdogTimestampMonotonic --value)"
[ "$after" -gt "$before" ]
old_pid="$(systemctl show "$APP_NAME" -p MainPID --value)"
# Останавливаем только PID собственной тестовой службы; systemd должен восстановить её.
systemctl kill --kill-whom=main --signal=STOP "$APP_NAME"
for _ in $(seq 1 30); do
  new_pid="$(systemctl show "$APP_NAME" -p MainPID --value)"
  if [ "$new_pid" != 0 ] && [ "$new_pid" != "$old_pid" ] && ready 2>/dev/null; then break; fi
  sleep 1
done
[ "$new_pid" != 0 ] && [ "$new_pid" != "$old_pid" ]
ready
[ "$(systemctl show "$APP_NAME" -p NRestarts --value)" -ge 1 ]
printf 'systemd sandbox, unrestricted /proc, watchdog heartbeats and restart: PASS\n'
