#!/usr/bin/env bash
# Просмотр журнала службы ServerSecurityGo (journald).
#
#   /opt/serversecuritygo/scripts/logs.sh                      # последние 100 строк и слежение
#   /opt/serversecuritygo/scripts/logs.sh --since "1 hour ago" # любые параметры journalctl
#   /opt/serversecuritygo/scripts/logs.sh -p warning           # только предупреждения и ошибки
#
# Ротацию выполняет journald (настройки в /etc/systemd/journald.conf).
set -euo pipefail
if [ "$#" -eq 0 ]; then
  exec journalctl -u serversecuritygo -n 100 -f --no-hostname
fi
exec journalctl -u serversecuritygo --no-pager --no-hostname "$@"
