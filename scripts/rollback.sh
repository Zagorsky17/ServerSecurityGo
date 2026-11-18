#!/usr/bin/env bash
# Откат ServerSecurityGo к версии, которая работала до последнего update.sh.
#   /opt/serversecuritygo/scripts/rollback.sh
# История и настройки не меняются; резервные копии лежат в
# /var/backups/serversecuritygo.
set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=lib.sh
. ./scripts/lib.sh
require_root
[ -f bin/serversecuritygo.prev ] || die "предыдущей версии нет (bin/serversecuritygo.prev) — откатывать не к чему"

log "Текущая: $(bin/serversecuritygo version 2>/dev/null || echo '?'); откат к: $(bin/serversecuritygo.prev version)"
cp -f bin/serversecuritygo bin/serversecuritygo.failed 2>/dev/null || true
was_active=false
if systemctl is-active --quiet "$APP_NAME"; then was_active=true; fi
systemctl stop "$APP_NAME"
cp -f bin/serversecuritygo.prev bin/serversecuritygo
if [ -f bin/.prev-ref ]; then
  git -c advice.detachedHead=false checkout -q "$(cat bin/.prev-ref)" || warn "не удалось вернуть исходники к $(cat bin/.prev-ref)"
fi
restore_self_baseline
if restart_if_active "$was_active"; then
  log "Откат выполнен: $(bin/serversecuritygo version)"
else
  die "служба не отвечает после отката — см. scripts/logs.sh"
fi
