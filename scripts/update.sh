#!/usr/bin/env bash
# Безопасное обновление ServerSecurityGo.
#
#   /opt/serversecuritygo/scripts/update.sh            # до последнего релиза
#   /opt/serversecuritygo/scripts/update.sh v0.2.0     # до указанной версии
#   /opt/serversecuritygo/scripts/update.sh main       # до свежей ветки main (нужен Go)
#
# Порядок: резервная копия истории и настроек → загрузка новой версии →
# проверка нового бинарника → замена с сохранением предыдущего (.prev) →
# перезапуск → проверка /healthz. Если служба не поднялась, предыдущая
# версия возвращается автоматически.
set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=lib.sh
. ./scripts/lib.sh
require_root
require_systemd
[ -d .git ] || die "$(pwd) — не git-репозиторий; переустановите по README"

TARGET="${1:-}"
git fetch -q --tags origin
if [ -z "$TARGET" ]; then
  TARGET="$(latest_tag)"
  [ -n "$TARGET" ] || TARGET="main"
fi

PREV_REF="$(git rev-parse HEAD)"
CURRENT="$(bin/serversecuritygo version 2>/dev/null || echo 'нет')"
log "Текущая версия: $CURRENT; обновление до: $TARGET"

backup_state

if [ "$TARGET" = "main" ]; then
  git checkout -q main
  git pull -q --ff-only origin main
  TAG=""
else
  git -c advice.detachedHead=false checkout -q "refs/tags/$TARGET" || die "версия $TARGET не найдена"
  TAG="$TARGET"
fi

obtain_binary bin/serversecuritygo.new "$TAG"

# Сохраняем предыдущую версию для отката.
if [ -f bin/serversecuritygo ]; then
  cp -f bin/serversecuritygo bin/serversecuritygo.prev
  echo "$PREV_REF" > bin/.prev-ref
fi
mv -f bin/serversecuritygo.new bin/serversecuritygo
[ -f .env ] && chmod 600 .env

install_unit
install_link
systemctl restart "$APP_NAME"
if health_check; then
  log "Обновлено: $(bin/serversecuritygo version)"
  exit 0
fi

warn "Новая версия не запустилась — возвращаю предыдущую"
journalctl -u "$APP_NAME" -n 30 --no-pager || true
if [ -f bin/serversecuritygo.prev ]; then
  cp -f bin/serversecuritygo.prev bin/serversecuritygo
  git -c advice.detachedHead=false checkout -q "$PREV_REF" || true
  install_unit
  systemctl restart "$APP_NAME"
  if health_check; then
    warn "Предыдущая версия восстановлена"
  else
    warn "Предыдущая версия тоже не отвечает — смотрите scripts/logs.sh"
  fi
fi
exit 1
