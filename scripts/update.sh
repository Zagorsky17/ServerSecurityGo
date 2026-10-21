#!/usr/bin/env bash
# Безопасное обновление ServerSecurityGo.
#
#   /opt/serversecuritygo/scripts/update.sh            # до последнего релиза
#   /opt/serversecuritygo/scripts/update.sh v0.2.0     # до указанной версии
#   /opt/serversecuritygo/scripts/update.sh main       # до свежей ветки main (нужен Go, без подписи)
#
# Каждый релиз подписан ключом сопровождающего (deploy/release-signers):
# подпись тега проверяется до перехода на новую версию, подпись бинарника —
# при загрузке (см. «Подпись релизов» в lib.sh). Ветка main не подписана.
#
# Порядок: резервная копия истории и настроек → загрузка новой версии →
# проверка нового бинарника → замена с сохранением предыдущего (.prev) →
# перезапуск → проверка /healthz. Если служба не поднялась, предыдущая
# версия возвращается автоматически.
#
# Работа идёт в два этапа. Первый (этот файл старой версии) делает резервную
# копию и переключает исходники на новую версию. Второй выполняется уже
# скриптом новой версии: после git checkout скрипт перезапускает себя через
# exec с внутренним флагом --apply. Без этого bash дочитывал бы старую копию
# файла, и шаги, добавленные в новой версии (например, ссылка в
# /usr/local/bin), срабатывали бы только при следующем обновлении.
# Признак поддержки второго этапа (ищется в файле новой версии): SSG_UPDATE_APPLY_STAGE
set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=lib.sh
. ./scripts/lib.sh
require_root
require_systemd
[ -d .git ] || die "$(pwd) — не git-репозиторий; переустановите по README"

if [ "${1:-}" = "--apply" ]; then
  # Второй этап: исходники уже переключены первым этапом.
  # $2 — тег релиза (пусто для main), $3 — коммит до обновления для отката.
  TAG="${2:-}"
  PREV_REF="${3:-}"
  [ -n "$PREV_REF" ] || die "--apply — внутренний флаг update.sh, запускайте скрипт без него"
  # Тег уже проверен первым этапом. Проверяем ещё раз ключом новой версии:
  # если первым этапом был старый update.sh без проверки подписи, это
  # хотя бы ловит подменённый релиз при нетронутом репозитории.
  [ -z "$TAG" ] || verify_release_tag "$TAG"
else
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
    warn "ветка main не подписана: для серверов используйте релизы"
    git checkout -q main
    git pull -q --ff-only origin main
    TAG=""
  else
    # Подпись проверяет этот (уже установленный и доверенный) скрипт со
    # своими ключами — до того, как управление получит код новой версии.
    verify_release_tag "$TARGET"
    git -c advice.detachedHead=false checkout -q "refs/tags/$TARGET" || die "версия $TARGET не найдена"
    TAG="$TARGET"
  fi

  # Продолжаем скриптом новой версии. Исключения — доделываем этим файлом
  # с уже подключённым lib.sh:
  #   - релизы до подписи: их update.sh не проверяет подпись бинарника;
  #   - версии без признака SSG_UPDATE_APPLY_STAGE (v0.2.0 и старше) не
  #     знают флага --apply.
  if ! is_legacy_tag "$TAG" && grep -q 'SSG_UPDATE_APPLY_STAGE' scripts/update.sh; then
    exec bash ./scripts/update.sh --apply "$TAG" "$PREV_REF"
  fi
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
