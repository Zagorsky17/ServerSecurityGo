#!/usr/bin/env bash
# Удаление ServerSecurityGo.
#
#   /opt/serversecuritygo/scripts/uninstall.sh          # удалить службу; код, настройки, история и копии остаются
#   /opt/serversecuritygo/scripts/uninstall.sh --purge  # также удалить /opt/serversecuritygo и историю
#                                                        # (перед удалением делается резервная копия)
#   /opt/serversecuritygo/scripts/uninstall.sh --full   # полная очистка, как будто приложения не было:
#                                                        # служба, /opt/serversecuritygo, история,
#                                                        # резервные копии, следы в systemd
#   добавьте -y, чтобы не спрашивать подтверждение
#
# Что не трогается никогда:
#   - пакеты git, curl, ca-certificates: install.sh ставит их, только если
#     их не было, но они нужны и другим программам, поэтому скрипт их не
#     удаляет (при необходимости: apt-get remove git curl);
#   - записи в journald: удалить записи одной службы нельзя, не стерев
#     журнал всей системы; они исчезнут сами по мере ротации журнала.
set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=lib.sh
. ./scripts/lib.sh
require_root

MODE="service"
YES=0
for a in "$@"; do
  case "$a" in
    --purge) [ "$MODE" = "full" ] || MODE="purge" ;;
    --full) MODE="full" ;;
    -y|--yes) YES=1 ;;
    *) die "неизвестный параметр $a (допустимо: --purge, --full, -y)" ;;
  esac
done

if [ "$YES" -ne 1 ]; then
  case "$MODE" in
    service) echo "Будет остановлена и удалена служба. ${APP_DIR}, ${DATA_DIR} и ${BACKUP_DIR} останутся." ;;
    purge)   echo "Будут удалены: служба, ${APP_DIR}, ${DATA_DIR}. Резервные копии в ${BACKUP_DIR} останутся." ;;
    full)    echo "ПОЛНАЯ ОЧИСТКА. Будут удалены без возможности восстановления: служба, ${APP_DIR}, ${DATA_DIR}, ${BACKUP_DIR}." ;;
  esac
  read -r -p "Продолжить? [y/N] " ans < /dev/tty
  [ "$ans" = "y" ] || [ "$ans" = "Y" ] || die "отменено"
fi

# При --purge сохраняем копию истории и настроек на случай, если
# передумаете; при --full копии не нужны — удаляется всё.
if [ "$MODE" = "purge" ]; then backup_state; fi

systemctl disable --now "$APP_NAME" >/dev/null 2>&1 || true
rm -f "$UNIT_PATH"
# Переопределения, созданные через systemctl edit.
rm -rf "${UNIT_PATH}.d"
systemctl daemon-reload
systemctl reset-failed "$APP_NAME" >/dev/null 2>&1 || true
log "Служба удалена"

case "$MODE" in
  service)
    log "Файлы сохранены: ${APP_DIR}, история: ${DATA_DIR}. Полное удаление: $0 --full"
    ;;
  purge)
    cd /
    rm -rf -- "$DATA_DIR" "$APP_DIR"
    log "Удалены ${APP_DIR} и ${DATA_DIR}. Резервные копии остались в ${BACKUP_DIR}"
    ;;
  full)
    cd /
    rm -rf -- "$DATA_DIR" "$APP_DIR" "$BACKUP_DIR"
    log "Удалены ${APP_DIR}, ${DATA_DIR}, ${BACKUP_DIR}. Следов приложения на сервере не осталось"
    log "(пакеты git/curl и записи journald не трогались — см. комментарий в начале скрипта)"
    ;;
esac
