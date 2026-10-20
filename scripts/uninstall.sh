#!/usr/bin/env bash
# Удаление ServerSecurityGo.
#
#   /opt/serversecuritygo/scripts/uninstall.sh           # остановить и удалить службу, данные сохранить
#   /opt/serversecuritygo/scripts/uninstall.sh --purge   # также удалить /opt/serversecuritygo и историю
#   добавьте -y, чтобы не спрашивать подтверждение
#
# Резервные копии в /var/backups/serversecuritygo не удаляются никогда —
# удалите их вручную, если они не нужны.
set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=lib.sh
. ./scripts/lib.sh
require_root

PURGE=0
YES=0
for a in "$@"; do
  case "$a" in
    --purge) PURGE=1 ;;
    -y|--yes) YES=1 ;;
    *) die "неизвестный параметр $a" ;;
  esac
done

if [ "$YES" -ne 1 ]; then
  if [ "$PURGE" -eq 1 ]; then
    echo "Будут удалены: служба, ${APP_DIR}, ${DATA_DIR}. Резервные копии в ${BACKUP_DIR} останутся."
  else
    echo "Будет остановлена и удалена служба. ${APP_DIR} и ${DATA_DIR} останутся."
  fi
  read -r -p "Продолжить? [y/N] " ans < /dev/tty
  [ "$ans" = "y" ] || [ "$ans" = "Y" ] || die "отменено"
fi

if [ "$PURGE" -eq 1 ]; then backup_state; fi

systemctl disable --now "$APP_NAME" 2>/dev/null || true
rm -f "$UNIT_PATH"
systemctl daemon-reload
log "Служба удалена"

if [ "$PURGE" -eq 1 ]; then
  cd /
  rm -rf -- "$DATA_DIR" "$APP_DIR"
  log "Удалены ${APP_DIR} и ${DATA_DIR}"
else
  log "Файлы сохранены: ${APP_DIR}, история: ${DATA_DIR}. Полное удаление: $0 --purge"
fi
