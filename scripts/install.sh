#!/usr/bin/env bash
# Установка ServerSecurityGo на Ubuntu/Debian.
#
# Запуск прямо из GitHub:
#   curl -fsSL https://raw.githubusercontent.com/Zagorsky17/ServerSecurityGo/main/scripts/install.sh | sudo bash
# Конкретная версия:
#   curl -fsSL https://raw.githubusercontent.com/Zagorsky17/ServerSecurityGo/main/scripts/install.sh | sudo SSG_VERSION=v0.1.0 bash
#
# Что делает скрипт:
#   1. клонирует репозиторий в /opt/serversecuritygo (публичный, ключ не нужен);
#   2. собирает бинарник, если установлен Go 1.24+, иначе скачивает готовый
#      из GitHub Releases и проверяет SHA256;
#   3. создаёт /opt/serversecuritygo/.env (права 600) из .env.example;
#   4. ставит systemd-юнит, включает и запускает службу, проверяет /healthz;
#   5. создаёт ссылку /usr/local/bin/serversecuritygo для запуска
#      терминального интерфейса одной командой.
# Скрипт ничего не удаляет и не трогает другие проекты в /opt.
set -euo pipefail

APP_DIR="/opt/serversecuritygo"
REPO_URL="https://github.com/Zagorsky17/ServerSecurityGo.git"
REPO_SLUG="Zagorsky17/ServerSecurityGo"

die() { printf '\033[1;31mОшибка:\033[0m %s\n' "$*" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || die "запустите от root: curl ... | sudo bash"

if [ -e "$APP_DIR" ]; then
  if [ -d "$APP_DIR/.git" ]; then
    die "$APP_DIR уже существует. Для обновления: $APP_DIR/scripts/update.sh"
  fi
  die "$APP_DIR уже существует и это не установка ServerSecurityGo — разберитесь вручную"
fi

. /etc/os-release 2>/dev/null || true
case "${ID:-}" in
  ubuntu|debian) ;;
  *) printf '!! ОС %s не проверялась; поддерживаются Ubuntu и Debian. Продолжаю.\n' "${PRETTY_NAME:-неизвестна}" >&2 ;;
esac

# Нужны только git, curl и сертификаты; ставим, если их нет.
missing=()
for bin in git curl; do command -v "$bin" >/dev/null 2>&1 || missing+=("$bin"); done
if [ "${#missing[@]}" -gt 0 ]; then
  printf '==> Установка пакетов: %s ca-certificates\n' "${missing[*]}"
  apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${missing[@]}" ca-certificates
fi

# Версия: явная (SSG_VERSION), иначе последний релиз, иначе ветка main.
TAG="${SSG_VERSION:-}"
if [ -z "$TAG" ]; then
  TAG="$(curl -fsSL --max-time 20 "https://api.github.com/repos/${REPO_SLUG}/releases/latest" 2>/dev/null \
    | grep -m1 '"tag_name"' | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/' || true)"
fi

printf '==> Клонирование %s в %s (%s)\n' "$REPO_URL" "$APP_DIR" "${TAG:-main}"
if [ -n "$TAG" ]; then
  git -c advice.detachedHead=false clone -q --branch "$TAG" "$REPO_URL" "$APP_DIR"
else
  git clone -q "$REPO_URL" "$APP_DIR"
fi

cd "$APP_DIR"
# shellcheck source=lib.sh
. "$APP_DIR/scripts/lib.sh"
require_systemd

install -d -m 0755 "$APP_DIR/bin"
obtain_binary "$APP_DIR/bin/serversecuritygo.new" "$TAG"
mv -f "$APP_DIR/bin/serversecuritygo.new" "$APP_DIR/bin/serversecuritygo"

if [ ! -f "$APP_DIR/.env" ]; then
  install -m 0600 "$APP_DIR/.env.example" "$APP_DIR/.env"
  log "Создан $APP_DIR/.env (права 600) — по умолчанию панель только на 127.0.0.1:8090"
fi
chmod 600 "$APP_DIR/.env"

install_unit
install_link
systemctl enable --now "$APP_NAME" >/dev/null 2>&1 || systemctl enable --now "$APP_NAME"

log "Проверка запуска…"
if health_check; then
  log "Готово. Версия: $("$APP_DIR/bin/serversecuritygo" version)"
else
  journalctl -u "$APP_NAME" -n 30 --no-pager || true
  die "служба не ответила на /healthz — см. журнал выше"
fi

cat <<INFO

Терминальный интерфейс (на сервере):  serversecuritygo
Веб-панель: http://$(listen_addr)/  (только с самого сервера), со своего компьютера через SSH-туннель:
  ssh -L 8090:127.0.0.1:8090 root@<IP-сервера>   →   http://127.0.0.1:8090

Разовая проверка в консоли:  $APP_DIR/bin/serversecuritygo scan --env-file $APP_DIR/.env
Журнал:      $APP_DIR/scripts/logs.sh
Обновление:  $APP_DIR/scripts/update.sh
Откат:       $APP_DIR/scripts/rollback.sh
Удаление:    $APP_DIR/scripts/uninstall.sh  (полная очистка: --full)
Настройки:   $APP_DIR/.env (после правки: systemctl restart $APP_NAME)
INFO
