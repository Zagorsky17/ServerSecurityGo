#!/usr/bin/env bash
# Общие функции для install.sh, update.sh и rollback.sh.
# Подключается через source; сам по себе ничего не делает.

APP_NAME="serversecuritygo"
APP_DIR="/opt/serversecuritygo"
REPO_SLUG="Zagorsky17/ServerSecurityGo"
UNIT_PATH="/etc/systemd/system/${APP_NAME}.service"
# Ссылка для запуска командой serversecuritygo из любого каталога.
LINK_PATH="/usr/local/bin/${APP_NAME}"
BACKUP_DIR="/var/backups/${APP_NAME}"
DATA_DIR="/var/lib/${APP_NAME}"
# Минимальная версия Go для сборки из исходников (см. go.mod).
GO_MIN_MINOR=24

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!!\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31mОшибка:\033[0m %s\n' "$*" >&2; exit 1; }

require_root() {
  [ "$(id -u)" -eq 0 ] || die "запустите от root (sudo -i или sudo bash ...)"
}

require_systemd() {
  if ! command -v systemctl >/dev/null 2>&1 || [ ! -d /run/systemd/system ]; then
    die "нужен systemd (Ubuntu/Debian)"
  fi
}

# detect_arch печатает архитектуру в терминах Go (amd64/arm64).
detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64) echo amd64 ;;
    aarch64|arm64) echo arm64 ;;
    *) die "архитектура $(uname -m) не поддерживается готовыми сборками; соберите из исходников (нужен Go 1.${GO_MIN_MINOR}+)" ;;
  esac
}

# latest_tag печатает тег последнего релиза или пустую строку.
latest_tag() {
  curl -fsSL --max-time 20 "https://api.github.com/repos/${REPO_SLUG}/releases/latest" 2>/dev/null \
    | grep -m1 '"tag_name"' | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/' || true
}

# have_go проверяет, что установлен Go нужной версии.
have_go() {
  command -v go >/dev/null 2>&1 || return 1
  local v minor
  v="$(go env GOVERSION 2>/dev/null)"   # go1.24.3
  minor="$(echo "$v" | sed -E 's/^go1\.([0-9]+).*/\1/')"
  [ -n "$minor" ] && [ "$minor" -ge "$GO_MIN_MINOR" ] 2>/dev/null
}

# build_binary DEST VERSION — собрать из исходников текущего каталога.
build_binary() {
  local dest="$1" ver="$2"
  log "Сборка из исходников ($(go env GOVERSION))"
  CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${ver}" -o "$dest" ./cmd/serversecuritygo
}

# fetch_binary DEST TAG — скачать готовый бинарник релиза и проверить SHA256.
fetch_binary() {
  local dest="$1" tag="$2" arch tmp asset
  arch="$(detect_arch)"
  asset="${APP_NAME}-linux-${arch}"
  tmp="$(mktemp -d)"
  log "Загрузка ${asset} (${tag}) с GitHub Releases"
  curl -fsSL --max-time 300 -o "${tmp}/${asset}" "https://github.com/${REPO_SLUG}/releases/download/${tag}/${asset}" \
    || { rm -rf "$tmp"; die "не удалось скачать ${asset} для ${tag}"; }
  curl -fsSL --max-time 60 -o "${tmp}/SHA256SUMS" "https://github.com/${REPO_SLUG}/releases/download/${tag}/SHA256SUMS" \
    || { rm -rf "$tmp"; die "не удалось скачать SHA256SUMS"; }
  ( cd "$tmp" && grep " ${asset}\$" SHA256SUMS | sha256sum -c --status ) \
    || { rm -rf "$tmp"; die "контрольная сумма ${asset} не совпадает — файл повреждён или подменён"; }
  install -m 0755 "${tmp}/${asset}" "$dest"
  rm -rf "$tmp"
}

# obtain_binary DEST TAG — собрать (если есть Go) или скачать бинарник.
# Для версии без релиза (ветка main) сборка обязательна.
obtain_binary() {
  local dest="$1" tag="$2"
  if have_go; then
    build_binary "$dest" "${tag:-$(git describe --tags --always 2>/dev/null || echo dev)}"
  elif [ -n "$tag" ]; then
    fetch_binary "$dest" "$tag"
  else
    die "релизов пока нет, а Go 1.${GO_MIN_MINOR}+ не установлен — собрать нечем"
  fi
  "$dest" version >/dev/null || die "новый бинарник не запускается"
}

# listen_addr печатает адрес панели из .env (по умолчанию 127.0.0.1:8090).
listen_addr() {
  local addr=""
  if [ -f "${APP_DIR}/.env" ]; then
    addr="$(grep -E '^SSG_LISTEN_ADDR=' "${APP_DIR}/.env" | tail -n1 | cut -d= -f2- | tr -d '"'"'" )"
  fi
  echo "${addr:-127.0.0.1:8090}"
}

# health_check ждёт ответа /healthz до 60 секунд. С выключенной панелью
# (SSG_LISTEN_ADDR=off) проверять нечего по HTTP: смотрим, что служба
# поднялась и держится, а не перезапускается по кругу.
health_check() {
  local addr port scheme="http" i
  addr="$(listen_addr)"
  if [ "$addr" = "off" ] || [ -z "$addr" ]; then
    for i in 1 2 3; do
      sleep 2
      systemctl is-active --quiet "$APP_NAME" || return 1
    done
    return 0
  fi
  port="${addr##*:}"
  if grep -qE '^SSG_TLS_CERT=.+' "${APP_DIR}/.env" 2>/dev/null; then scheme="https"; fi
  for i in $(seq 1 30); do
    if curl -fsSk --max-time 3 "${scheme}://127.0.0.1:${port}/healthz" >/dev/null 2>&1; then
      return 0
    fi
    if ! systemctl is-active --quiet "$APP_NAME" && [ "$i" -gt 3 ]; then
      return 1
    fi
    sleep 2
  done
  return 1
}

# backup_state сохраняет историю и настройки в /var/backups/serversecuritygo
# и оставляет 5 последних архивов.
backup_state() {
  install -d -m 0700 "$BACKUP_DIR"
  local f
  f="${BACKUP_DIR}/${APP_NAME}-$(date +%Y%m%d-%H%M%S).tar.gz"
  local items=()
  [ -d "$DATA_DIR" ] && items+=("$DATA_DIR")
  [ -f "${APP_DIR}/.env" ] && items+=("${APP_DIR}/.env")
  [ -f "${APP_DIR}/allowlist.json" ] && items+=("${APP_DIR}/allowlist.json")
  if [ "${#items[@]}" -gt 0 ]; then
    tar -czf "$f" "${items[@]}" 2>/dev/null && chmod 600 "$f" && log "Резервная копия: $f"
  fi
  # Имена архивов содержат дату, поэтому сортировка по имени = по времени.
  find "$BACKUP_DIR" -maxdepth 1 -name "${APP_NAME}-*.tar.gz" -printf '%f\n' | sort -r | tail -n +6 \
    | while read -r old; do rm -f -- "${BACKUP_DIR}/${old}"; done
}

# install_unit копирует systemd-юнит, если он изменился.
install_unit() {
  if ! cmp -s "${APP_DIR}/deploy/${APP_NAME}.service" "$UNIT_PATH" 2>/dev/null; then
    install -m 0644 "${APP_DIR}/deploy/${APP_NAME}.service" "$UNIT_PATH"
    systemctl daemon-reload
    log "systemd-юнит обновлён"
  fi
}

# install_link создаёт /usr/local/bin/serversecuritygo → бинарник в
# /opt/serversecuritygo, чтобы терминальный интерфейс открывался одной
# командой. Чужой файл с тем же именем не перезаписывается.
install_link() {
  if [ -e "$LINK_PATH" ] && [ ! -L "$LINK_PATH" ]; then
    warn "$LINK_PATH уже существует и это не ссылка — пропускаю; запускайте ${APP_DIR}/bin/${APP_NAME}"
    return 0
  fi
  ln -sfn "${APP_DIR}/bin/${APP_NAME}" "$LINK_PATH"
}

# remove_link удаляет ссылку, только если она указывает на наш бинарник.
remove_link() {
  if [ -L "$LINK_PATH" ] && [ "$(readlink "$LINK_PATH")" = "${APP_DIR}/bin/${APP_NAME}" ]; then
    rm -f "$LINK_PATH"
  fi
}
