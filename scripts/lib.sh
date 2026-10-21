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
# Ключи подписи релизов (allowed_signers) и имя подписанта в них.
RELEASE_SIGNERS="${APP_DIR}/deploy/release-signers"
SIGNER_ID="release@serversecuritygo"
# Пространство имён подписи SHA256SUMS (подпись тега — namespace git).
SUMS_NAMESPACE="serversecuritygo-release"

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

# Подпись релизов. Контрольная сумма из того же релиза защищает только от
# повреждения при загрузке: взломав аккаунт GitHub или CI, можно выложить
# и свой бинарник, и свои SHA256SUMS. Поэтому релизы подписываются ключом
# сопровождающего (не хранится в GitHub), а серверы проверяют подпись
# открытым ключом из deploy/release-signers:
#   - тег версии — SSH-подписью (git tag -s): её проверяет текущий, уже
#     доверенный update.sh до перехода на новую версию, ведь дальше
#     обновление продолжает скрипт новой версии;
#   - бинарник — подписью строки «serversecuritygo-release <тег>» плюс
#     SHA256SUMS: привязка к тегу не даёт подложить в новый релиз
#     подписанные суммы старой (уязвимой) версии.
# Релизы до подписи (v0.1.0–v0.2.2) проверяются по зашитым ниже коммитам
# тегов и хешам бинарников.

# legacy_releases — «тег коммит sha256-amd64 sha256-arm64» неподписанных релизов.
legacy_releases() {
  cat <<'LEGACY'
v0.1.0 3cba64e5973a811ef96bb915ee7106675c4a3c65 0e574938a79c053eabf3d13d961c4650893d76c23b3cff634fd22e3a1091f7a0 1128b0dc2e6c7fbba18c25cbf5cf3793045bfc6e558537fdada43717c29915b1
v0.1.1 65c00957fb347961c8027c76da5334fb789b3b0a f3b8ca420807388f7124fbfa212987d2dc6243690d415ae855dcad2575cc8259 ba40b253e6079450690b0636804801dc7c7a36fb4dab2b26d9d23b090e9a0c05
v0.1.2 60062e12643f6889c183f64e906d33b44fabf1b2 c24b72c81e091fbcabad4a9590987e7ee2f3ae8ad40ab841badb5907098f9689 c133d7b625782bb0110c876fcd2453e68c9b17481bc9203a94968ce814cdfa9f
v0.2.0 1551bce93869fa50aa47e7660f7e4c499ca52217 9d1cbe83c6c710fb1203bb40adaf2042cbb23483f25b467c0e1bc6bd20d5ebb8 829171595e61f8f78191b6a8d25d3e857a4af4dd850403aa64a7eebe7c623dea
v0.2.1 d4c0cb4e822dea841ea27a55bcbb67af2363cc1a 10c7e88daed716e6eff0f6d97d7a4cb4b5cbf506b44951a6a5ad43ba10744086 eba8a56950c82a87fa23abcb0868b9e504989c26519fa92bcd937363db88da39
v0.2.2 5e11c70f146691e27369e57c2588558c59146bb5 4793224350b793d9165c423737f6b0edc1ae9c848f38ddc787256596d17d71cd 2cdd0d3c00ef8842b31bc9d94b51c00bce805d52afb73bfa1703277063c5a54c
LEGACY
}

# legacy_field TAG N — поле N (2 — коммит, 3 — amd64, 4 — arm64) или пусто.
legacy_field() {
  legacy_releases | awk -v t="$1" -v n="$2" '$1 == t { print $n }'
}

# is_legacy_tag TAG — релиз выпущен до введения подписи.
is_legacy_tag() { [ -n "$(legacy_field "$1" 2)" ]; }

# verify_release_tag TAG [SIGNERS] — проверить, что тег подписан ключом
# релизов (или это известный неподписанный релиз с тем же коммитом).
verify_release_tag() {
  local tag="$1" signers="${2:-$RELEASE_SIGNERS}" commit want tmp
  commit="$(git rev-parse -q --verify "refs/tags/${tag}^{commit}" 2>/dev/null)" || die "версия $tag не найдена"
  if is_legacy_tag "$tag"; then
    want="$(legacy_field "$tag" 2)"
    [ "$commit" = "$want" ] || die "тег $tag указывает на $commit вместо известного $want — репозиторий мог быть подменён"
    return 0
  fi
  [ -f "$signers" ] || die "нет $signers — нечем проверить подпись релиза"
  tmp="$(mktemp -d)"
  if ! git cat-file tag "$tag" > "${tmp}/tag" 2>/dev/null; then
    rm -rf "$tmp"; die "$tag — не аннотированный тег, подписи нет"
  fi
  # Подписано всё содержимое объекта тега до строки начала подписи.
  sed '/^-----BEGIN SSH SIGNATURE-----$/,$d' "${tmp}/tag" > "${tmp}/payload"
  sed -n '/^-----BEGIN SSH SIGNATURE-----$/,$p' "${tmp}/tag" > "${tmp}/sig"
  if [ ! -s "${tmp}/sig" ]; then
    rm -rf "$tmp"; die "тег $tag не подписан — релиз мог быть подменён"
  fi
  if ! ssh-keygen -Y verify -f "$signers" -I "$SIGNER_ID" -n git -s "${tmp}/sig" < "${tmp}/payload" >/dev/null 2>&1; then
    rm -rf "$tmp"; die "подпись тега $tag не прошла проверку ключом из $signers — релиз мог быть подменён"
  fi
  rm -rf "$tmp"
  log "Подпись тега $tag проверена"
}

# sums_payload TAG SUMS — то, что подписывается для бинарников релиза.
sums_payload() { printf '%s %s\n' "$SUMS_NAMESPACE" "$1"; cat "$2"; }

# fetch_binary DEST TAG — скачать готовый бинарник релиза и проверить его
# подпись (или зашитый хеш для релизов до подписи).
fetch_binary() {
  local dest="$1" tag="$2" arch tmp asset url want field=3
  arch="$(detect_arch)"
  asset="${APP_NAME}-linux-${arch}"
  [ "$arch" = arm64 ] && field=4
  url="https://github.com/${REPO_SLUG}/releases/download/${tag}"
  tmp="$(mktemp -d)"
  log "Загрузка ${asset} (${tag}) с GitHub Releases"
  curl -fsSL --max-time 300 -o "${tmp}/${asset}" "${url}/${asset}" \
    || { rm -rf "$tmp"; die "не удалось скачать ${asset} для ${tag}"; }
  if is_legacy_tag "$tag"; then
    want="$(legacy_field "$tag" "$field")"
    echo "${want}  ${asset}" > "${tmp}/SHA256SUMS"
  else
    curl -fsSL --max-time 60 -o "${tmp}/SHA256SUMS" "${url}/SHA256SUMS" \
      || { rm -rf "$tmp"; die "не удалось скачать SHA256SUMS"; }
    curl -fsSL --max-time 60 -o "${tmp}/SHA256SUMS.sig" "${url}/SHA256SUMS.sig" \
      || { rm -rf "$tmp"; die "у релиза ${tag} нет подписи SHA256SUMS.sig — он не подписан или подменён"; }
    if ! sums_payload "$tag" "${tmp}/SHA256SUMS" | ssh-keygen -Y verify -f "$RELEASE_SIGNERS" -I "$SIGNER_ID" -n "$SUMS_NAMESPACE" -s "${tmp}/SHA256SUMS.sig" >/dev/null 2>&1; then
      rm -rf "$tmp"; die "подпись SHA256SUMS релиза ${tag} не прошла проверку — файлы подменены"
    fi
  fi
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

# health_check ждёт ответа /healthz до 60 секунд.
health_check() {
  local addr port scheme="http" i
  addr="$(listen_addr)"
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
