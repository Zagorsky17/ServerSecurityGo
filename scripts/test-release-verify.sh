#!/usr/bin/env bash
# Тест проверки подписи релизов (verify_release_tag, fetch_binary из
# lib.sh) без сети и без настоящего ключа: одноразовый ключ, временный
# git-репозиторий и заглушка curl, отдающая «релиз» из локального каталога.
# Запуск: bash scripts/test-release-verify.sh (в CI — после shellcheck).
set -uo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
fails=0
ok()   { printf 'ok   %s\n' "$1"; }
fail() { printf 'FAIL %s\n' "$1"; fails=$((fails + 1)); }
# expect <ok|текст ошибки> <описание> <команда…> — команда выполняется в
# подоболочке (die из lib.sh завершает только её). Для отказа проверяется и
# текст: команда должна упасть именно на проверке, а не по другой причине.
expect() {
  local want="$1" name="$2" got
  shift 2
  if ( "$@" ) > "$work/out" 2>&1; then got=ok; else got=fail; fi
  if [ "$want" = ok ]; then
    if [ "$got" = ok ]; then ok "$name"; else fail "$name (ожидался успех): $(tail -n 2 "$work/out")"; fi
  elif [ "$got" = fail ] && grep -qF -- "$want" "$work/out"; then
    ok "$name"
  else
    fail "$name (ожидалась ошибка «$want»): $(tail -n 2 "$work/out")"
  fi
}

# Ключи: «наш» в allowed_signers и чужой.
ssh-keygen -q -t ed25519 -N "" -C test -f "$work/key"
ssh-keygen -q -t ed25519 -N "" -C evil -f "$work/evil"
printf 'release@serversecuritygo namespaces="git,serversecuritygo-release" %s\n' "$(cut -d' ' -f1,2 "$work/key.pub")" > "$work/signers"

# shellcheck source=lib.sh
. "$root/scripts/lib.sh"
RELEASE_SIGNERS="$work/signers"
REPO_SLUG="test/repo"

# --- Подпись тега -------------------------------------------------------
repo="$work/repo"
git init -q "$repo"
gitc() { git -C "$repo" -c user.name=t -c user.email=t@t "$@"; }
gitc commit -q --allow-empty -m init
sign() { gitc -c gpg.format=ssh -c user.signingkey="$1" tag -s -a "$2" -m "$2"; }
sign "$work/key.pub" v9.0.0
sign "$work/evil.pub" v9.0.1
gitc tag -a v9.0.2 -m unsigned
gitc tag v9.0.3
gitc tag -a v0.2.2 -m "поддельный старый тег"
in_repo() { cd "$repo" && "$@"; }
expect ok                      "тег подписан нашим ключом"          in_repo verify_release_tag v9.0.0
expect "не прошла проверку"    "тег подписан чужим ключом"          in_repo verify_release_tag v9.0.1
expect "не подписан"           "аннотированный тег без подписи"     in_repo verify_release_tag v9.0.2
expect "не аннотированный тег" "лёгкий тег"                         in_repo verify_release_tag v9.0.3
expect "не найдена"            "несуществующий тег"                 in_repo verify_release_tag v9.9.9
expect "вместо известного"     "старый тег v0.2.2 на чужом коммите" in_repo verify_release_tag v0.2.2

# --- Подпись бинарников -------------------------------------------------
# Заглушка curl: «-o файл URL» копирует $REL_DIR/<тег>/<файл>.
mkdir -p "$work/bin" "$work/rel"
cat > "$work/bin/curl" <<'STUB'
#!/usr/bin/env bash
out=""; url=""
while [ $# -gt 0 ]; do case "$1" in -o) out="$2"; shift 2 ;; -*) shift ;; *) url="$1"; shift ;; esac; done
src="$REL_DIR/$(basename "$(dirname "$url")")/$(basename "$url")"
[ -f "$src" ] || exit 22
cp "$src" "$out"
STUB
chmod +x "$work/bin/curl"
# В macOS sha256sum (BSD) не читает список сумм из stdin; на серверах — coreutils.
echo x > "$work/probe"
( cd "$work" && sha256sum probe > probe.sum )
# fetch_binary передаёт список сумм через stdin — проверяем так же.
if ! ( cd "$work" && sha256sum -c --status < probe.sum ) 2>/dev/null; then
  printf '#!/bin/sh\nexec shasum -a 256 "$@"\n' > "$work/bin/sha256sum"
  chmod +x "$work/bin/sha256sum"
fi
export REL_DIR="$work/rel"
PATH="$work/bin:$PATH"
asset="${APP_NAME}-linux-$(detect_arch)"
# release TAG [ключ|-] — «релиз» с бинарником-заглушкой и подписью ключом.
release() {
  local d="$work/rel/$1"
  mkdir -p "$d"
  printf '#!/bin/sh\necho "serversecuritygo %s"\n' "$1" > "$d/$asset"
  ( cd "$d" && sha256sum "$asset" > SHA256SUMS )
  if [ "${2:--}" != - ]; then
    sums_payload "$1" "$d/SHA256SUMS" | ssh-keygen -q -Y sign -f "$2" -n "$SUMS_NAMESPACE" > "$d/SHA256SUMS.sig"
  fi
}
release v9.1.0 "$work/key"
release v9.1.1 -
release v9.1.2 "$work/evil"
release v9.1.3 "$work/key"
cp "$work/rel/v9.1.0/SHA256SUMS.sig" "$work/rel/v9.1.3/SHA256SUMS.sig"   # подпись другого тега
release v9.1.4 "$work/key"
printf '#!/bin/sh\necho evil\n' > "$work/rel/v9.1.4/$asset"            # бинарник подменён после подписи
release v0.2.2 -                                                        # «старый» релиз с чужим бинарником
fetch() { fetch_binary "$work/out.bin" "$1"; }
installed() { fetch v9.1.0 && "$work/out.bin" | grep -q "serversecuritygo v9.1.0"; }
expect ok                   "подписанный релиз установлен"             installed
expect "нет подписи"        "релиз без SHA256SUMS.sig"                 fetch v9.1.1
expect "не прошла проверку" "SHA256SUMS подписан чужим ключом"         fetch v9.1.2
expect "не прошла проверку" "подпись перенесена из другого релиза"     fetch v9.1.3
expect "контрольная сумма"  "бинарник подменён после подписи"          fetch v9.1.4
expect "контрольная сумма"  "старый релиз v0.2.2 с подменённым файлом" fetch v0.2.2
legacy_table() {
  [ "$(legacy_field v0.2.2 3)" = 4793224350b793d9165c423737f6b0edc1ae9c848f38ddc787256596d17d71cd ] &&
    is_legacy_tag v0.1.0 && ! is_legacy_tag v0.2.3
}
expect ok                   "таблица старых релизов"                   legacy_table

if [ "$fails" -gt 0 ]; then
  echo "провалено: $fails"
  exit 1
fi
echo "все проверки пройдены"
