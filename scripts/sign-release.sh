#!/usr/bin/env bash
# Выпуск подписанного релиза. Запускает сопровождающий на своём
# компьютере (не на сервере): нужны git, gh, ssh-keygen и ключ подписи.
#
#   scripts/sign-release.sh tag vX.Y.Z "описание"   # подписанный тег на main + push
#   scripts/sign-release.sh publish vX.Y.Z          # после CI: подпись и публикация
#
# Порядок: tag → CI (release.yml) собирает бинарники и создаёт ЧЕРНОВИК
# релиза → publish проверяет подпись тега, что CI собрал именно этот
# коммит и что файлы совпадают с SHA256SUMS, подписывает «строка тега +
# SHA256SUMS», загружает SHA256SUMS.sig и публикует черновик. Пока релиз
# черновик, серверы его не видят — неподписанной версии в latest не бывает.
#
# Ключ подписи — SSG_RELEASE_KEY, по умолчанию ~/.ssh/ssg_release_ed25519
# (открытая часть — в deploy/release-signers). Ключ не хранится в GitHub:
# взлом аккаунта или CI не позволяет выпустить релиз, который примут серверы.
set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=lib.sh
. ./scripts/lib.sh
# Здесь проверяем ключами из рабочей копии, а не из /opt/serversecuritygo.
RELEASE_SIGNERS="$PWD/deploy/release-signers"
key="${SSG_RELEASE_KEY:-$HOME/.ssh/ssg_release_ed25519}"
[ -f "$key" ] || die "нет ключа подписи $key (SSG_RELEASE_KEY)"

cmd="${1:-}"; tag="${2:-}"
case "$tag" in v[0-9]*.[0-9]*.[0-9]*) ;; *) die "использование: $0 tag|publish vX.Y.Z [описание]" ;; esac

case "$cmd" in
  tag)
    msg="${3:-$tag}"
    [ "$(git rev-parse --abbrev-ref HEAD)" = main ] || die "тег ставится на main"
    git fetch -q origin main
    [ "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)" ] || die "локальный main не совпадает с origin/main"
    git -c gpg.format=ssh -c user.signingkey="${key}.pub" tag -s -a "$tag" -m "$msg"
    verify_release_tag "$tag"
    git push -q origin "$tag"
    log "Тег $tag подписан и отправлен. Дождитесь release.yml и выполните: $0 publish $tag"
    ;;
  publish)
    git fetch -q --tags origin
    verify_release_tag "$tag"
    commit="$(git rev-parse "refs/tags/${tag}^{commit}")"
    run="$(gh run list --workflow release.yml --branch "$tag" -L 1 --json headSha,conclusion -q '.[0] | .headSha + " " + .conclusion')"
    [ "$run" = "$commit success" ] || die "сборка release.yml для $tag: «$run», ожидалось «$commit success»"
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT
    gh release download "$tag" -p "${APP_NAME}-linux-*" -p SHA256SUMS -D "$tmp"
    ( cd "$tmp" && sha256sum -c --quiet SHA256SUMS ) || die "файлы релиза не совпадают с SHA256SUMS"
    sums_payload "$tag" "$tmp/SHA256SUMS" | ssh-keygen -q -Y sign -f "$key" -n "$SUMS_NAMESPACE" > "$tmp/SHA256SUMS.sig"
    sums_payload "$tag" "$tmp/SHA256SUMS" | ssh-keygen -Y verify -f "$RELEASE_SIGNERS" -I "$SIGNER_ID" -n "$SUMS_NAMESPACE" -s "$tmp/SHA256SUMS.sig" >/dev/null \
      || die "созданная подпись не проверяется ключом из deploy/release-signers"
    gh release upload "$tag" "$tmp/SHA256SUMS.sig" --clobber
    gh release edit "$tag" --draft=false --latest >/dev/null
    log "Релиз $tag подписан и опубликован"
    ;;
  *) die "использование: $0 tag|publish vX.Y.Z [описание]" ;;
esac
